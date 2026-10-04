import { hostScanProgress } from '../../../../contracts/host-scan-contract.js';

// View-only controller; authorization and report validation remain in security-ui.
const GROUPS = Object.freeze({
  malware: ['malware.program', 'malware.business'],
  environment: ['host.os-release', 'host.systemd-state', 'ssh.effective', 'permissions.secret-inventory', 'permissions.installation', 'permissions.cron', 'network.listeners', 'network.udp-listeners', 'network.routes', 'host.kernel-security', 'network.firewall', 'host.process-executables', 'host.failed-units', 'cloudflare.dns', 'cloudflare.workers', 'cloudflare.rules', 'cloudflare.settings'],
  containers: ['integrity.program', 'host.configuration', 'container.contract', 'container.approved-image', 'database.sqlite'],
  realtime: ['response.containment', 'host.systemd-state', 'integrity.program', 'host.configuration'],
  recovery: ['response.containment', 'container.approved-image'],
});
const LABELS = { ok: '正常', warning: '需复核', finding: '发现问题', unavailable: '不可用' };

// UI progress reflects accepted report state, never an invented file counter.
export function describeScan(report, { trusted = false, busy = false, issue = '等待有效报告' } = {}) {
  const checks = Array.isArray(report?.checks) ? report.checks : [];
  const running = report?.state === 'running';
  const complete = trusted && report?.state === 'finished';
  const p=report?.progress;
  const progress=running ? hostScanProgress(report) : null;
  const phase = running ? 'running' : busy ? 'requesting' : complete ? 'complete' : report?.state === 'finished' || report?.state === 'failed' ? 'review' : 'waiting';
  const findings = phase === 'complete' ? checks.filter(item => item.state === 'finding').length : null;
  const attention = phase === 'complete' ? checks.filter(item => ['warning', 'unavailable'].includes(item.state)).length : null;
  const checkedAt = phase === 'complete' && Number.isFinite(Date.parse(report.checked_at)) ? new Date(report.checked_at).toLocaleTimeString('zh-CN', { hour12: false }) : '—';
  return {
    phase, active: running || busy, complete: phase === 'complete', percent: phase === 'complete' ? 100 : progress ? Math.floor(progress.completed * 100 / progress.total) : null,
    status: running ? '本机检查正在执行' : busy ? '正在提交扫描请求' : complete ? findings ? '检查完成 · 发现问题' : attention ? '检查完成 · 需要复核' : '检查完成 · 查看报告' : phase === 'review' ? '报告需要复核' : '等待本机扫描',
    tag: running ? '执行中' : busy ? '请求中' : complete ? '已完成' : phase === 'review' ? '需要复核' : issue.includes('代理') ? '等待连接' : '尚未开始',
    activity: running ? progress ? '已完成 ' + progress.completed + ' / ' + progress.total + ' 项检查；当前：' + (progress.current || '汇总报告') : '本机代理正在检查，等待结果汇总' : busy ? '正在联系本机代理，等待请求确认' : complete ? '结果已核验，' + (findings || attention ? '请查看发现的问题与复核项' : '固定检查范围内未发现异常') : issue,
    buttonLabel: running ? '检查进行中…' : busy ? '正在提交…' : '开始全面检查',
    count: phase === 'complete' ? checks.filter(item => item.id !== 'host.history').length : progress ? progress.completed : null,
    findings, attention, checkedAt,
  };
}

export function createSecurityConsole() {
  const scope = document.querySelector('.security-console');
  const set = (selector, value) => scope?.querySelectorAll(selector).forEach(node => { node.textContent = value; });
  let bound = false;
  let latestReport = null;
  let latestContext = { trusted: false, issue: "等待有效报告" };
  let requestBusy = false;
  function open(name, focus = false) {
    const tab = scope?.querySelector('[data-security-tab="' + name + '"]');
    if (!tab) return;
    set("[data-iron-page-title]", name === "home" ? "安全总览" : tab.textContent.trim());
    scope.querySelectorAll('[data-security-tab]').forEach(node => {
      const selected = node === tab;
      node.classList.toggle('active', selected);
      node.setAttribute('aria-selected', String(selected));
      node.tabIndex = selected ? 0 : -1;
    });
    scope.querySelectorAll('[data-security-panel]').forEach(node => { node.hidden = node.dataset.securityPanel !== name; });
    if (focus) tab.focus();
  }
  function bind() {
    if (!scope || bound) return;
    bound = true;
    scope.querySelectorAll('[data-security-tab], [data-security-open]').forEach(button => {
      button.addEventListener('click', () => open(button.dataset.securityTab || button.dataset.securityOpen, Boolean(button.dataset.securityOpen)));
    });
    scope.querySelectorAll('[data-security-scan]').forEach(button => {
      button.addEventListener('click', () => open('scan'));
    });
    const tabs = [...scope.querySelectorAll('[data-security-tab]')];
    tabs.forEach((tab, index) => tab.addEventListener('keydown', event => {
      let next;
      if (event.key === 'ArrowDown' || event.key === 'ArrowRight') next = (index + 1) % tabs.length;
      if (event.key === 'ArrowUp' || event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
      if (event.key === 'Home') next = 0;
      if (event.key === 'End') next = tabs.length - 1;
      if (next === undefined) return;
      event.preventDefault(); open(tabs[next].dataset.securityTab, true);
    }));
  }
  function renderScan() {
    if (!scope) return;
    const view = describeScan(latestReport, { ...latestContext, busy: requestBusy });
    scope.dataset.scRunning = String(view.active);
    scope.dataset.scScanPhase = view.phase;
    scope.querySelectorAll('[data-security-scan]').forEach(button => { button.disabled = view.active; });
    set('[data-scan-status]', view.status);
    set('[data-scan-progress-tag]', view.tag);
    set('[data-scan-percent]', view.percent === null ? '—' : String(view.percent));
    set('[data-scan-percent-unit]', view.percent === null ? '' : '%');
    set('[data-scan-activity]', view.activity);
    set('[data-scan-button-label]', view.buttonLabel);
    set('[data-scan-check-count]', view.count === null ? '—' : String(view.count));
    set('[data-scan-finding-count]', view.findings === null ? '—' : String(view.findings));
    set('[data-scan-attention-count]', view.attention === null ? '—' : String(view.attention));
    set('[data-scan-checked-time]', view.checkedAt);
    set('[data-scan-result-label]', view.complete ? '报告已核验' : view.active ? '等待汇总' : '等待有效报告');
    scope.querySelectorAll('[data-scan-progress]').forEach(node => {
      if (view.percent === null) node.removeAttribute('aria-valuenow');
      else node.setAttribute('aria-valuenow', String(view.percent));
      node.setAttribute('aria-valuetext', view.status);
      node.setAttribute('aria-busy', String(view.active));
    });
    const checks = Array.isArray(latestReport?.checks) ? latestReport.checks : [];
    scope.querySelectorAll('[data-scan-stage]').forEach(node => {
      const group = node.dataset.scanStage;
      const items = checks.filter(item => GROUPS[group]?.includes(item.id));
      const state = !view.complete ? 'unavailable' : items.some(item => item.state === 'finding') ? 'finding' : items.some(item => item.state !== 'ok') ? 'warning' : 'ok';
      node.dataset.state = state;
      const progress = hostScanProgress(latestReport);
      const groupIds = GROUPS[group] || [];
      const done = progress ? items.length : 0;
      const current = progress && groupIds.includes(progress.current);
      const label = view.complete ? items.length + ' 项 · ' + (LABELS[state] || '未知') : progress ? done + ' / ' + groupIds.length + ' 项 · ' + (current ? '正在检查' : done === groupIds.length ? '本阶段已完成 · 待汇总' : '等待检查') : view.phase === 'requesting' ? '请求中 · 待确认' : '等待有效报告';
      set('[data-scan-stage-label="' + group + '"]', label);
      const indicator = node.querySelector('.sc-stage-indicator');
      if (indicator) indicator.textContent = !view.complete ? '○' : state === 'ok' ? '✓' : '!';
    });
  }
  function setBusy(busy) {
    requestBusy = Boolean(busy);
    renderScan();
  }
  function update(report, { trusted = false, busy = false, issue = '等待有效报告' } = {}) {
    const checks = Array.isArray(report?.checks) ? report.checks : [];
    latestReport = report;
    latestContext = { trusted, issue };
    setBusy(busy);
    set('[data-security-stat="coverage"]', trusted ? checks.filter(item => item.id !== 'host.history').length + ' / 25' : '—');
    set('[data-security-stat="findings"]', trusted ? String(checks.filter(item => item.state === 'finding').length) : '—');
    set('[data-security-stat="attention"]', trusted ? String(checks.filter(item => ['warning', 'unavailable'].includes(item.state)).length) : '—');
    set('[data-security-stat="time"]', trusted ? new Date(report.checked_at).toLocaleTimeString('zh-CN', { hour12: false }) : '尚无有效报告');
    set('[data-security-stat="freshness"]', trusted ? '最近十五分钟内' : issue);
    for (const [group, ids] of Object.entries(GROUPS)) {
      const items = checks.filter(item => ids.includes(item.id));
      const groupState = !trusted ? 'unavailable' : items.some(item => item.state === 'finding') ? 'finding' : items.some(item => item.state !== 'ok') ? 'warning' : 'ok';
      const label = !trusted ? issue : groupState === 'ok' ? '检查范围内正常' : groupState === 'finding' ? '发现问题 · 查看报告' : '需要复核 · 查看报告';
      set('[data-security-summary="' + group + '"]', label);
      scope?.querySelectorAll('[data-security-summary="' + group + '"]').forEach(node => { node.dataset.state = groupState; });
      set('[data-security-group-state="' + group + '"]', !trusted ? issue : items.length + ' 项已检查');
      for (const list of scope?.querySelectorAll('[data-security-group="' + group + '"]') ?? []) {
        list.replaceChildren();
        if (!trusted) {
          const row = document.createElement('li'); row.className = 'sc-empty-row'; row.textContent = issue + '；原始结果可在完整报告中查看'; list.append(row);
        } else for (const item of items) {
          const row = document.createElement('li'); row.dataset.state = item.state;
          row.textContent = item.name + ' · ' + (LABELS[item.state] || '未知') + ' · ' + item.detail;
          list.append(row);
        }
      }
    }
    set('[data-security-summary="backup"]', '系统运维入口 · 容灾待完善');
    set('[data-security-recent]', trusted && report.history?.length ? report.history.at(-1).name + ' · ' + (LABELS[report.history.at(-1).state] || '未知') : trusted ? '暂无状态变化记录' : issue + '，暂不能确认防护动态');
  }
  function clear(reason) {
    update(null, { issue: reason });
    scope?.querySelectorAll('[data-security-group]').forEach(node => { node.replaceChildren(); });
    open('home');
  }
  return Object.freeze({ bind, update, clear, setBusy });
}
