import {engineDisplayText} from './engine-labels.js';
import { describeAntivirus } from '../../../../contracts/antivirus-status.js';
import { describeCheckup } from '../../../../contracts/checkup-status.js';
import { createHostWorkspace } from './host-workspace.js';
import { describeFullScan, sanitizeFullScan } from '../../../../contracts/protection-status.js';
import { hostScanProgress } from '../../../../contracts/host-scan-contract.js';
import { summarizeLocalSecurity, describeWorkbenchTask, friendlyActivity, checkName } from '/contracts/local-workbench.js';
import { sanitizeInventory, sanitizeProtection } from '/contracts/protection-status.js';

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
    phase, active: running || busy, complete: phase === 'complete', percent: phase === 'complete' ? 100 : progress ? Math.min(99,Math.floor(progress.completed * 100 / progress.total)) : null,
    status: running ? '本机检查正在执行' : busy ? '正在提交扫描请求' : complete ? findings ? '检查完成 · 发现问题' : attention ? '检查完成 · 需要复核' : '检查完成 · 查看报告' : phase === 'review' ? '报告需要复核' : '等待本机扫描',
    tag: running ? '执行中' : busy ? '请求中' : complete ? '已完成' : phase === 'review' ? '需要复核' : issue.includes('代理') ? '等待连接' : '尚未开始',
    activity: running ? progress ? '已完成 ' + progress.completed + ' / ' + progress.total + ' 项检查；当前：' + (progress.current || '汇总报告') : '本机代理正在检查，等待结果汇总' : busy ? '正在联系本机代理，等待请求确认' : complete ? '结果已核验，' + (findings || attention ? '请查看发现的问题与复核项' : '固定检查范围内未发现异常') : issue,
    buttonLabel: running ? '检查进行中…' : busy ? '正在提交…' : '环境与范围核验',
    count: phase === 'complete' ? checks.filter(item => item.id !== 'host.history').length : progress ? progress.completed : null,
    findings, attention, checkedAt,
  };
}

export function createSecurityConsole() {
  const scope = document.querySelector('.security-console');
  const set = (selector, value) => scope?.querySelectorAll(selector).forEach(node => { node.textContent = value; });
  const hostWorkspace = createHostWorkspace(scope);
  let bound = false;
  let latestReport = null;
  let latestContext = { trusted: false, issue: "等待有效报告" };
  let requestBusy = false;
  let requestAction = null;
  let requestIssue = null, requestedTaskId = null;
  function open(name, focus = false) {
    name = ({engine:'scan',containers:'environment',logs:'quarantine',backup:'recovery',cloud:'settings',security:'home'})[name] || name;
    const tab = scope?.querySelector('[data-security-tab="' + name + '"]');
    if (!tab) return;
    const changed = !tab.classList.contains('active');
    set("[data-iron-page-title]", name === "home" ? "安全总览" : tab.textContent.trim());
    scope.querySelectorAll('[data-security-tab]').forEach(node => {
      const selected = node === tab;
      node.classList.toggle('active', selected);
      node.setAttribute('aria-selected', String(selected));
      node.tabIndex = selected ? 0 : -1;
    });
    scope.querySelectorAll('[data-security-panel]').forEach(node => { node.hidden = node.dataset.securityPanel !== name; });
    if (focus) tab.focus({ preventScroll: true });
    if (changed) window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    if (location.hash !== '#'+name) history.replaceState(null, '', '#'+name);
  }
  function bind() {
    if (!scope || bound) return;
    bound = true;
    hostWorkspace.bind();
    const restore = () => open(location.hash.slice(1) || 'home');
    window.addEventListener('hashchange', restore);
    restore();
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
    const view = describeScan(latestReport, { ...latestContext, busy: requestBusy && requestAction==='scan' });
    scope.dataset.scRunning = String(view.active || describeFullScan(latestReport?.full_scan).active);
    scope.dataset.scScanPhase = view.phase;
    const fileView = describeFullScan(latestReport?.full_scan);
    const checkup = describeCheckup(latestReport, {busy:requestBusy && requestAction==='checkup'});
    scope.dataset.scRunning = String(view.active || fileView.active || checkup.active);
    set('[data-checkup-status]',checkup.status);
    set('[data-checkup-detail]',friendlyActivity(checkup.detail));
    set('[data-checkup-button]',checkup.button);
    set('[data-checkup-percent]',checkup.percent===null?'阶段进度':checkup.percent+'%');
    scope.querySelectorAll('[data-security-checkup]').forEach(button=>{button.disabled=requestBusy || view.active || fileView.active || checkup.active;});
    scope.querySelectorAll('[data-checkup-progress]').forEach(node=>{
      if(checkup.percent===null) node.removeAttribute('aria-valuenow'); else node.setAttribute('aria-valuenow',String(checkup.percent));
      node.setAttribute('aria-valuetext',checkup.status+' · '+checkup.detail); node.setAttribute('aria-busy',String(checkup.active));
      node.dataset.active=String(checkup.active); node.dataset.state=checkup.state;
      const bar=node.querySelector('span'); if(bar)bar.style.width=checkup.percent===null?(checkup.active?'24%':'0%'):checkup.percent+'%';
    });
    scope.querySelectorAll('[data-security-scan], [data-security-container-scan]').forEach(button => { button.disabled = requestBusy || view.active || fileView.active || checkup.active; });
    set('[data-container-scan-button]', view.active ? view.buttonLabel : '检查主机与容器');
    set('[data-scan-status]', view.status);
    set('[data-scan-progress-tag]', view.tag);
    set('[data-scan-percent]', view.percent === null ? '—' : String(view.percent));
    set('[data-scan-percent-unit]', view.percent === null ? '' : '%');
    set('[data-scan-activity]', friendlyActivity(view.activity));
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
      const bar=node.querySelector('.sc-progress-fill'); if(bar)bar.style.width=view.percent===null?(view.active?'24%':'0%'):view.percent+'%';
    });
    const checks = Array.isArray(latestReport?.checks) ? latestReport.checks : [];
    scope.querySelectorAll('[data-scan-stage]').forEach(node => {
      const group = node.dataset.scanStage;
      const items = checks.filter(item => GROUPS[group]?.includes(item.id));
      const state = !view.complete || !items.length ? 'unavailable' : items.some(item => item.state === 'finding') ? 'finding' : items.some(item => item.state !== 'ok') ? 'warning' : 'ok';
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
  function renderProtection() {
    const protection = latestReport?.protection;
    const inventory = latestReport?.inventory;
    const recent = stamp => Number.isFinite(Date.parse(stamp)) && Date.parse(stamp) >= Date.now()-900000 && Date.parse(stamp) <= Date.now()+30000;
    const usable = ['ready','incomplete','attention'].includes(protection?.state);
    const fresh = usable && recent(protection.checked_at);
    set('[data-protection-state]', !usable ? '防护范围尚不可核验' : !fresh ? '防护核验尚未完成或已过期' : ({ready:'已配置范围核验通过',incomplete:'防护尚未完整配置',attention:'防护范围存在风险'})[protection.state]);
    set('[data-protection-roots]', usable ? protection.program_roots+' 个程序目录 · '+protection.business_roots+' 个业务目录' : '等待纳管目录');
    set('[data-protection-containers]', usable ? protection.enrolled_containers+' 个已纳管 · '+protection.unenrolled_containers+' 个未纳管' : '等待容器发现');
    const gaps=scope?.querySelector('[data-protection-gaps]'); gaps?.replaceChildren();
    for (const message of usable ? protection.issues : ['等待主机代理报告；在 Linux 菜单发现并纳管范围']) {
      const item=document.createElement('li'); item.textContent=message; gaps?.append(item);
    }
    const list=scope?.querySelector('[data-host-inventory]'); list?.replaceChildren();
    const observed=inventory?.schema==='ironcurtain-inventory/v1';
    set('[data-inventory-time]', observed ? (recent(inventory.observed_at) ? '发现于 ' : '发现记录已过期：')+inventory.observed_at : '尚无主机发现记录');
    if (observed) {
      const states={complete:'已完成',partial:'部分可用',unavailable:'不可用'};
      const rows=['容器发现：'+states[inventory.container_state]+' · 端口发现：'+states[inventory.listener_state]+' · 目录发现：'+states[inventory.directory_state],...inventory.containers.map(item => '容器 '+item.name+' · '+(item.running?'运行中':'已停止')+' · '+(item.readonly?'只读根文件系统':'可写根文件系统')+' · '+(item.process_count===null?'进程未读到':item.process_count+' 个进程')+' · '+(item.changed_paths===null?'可写层未读取':item.changed_paths+' 处可写层变化')+(item.risks.length?' · '+item.risks.join(' / '):'')),
        ...inventory.listeners.map(item => item.protocol.toUpperCase()+' '+item.address+' · '+(item.processes.length?item.processes.map(p=>p.name+' ['+p.pid+']').join(', '):'未读到进程归属')),
        ...inventory.issues,...inventory.drift];
      for (const text of rows) { const row=document.createElement('li');row.textContent=text;list?.append(row); }
      set('[data-inventory-counts]', inventory.container_count+' 个容器 · '+inventory.listener_count+' 个监听 · '+inventory.candidate_count+' 个范围候选；页面仅显示前八项');
    } else set('[data-inventory-counts]', '容器与监听状态不可用');
  }
  function renderFullScan() {
    const scan=latestReport?.full_scan;
    const view=describeFullScan(scan);
    set('[data-full-scan-state]', view.label);
    set('[data-full-scan-count]', view.files);
    set('[data-full-scan-current]',view.detail || (scan?.state==='finished'?'本次已纳管目录扫描结束':'当前没有正在检查的文件'));
    set('[data-full-scan-task]',scan?.task_id?'任务 '+scan.task_id.slice(0,8)+(scan.resumed_from?' · 续接 '+scan.resumed_from.slice(0,8):''):'尚无任务标识');
    const recentFiles=scope?.querySelector('[data-full-scan-recent]');recentFiles?.replaceChildren();
    const outcomes={clean:'未命中',infected:'发现威胁',skipped:'跳过',errors:'检查失败'};
    for(const item of scan?.recent_files || []){const row=document.createElement('li');row.dataset.state=item.state;row.textContent=outcomes[item.state]+' · '+item.path+(item.reason?' · '+item.reason:'');recentFiles?.append(row);}
    if(!scan?.recent_files?.length){const row=document.createElement('li');row.textContent='等待实际文件检查结果；仅保留最近八项。';recentFiles?.append(row);}
    set('[data-full-scan-percent]', view.percent===null ? '—' : view.percent+'%');
    set('[data-full-scan-time]', scan?.updated_at ? '更新于 '+scan.updated_at : '尚无扫描记录');
    set('[data-full-scan-button]', scan?.state==='paused' ? '继续文件查杀' : '文件深度查杀');
    for(const key of ['clean','infected','skipped','errors','bytes_scanned']) set('[data-full-scan-'+key+']', Number.isSafeInteger(scan?.[key]) ? scan[key].toLocaleString() : '—');
    scope?.querySelectorAll('[data-security-full-scan]').forEach(button => {button.disabled=requestBusy || view.active || latestReport?.state==='running' || latestReport?.checkup?.state==='running';});
    scope?.querySelectorAll('[data-full-scan-progress]').forEach(node => {
      if(view.percent===null) node.removeAttribute('aria-valuenow'); else node.setAttribute('aria-valuenow',String(view.percent));
      node.setAttribute('aria-valuetext',view.label+' · '+view.files); node.setAttribute('aria-busy',String(view.active));
      node.dataset.active=String(view.active);node.dataset.state=view.tone;
      const bar=node.querySelector('span');if(bar)bar.style.width=view.percent===null ? view.active?'24%':'0%' : view.percent+'%';
    });
    const reasons=scope?.querySelector('[data-full-scan-reasons]');reasons?.replaceChildren();
    for(const message of scan?.reasons || []) {const row=document.createElement('li');row.textContent=message;reasons?.append(row);}
  }
  function renderEngine() {
    const value=describeAntivirus(latestReport?.antivirus);
    set('[data-engine-title]',value.title); set('[data-engine-summary]',value.title);
    set('[data-engine-detail]',engineDisplayText(value.detail)); set('[data-engine-source]',value.source_label);
    set('[data-engine-version]',value.installed===null ? '尚不可核验' : value.installed ? value.version || '版本不可用' : '未安装');
    set('[data-engine-database-version]',value.database_version?.toLocaleString() || '—');
    set('[data-engine-signatures]',value.signatures?.toLocaleString() || '—');
    set('[data-engine-database-at]',value.database_at ? new Date(value.database_at).toLocaleString('zh-CN',{hour12:false}) : '—');
    set('[data-engine-updater]',value.updater_label);
    set('[data-engine-update-state]',requestBusy && requestAction==='engine-update'?'正在提交本机更新请求':value.update_label);
    set('[data-engine-update-button]',value.update_state==='running'?'官方病毒库更新中…':'更新官方病毒库');
    scope?.querySelectorAll('[data-engine-summary]').forEach(node=>{node.dataset.state=value.state==='configured'?'ok':value.state==='stale'?'warning':'unavailable';});
    scope?.querySelectorAll('[data-security-engine-update]').forEach(button=>{button.disabled=requestBusy || !value.can_update || latestReport?.state==='running' || latestReport?.checkup?.state==='running' || ['indexing','scanning'].includes(latestReport?.full_scan?.state);});
  }
  function renderWorkbench() {
    const report=latestReport;
    const summary=latestContext.overview || summarizeLocalSecurity(report);
    const task=describeWorkbenchTask(report,{busy:requestBusy,action:requestAction,trusted:latestContext.trusted,requestIssue,requestedTaskId});
    const inv=sanitizeInventory(report?.inventory), protection=sanitizeProtection(report?.protection);
    const engine=describeAntivirus(report?.antivirus);
    const observed=inv.schema==='ironcurtain-inventory/v1';
    const knownReport=Array.isArray(report?.checks) && report.checks.length>0;
    const file=sanitizeFullScan(report?.full_scan);
    const waiting=requestBusy && summary.tone!=='finding';
    set('#security-local-state',waiting?'正在提交检测任务':summary.title);
    set('[data-overview-label]',({ok:'检查完成',finding:'风险待处理',running:'检测进行中',warning:'防护需要关注'})[waiting?'running':summary.tone]);
    set('[data-overview-detail]',waiting?'等待本机代理确认，随后显示真实阶段进度。':summary.detail);
    scope?.querySelectorAll('[data-overview-hero], #security-local-state').forEach(node=>{node.dataset.state=waiting?'running':summary.tone;});
    set('[data-overview-findings]',knownReport?summary.findings:'—');
    set('[data-overview-infected]',file.schema?summary.infected:'—');
    set('[data-overview-containers]',observed?inv.container_count+' 个容器':'—');
    set('[data-overview-listeners]',observed?inv.listener_count+' 个监听 · '+(inv.container_state==='complete' && inv.listener_state==='complete'?'采集完整':'采集不完整'):'等待主机观测');
    set('[data-overview-engine]',engine.state==='configured'?'引擎已就绪':engine.state==='stale'?'病毒库过期':engine.installed===false?'尚未安装':'尚未就绪');
    set('[data-overview-engine-detail]',engine.installed===null?'等待本机引擎报告':engine.version?'文件查杀 · '+engine.version:engineDisplayText(engine.detail));
    set('[data-overview-coverage]',summary.coverage);
    const notes=scope?.querySelector('[data-overview-notes]');notes?.replaceChildren();
    for(const text of summary.notes){const li=document.createElement('li');li.textContent=text;notes?.append(li);}
    const ready=report && !['unavailable','failed'].includes(report.state);
    set('[data-readiness-agent]',ready?'已取得本机报告 · '+(report.state==='running'?'检查执行中':latestContext.trusted?'环境报告有效':'请核对范围与报告时间'):report?.reason || latestContext.issue || '等待本机代理报告');
    set('[data-engine-overview]',engine.title+(engine.database_version?' · 病毒库 '+engine.database_version:''));
    set('[data-readiness-state]',ready && engine.state==='configured' && protection.state==='ready' && latestContext.trusted?'当前检查范围已就绪':'尚需核验');
    set('[data-task-stage]',task.stage);set('[data-task-title]',task.title);set('[data-task-detail]',task.detail);
    set('[data-task-kind]',({checkup:'全面体检',scan:'环境与容器核验','full-scan':'文件深度查杀','engine-update':'病毒库维护',idle:'当前任务'})[task.kind] || '当前任务');
    set('[data-task-percent]',task.percent===null?task.active?'等待进度':'—':task.percent+'%');
    set('[data-task-scope]',task.active?'百分比仅代表当前阶段；结果以本机报告为准。':task.at?'任务记录：'+new Date(task.at).toLocaleString('zh-CN',{hour12:false}):'仅查杀已纳管目录；未配置范围时不会假报全盘安全。');
    scope?.querySelectorAll('[data-task-progress]').forEach(node=>{
      if(task.percent===null)node.removeAttribute('aria-valuenow');else node.setAttribute('aria-valuenow',String(task.percent));
      node.setAttribute('aria-valuetext',task.title+' · '+task.detail);node.setAttribute('aria-busy',String(task.active));
      node.dataset.active=String(task.active);node.dataset.indeterminate=String(task.active && task.percent===null);
      const bar=node.querySelector('span');if(bar)bar.style.width=task.percent===null?task.active?'24%':'0%':task.percent+'%';
    });

  }

  function setBusy(busy, action = null) {
    requestBusy = Boolean(busy);
    if (requestBusy && action) { requestAction=action; requestIssue=null; requestedTaskId=null; }
    renderScan();
    renderFullScan();
    renderEngine();
    renderWorkbench();
  }
  function requestResult(result) {
    requestIssue=result?.error ? String(result.error).slice(0,240) : null;
    requestedTaskId=typeof result?.task_id==='string' && /^[a-f0-9]{32}$/.test(result.task_id) ? result.task_id : null;
    renderWorkbench();
  }
  function update(report, { trusted = false, busy = false, issue = '等待有效报告', overview = null } = {}) {
    const checks = Array.isArray(report?.checks) ? report.checks : [];
    latestReport = report;
    latestContext = { trusted, issue, overview };
    setBusy(busy);
    renderProtection();
    hostWorkspace.update(report);
    set('[data-security-stat="coverage"]', trusted ? checks.filter(item => item.id !== 'host.history').length + ' / 25' : '—');
    set('[data-security-stat="findings"]', trusted ? String(checks.filter(item => item.state === 'finding').length) : '—');
    set('[data-security-stat="attention"]', trusted ? String(checks.filter(item => ['warning', 'unavailable'].includes(item.state)).length) : '—');
    set('[data-security-stat="time"]', trusted ? new Date(report.checked_at).toLocaleTimeString('zh-CN', { hour12: false }) : '尚无有效报告');
    set('[data-security-stat="freshness"]', trusted ? '最近十五分钟内' : issue);
    for (const [group, ids] of Object.entries(GROUPS)) {
      const items = checks.filter(item => ids.includes(item.id));
      const groupState = !trusted || !items.length ? 'unavailable' : items.some(item => item.state === 'finding') ? 'finding' : items.some(item => item.state !== 'ok') ? 'warning' : 'ok';
      const label = !trusted ? issue : !items.length ? '尚无本组检查结果' : groupState === 'ok' ? '检查范围内正常' : groupState === 'finding' ? '发现问题 · 查看报告' : '需要复核 · 查看报告';
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
    set('[data-security-recent]', trusted && report.history_state==='unavailable' ? '当前报告有效 · 告警历史不可用，请检查状态目录' : trusted && report.history?.length ? report.history.at(-1).name + ' · ' + (LABELS[report.history.at(-1).state] || '未知') : trusted ? '暂无状态变化记录' : issue + '，暂不能确认防护动态');
  }
  function clear(reason) {
    requestIssue=null; requestedTaskId=null; requestAction=null;
    update(null, { issue: reason });
    scope?.querySelectorAll('[data-security-group]').forEach(node => { node.replaceChildren(); });
    open('home');
  }
  return Object.freeze({ bind, update, clear, setBusy, requestResult });
}
