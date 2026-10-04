import { createSecurityPoller } from './security-poller.js';
const $ = id => document.getElementById(id);
import { createSecurityConsole } from './security-console.js?v=ironcurtain-login-20261004';

// Keep this fixed browser view in sync with the core/agent contract (verified in tests).
const HOST_SCAN_IDS = Object.freeze([
  'integrity.program',
  'host.configuration',
  'container.contract',
  'container.approved-image',
  'response.containment',
  'host.os-release',
  'host.systemd-state',
  'ssh.effective',
  'permissions.secret-inventory',
  'permissions.installation',
  'permissions.cron',
  'network.listeners',
  'network.udp-listeners',
  'network.routes',
  'host.kernel-security',
  'network.firewall',
  'malware.program',
  'malware.business',
  'database.sqlite',
  'host.process-executables',
  'host.failed-units',
  'cloudflare.dns',
  'cloudflare.workers',
  'cloudflare.rules',
  'cloudflare.settings'
]);
const CHECK_STATES = new Set(['ok', 'warning', 'finding', 'unavailable']);
const CHECK_CATEGORIES = new Set(['host', 'container', 'permissions', 'ssh', 'network', 'malware']);
const CHECK_SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical', 'unknown']);
function safeTimestamp(value) {
  return typeof value === 'string' && value.length <= 40 &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0, 19) === value.slice(0, 19);
}

function completeReport(report, checks) {
  const coverage = report.coverage;
  const seen = new Set();
  if (!safeTimestamp(report.checked_at) || !coverage || coverage.schema !== 'appgog-host-scan/v1' || coverage.expected !== HOST_SCAN_IDS.length ||
      coverage.checked !== HOST_SCAN_IDS.length || coverage.complete !== true ||
      checks.length < HOST_SCAN_IDS.length || checks.length > HOST_SCAN_IDS.length + 1) return false;
  for (const item of checks) {
    if (!item || seen.has(item.id) || !CHECK_STATES.has(item.state) ||
        (!HOST_SCAN_IDS.includes(item.id) && item.id !== 'host.history') ||
        typeof item.evidence_digest !== 'string' || !/^[a-f0-9]{64}$/.test(item.evidence_digest) ||
        !CHECK_CATEGORIES.has(item.category) || !CHECK_SEVERITIES.has(item.severity) ||
        typeof item.name !== 'string' || !item.name || typeof item.detail !== 'string' ||
        typeof item.scope !== 'string' || !item.scope || item.scope.length > 120 ||
        !safeTimestamp(item.checked_at) ||
        Date.parse(item.checked_at) > Date.parse(report.checked_at) + 120000) return false;
    if (item.id === 'host.history' && (item.state !== 'unavailable' || report.history_state !== 'unavailable')) return false;
    seen.add(item.id);
  }
  return HOST_SCAN_IDS.every(id => seen.has(id));
}

export function createSecurityUi({ state, can, request, notify }) {
  const consoleView = createSecurityConsole();
  let localRunning = false;
  let scanRequested = false;
  let scanGeneration = 0;
  let bound = false;
  const localStateLabels = { ok: '正常', warning: '需复核', finding: '发现问题', unavailable: '不可用' };
  function renderFileFindings(report) {
    const list = $('security-malware-findings'), status = $('security-malware-findings-state');
    list?.replaceChildren();
    const visible = report.state === 'finished' && ['complete','partial'].includes(report.findings_state);
    if (status) status.textContent = !visible ? '等候本次扫描的可核验文件证据' : report.findings_total > (report.findings?.length || 0)
      ? '特征命中 '+report.findings_total+'；页面仅展示已复核的 '+(report.findings?.length || 0)+' 条，完整记录请在 Linux 菜单查看'
      : report.findings_state === 'partial' ? '部分文件证据未完成复核；扫描告警继续保留' : '本次命中 '+report.findings_total+' 个文件；隔离请在可信 Linux 菜单执行';
    if (!visible) return;
    for (const item of report.findings || []) {
      const row = document.createElement('li'); row.dataset.state = 'finding';
      const title = document.createElement('strong'); title.textContent = item.signature;
      const path = document.createElement('p'); path.textContent = item.path;
      const evidence = document.createElement('p'); evidence.className = 'sc-muted';
      evidence.textContent = '证据编号 '+item.id+' · SHA-256 '+item.sha256+' · '+item.size+' 字节';
      row.append(title, path, evidence); list?.append(row);
    }
  }
  function renderQuarantine(report) {
    const list=$('security-quarantine-records'), status=$('security-quarantine-state');
    list?.replaceChildren();
    const value=report.quarantine;
    if(status) status.textContent = !value || value.state==='unavailable' ? '本机隔离记录不可用，等待代理状态' : value.state==='empty' ? '暂无本机隔离记录' : '处置记录 '+value.count+' 项 · 待人工核查 '+value.pending+' 项；页面最多显示 8 项';
    const labels={preparing:'副本准备中，尚未隔离',captured:'已保存副本，移除尚未确认',quarantined:'已完成路径隔离',restoring:'恢复未完成，需人工核查',restored:'已取回，副本仍保留'};
    for(const item of value?.items || []) {
      const row=document.createElement('li');row.dataset.state=['preparing','captured','restoring'].includes(item.state)?'warning':'ok';
      const title=document.createElement('strong');title.textContent=labels[item.state] || '记录状态未知';
      const path=document.createElement('p');path.textContent=item.path;
      const evidence=document.createElement('p');evidence.className='sc-muted';evidence.textContent='证据编号 '+item.id+' · '+item.signature+' · '+item.size+' 字节';
      row.append(title,path,evidence);list?.append(row);
    }
  }
  function renderLocalReport(report) {
    renderFileFindings(report);
    renderQuarantine(report);
    const engine = $('security-antivirus-state');
    if (engine) {
      const value=report.antivirus;
      const updater={scheduled:'定时更新已启用',disabled:'定时更新未启用',failed:'最近更新失败',unknown:'更新状态未知'};
      engine.textContent = value?.engine === 'ClamAV' ? value.detail + (value.database_version ? ' · 库版本 '+value.database_version : '') + ' · '+(updater[value.updater] || updater.unknown) : '病毒引擎状态待检查';
      engine.dataset.state = value?.state || 'unavailable';
    }
    const status = $('security-local-state');
    const timestamp = $('security-local-time');
    const list = $('security-local-checks');
    const history = $('security-local-history');
    const historyState = $('security-local-history-state');
    if (!status || !timestamp || !list) return;
    localRunning = report.state === 'running';
    const checks = Array.isArray(report.checks) ? report.checks : [];
    const findings = checks.filter(item => item.state === 'finding').length;
    const incomplete = checks.length ? checks.filter(item => item.state !== 'ok').length : 1;
    const now = Date.now();
    const stale = [report.checked_at, ...checks.map(item => item.checked_at)].some(value => {
      const epoch = Date.parse(value); return !Number.isFinite(epoch) || epoch < now - 900000 || epoch > now + 120000;
    });
    const coverageIncomplete = !completeReport(report, checks);
    const historyUnavailable = !['ok', 'truncated'].includes(report.history_state) || !Array.isArray(report.history);
    status.textContent = ({ idle: '等待首次检查', running: '本机检查正在执行', finished: coverageIncomplete ? '检查报告覆盖不完整，请重新扫描' : stale ? '检查结果过期或时间异常' : historyUnavailable ? '检查完成，告警历史不可用' : findings ? '警报：发现 ' + findings + ' 项问题' : incomplete ? '检查完成，有 ' + incomplete + ' 项需要复核或不可用' : '固定检查范围内未发现异常', failed: '本机检查失败', unavailable: '本机代理不可用' })[report.state] || '状态未知';
    status.dataset.state = report.state === 'finished' && !coverageIncomplete && !stale && !historyUnavailable && findings ? 'finding' : (report.state !== 'finished' || stale || incomplete || coverageIncomplete || historyUnavailable ? 'warning' : 'ok');
    timestamp.textContent = report.checked_at ? '检查时间：' + report.checked_at : (report.reason || '尚无检查时间');
    list.replaceChildren();
    for (const item of checks) {
      const row = document.createElement('li');
      row.dataset.state = item.state;
      row.textContent = item.name + ' · ' + (localStateLabels[item.state] || '未知') + ' · ' + item.detail;
      list.append(row);
    }
    history?.replaceChildren();
    for (const item of report.history ?? []) {
      const row = document.createElement('li');
      row.textContent = item.checked_at + ' · ' + item.name + ' · ' + (localStateLabels[item.previous_state] || '首次记录') + ' → ' + (localStateLabels[item.state] || '未知') + ' · ' + item.detail;
      history?.append(row);
    }
    consoleView.update(report, { busy: scanRequested, trusted: report.state === 'finished' && !coverageIncomplete && !stale && !historyUnavailable, issue: report.state === 'running' ? '本机检查中' : report.state === 'idle' ? '等待首次检查' : report.state === 'unavailable' ? '本机代理不可用' : report.state === 'failed' ? '本机检查失败' : coverageIncomplete ? '等待完整有效报告' : stale ? '报告过期或时间异常' : historyUnavailable ? '告警历史不可用' : '本机检查不可用' });
    if (historyState) historyState.textContent = historyUnavailable ? '告警历史不可用；请检查本地代理与状态目录' : report.history_state === 'truncated' ? '仅显示响应容量内的最近记录；完整记录保留在服务器' : report.history?.length ? '显示最近八条状态变化；本机最多保留一百二十八条' : '暂无状态变化记录';
  }
  const localSecurityPoller = createSecurityPoller({
    request: () => request('/api/scan'),
    session: () => state.csrf,
    allowed: () => Boolean(state.csrf) && can('system.manage') && !document.hidden && Boolean($('security-local-state')),
    render: renderLocalReport,
    onError: error => {
      localRunning = false;
      consoleView.update(null, { busy: scanRequested, issue: '本机代理不可用' });
      const status = $('security-local-state');
      if (status) { status.textContent = '本机代理不可用'; status.dataset.state = 'warning'; }
      if ($('security-local-time')) $('security-local-time').textContent = error.message;
      renderFileFindings({state:'unavailable'});
      renderQuarantine({state:'unavailable'});
      $('security-local-checks')?.replaceChildren(); $('security-local-history')?.replaceChildren();
      if ($('security-local-history-state')) $('security-local-history-state').textContent = '告警历史读取失败';
    },
  });
  let securityRenderGeneration = 0;
  const renderLocalSecurity = () => localSecurityPoller.run();
  document.addEventListener('ironcurtain-session-cleared', () => {
    localSecurityPoller.stop();
    localRunning = false;
    scanRequested = false;
    scanGeneration++;
    consoleView.clear('请登录后查看');
    securityRenderGeneration++;
    for (const id of ['security-cloud-state', 'security-cloud-reason', 'security-identity', 'security-build-probe', 'security-license-probe', 'security-integrity', 'security-host-scan', 'security-build-host-scan', 'security-event-title', 'security-event-message']) {
      const node = $(id); if (node) node.textContent = '请登录后查看';
    }
    const status = $('security-local-state');
    if (status) { status.textContent = '请登录后查看'; status.dataset.state = 'warning'; }
    renderFileFindings({state:'unavailable'});
    renderQuarantine({state:'unavailable'});
    for (const id of ['security-local-time', 'security-local-checks', 'security-local-history', 'security-local-history-state']) $(id)?.replaceChildren();
  });
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { securityRenderGeneration++; localSecurityPoller.stop(); }
    else { void renderLocalSecurity(); void renderSecurity(); }
  });
  window.addEventListener('pagehide', () => { securityRenderGeneration++; localSecurityPoller.stop(); });
  window.addEventListener('pageshow', () => { void renderLocalSecurity(); void renderSecurity(); });

  async function renderSecurity() {
    if (!state.csrf || !can('system.manage') || document.hidden) return;
    const session = state.csrf;
    const generation = ++securityRenderGeneration;
    const current = () => generation === securityRenderGeneration && state.csrf === session && can('system.manage') && !document.hidden;
    const set = (id, value) => { const node = $(id); if (node) node.textContent = value; };
    const probe = value => value === 'healthy' ? '可达 · 健康响应' : value === 'unreachable' ? '不可达 · 请检查' : value === 'unhealthy' ? '健康检查失败' : '未知 / 未配置';
    set('security-cloud-state', '正在核对');
    try {
      const data = await request('/api/cloud/status');
      if (!current()) return;
      if (!data.connected) throw new Error(data.reason ?? '云端不可达');
      set('security-cloud-state', '云端已连接');
      set('security-cloud-reason', `验证于 ${data.generated_at ?? '未知时间'}`);
      set('security-identity', '双重身份验证通过');
      const own = data.node ?? Object.values(data.nodes ?? {})[0];
      set('security-build-probe', '独立节点 · ' + (data.node_id ?? '身份已核验'));
      set('security-license-probe', probe(own?.probe?.state));
      const hostLabel = host => !host?.fresh ? '未上报 / 检查过期' : ({ ok: '固定范围未发现异常', warning: '配置需复核', finding: '发现异常', unavailable: '检查不可用' })[host.state] || '检查未知';
      set('security-build-host-scan', own?.report_fresh ? '当前摘要已上报' : '等待新报告');
      const host = own?.host_scan;
      set('security-host-scan', hostLabel(host));
      const reports = Object.values(data.nodes ?? {});
      const stale = reports.some(item => !item.report_fresh);
      const changed = reports.some(item => item.integrity?.state === 'changed');
      const matched = reports.length > 0 && reports.every(item => item.integrity?.state === 'matched' && item.report_fresh);
      set('security-integrity', changed ? '发现文件偏移' : matched ? '可信摘要匹配' : stale ? '报告过期 / 未上报' : '基线未配置');
      const latest = data.events?.[0];
      set('security-event-title', latest ? `${latest.node}: ${latest.kind}` : '暂无安全事件');
      set('security-event-message', latest ? `发生于 ${latest.at}` : '本机仅能查询自身核验状态；完整审计在玄武面板查看。');
    } catch (error) {
      if (!current()) return;
      set('security-cloud-state', '无法验证'); set('security-cloud-reason', error.message);
      set('security-identity', '验证失败 / 未配置'); set('security-build-probe', '未知');
      set('security-license-probe', '未知'); set('security-integrity', '未知'); set('security-host-scan', '未知'); set('security-build-host-scan', '未知');
      set('security-event-title', '云端状态未知'); set('security-event-message', '无法读取独立云端事件。');
    }
  }
  function bind() {
    if (bound) return;
    bound = true;
    consoleView.bind();
    void renderSecurity(); void renderLocalSecurity();
    document.querySelectorAll('[data-security-scan]').forEach(button => button.addEventListener('click', async () => {
      if (scanRequested || !state.csrf || !can('system.manage')) return;
      const session = state.csrf;
      const generation = ++scanGeneration;
      const current = () => generation === scanGeneration && state.csrf === session && can('system.manage');
      scanRequested = true;
      consoleView.setBusy(true);
      try {
        await request('/api/scan', { method: 'POST', body: {} });
        if (current()) await localSecurityPoller.refresh();
      } catch (error) { if (current()) notify(error.message, true); }
      finally { if (current()) { scanRequested = false; consoleView.setBusy(localRunning); } }
    }));
  }
  return Object.freeze({ bind, render() { void renderSecurity(); void renderLocalSecurity(); } });
}
