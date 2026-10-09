import {createOperationsWorkspace} from './operations-workspace.js';
import {createScheduleSettings} from './schedule-settings.js';
import { createCloudIntelligence } from './cloud-intelligence.js';
import {engineDisplayText} from './engine-labels.js';
import {createEngineMaintenance} from './engine-maintenance.js';
import {createEngineReadiness} from './engine-readiness.js';
import { createMultiEngine } from './multi-engine.js';
import { createUpdateSettings } from './update-settings.js';
import { createDomainSettings } from './domain-settings.js';
import { createSecurityPoller } from './security-poller.js';
const $ = id => document.getElementById(id);
import { createSecurityConsole } from './security-console.js';
import { summarizeLocalSecurity } from '/contracts/local-workbench.js';

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
  const operationsWorkspace = createOperationsWorkspace({state,request,notify,
    isScanBusy:()=>scanRequested || localRunning,
    recheck:async(action,panel)=>{const session=state.csrf,generation=scanGeneration+1;const receipt=await runLocalCheck(action);if(session!==state.csrf || generation!==scanGeneration || !can('system.manage'))throw Error('登录状态已改变，请重新核对检测状态');consoleView.open(panel,true);return receipt;}
  });
  const cloudIntelligence = createCloudIntelligence({state,request,notify});
  const multiEngine = createMultiEngine({state,request,notify});
  const engineReadiness = createEngineReadiness({state,request,notify});
  const engineMaintenance = createEngineMaintenance({state,request,notify,onFinished:()=>void engineReadiness.refresh()});
  const scheduleSettings = createScheduleSettings({state,request,notify});
  const updateSettings = createUpdateSettings({state,request,notify});
  const domainSettings = createDomainSettings({state,request,notify});
  let localRunning = false;
  let scanRequested = false;
  let scanGeneration = 0;
  let bound = false;
  const localStateLabels = { ok: '正常', warning: '需复核', finding: '发现问题', unavailable: '不可用' };
  let findingsSignature=null,latestFindingsReport=null;
  document.addEventListener('focusout',()=>queueMicrotask(()=>{if(latestFindingsReport)renderFileFindings(latestFindingsReport);}));
  function renderFileFindings(report) {
    latestFindingsReport=report;
    const list = $('security-malware-findings'), status = $('security-malware-findings-state');
    const signature=JSON.stringify([report.state,report.findings_source,report.findings_state,report.findings_total,report.findings]);
    if(signature===findingsSignature){operationsWorkspace.sync();return;}
    if(list?.contains(document.activeElement) && state.csrf)return;
    findingsSignature=signature;list?.replaceChildren();
    const visible = (report.state === 'finished' || ['full','multi'].includes(report.findings_source)) && ['complete','partial'].includes(report.findings_state);
    if (status) status.textContent = !visible ? '等候本次扫描的可核验文件证据' : report.findings_total > (report.findings?.length || 0)
      ? '特征命中 '+report.findings_total+'；页面仅展示已复核的 '+(report.findings?.length || 0)+' 条，完整记录请在 Linux 菜单查看'
      : report.findings_state === 'partial' ? '部分文件证据未完成复核；扫描告警继续保留' : '本次命中 '+report.findings_total+' 个文件；可在本页核对后隔离，系统再次验证证据';
    if (visible && status) status.textContent = (report.findings_source==='multi'?'联合检测文件证据：':report.findings_source==='full'?'文件深度查杀：':'环境与范围核验：')+status.textContent;
    if (!visible) return;
    for (const item of report.findings || []) {
      const row = document.createElement('li'); row.dataset.state = 'finding';
      const title = document.createElement('strong'); title.textContent = item.signature;
      const path = document.createElement('p'); path.textContent = item.path;
      const evidence = document.createElement('p'); evidence.className = 'sc-muted';
      evidence.textContent = '证据编号 '+item.id+' · SHA-256 '+item.sha256+' · '+item.size+' 字节';
      const action=document.createElement('button');action.type='button';action.className='sc-outline';action.textContent='隔离命中文件';action.dataset.quarantineId=item.id;action.disabled=true;
      row.append(title, path, evidence, action); list?.append(row);
    }
    operationsWorkspace.sync();
  }
  function ruleLabel(value) {
    return value?.state==='ready' ? 'v'+value.version+' · 序号 '+value.sequence+' · '+value.indicators+' 条 · 有效至 '+new Date(value.expires_at*1000).toLocaleString() : value?.state==='missing' ? '尚未安装签名规则' : '规则不可用 / 未核验';
  }
  function renderRules(report) {
    const meta=$('security-local-rules');if(meta)meta.textContent=ruleLabel(report.rules);
    const hits=report.rule_hits,list=$('security-rule-hits'),status=$('security-rule-hits-state');list?.replaceChildren();
    if(status)status.textContent=hits?.state==='unavailable' || !hits ? '哈希检测未启用 / 无有效报告' : '哈希命中 '+hits.total+' 项 · '+(hits.state==='complete'?'本次范围检查完整':'本次检查不完整')+'；仅告警，未自动删除文件';
    for(const item of hits?.items || []) {
      const row=document.createElement('li');row.dataset.state='finding';const name=document.createElement('strong');name.textContent=item.label+' · '+item.rule_id;
      const detail=document.createElement('p');detail.textContent=item.path;const digest=document.createElement('p');digest.textContent='SHA-256 '+item.sha256;row.append(name,detail,digest);list?.append(row);
    }
  }
  function renderLocalReport(report) {
    renderRules(report);
    renderFileFindings(report);
    const engine = $('security-antivirus-state');
    if (engine) {
      const value=report.antivirus;
      const updater={scheduled:'定时更新已启用',disabled:'定时更新未启用',failed:'最近更新失败',unknown:'更新状态未知'};
      const updateText=value?.source==='xuanwu-signed'?'玄武签名库 · Linux 菜单更新':(updater[value?.updater] || updater.unknown);
      engine.textContent = value?.engine === 'ClamAV' ? engineDisplayText(value.detail) + (value.database_version ? ' · 库版本 '+value.database_version : '') + ' · '+updateText : '病毒引擎状态待检查';
      engine.dataset.state = value?.state || 'unavailable';
    }
    const status = $('security-local-state');
    const timestamp = $('security-local-time');
    const list = $('security-local-checks');
    const history = $('security-local-history');
    const historyState = $('security-local-history-state');
    localRunning = report.checkup?.state === 'running' || report.state === 'running' || ['indexing','scanning'].includes(report.full_scan?.state) || report.antivirus?.update_state==='running';
    operationsWorkspace.sync();
    if (!status || !timestamp || !list) return;
    const checks = Array.isArray(report.checks) ? report.checks : [];
    const findings = checks.filter(item => item.state === 'finding').length;
    const incomplete = checks.length ? checks.filter(item => item.state !== 'ok').length : 1;
    const now = Date.now();
    const stale = [report.checked_at, ...checks.map(item => item.checked_at)].some(value => {
      const epoch = Date.parse(value); return !Number.isFinite(epoch) || epoch < now - 900000 || epoch > now + 120000;
    });
    const coverageIncomplete = !completeReport(report, checks);
    const historyUnavailable = !['ok', 'truncated'].includes(report.history_state) || !Array.isArray(report.history);
    const overview=summarizeLocalSecurity(report,{coverageComplete:!coverageIncomplete,stale,historyUnavailable,now});
    status.textContent=overview.title;
    status.dataset.state=overview.tone;
    timestamp.textContent = report.checked_at ? '检查时间：' + report.checked_at : (report.reason || '尚无检查时间');
    list.replaceChildren();
    for (const item of [...checks].sort((a,b)=>(a.state==='finding'?0:a.state==='ok'?2:1)-(b.state==='finding'?0:b.state==='ok'?2:1))) {
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
    consoleView.update(report, { overview, busy: scanRequested, trusted: report.state === 'finished' && !coverageIncomplete && !stale, issue: report.state === 'running' ? '本机检查中' : report.state === 'idle' ? '等待首次检查' : report.state === 'unavailable' ? '本机代理不可用' : report.state === 'failed' ? '本机检查失败' : coverageIncomplete ? '等待完整有效报告' : stale ? '报告过期或时间异常' : historyUnavailable ? '告警历史不可用' : '本机检查不可用' });
    if (historyState) historyState.textContent = historyUnavailable ? '告警历史不可用；请检查本地代理与状态目录' : report.history_state === 'truncated' ? '仅显示响应容量内的最近记录；完整记录保留在服务器' : report.history?.length ? '显示最近八条状态变化；本机最多保留一百二十八条' : '暂无状态变化记录';
  }
  const localSecurityPoller = createSecurityPoller({
    request: () => request('/api/scan'),
    session: () => state.csrf,
    allowed: () => Boolean(state.csrf) && can('system.manage') && !document.hidden && Boolean($('security-local-state')),
    render: renderLocalReport,
    onError: error => {
      localRunning = false;
      operationsWorkspace.sync();
      consoleView.update(null, { busy: scanRequested, issue: '本机代理不可用' });
      const status = $('security-local-state');
      if (status) { status.textContent = '本机代理不可用'; status.dataset.state = 'warning'; }
      if ($('security-local-time')) $('security-local-time').textContent = error.message;
      renderFileFindings({state:'unavailable'});
      renderRules({state:'unavailable'});
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
    for (const id of ['security-cloud-state', 'security-cloud-reason', 'security-identity', 'security-build-probe', 'security-license-probe', 'security-integrity', 'security-host-scan', 'security-build-host-scan', 'security-event-title', 'security-event-message', 'security-cloud-rules', 'security-local-rules', 'security-cloud-release']) {
      const node = $(id); if (node) node.textContent = '请登录后查看';
    }
    const status = $('security-local-state');
    if (status) { status.textContent = '请登录后查看'; status.dataset.state = 'warning'; }
    renderFileFindings({state:'unavailable'});
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
      if (data.state === 'unpaired' && data.connected === false) {
        set('security-cloud-state', '尚未对接');
        set('security-cloud-reason', '玄武为可选服务；本机体检和病毒查杀独立运行。');
        set('security-identity', '尚未配置节点身份');
        for (const id of ['security-cloud-rules', 'security-cloud-release', 'security-build-probe', 'security-license-probe', 'security-integrity', 'security-host-scan', 'security-build-host-scan']) set(id, '尚未对接');
        set('security-event-title', '尚无云端事件');
        set('security-event-message', '需要集中管理时，在 Linux 菜单完成玄武配对。');
        return;
      }
      if (!data.connected) throw new Error(data.reason ?? '云端不可达');
      set('security-cloud-state', '云端已连接');
      set('security-cloud-rules',ruleLabel(data.rules));
      set('security-cloud-release', data.releases?.state === 'ready' ? '云端提供 v' + data.releases.version + ' · Linux 菜单验签安装' : data.releases?.state === 'missing' ? '云端尚未导入程序包' : '云端发布状态无法核验');
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
      set('security-cloud-rules','云端规则状态无法核验');
      set('security-cloud-release','云端发布状态无法核验');
      set('security-cloud-state', '无法验证'); set('security-cloud-reason', error.message);
      set('security-identity', '验证失败 / 未配置'); set('security-build-probe', '未知');
      set('security-license-probe', '未知'); set('security-integrity', '未知'); set('security-host-scan', '未知'); set('security-build-host-scan', '未知');
      set('security-event-title', '云端状态未知'); set('security-event-message', '无法读取独立云端事件。');
    }
  }
  async function runLocalCheck(action) {
    const endpoints={scan:'/api/scan','full-scan':'/api/full-scan',checkup:'/api/checkup','engine-update':'/api/engine/update'};
    if(!Object.hasOwn(endpoints,action))throw Error('不支持的检测操作');
    if(!state.csrf || !can('system.manage'))throw Error('请登录有检测权限的账户');
    if(scanRequested || localRunning)throw Error('已有检测任务，请等待当前任务完成');
    const session=state.csrf,generation=++scanGeneration;
    const current=()=>generation===scanGeneration && state.csrf===session && can('system.manage');
    scanRequested=true;consoleView.setBusy(true,action);operationsWorkspace.sync();
    try {
      const receipt=await request(endpoints[action],{method:'POST',body:{}});
      if(!current())throw Error('登录状态已改变，请重新核对检测状态');
      if(receipt?.state!=='running' || (action!=='engine-update' && !/^[a-f0-9]{32}$/.test(receipt.task_id || '')))throw Error(receipt?.error || '未取得有效检测任务确认，请刷新核对');
      localRunning=true;operationsWorkspace.sync();
      consoleView.requestResult(receipt);await localSecurityPoller.refresh();
      if(!current())throw Error('登录状态已改变，请重新核对检测状态');
      return receipt;
    } catch(error) {if(current())consoleView.requestResult({error:error.message});throw error;}
    finally {if(generation===scanGeneration){scanRequested=false;consoleView.setBusy(false);operationsWorkspace.sync();}}
  }
  function bind() {
    if (bound) return;
    bound = true;
    consoleView.bind(); operationsWorkspace.bind(); operationsWorkspace.start();
    cloudIntelligence.bind();
    multiEngine.bind(); multiEngine.start(); engineReadiness.bind(); engineReadiness.start(); engineMaintenance.bind(); engineMaintenance.start();
    scheduleSettings.bind(); scheduleSettings.start();
    updateSettings.bind(); updateSettings.start(); domainSettings.bind(); domainSettings.start();
    void renderSecurity(); void renderLocalSecurity();
    document.querySelectorAll('[data-security-refresh]').forEach(button => button.addEventListener('click', async () => {
      if (button.disabled || !state.csrf || !can('system.manage')) return;
      button.disabled = true;
      try { await localSecurityPoller.refresh(); }
      finally { button.disabled = false; }
    }));
    document.querySelectorAll('[data-security-scan], [data-security-container-scan], [data-security-full-scan], [data-security-checkup], [data-security-engine-update]').forEach(button => button.addEventListener('click', async () => {
      if (scanRequested || localRunning || !state.csrf || !can('system.manage')) return;
      const session=state.csrf,generation=scanGeneration;
      const action=button.hasAttribute('data-security-engine-update')?'engine-update':button.hasAttribute('data-security-checkup')?'checkup':button.hasAttribute('data-security-full-scan')?'full-scan':'scan';
      try {await runLocalCheck(action);}
      catch(error){if(state.csrf===session && can('system.manage') && scanGeneration===generation+1)notify(error.message,true);}
    }));
  }
  return Object.freeze({ bind, render() { operationsWorkspace.start(); scheduleSettings.start(); engineReadiness.start(); engineMaintenance.start(); multiEngine.start(); updateSettings.start(); domainSettings.start(); void renderSecurity(); void renderLocalSecurity(); } });
}
