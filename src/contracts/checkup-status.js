import { hostScanProgress, completeHostScan, safeTimestamp } from './host-scan-contract.js';
import { describeFullScan, sanitizeFullScan } from './protection-status.js';
export function sanitizeCheckup(value) {
  const unavailable = {state:'unavailable'};
  if (value?.schema !== 'ironcurtain-checkup/v1' || !['idle','running','finished','partial','failed','paused'].includes(value.state)) return unavailable;
  if (value.state === 'idle') return {state:'idle'};
  if (!/^[a-f0-9]{64}$/.test(value.profile_digest || '') || !['environment','files','complete'].includes(value.stage) || !safeTimestamp(value.started_at) || !safeTimestamp(value.updated_at) || Date.parse(value.updated_at)<Date.parse(value.started_at) ||
      !Array.isArray(value.reasons) || value.reasons.length>8 || value.reasons.some(x => typeof x!=='string' || !x.length || x.length>240 || /[\x00-\x1f\x7f]/.test(x)) ||
      value.environment_at!==undefined && (!safeTimestamp(value.environment_at) || Date.parse(value.environment_at)<Date.parse(value.started_at) || Date.parse(value.environment_at)>Date.parse(value.updated_at)) ||
      ['finished','partial'].includes(value.state) && (value.stage!=='complete' || !value.environment_at) ||
      value.state==='finished' && value.reasons.length || value.stage==='files' && !value.environment_at) return unavailable;
  return {schema:value.schema,profile_digest:value.profile_digest,state:value.state,stage:value.stage,started_at:value.started_at,updated_at:value.updated_at,environment_at:value.environment_at,reasons:[...value.reasons]};
}
export function describeCheckup(report, {busy=false,now=Date.now()}={}) {
  const task=sanitizeCheckup(report?.checkup), file=sanitizeFullScan(report?.full_scan);
  const running=task.state==='running';
  const historical=!running && task.updated_at && (Date.parse(task.updated_at)<now-900000 || Date.parse(task.updated_at)>now+30000);
  const boundProfile=/^[a-f0-9]{64}$/.test(report?.profile_digest || '') && task.profile_digest===report.profile_digest;
  const environment=boundProfile && completeHostScan(report) && task.environment_at===report.checked_at && report.checks.every(x => Date.parse(x.checked_at)>=Date.parse(task.started_at));
  const matchingFiles=environment && file.profile_digest===task.profile_digest && Date.parse(file.started_at)>=Date.parse(task.environment_at);
  const files=matchingFiles ? describeFullScan(file,now) : null;
  const inventory=report?.inventory;
  const coverage=['container_state','listener_state','directory_state'].every(k=>inventory?.[k]==='complete') && ['system_state','package_state','service_state'].every(k=>inventory?.environment?.[k]==='complete');
  const verified=task.state!=='finished' || coverage && environment && report.checks.every(x=>x.state!=='unavailable' || x.id.startsWith('cloudflare.')) && file.state==='finished' && matchingFiles && Date.parse(file.finished_at)<=Date.parse(task.updated_at);
  const progress=task.stage==='environment' && running && Date.parse(report?.started_at)>=Date.parse(task.started_at) ? hostScanProgress(report) : null;
  const activity=task.stage==='files' ? file.updated_at || file.started_at : (Array.isArray(report?.checks) ? report.checks.at(-1)?.checked_at : null) || task.updated_at;
  const stale=running && (!safeTimestamp(activity) || Date.parse(activity)<now-180000 || Date.parse(activity)>now+30000);
  const active=running || busy;
  const labels={running:task.stage==='files'?'第二阶段 · 文件病毒查杀':'第一阶段 · 服务器环境体检',finished:'全面体检完成',partial:'体检完成 · 存在未覆盖项',failed:'全面体检失败',paused:'体检已中断 · 请重新开始'};
  const status=busy&&!running?'正在提交全面体检请求':historical?'历史体检记录 · 请重新检查':!verified?'体检完成证据不匹配 · 请重新检查':stale?'体检进度已过期 · 请核对本机代理':labels[task.state] || '等待一键全面体检';
  const percent=busy&&!running || historical || !verified || stale ? null : progress ? Math.floor(progress.completed*100/progress.total) : task.stage==='files' && running ? files?.percent ?? null : task.state==='finished' ? 100 : null;
  const detail=busy&&!running?'正在联系本机代理':!verified?'缺少同一次体检的完整环境报告或文件查杀结果':stale?'未收到近期进度；请刷新并检查本机代理，不能确认任务已完成':progress?'环境检查 '+progress.completed+' / '+progress.total+' 项 · '+(progress.current || '汇总报告'):task.stage==='files'&&running?'环境检查已完成 · '+(files?files.label+' · '+files.files:'等待本次文件查杀记录'):task.state==='finished'?'环境与已纳管目录文件查杀已完成，请查看结果':task.reasons?.join('；') || report?.reason || '检查 Linux 环境、已安装软件、服务、端口、容器与已纳管文件';
  return {active,status,detail,percent,button:active?'全面体检进行中…':'一键全面体检',state:!verified?'unavailable':historical?'historical':stale?'stale':task.state};
}
