import { sanitizeEnvironment } from './environment-status.js';
import { safeTimestamp } from './host-scan-contract.js';
const count = value => Number.isSafeInteger(value) && value >= 0;
const text = (value, size = 180) => typeof value === 'string' && value.length <= size && !/[\x00-\x1f\x7f]/.test(value);
const texts = (value, limit = 16) => Array.isArray(value) && value.length <= limit && value.every(x => text(x));
const unavailable = () => ({ state: 'unavailable' });
export function sanitizeProtection(value) {
  if (!value || value.schema !== 'ironcurtain-protection/v1' || !['ready','incomplete','attention'].includes(value.state) ||
      !texts(value.issues) || !['program_roots','business_roots','enrolled_containers','discovered_containers','unenrolled_containers'].every(k => count(value[k])) ||
      value.program_roots > 32 || value.business_roots > 32 || value.enrolled_containers > 32 || value.discovered_containers > 32 ||
      value.unenrolled_containers > value.discovered_containers || value.discovered_containers - value.unenrolled_containers > value.enrolled_containers || value.file_scope !== 'configured-directories-only' ||
      value.trust !== 'independent-signatures-required' || value.monitor_interval_seconds !== 300 ||
      value.state === 'ready' && (value.issues.length || value.unenrolled_containers || !value.program_roots && !value.business_roots || !safeTimestamp(value.checked_at))) return unavailable();
  return {schema:value.schema, state:value.state, checked_at:safeTimestamp(value.checked_at), issues:[...value.issues],
    program_roots:value.program_roots, business_roots:value.business_roots, enrolled_containers:value.enrolled_containers,
    discovered_containers:value.discovered_containers, unenrolled_containers:value.unenrolled_containers,
    file_scope:value.file_scope, trust:value.trust, monitor_interval_seconds:300};
}
export function sanitizeInventory(value) {
  if (!value || value.schema !== 'ironcurtain-inventory/v1' || !safeTimestamp(value.observed_at) ||
      !['container_state','listener_state','directory_state'].every(k => ['complete','partial','unavailable'].includes(value[k])) ||
      !['first-observation','compared','partial'].includes(value.drift_state) || typeof value.truncated !== 'boolean' ||
      !['container_count','listener_count','candidate_count'].every(k => count(value[k])) ||
      !texts(value.issues,8) || !texts(value.drift,8) || !['containers','listeners','candidates'].every(k => Array.isArray(value[k]) && value[k].length <= 8) ||
      value.containers.length > value.container_count || value.listeners.length > value.listener_count || value.candidates.length > value.candidate_count) return unavailable();
  const containers=[]; const listeners=[]; const candidates=[];
  for (const item of value.containers) {
    if (typeof item?.name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(item.name) || typeof item.running !== 'boolean' || typeof item.readonly !== 'boolean' ||
        !texts(item.risks,8) || !(item.process_count === null || count(item.process_count)) ||
        !['observed','unavailable'].includes(item.filesystem_state) || !(item.changed_paths === null || count(item.changed_paths))) return unavailable();
    containers.push({name:item.name,running:item.running,readonly:item.readonly,risks:[...item.risks],process_count:item.process_count,filesystem_state:item.filesystem_state,changed_paths:item.changed_paths});
  }
  for (const item of value.listeners) {
    if (!item || !['tcp','udp'].includes(item.protocol) || !text(item.address,160) || !Number.isInteger(item.port) || item.port < 1 || item.port > 65535 ||
        !Array.isArray(item.processes) || item.processes.length > 4 || item.processes.some(p => !p || !text(p.name,80) || !count(p.pid) || p.pid === 0)) return unavailable();
    listeners.push({protocol:item.protocol,address:item.address,port:item.port,processes:item.processes.map(p => ({name:p.name,pid:p.pid}))});
  }
  for (const item of value.candidates) {
    if (typeof item?.id !== 'string' || !/^[a-f0-9]{16}$/.test(item.id) || !['program_roots','business_roots','containers'].includes(item.kind) || !text(item.value,1024) || !text(item.origin,180)) return unavailable();
    candidates.push({id:item.id,kind:item.kind,value:item.value,origin:item.origin});
  }
  return {schema:value.schema,observed_at:value.observed_at,container_state:value.container_state,listener_state:value.listener_state,directory_state:value.directory_state,
    drift_state:value.drift_state,container_count:value.container_count,listener_count:value.listener_count,candidate_count:value.candidate_count,
    environment:sanitizeEnvironment(value.environment),containers,listeners,candidates,issues:[...value.issues],drift:[...value.drift],truncated:value.truncated};
}
function scanProgress(value) {
  const id=value.task_id, resumed=value.resumed_from;
  if (id!==undefined && (typeof id!=='string' || !/^[a-f0-9]{32}$/.test(id)) || resumed!==undefined && (typeof resumed!=='string' || !/^[a-f0-9]{32}$/.test(resumed))) return null;
  const validFile=item=>item && text(item.path,1024) && item.path.startsWith('/') && !item.path.split('/').includes('..') && count(item.size);
  const current=value.current_file;
  if(current!==undefined && current!==null && (!validFile(current) || !['opening','hashing','engine'].includes(current.phase) || !count(current.bytes_read) || current.bytes_read>current.size)) return null;
  const recent=value.recent_files ?? [];
  if(!Array.isArray(recent) || recent.length>8 || recent.some(item=>!validFile(item) || !['clean','infected','skipped','errors'].includes(item.state) || !safeTimestamp(item.checked_at) || item.reason!==null && item.reason!==undefined && !text(item.reason))) return null;
  return {task_id:id,resumed_from:resumed,current_file:current?{path:current.path,size:current.size,phase:current.phase,bytes_read:current.bytes_read}:null,recent_files:recent.map(item=>({path:item.path,size:item.size,state:item.state,reason:item.reason || null,checked_at:item.checked_at}))};
}
export function sanitizeFullScan(value) {
  if (!value || value.schema !== 'ironcurtain-full-scan/v1' || !['idle','indexing','scanning','paused','finished','partial','failed'].includes(value.state)) return unavailable();
  if (value.state === 'idle') return {state:'idle'};
  const progress=scanProgress(value);
  if (!safeTimestamp(value.started_at) || !progress) return unavailable();
  if (value.state === 'indexing' && value.indexed === undefined) return {state:'indexing',started_at:value.started_at,...progress};
  const keys=['indexed','processed','clean','infected','skipped','errors','bytes_scanned'];
  if (!keys.every(k => count(value[k])) || value.indexed > 200000 || value.processed > value.indexed || value.clean + value.infected + value.errors > value.processed ||
      value.clean + value.infected + value.errors + value.skipped < value.processed || typeof value.index_complete !== 'boolean' ||
      value.scope !== 'enrolled-directories-only' || !texts(value.reasons) || !safeTimestamp(value.updated_at) || Date.parse(value.updated_at)<Date.parse(value.started_at) ||
      ['finished','partial','failed'].includes(value.state) && (!safeTimestamp(value.finished_at) || Date.parse(value.finished_at)<Date.parse(value.started_at) || Date.parse(value.finished_at)>Date.parse(value.updated_at)) ||
      value.state === 'finished' && (!value.index_complete || !value.indexed || value.processed !== value.indexed || value.skipped || value.errors)) return unavailable();
  return {...progress,schema:value.schema,state:value.state,profile_digest:/^[a-f0-9]{64}$/.test(value.profile_digest || '')?value.profile_digest:undefined,started_at:value.started_at,updated_at:value.updated_at,finished_at:safeTimestamp(value.finished_at),
    ...Object.fromEntries(keys.map(k => [k,value[k]])),index_complete:value.index_complete,scope:value.scope,reasons:[...value.reasons]};
}
export function describeFullScan(value, now = Date.now()) {
  const running=['indexing','scanning'].includes(value?.state);
  const timestamp=Date.parse(value?.updated_at || value?.started_at);
  const recorded=['paused','finished','partial','failed'].includes(value?.state);
  const stale=(running || recorded) && (!Number.isFinite(timestamp) || timestamp < now-(running ? 180000 : 900000) || timestamp > now+30000);
  const active=running && !stale;
  const labels={idle:'尚未进行文件深度查杀',indexing:'正在建立文件清单',scanning:'正在逐文件查杀',paused:'扫描已暂停，可继续',finished:'文件查杀完成',partial:'扫描不完整，需要复核',failed:'文件查杀失败',unavailable:'文件查杀状态不可用'};
  const counted=count(value?.processed) && count(value?.indexed);
  const percent=counted && value.indexed > 0 && value.state !== 'indexing' ? Math.min(running ? 99 : 100,Math.floor(100 * value.processed / value.indexed)) : null;
  const current=active ? value?.current_file : null;
  const phases={opening:'正在读取文件',hashing:'正在校验文件摘要',engine:'正在引擎检测'};
  const detail=current ? phases[current.phase]+' · '+current.path+(current.phase==='hashing'?' · '+current.bytes_read.toLocaleString()+' / '+current.size.toLocaleString()+' 字节':'') : active && value.state==='indexing' ? '正在枚举已纳管目录，文件总数尚未确定' : active ? '等待下一文件或汇总报告' : '';
  return {detail,active,stale,percent:stale ? null : percent,label:stale ? (running ? '进度已过期，请核对主机代理' : '历史查杀记录，需重新扫描') : labels[value?.state] || labels.unavailable,
    tone:value?.infected > 0 ? 'finding' : value?.state === 'finished' && !stale ? 'ok' : 'warning',
    files:counted ? value.processed.toLocaleString()+' / '+value.indexed.toLocaleString()+' 文件' : '等待真实文件计数'};
}
