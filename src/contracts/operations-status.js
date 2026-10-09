const SCHEMA = 'ironcurtain-operations/v1';
const hex = (v, n=64) => typeof v === 'string' && new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const text = (v, max) => typeof v === 'string' && Array.from(v).length <= max && !/[\x00-\x1f\x7f]/.test(v);
const time = v => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(v) && Number.isFinite(Date.parse(v));
const object = v => v && typeof v === 'object' && !Array.isArray(v);
const keys = (v, expected) => object(v) && Object.keys(v).sort().join() === [...expected].sort().join();
export function validatePorts(value) {
  if (!Array.isArray(value) || value.length > 128 || value.some(v => !Number.isInteger(v) || v < 1 || v > 65535) || new Set(value).size !== value.length) throw Error('端口须为 1–65535 的不重复整数，每种协议最多 128 项');
  return [...value].sort((a,b)=>a-b);
}
export function validateOperation(value) {
  const actions = {discover:['action'],enroll:['action','revision','inventory','ids'],ports:['action','revision','tcp','udp'],review:['action','id','evidence','status','reason'],quarantine:['action','id','confirm'],restore:['action','id','confirm']};
  const expected = typeof value?.action === 'string' && Object.hasOwn(actions,value.action) ? actions[value.action] : null;
  if (!expected || !keys(value,expected)) throw Error('处置请求包含缺失或未支持字段');
  if (value.action === 'discover') return {action:'discover'};
  if (value.action === 'enroll') {
    if (!hex(value.revision) || !hex(value.inventory) || !Array.isArray(value.ids) || value.ids.length < 1 || value.ids.length > 32 || value.ids.some(id=>!hex(id,16)) || new Set(value.ids).size !== value.ids.length) throw Error('请选择 1–32 个不重复的当前保护候选');
    return {...value,ids:[...value.ids]};
  }
  if (value.action === 'ports') { if (!hex(value.revision)) throw Error('配置版本无效'); return {...value,tcp:validatePorts(value.tcp),udp:validatePorts(value.udp)}; }
  if (!hex(value.id)) throw Error('证据编号无效');
  if (value.action === 'review') {
    if (!hex(value.evidence) || !['open','investigating','accepted'].includes(value.status) || !text(typeof value.reason === 'string' ? value.reason.trim() : value.reason,240) || Array.from(value.reason.trim()).length < 4 || /[\r\n\t]/.test(value.reason)) throw Error('请选择处理状态并填写 4–240 字的原因');
    return {...value,reason:value.reason.trim()};
  }
  if (value.confirm !== (value.action === 'quarantine' ? 'quarantine' : 'restore-original')) throw Error('请明确确认文件操作');
  return {...value};
}
// Successful persisted operations select one fixed follow-up; review is not a repair.
export function operationRecheckPlan(job) {
  if (job?.state !== 'complete' || !hex(job.id,32) || !time(job.finished_at)) return null;
  if (['ports','enroll'].includes(job.action)) return {action:'scan',panel:'environment',label:'复检环境与端口'};
  if (['quarantine','restore'].includes(job.action)) return {action:'checkup',panel:'scan',label:'复检文件与环境'};
  return null;
}
export const unavailableOperations = (reason='本机处置服务未就绪') => ({schema:SCHEMA,state:'unavailable',reason});
function job(v) {
  if (!object(v) || !['idle','running','complete','failed','interrupted'].includes(v.state)) throw Error();
  if (v.state === 'idle') return {state:'idle'};
  if (!hex(v.id,32) || !['ports','review','quarantine','restore','discover','enroll'].includes(v.action) || !time(v.started_at) || !text(v.reason,500) || (v.state !== 'running' && (!time(v.finished_at) || v.finished_at < v.started_at))) throw Error();
  return {id:v.id,state:v.state,action:v.action,started_at:v.started_at,reason:v.reason,...(v.finished_at?{finished_at:v.finished_at}:{})};
}
function scope(v) {
  // Older controllers do not provide an editable scope; never infer it from an asset report.
  if (v === undefined || v === null) return null;
  if (!object(v) || !['program_roots','business_roots','containers'].every(k=>Array.isArray(v[k]) && v[k].length<=32)) throw Error();
  for(const key of ['program_roots','business_roots']) if(v[key].some(p=>!text(p,4096) || !p.startsWith('/'))) throw Error();
  if(v.containers.some(p=>!text(p,128) || !/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(p)))throw Error();
  const d=v.discovery;
  if (!object(d) || !['ready','stale','unavailable'].includes(d.state) || !Array.isArray(d.candidates) || d.candidates.length>128 || !Number.isInteger(d.count) || d.count<d.candidates.length || d.count>128 || typeof d.truncated!=='boolean' || d.truncated!==(d.count>d.candidates.length) || !Array.isArray(d.issues) || d.issues.length>8 || d.issues.some(i=>!text(i,180)))throw Error();
  if(d.state==='unavailable') {if(d.revision!==null || d.observed_at!==null || d.count!==0)throw Error();}
  else if(!hex(d.revision) || !time(d.observed_at))throw Error();
  const candidates=d.candidates.map(i=>{
    if(!object(i) || !hex(i.id,16) || !['program_roots','business_roots','containers'].includes(i.kind) || !text(i.value,1024) || !text(i.origin,180) || typeof i.enrolled!=='boolean')throw Error();
    if(i.kind==='containers'?!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(i.value):!i.value.startsWith('/'))throw Error();
    return {id:i.id,kind:i.kind,value:i.value,origin:i.origin,enrolled:i.enrolled};
  });
  if(new Set(candidates.map(i=>i.id)).size!==candidates.length)throw Error();
  return {program_roots:[...v.program_roots],business_roots:[...v.business_roots],containers:[...v.containers],discovery:{state:d.state,revision:d.revision,observed_at:d.observed_at,candidates,count:d.count,truncated:d.truncated,issues:[...d.issues]}};
}
export function sanitizeOperations(v) {
  try {
    if (v?.schema !== SCHEMA) throw Error();
    if (v.state === 'running') { const active=job(v.job); if(active.state !== 'running')throw Error(); return {schema:SCHEMA,state:'running',job:active}; }
    if (v.state !== 'ready' || !hex(v.policy?.revision)) throw Error();
    const policy={revision:v.policy.revision,tcp:validatePorts(v.policy.tcp),udp:validatePorts(v.policy.udp)};
    if (!Array.isArray(v.risks) || v.risks.length > 96 || !Array.isArray(v.audit) || v.audit.length > 12 || !object(v.sources)) throw Error();
    const risks=v.risks.map(r=>{
      if (!hex(r.id) || !hex(r.evidence) || !text(r.source,40) || !text(r.rule,256) || !text(r.target,256) || !text(r.title,160) || !text(r.detail,500) || !['critical','high','medium','low','info','unknown'].includes(r.severity) || !time(r.observed_at) || typeof r.fresh !== 'boolean' || !['open','investigating','accepted'].includes(r.review?.status) || !text(r.review.reason,240) || !(r.review.updated_at === null || time(r.review.updated_at))) throw Error();
      return {id:r.id,evidence:r.evidence,source:r.source,rule:r.rule,target:r.target,title:r.title,detail:r.detail,severity:r.severity,observed_at:r.observed_at,fresh:r.fresh,review:{status:r.review.status,reason:r.review.reason,updated_at:r.review.updated_at}};
    });
    if (new Set(risks.map(r=>r.id)).size !== risks.length || !['current','historical','unavailable'].includes(v.sources.environment) || !['current','historical','unavailable'].includes(v.sources.engines)) throw Error();
    const q=v.quarantine;
    if (!object(q) || !['recorded','empty','unavailable'].includes(q.state) || !Array.isArray(q.items) || q.items.length>8 || !Number.isInteger(q.count) || q.count<0 || q.count>128 || !Number.isInteger(q.pending) || q.pending<0 || q.pending>q.count) throw Error();
    const items=q.items.map(i=>{if (!hex(i.id) || !text(i.path,4096) || !text(i.signature,256) || !['preparing','captured','quarantined','restoring','restored'].includes(i.state) || !Number.isSafeInteger(i.size) || i.size<0) throw Error(); return {id:i.id,path:i.path,signature:i.signature,state:i.state,size:i.size};});
    return {schema:SCHEMA,state:'ready',policy,scope:scope(v.scope),job:job(v.job),risks,sources:{environment:v.sources.environment,engines:v.sources.engines,engine_coverage:/^[0-4]\/4$/.test(v.sources.engine_coverage)?v.sources.engine_coverage:'0/4',truncated:v.sources.truncated===true},audit:v.audit.map(i=>{const record=job(i);if(['idle','running'].includes(record.state) || !text(i.target,256))throw Error();return {...record,target:i.target};}),quarantine:{state:q.state,items,count:q.count,pending:q.pending}};
  } catch { return unavailableOperations('处置数据无法核验，请检查宿主服务'); }
}
