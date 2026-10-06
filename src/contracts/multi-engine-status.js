// A bounded view of evidence from the fixed local Go manager.
export const ENGINE_IDS = Object.freeze(['clamav','trivy','osquery','falco']);
export const ENGINE_META = Object.freeze({
 clamav: {name:'文件查杀',kind:'malware',scope:'已纳管文件目录 · 官方病毒库'},
 trivy: {name:'镜像漏洞',kind:'vulnerability',scope:'本机容器的不可变镜像 · 本地漏洞库'},
 osquery: {name:'端口资产',kind:'asset',scope:'当前监听端口与进程归属'},
 falco: {name:'行为事件',kind:'behavior',scope:'最近 15 分钟 · 可信事件文件'}
});
const terminal = new Set(['complete','partial','unavailable','failed','cancelled']);
const safe = (x,n) => typeof x === 'string' && [...x].length<=n && !/[\x00-\x1f\x7f]/.test(x);
const count = (x,n=200000) => Number.isSafeInteger(x) && x>=0 && x<=n;
const hex = x => typeof x==='string' && /^[a-f0-9]{64}$/.test(x);
const time = x => typeof x==='string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(x) && Number.isFinite(Date.parse(x)) && new Date(x).toISOString()===x;
export function sanitizeMultiEngine(value) {
 const bad={schema:'ironcurtain-multi-engine/v1',state:'unavailable',reason:'本机多引擎检测尚未就绪或报告无法核验'};
 if (!value || typeof value!=='object' || Array.isArray(value)) return bad;
 const status=[202,409,429,503].includes(value.response_status)?{response_status:value.response_status}:{};
 if (['idle','unavailable'].includes(value.state)) return {schema:bad.schema,state:value.state,...(safe(value.reason,180)?{reason:value.reason}:value.state==='unavailable'?{reason:bad.reason}:{}),...status};
 if (value.schema!==bad.schema || !['running','finished','partial','cancelled','failed'].includes(value.state) || !hex(value.job_id) || !hex(value.profile_digest) || !time(value.started_at) || !time(value.updated_at) || value.updated_at<value.started_at || !count(value.completed,4) || value.total!==4 || !count(value.coverage,4) || !Array.isArray(value.engines) || value.engines.length!==4) return bad;
 const engines=[];
 for (let i=0;i<4;i++) {
  const e=value.engines[i]; const id=ENGINE_IDS[i];
  if (!e || e.id!==id || ![...terminal,'queued','running'].includes(e.state) || !safe(e.detail,180) || !count(e.completed) || !count(e.total) || e.completed>e.total || (e.state==='complete' && e.completed!==e.total) || !count(e.finding_total) || !Array.isArray(e.findings) || e.findings.length>16 || e.finding_total<e.findings.length || (e.evidence_digest!==undefined && !hex(e.evidence_digest))) return bad;
  const findings=[];
  for (const f of e.findings) {
   if (!f || f.kind!==ENGINE_META[id].kind || !['info','low','medium','high','critical'].includes(f.severity) || !safe(f.target,256) || !safe(f.rule,160) || !safe(f.detail,180)) return bad;
   findings.push({kind:f.kind,severity:f.severity,target:f.target,rule:f.rule,detail:f.detail});
  }
  engines.push({id,state:e.state,detail:e.detail,completed:e.completed,total:e.total,finding_total:e.finding_total,findings,...(e.evidence_digest?{evidence_digest:e.evidence_digest}:{})});
 }
 if (value.completed!==engines.filter(e=>terminal.has(e.state)).length || value.coverage!==engines.filter(e=>e.state==='complete').length || (value.state==='finished' && value.coverage!==4) || (value.state==='partial' && value.coverage===4)) return bad;
 if (value.state!=='running' && (value.completed!==4 || !time(value.finished_at) || value.finished_at<value.started_at || value.finished_at>value.updated_at)) return bad;
 return {schema:bad.schema,state:value.state,job_id:value.job_id,profile_digest:value.profile_digest,started_at:value.started_at,updated_at:value.updated_at,...(value.state!=='running'?{finished_at:value.finished_at}:{}),completed:value.completed,total:4,coverage:value.coverage,engines,...status};
}
