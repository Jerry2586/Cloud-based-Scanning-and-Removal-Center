// Fixed, bounded contract for authenticated cloud hash tasks. No executable actions.
export const HASH_PATTERN = /^[a-f0-9]{64}$/;
export const TASK_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const states = new Set(['queued','running','complete','partial','failed']);
const providers = new Set(['signed-rules','hash-intelligence']);
const text = (v,n) => typeof v === 'string' && v.length <= n && !/[\x00-\x1f\x7f]/.test(v);
const time = v => typeof v === 'string' && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
const integer = (v,n) => Number.isSafeInteger(v) && v >= 0 && v <= n;
export function validateHashRequest(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'request_key,sha256' || typeof value.sha256 !== 'string' || !HASH_PATTERN.test(value.sha256) || typeof value.request_key !== 'string' || !TASK_PATTERN.test(value.request_key)) throw Object.assign(Error('仅支持 SHA-256 与唯一请求编号'), {status:400});
  return {sha256:value.sha256,request_key:value.request_key};
}
export function validateHashJob(value, {nodeId, requester, id, sha256} = {}) {
  const bad = () => { throw Error('INVALID_CLOUD_TASK'); };
  if (!value || typeof value !== 'object' || Array.isArray(value) || !text(value.requester,100) || !/^(?:admin|node\/(?:node-[a-z0-9][a-z0-9-]{0,63}|license-center|build-center))$/.test(value.requester) || typeof value.id !== 'string' || !TASK_PATTERN.test(value.id) || (id && value.id !== id) || (requester && value.requester !== requester) || (nodeId && value.requester !== 'node/' + nodeId) || typeof value.sha256 !== 'string' || !HASH_PATTERN.test(value.sha256) || (sha256 && value.sha256 !== sha256) || !states.has(value.state) || !time(value.created_at) || !time(value.updated_at) || value.updated_at < value.created_at || !integer(value.attempts,100000) || !value.policy || !integer(value.policy.revision,Number.MAX_SAFE_INTEGER) || value.policy.revision < 1 || !integer(value.policy.malicious_threshold,20) || value.policy.malicious_threshold < 1 || typeof value.policy.external_hash_lookup !== 'boolean' || !Array.isArray(value.providers) || value.providers.length > 2 || new Set(value.providers).size !== value.providers.length || value.providers.some(x => !providers.has(x))) return bad();
  let result = null;
  if (['complete','partial'].includes(value.state)) {
    const r=value.result;
    if (!r || !['unknown','suspicious','malicious'].includes(r.verdict) || r.automatic_remediation !== false || r.policy_revision !== value.policy.revision || !text(r.reason,300) || !Array.isArray(r.evidence) || r.evidence.length !== value.providers.length) return bad();
    const evidence=[];
    for (const e of r.evidence) {
      if (!e || !value.providers.includes(e.provider) || evidence.some(x => x.provider === e.provider) || !['malicious','known','unknown','unavailable'].includes(e.state)) return bad();
      const item={provider:e.provider,state:e.state};
      if (e.reason !== undefined) { if (!text(e.reason,300)) return bad(); item.reason=e.reason; }
      if (e.state === 'known') {
        if (e.provider !== 'hash-intelligence') return bad();
        for (const k of ['malicious','suspicious','undetected','harmless']) { if (!integer(e[k],1000)) return bad(); item[k]=e[k]; }
        if (e.analyzed_at !== null && !time(e.analyzed_at)) return bad(); item.analyzed_at=e.analyzed_at;
      }
      if (e.state === 'malicious' && e.provider !== 'signed-rules') return bad();
      for (const k of ['version','indicator','label','digest']) if (e[k] !== undefined) { if (!text(e[k],160)) return bad(); item[k]=e[k]; }
      evidence.push(item);
    }
    const malicious=evidence.some(e => e.state==='malicious' || (e.state==='known' && e.malicious>=value.policy.malicious_threshold));
    const suspicious=evidence.some(e => e.state==='known' && (e.malicious>0 || e.suspicious>0));
    if (r.verdict !== (malicious?'malicious':suspicious?'suspicious':'unknown') || (value.state==='complete' && (!evidence.length || evidence.some(e => e.state==='unavailable')))) return bad();
    result={verdict:r.verdict,evidence,policy_revision:r.policy_revision,automatic_remediation:false,reason:r.reason};
  } else if (value.result !== null) return bad();
  return {id:value.id,requester:value.requester,sha256:value.sha256,state:value.state,created_at:value.created_at,updated_at:value.updated_at,attempts:value.attempts,policy:{revision:value.policy.revision,malicious_threshold:value.policy.malicious_threshold,external_hash_lookup:value.policy.external_hash_lookup},providers:[...value.providers],result};
}
