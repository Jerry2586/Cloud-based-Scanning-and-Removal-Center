// Metadata is display-only. Activation always verifies the publisher signature locally.
export function sanitizeRules(value) {
  const unknown={state:'unavailable',detail:'签名哈希规则状态不可用'};
  if(!value || !['ready','missing','unavailable'].includes(value.state))return unknown;
  if(value.state!=='ready')return {state:value.state,detail:value.state==='missing'?'尚未安装签名哈希规则':'规则签名、有效期或权限不可用'};
  if(typeof value.version!=='string' || !/^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$/.test(value.version) || ![value.sequence,value.issued_at,value.expires_at].every(n=>Number.isSafeInteger(n)&&n>0) || value.expires_at<=Math.floor(Date.now()/1000) || value.issued_at>Math.floor(Date.now()/1000)+300 || value.expires_at<=value.issued_at || value.expires_at-value.issued_at>2678400 || !Number.isInteger(value.indicators) || value.indicators<0 || value.indicators>1024 || typeof value.payload_sha256!=='string' || !/^[a-f0-9]{64}$/.test(value.payload_sha256))return unknown;
  return {state:'ready',version:value.version,sequence:value.sequence,issued_at:value.issued_at,expires_at:value.expires_at,indicators:value.indicators,payload_sha256:value.payload_sha256,detail:'发布签名已核验；固定 SHA-256 特征'};
}
export function sanitizeRuleHits(value) {
  const unknown={state:'unavailable',items:[],total:0};
  if(!value || !['complete','partial','unavailable'].includes(value.state) || !Array.isArray(value.items) || value.items.length>8 || !Number.isInteger(value.total) || value.total<value.items.length || value.total>20000)return unknown;
  const ids=new Set();
  for(const item of value.items) {
    if(!item || typeof item.id!=='string' || !/^[a-f0-9]{64}$/.test(item.id) || ids.has(item.id) || typeof item.sha256!=='string' || !/^[a-f0-9]{64}$/.test(item.sha256) || typeof item.rule_id!=='string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(item.rule_id) || typeof item.label!=='string' || !item.label || [...item.label].length>128 || /[\x00-\x1f\x7f]/.test(item.label) || typeof item.path!=='string' || !item.path.startsWith('/') || item.path.length>1024 || /[\x00-\x1f\x7f]/.test(item.path) || item.path.split('/').includes('..') || !Number.isSafeInteger(item.rule_sequence) || item.rule_sequence<1 || typeof item.observed_at!=='string' || !Number.isFinite(Date.parse(item.observed_at))) return unknown;
    ids.add(item.id);
  }
  return {state:value.state,total:value.total,items:value.items.map(({id,sha256,rule_id,label,path,rule_sequence,observed_at})=>({id,sha256,rule_id,label,path,rule_sequence,observed_at}))};
}
