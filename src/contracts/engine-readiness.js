import {ENGINE_IDS} from './multi-engine-status.js';
export {ENGINE_IDS};
const states=new Set(['ready','partial','stale','unavailable']);
const safe=(v,n)=>typeof v==='string' && v.length<=n && !/[\x00-\x1f\x7f]/.test(v);
const timestamp=v=>safe(v,40) && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && new Date(v).toISOString().slice(0,19)===v.slice(0,19);
const version=v=>safe(v,64) && /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?$/.test(v);
export function unavailableReadiness(reason='本机引擎状态无法核验') {
 return {schema:'ironcurtain-engine-readiness/v1',state:'unavailable',reason:safe(reason,180)?reason:'本机引擎状态无法核验',ready_count:0,engines:ENGINE_IDS.map(id=>({id,state:'unavailable',detail:'等待本机可信检查代理'}))};
}
export function sanitizeEngineReadiness(value,now=Date.now()) {
 const fail=()=>unavailableReadiness();
 if(!value || value.schema!=='ironcurtain-engine-readiness/v1' || !['checking','checked','unavailable'].includes(value.state) || !safe(value.reason,180) || !Array.isArray(value.engines) || value.engines.length!==4 || value.engines.some((e,i)=>e?.id!==ENGINE_IDS[i]))return fail();
 if(value.state==='checked' && (!timestamp(value.checked_at) || Date.parse(value.checked_at)>now+5000 || now-Date.parse(value.checked_at)>120000))return fail();
 const engines=[];
 for(const e of value.engines) {
  if(!states.has(e.state) || !safe(e.detail,180) || (e.id==='falco' && !['partial','unavailable'].includes(e.state)) || (value.state!=='checked' && e.state!=='unavailable'))return fail();
  const row={id:e.id,state:e.state,detail:e.detail};
  if(e.version!==undefined){if(!(e.id==='clamav'?safe(e.version,64) && /^[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9.-]{1,32})?$/.test(e.version):version(e.version)))return fail();row.version=e.version;}
  for(const k of ['database_at','next_update'])if(e[k]!==undefined){if(!timestamp(e[k]))return fail();row[k]=e[k];}
  if(e.source!==undefined){if(e.id!=='clamav' || !['official-direct','xuanwu-signed'].includes(e.source))return fail();row.source=e.source;}
  if(e.id==='clamav' && ['ready','stale'].includes(e.state) && !row.source)return fail();
  if(['ready','stale'].includes(e.state) && e.id!=='falco' && !row.version)return fail();
  if(['ready','stale'].includes(e.state) && ['clamav','trivy'].includes(e.id) && !row.database_at)return fail();
  if(e.id==='trivy' && ['ready','stale'].includes(e.state) && !row.next_update)return fail();
  if(row.database_at && Date.parse(row.database_at)>now+300000)return fail();
  if(e.id==='trivy' && row.next_update && (Date.parse(row.next_update)<=Date.parse(row.database_at) || Date.parse(row.next_update)-Date.parse(row.database_at)>48*3600000))return fail();
  if(e.id==='trivy' && e.state==='ready' && (Date.parse(row.next_update)<=now || now-Date.parse(row.database_at)>48*3600000))return fail();
  engines.push(row);
 }
 const ready_count=engines.filter(e=>e.state==='ready').length;
 if(value.ready_count!==ready_count)return fail();
 return {schema:value.schema,state:value.state,reason:value.reason,ready_count,engines,...(value.state==='checked'?{checked_at:value.checked_at}:{}),...([202,409,429,503].includes(value.response_status)?{response_status:value.response_status}:{})};
}
