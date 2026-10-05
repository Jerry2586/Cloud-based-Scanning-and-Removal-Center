// Public host metadata only; missing or malformed observations stay unavailable.
const states = ['complete','partial','unavailable'];
const text = (v,n=180) => typeof v==='string' && v.length<=n && !/[\x00-\x1f\x7f]/.test(v);
const count = (v,n) => Number.isSafeInteger(v) && v>=0 && v<=n;
const token = v => text(v,160) && /^[A-Za-z0-9][A-Za-z0-9_.+:~%/@=\-]*$/.test(v);
const list = (v,n) => Array.isArray(v) && v.length<=n;
export function sanitizeEnvironment(v) {
  const unavailable=()=>({state:'unavailable'});
  if (!v || v.schema!=='ironcurtain-environment/v1' || !['system_state','package_state','service_state'].every(k=>states.includes(v[k])) ||
      !['dpkg','rpm','unknown'].includes(v.package_manager) || !['first-observation','compared','partial'].includes(v.change_state) ||
      !v.os || Array.isArray(v.os) || typeof v.os!=='object' || Object.keys(v.os).some(k=>!['PRETTY_NAME','ID','VERSION_ID'].includes(k)) || !Object.values(v.os).every(x=>text(x,160)) || !text(v.kernel,160) ||
      v.system_state==='complete' && (!v.os.ID || !v.kernel) ||
      !count(v.package_count,4096) || !count(v.service_count,512) || !count(v.running_services,v.service_count) || !count(v.failed_services,v.service_count-v.running_services) ||
      !list(v.packages,32) || !list(v.services,16) || v.packages.length>v.package_count || v.services.length>v.service_count ||
      !list(v.issues,8) || !list(v.changes,32) || ![...v.issues,...v.changes].every(x=>text(x)) || !count(v.changes_total,9217) || v.changes_total<v.changes.length ||
      !['packages_digest','services_digest'].every(k=>typeof v[k]==='string' && /^[a-f0-9]{64}$/.test(v[k])) || typeof v.truncated!=='boolean' ||
      v.package_state==='unavailable' && v.package_count!==0 || v.service_state==='unavailable' && v.service_count!==0) return unavailable();
  if(v.packages.some(x=>!x || !token(x.name) || !token(x.version)) || v.services.some(x=>!x || !token(x.name) || !x.name.endsWith('.service') || !['load','active','sub'].every(k=>token(x[k]))) ||
     new Set(v.packages.map(x=>x.name+'\0'+x.version)).size!==v.packages.length || new Set(v.services.map(x=>x.name)).size!==v.services.length) return unavailable();
  return {schema:v.schema,os:{...v.os},kernel:v.kernel,system_state:v.system_state,package_state:v.package_state,service_state:v.service_state,package_manager:v.package_manager,
    package_count:v.package_count,service_count:v.service_count,running_services:v.running_services,failed_services:v.failed_services,
    packages:v.packages.map(x=>({name:x.name,version:x.version})),services:v.services.map(x=>({name:x.name,load:x.load,active:x.active,sub:x.sub})),
    issues:[...v.issues],changes:[...v.changes],changes_total:v.changes_total,change_state:v.change_state,packages_digest:v.packages_digest,services_digest:v.services_digest,truncated:v.truncated};
}
