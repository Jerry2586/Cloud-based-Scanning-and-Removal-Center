import { safeTimestamp } from './host-scan-contract.js';
const ver=v=>typeof v==='string'&&/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(v)&&v.length<=32;
const hash=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const sha=v=>typeof v==='string'&&/^[a-f0-9]{40}$/.test(v);
export function compareVersions(a,b){if(!ver(a)||!ver(b))return null;const x=a.split('.').map(BigInt),y=b.split('.').map(BigInt);for(let i=0;i<3;i++)if(x[i]!==y[i])return x[i]>y[i]?1:-1;return 0;}
function record(v,kind){
 if(!v||!['idle','running','failed','unavailable',...(kind==='check'?['verified']:['finished'])].includes(v.state))return {state:'unavailable'};
 const out={state:v.state};for(const k of ['checked_at','started_at','finished_at'])if(safeTimestamp(v[k]))out[k]=v[k];
 for(const k of ['version','installed_version','latest_version'])if(ver(v[k]))out[k]=v[k];
 if(['updated','already-current'].includes(v.result))out.result=v.result;
 if(['failed','unavailable'].includes(v.state))out.reason='检查或更新未完成，请在 Linux 菜单核对网络、凭据和安装记录。';
 if(kind==='check'){
 out.installed_integrity=['verified','mismatch'].includes(v.installed_integrity)?v.installed_integrity:'unavailable';out.source={state:'unavailable'};out.update_available=false;
 if(v.source?.state==='observed'&&sha(v.source.commit)){out.source={state:'observed',commit:v.source.commit};if(sha(v.source.release_commit))Object.assign(out.source,{release_commit:v.source.release_commit,has_unreleased_changes:v.source.commit!==v.source.release_commit});}
 if(v.state==='verified'){
 const relation=compareVersions(v.latest_version,v.installed_version);
 if(out.installed_integrity!=='verified'||!out.checked_at||relation===null||relation<0||!hash(v.manifest_sha256)||!hash(v.package_sha256))return {state:'unavailable'};
 Object.assign(out,{update_available:relation>0,manifest_sha256:v.manifest_sha256,package_sha256:v.package_sha256});
 }
 }return out;
}
export function sanitizeUpdateStatus(v){
 if(!v||v.schema!=='ironcurtain-update-status/v1')return {schema:'ironcurtain-update-status/v1',installed_version:null,check:{state:'unavailable'},job:{state:'unavailable'}};
 return {schema:v.schema,installed_version:ver(v.installed_version)?v.installed_version:null,check:record(v.check,'check'),job:record(v.job,'job')};
}
export function updateView(v,running,now=Date.now()){
 const status=sanitizeUpdateStatus(v),check=status.check;
 const fresh=check.checked_at&&Date.parse(check.checked_at)<=now+30000&&Date.parse(check.checked_at)>=now-900000;
 return {...status,running_version:ver(running)?running:null,can_install:Boolean(fresh&&check.state==='verified'&&check.update_available&&check.installed_version===status.installed_version&&running===status.installed_version&&!['running'].includes(status.job.state)),fresh:Boolean(fresh)};
}
