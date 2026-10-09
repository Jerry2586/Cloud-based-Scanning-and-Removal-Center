export const ENGINE_MAINTENANCE_SCHEMA='ironcurtain-engine-maintenance/v1';
const reasons=Object.freeze({idle:'尚未运行文件引擎维护',queued:'文件引擎维护已排队',installing:'正在从系统受信任软件源安装或修复文件引擎',finished:'文件引擎维护完成；请重新核验依赖并运行文件扫描',busy:'检测或其他管理任务正在运行；维护未执行，请稍后重试',failed:'文件引擎维护失败；请检查系统软件源、网络和病毒库状态后重试',interrupted:'维护任务已中断；请重新核验引擎并重试',unavailable:'文件引擎维护服务无法核验',cooldown:'请求过于频繁，请稍后重试'});
const codes={idle:['idle'],queued:['queued'],running:['installing'],finished:['finished'],failed:['failed','busy','interrupted'],unavailable:['unavailable','busy','cooldown']};
export const unavailableMaintenance=()=>({schema:ENGINE_MAINTENANCE_SCHEMA,state:'unavailable',code:'unavailable',reason:reasons.unavailable});
const time=v=>typeof v==='string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && Date.parse(v)<=Date.now()+5000;
export function sanitizeEngineMaintenance(v){
 if(!v || v.schema!==ENGINE_MAINTENANCE_SCHEMA || !codes[v.state]?.includes(v.code))return unavailableMaintenance();
 const out={schema:ENGINE_MAINTENANCE_SCHEMA,state:v.state,code:v.code,reason:reasons[v.code]};
 if(['queued','running','finished','failed'].includes(v.state)){
  if(!/^[a-f0-9]{32}$/.test(v.id || '') || !time(v.requested_at))return unavailableMaintenance();
  out.id=v.id;out.requested_at=v.requested_at;
  for(const key of ['started_at','finished_at'])if(v[key]!==undefined){if(!time(v[key]) || Date.parse(v[key])<Date.parse(v.requested_at))return unavailableMaintenance();out[key]=v[key];}
  if(v.state==='running' && !out.started_at || ['finished','failed'].includes(v.state) && !out.finished_at || out.started_at && out.finished_at && Date.parse(out.finished_at)<Date.parse(out.started_at))return unavailableMaintenance();
 }
 return out;
}
