import {sanitizeEngineMaintenance,unavailableMaintenance} from '/contracts/engine-maintenance.js';
const $=id=>document.getElementById(id);
export function createEngineMaintenance({state,request,notify,onFinished=()=>{}}){
 let bound=false,starting=false,pending=false,timer=null,generation=0,session=null,last=unavailableMaintenance(),terminal=null;
 function render(raw){
  const v=sanitizeEngineMaintenance(raw);last=v;
  const label={idle:'尚未维护',queued:'已排队',running:'安装或修复中',finished:'维护完成',failed:'维护失败',unavailable:'服务未就绪'};
  if($('engine-maintenance-state'))$('engine-maintenance-state').textContent=label[v.state];
  if($('engine-maintenance-detail'))$('engine-maintenance-detail').textContent=v.reason+(v.finished_at?' · '+new Date(v.finished_at).toLocaleString():'');
  const b=$('engine-maintenance-install');if(b){b.disabled=starting || !state.csrf || ['queued','running','unavailable'].includes(v.state);b.textContent=starting?'正在提交…':['queued','running'].includes(v.state)?'文件引擎维护中':'安装 / 修复文件引擎';}
  if(['finished','failed'].includes(v.state) && v.id && terminal!==v.id){terminal=v.id;if(v.state==='finished')onFinished();}
 }
 async function refresh(){
  if(!state.csrf || pending)return;clearTimeout(timer);timer=null;
  const current=state.csrf,epoch=generation;pending=true;
  try{const v=await request('/api/engines/maintenance');if(current===state.csrf && epoch===generation)render(v);}
  catch{if(current===state.csrf && epoch===generation)render(unavailableMaintenance());}
  finally{pending=false;if(state.csrf && epoch!==generation){void refresh();}else if(current===state.csrf && epoch===generation)timer=setTimeout(()=>void refresh(),['queued','running'].includes(last.state)?2000:20000);}
 }
 function bind(){if(bound)return;bound=true;$('engine-maintenance-install')?.addEventListener('click',async()=>{
  if(starting || !state.csrf || ['queued','running','unavailable'].includes(last.state))return;
  const current=state.csrf;generation++;clearTimeout(timer);timer=null;starting=true;render(last);
  try{const v=await request('/api/engines/install',{method:'POST',body:{}});if(current===state.csrf)render(v);}
  catch(e){if(current===state.csrf)notify(e.message,true);}
  finally{starting=false;if(current===state.csrf){render(last);void refresh();}}
 });}
 return Object.freeze({bind,start(){if(session===state.csrf)return;session=state.csrf;generation++;clearTimeout(timer);timer=null;terminal=null;if(!state.csrf){render(unavailableMaintenance());return;}void refresh();}});
}
