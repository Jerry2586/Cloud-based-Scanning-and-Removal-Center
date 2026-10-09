import {CAPABILITY_NAMES,engineDisplayText} from './engine-labels.js';
import {sanitizeEngineReadiness,unavailableReadiness,ENGINE_IDS} from '/contracts/engine-readiness.js';
const $=id=>document.getElementById(id);
const names=CAPABILITY_NAMES;
const labels={ready:'依赖可用',partial:'部分就绪',stale:'数据过期',unavailable:'未就绪'};
const maintenance={clamav:'使用下方按钮安装或修复文件引擎；维护官方病毒库或选择玄武签名库时保留当前更新来源。',trivy:'在可信终端安装镜像检测组件到固定位置并更新本机漏洞缓存；当前不提供网页自动安装。',osquery:'在可信终端安装资产采集组件；固定资产查询通过后再运行联合检测。',falco:'配置宿主探针与受保护事件输出，并核验服务健康；事件文件不能证明持续防护。'};
export function createEngineReadiness({state,request,notify}) {
 let bound=false,pending=false,starting=false,timer=null,generation=0,activeSession=null,lastValue=unavailableReadiness(),refreshWanted=false;
 function render(value) {
  const data=sanitizeEngineReadiness(value);lastValue=data;
  const title=$('engine-readiness-state'),note=$('engine-readiness-detail'),list=$('engine-readiness-list'),button=$('engine-readiness-check');
  if(title)title.textContent=data.state==='checking'?'正在核验本机引擎':data.state==='checked'?'检测依赖可用 '+data.ready_count+'/4':'等待可信主机检查';
  if(note)note.textContent=data.reason+(data.checked_at?' · 检查于 '+new Date(data.checked_at).toLocaleString():'');
  if(button)button.disabled=starting || data.state==='checking' || !state.csrf;
  list?.replaceChildren();
  for(const id of ENGINE_IDS) {
   const e=data.engines.find(x=>x.id===id);const row=document.createElement('li');row.className='ic-engine-readiness-card';row.dataset.state=e.state==='ready'?'ok':e.state==='stale'?'warning':'unavailable';
   const heading=document.createElement('div');heading.className='ic-readiness-heading';const name=document.createElement('strong');name.textContent=names[id];const badge=document.createElement('span');badge.className='ic-readiness-badge';badge.textContent=labels[e.state];heading.append(name,badge);
   const version=document.createElement('p');version.className='sc-muted';version.textContent='版本 '+(e.version || '未核验')+(e.database_at?' · 数据时间 '+new Date(e.database_at).toLocaleString():'')+(e.next_update?' · 更新期限 '+new Date(e.next_update).toLocaleString():'');
   const detail=document.createElement('p');detail.textContent=engineDisplayText(e.detail);
   const guide=document.createElement('p');guide.className='ic-readiness-guide';guide.textContent=maintenance[id];row.append(heading,version,detail,guide);list?.append(row);
  }
 }
 async function refresh() {
  if(!state.csrf)return;if(pending){refreshWanted=true;return;}clearTimeout(timer);timer=null;
  const session=state.csrf,epoch=generation;pending=true;let delay=20000;
  try{const data=await request('/api/engines');if(session!==state.csrf || epoch!==generation)return;render(data);if(data.state==='checking')delay=2000;}
  catch(error){if(session===state.csrf && epoch===generation)render(unavailableReadiness(error.message));}
  finally{pending=false;if(refreshWanted){refreshWanted=false;void refresh();}else if(session===state.csrf && epoch===generation)timer=setTimeout(()=>void refresh(),delay);}
 }
 function bind(){if(bound)return;bound=true;$('engine-readiness-check')?.addEventListener('click',async()=>{
  if(starting || !state.csrf)return;const session=state.csrf;generation++;clearTimeout(timer);timer=null;starting=true;render(lastValue);
  try{const data=await request('/api/engines/check',{method:'POST',body:{}});if(session===state.csrf)render(data);}
  catch(error){if(session===state.csrf)notify(error.message,true);}
  finally{starting=false;if(session===state.csrf){render(lastValue);void refresh();}}
 });}
 return Object.freeze({bind,refresh,start(){if(activeSession===state.csrf)return;activeSession=state.csrf;generation++;clearTimeout(timer);timer=null;if(!state.csrf){render(unavailableReadiness('请登录后查看本机引擎'));return;}void refresh();}});
}
