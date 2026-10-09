import {engineDisplayText} from './engine-labels.js';
import {ENGINE_IDS,ENGINE_META,sanitizeMultiEngine} from '/contracts/multi-engine-status.js';
const $=id=>document.getElementById(id);
const states={queued:'等待执行',running:'检测中',complete:'范围已完成',partial:'存在覆盖缺口',unavailable:'尚未就绪',failed:'检测失败',cancelled:'已中断'};
const kinds={malware:'病毒命中',vulnerability:'镜像漏洞',asset:'端口资产',behavior:'行为事件'};
export function createMultiEngine({state,request,notify}) {
 let bound=false,timer=null,pending=false,starting=false,generation=0,activeSession=null,refreshWanted=false,lastValue={state:"idle"},requestIssue=null,requestedJobId=null;
 function render(value) {
  const report=sanitizeMultiEngine(value);lastValue=report;
  const job=requestIssue?{state:'unavailable',reason:requestIssue}:starting?{state:'idle',reason:'正在请求本机检测，请等待任务确认'}:requestedJobId && report.job_id!==requestedJobId?{state:'unavailable',reason:'正在等待本次任务报告，旧报告不代表本次检测结果'}:report;
  const ready=Array.isArray(job.engines),progress=ready?Math.min(job.state==='running'?99:100,Math.round(job.completed/4*100)):null;
  const panel=$('multi-engine-panel');if(panel){panel.dataset.state=job.state;panel.setAttribute('aria-busy',String(job.state==='running'));}
  const percent=$('multi-engine-percent');if(percent)percent.textContent=progress===null?'—':progress+'%';
  const completed=$('multi-engine-completed');if(completed)completed.textContent=ready?job.completed+' / 4':'— / 4';
  const coverage=$('multi-engine-coverage');if(coverage)coverage.textContent=ready?job.coverage+' / 4':'待核验';
  const title=$('multi-engine-state'),detail=$('multi-engine-detail'),bar=$('multi-engine-progress'),rows=$('multi-engine-list'),items=$('multi-engine-findings'),button=$('multi-engine-start');
  if(title) title.textContent=job.state==='idle'?'尚未运行':job.state==='unavailable'?'本机检测未就绪':job.state==='running'?'玄武引擎检测中':job.state==='finished'?'本次检测已结束':'任务已结束 · 请核查覆盖缺口';
  if(detail) detail.textContent=ready?'任务完成 '+job.completed+'/4 · 完整覆盖 '+job.coverage+'/4 · '+(job.state==='running'?'正在读取本机证据':'报告时间 '+new Date(job.updated_at).toLocaleString()):job.reason || '玄武引擎在本机执行检测，云端连接为可选项。';
  if(bar) {bar.value=progress??0;bar.max=100;bar.setAttribute('aria-label',ready?'已结束 '+job.completed+' 项检测，共 4 项':'尚无已核验检测进度');}
  rows?.replaceChildren();items?.replaceChildren();
  for(const id of ENGINE_IDS) {
   const e=job.engines?.find(x=>x.id===id); const meta=ENGINE_META[id];
   const row=document.createElement('li');row.dataset.state=e?.state==='complete'?'ok':e?.state==='failed'?'finding':e?.state==='running'?'running':'unavailable';
   row.dataset.capability=id;
   const heading=document.createElement('div');heading.className='ic-capability-heading';
   const symbol=document.createElement('span');symbol.className='ic-capability-icon';symbol.setAttribute('aria-hidden','true');symbol.textContent=({clamav:'◈',trivy:'▧',osquery:'⌁',falco:'ϟ'})[id];
   const name=document.createElement('strong');name.textContent=meta.name;heading.append(symbol,name);
   const badge=document.createElement('span');badge.className='ic-capability-state';badge.textContent=e?states[e.state]:'等待代理';
   const scope=document.createElement('p');scope.className='sc-muted ic-capability-scope';scope.textContent=meta.scope;
   const info=document.createElement('p');info.className='ic-capability-detail';info.textContent=e?engineDisplayText(e.detail):'尚未取得检测证据';
   const counts=document.createElement('small');counts.className='ic-capability-count';counts.textContent=e?(e.total?e.completed+' / '+e.total:'数量待核验')+' · '+kinds[meta.kind]+' '+e.finding_total:'等待首次检测';
   row.append(heading,badge,scope,info,counts);rows?.append(row);
   for(const f of e?.findings || []) {
    const line=document.createElement('li');line.dataset.state=f.kind==='asset'?'ok':'warning';
    const label=document.createElement('strong');label.textContent=kinds[f.kind]+' · '+f.rule;
    const target=document.createElement('p');target.textContent=f.target;
    const note=document.createElement('p');note.className='sc-muted';note.textContent=f.severity+' · '+f.detail;
    line.append(label,target,note);items?.append(line);
   }
  }
  const summary=$('multi-engine-evidence');if(summary) summary.textContent=ready?'每类最多展示 16 条摘要。端口资产数量独立统计，不计为病毒命中。'+(job.file_evidence?' '+job.file_evidence.reason:''):'暂无可核验结果';
  if(button) button.disabled=starting || job.state==='running' || !state.csrf;
 }
 async function refresh() {
  if(!state.csrf)return; if(pending){refreshWanted=true;return;}
  clearTimeout(timer);timer=null;
  const session=state.csrf,version=generation;pending=true;let interval=15000;
  try {const job=await request('/api/multi-engine');if(session!==state.csrf || version!==generation)return;render(job);if(job.state==='running')interval=2000;}
  catch(error){if(session===state.csrf && version===generation)render({state:'unavailable',reason:error.message});}
  finally{pending=false;if(refreshWanted){refreshWanted=false;void refresh();}else if(session===state.csrf && version===generation)timer=setTimeout(()=>void refresh(),interval);}
 }
 function bind() {
  if(bound)return;bound=true;
  $('multi-engine-start')?.addEventListener('click',async()=>{
   if(starting || !state.csrf)return;const session=state.csrf;generation++;clearTimeout(timer);timer=null;starting=true;requestIssue=null;requestedJobId=null;render(lastValue);
   try{const result=sanitizeMultiEngine(await request('/api/multi-engine',{method:'POST',body:{}}));if(session===state.csrf){if(!result.job_id)throw new Error(result.reason || '本机启动响应无法核验');requestedJobId=result.job_id;render(result);}}
   catch(error){if(session===state.csrf){requestIssue=error.message;notify(error.message,true);}}
   finally{starting=false;if(session===state.csrf){render(lastValue);void refresh();}}
  });
 }
 return Object.freeze({bind,start(){if(activeSession===state.csrf)return;activeSession=state.csrf;requestIssue=null;requestedJobId=null;generation++;clearTimeout(timer);timer=null;if(!state.csrf){render({state:'unavailable',reason:'请登录后读取本机检测状态'});return;}void refresh();}});
}
