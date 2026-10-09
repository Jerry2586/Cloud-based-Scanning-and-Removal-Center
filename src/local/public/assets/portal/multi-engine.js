import {engineDisplayText} from './engine-labels.js';
import {ENGINE_IDS,ENGINE_META,sanitizeMultiEngine} from '/contracts/multi-engine-status.js';
const $=id=>document.getElementById(id);
const states={queued:'等待执行',running:'检测中',complete:'范围已完成',partial:'存在覆盖缺口',unavailable:'尚未就绪',failed:'检测失败',cancelled:'已中断'};
const kinds={malware:'病毒命中',vulnerability:'镜像漏洞',asset:'端口资产',behavior:'行为事件'};
const units={clamav:'文件',trivy:'镜像',osquery:'记录',falco:'事件'};
export function createMultiEngine({state,request,notify,allowed=()=>Boolean(state.csrf),isScanBusy=()=>false,onStateChange=()=>{},onFinished=()=>{}}) {
 let bound=false,timer=null,pending=false,starting=false,generation=0,activeSession=null,activeAllowed=null,refreshWanted=false,lastValue={state:'idle'},requestIssue=null,requestedJobId=null,observedJob=null,completionNotified=null,evidenceSignature=null;
 const ownBusy=()=>Boolean(starting || observedJob?.state==='running');
 function sync() {
  const busy=ownBusy() || isScanBusy() || !allowed();
  const button=$('multi-engine-start');if(button)button.disabled=busy;
  document.querySelectorAll('[data-security-container-scan]').forEach(button=>{button.disabled=busy;});
  document.querySelectorAll('[data-container-scan-button]').forEach(node=>{node.textContent=starting?'正在提交联合检测…':observedJob?.state==='running'?'联合检测进行中…':isScanBusy()?'等待当前任务完成':'容器与文件联合检测';});
 }
 function render(value,clearEvidence=false) {
  const report=sanitizeMultiEngine(value);
  const matches=!requestedJobId || report.job_id===requestedJobId;
  const newer=(requestedJobId && report.job_id===requestedJobId && report.job_id!==observedJob?.job_id) || !observedJob || report.started_at>observedJob.started_at || (report.job_id===observedJob.job_id && report.updated_at>=observedJob.updated_at && (observedJob.state==='running' || report.state!=='running'));
  if(report.job_id && matches && newer) {
   observedJob=report;
   if(report.state!=='running')requestedJobId=null;
  }
  lastValue=report;
  const outdated=Boolean(report.job_id && (!matches || !newer));
  const job=requestIssue?{state:'unavailable',reason:requestIssue}:starting?{state:'idle',reason:'正在请求本机检测，请等待任务确认'}:outdated?{state:'unavailable',reason:'正在等待本次任务报告，旧报告不代表本次检测结果'}:report;
  const ready=Array.isArray(job.engines),progress=ready?Math.min(job.state==='running'?99:100,Math.round(job.completed/4*100)):null;
  const panel=$('multi-engine-panel');if(panel){panel.dataset.state=job.state;panel.setAttribute('aria-busy',String(ownBusy()));}
  const percent=$('multi-engine-percent');if(percent)percent.textContent=progress===null?'—':progress+'%';
  const completed=$('multi-engine-completed');if(completed)completed.textContent=ready?job.completed+' / 4':'— / 4';
  const coverage=$('multi-engine-coverage');if(coverage)coverage.textContent=ready?job.coverage+' / 4':'待核验';
  const title=$('multi-engine-state'),detail=$('multi-engine-detail'),bar=$('multi-engine-progress'),rows=$('multi-engine-list'),items=$('multi-engine-findings');
  if(title)title.textContent=job.state==='idle'?'尚未运行':job.state==='unavailable'?'本机检测状态待核验':job.state==='running'?'玄武引擎检测中':job.state==='finished'?'本次检测已结束':'任务已结束 · 请核查覆盖缺口';
  if(detail)detail.textContent=ready?'检测类别结束 '+job.completed+'/4 · 完整覆盖 '+job.coverage+'/4 · '+(job.state==='running'?'正在读取本机证据':'报告时间 '+new Date(job.updated_at).toLocaleString()):(job.reason || '玄武引擎在本机执行检测，云端连接为可选项。')+(ownBusy() && !starting?'；任务终态尚未确认，暂不能启动其他扫描':'');
  if(bar){bar.value=progress??0;bar.max=100;bar.setAttribute('aria-label',ready?'已结束 '+job.completed+' 类检测，共 4 类；不是文件扫描百分比':'尚无已核验检测进度');}
  rows?.replaceChildren();
  for(const id of ENGINE_IDS) {
   const e=job.engines?.find(x=>x.id===id),meta=ENGINE_META[id];
   const row=document.createElement('li');row.dataset.state=e?.state==='complete'?'ok':e?.state==='failed'?'finding':e?.state==='running'?'running':'unavailable';row.dataset.capability=id;
   const heading=document.createElement('div');heading.className='ic-capability-heading';
   const symbol=document.createElement('span');symbol.className='ic-capability-icon';symbol.setAttribute('aria-hidden','true');symbol.textContent=({clamav:'◈',trivy:'▧',osquery:'⌁',falco:'ϟ'})[id];
   const name=document.createElement('strong');name.textContent=meta.name;heading.append(symbol,name);
   const badge=document.createElement('span');badge.className='ic-capability-state';badge.textContent=e?states[e.state]:'等待代理';
   const scope=document.createElement('p');scope.className='sc-muted ic-capability-scope';scope.textContent=meta.scope;
   const info=document.createElement('p');info.className='ic-capability-detail';info.textContent=e?engineDisplayText(e.detail):'尚未取得检测证据';
   const counts=document.createElement('small');counts.className='ic-capability-count';counts.textContent=e?(e.total?e.completed+' / '+e.total+' '+units[id]:e.state==='complete'?'本次范围内 0 '+units[id]:'数量待核验')+' · '+kinds[meta.kind]+' '+e.finding_total:'等待首次检测';
   const meter=document.createElement('progress');meter.className='ic-capability-progress';meter.max=100;meter.setAttribute('aria-label',meta.name+' · '+(e?.total?e.completed+' / '+e.total+' '+units[id]:'数量待核验'));meter.setAttribute('aria-busy',String(e?.state==='running'));
   // A real denominator supports unit progress. Empty/unknown scopes never become a fabricated 100%.
   if(e?.total)meter.value=Math.min(e.state==='running'?99:100,Math.floor(e.completed*100/e.total));else if(e?.state!=='running')meter.value=0;
   const progressText=document.createElement('span');progressText.className='ic-capability-progress-text';progressText.textContent=e?.total?meter.value+'% · '+(e.state==='running'?'已处理数量，等待汇总':'已处理数量') : e?.state==='running'?'正在核验范围与数量':e?.state==='complete'?'空范围 · 未检查任何'+units[id]:'进度尚不可核验';
   row.append(heading,badge,scope,info,meter,progressText,counts);rows?.append(row);
  }
  const signature=JSON.stringify([job.job_id,job.state,job.engines,job.file_evidence]);
  if(signature!==evidenceSignature && (clearEvidence || !items?.contains(document.activeElement))) {
   evidenceSignature=signature;items?.replaceChildren();
   for(const e of job.engines || [])for(const f of e.findings) {
    const line=document.createElement('li');line.dataset.state=f.kind==='asset'?'ok':'warning';
    const label=document.createElement('strong');label.textContent=kinds[f.kind]+' · '+f.rule;
    const target=document.createElement('p');target.textContent=f.target;
    const note=document.createElement('p');note.className='sc-muted';note.textContent=f.severity+' · '+f.detail;
    const next=document.createElement('a');next.className='sc-outline ic-evidence-action';
    if(f.kind==='malware'){next.href='#quarantine';next.textContent=job.file_evidence?.state==='ready'?'核对文件证据并处置':'查看文件证据可用状态';}
    else {next.href='#environment';next.textContent=f.kind==='vulnerability'?'核对镜像与修复版本':f.kind==='asset'?'管理端口允许清单':'核查主机与行为风险';}
    line.append(label,target,note,next);items?.append(line);
   }
  }
  const summary=$('multi-engine-evidence');if(summary)summary.textContent=ready?'每类最多展示 16 条摘要。端口资产数量独立统计，不计为病毒命中。'+(job.file_evidence?' '+job.file_evidence.reason:''):'暂无可核验结果';
  sync();onStateChange();
  if(ready && job.state!=='running' && completionNotified!==job.job_id){completionNotified=job.job_id;onFinished(job);}
 }
 async function refresh() {
  if(!allowed())return;if(pending){refreshWanted=true;return;}
  clearTimeout(timer);timer=null;
  const session=state.csrf,version=generation;pending=true;let interval=15000;
  try{const job=await request('/api/multi-engine');if(session!==state.csrf || version!==generation || !allowed())return;render(job);if(ownBusy())interval=2000;}
  catch(error){if(session===state.csrf && version===generation && allowed()){render({state:'unavailable',reason:error.message});if(ownBusy())interval=2000;}}
  finally{pending=false;if(refreshWanted){refreshWanted=false;void refresh();}else if(session===state.csrf && version===generation && allowed())timer=setTimeout(()=>void refresh(),interval);}
 }
 async function run() {
  if(!allowed())throw Error('请登录有检测权限的账户');
  if(ownBusy() || isScanBusy())throw Error('已有检测任务，请等待当前任务完成');
  const session=state.csrf,version=++generation;clearTimeout(timer);timer=null;starting=true;requestIssue=null;requestedJobId=null;render(lastValue);
  const current=()=>session===state.csrf && version===generation && allowed();
  try {
   const result=sanitizeMultiEngine(await request('/api/multi-engine',{method:'POST',body:{}}));
   if(!current())throw Error('登录状态已改变，请重新核对检测状态');
   if(!result.job_id)throw Error(result.reason || '本机启动响应无法核验');
   requestedJobId=result.job_id;render(result);return result;
  } catch(error){if(current())requestIssue=error.message;throw error;}
  finally{if(version===generation){starting=false;if(current()){render(lastValue);void refresh();}}}
 }
 function bind() {
  if(bound)return;bound=true;
  const handle=async()=>{const session=state.csrf;try{await run();}catch(error){if(session===state.csrf && allowed())notify(error.message,true);}};
  $('multi-engine-start')?.addEventListener('click',handle);
  document.querySelectorAll('[data-security-container-scan]').forEach(button=>button.addEventListener('click',handle));
 }
 return Object.freeze({bind,run,sync,isBusy:ownBusy,start(){
  const permitted=Boolean(allowed()),sessionChanged=activeSession!==state.csrf;
  if(!sessionChanged && activeAllowed===permitted){sync();return;}
  activeSession=state.csrf;activeAllowed=permitted;generation++;clearTimeout(timer);timer=null;requestIssue=null;starting=false;lastValue={state:'idle'};evidenceSignature=null;
  if(sessionChanged){requestedJobId=null;observedJob=null;completionNotified=null;}
  render({state:'unavailable',reason:permitted?'正在读取本机检测状态':'请登录有检测权限的账户后查看'},true);
  if(permitted)void refresh();
 }});
}
