import {sanitizeOperations,unavailableOperations,validateOperation,operationRecheckPlan} from '/contracts/operations-status.js';
import {createScopeWorkspace} from './scope-workspace.js';
import {createListenerWorkspace,parsePortDraft} from './listener-workspace.js';
const states={open:'待处理',investigating:'处理中',accepted:'已接受风险'};
const phases={idle:'暂无处置任务',running:'处置执行中',complete:'操作完成 · 等待复核',failed:'操作失败',interrupted:'任务中断 · 核对实际状态'};
const quarantineLabels={preparing:'准备副本',captured:'副本已保存，路径移除未确认',quarantined:'已隔离',restoring:'恢复中断，需要核查',restored:'原始内容已取回，副本保留'};
export function createOperationsWorkspace({state,request,notify,recheck=null,isScanBusy=()=>false,allowed=()=>true}) {
  let last=unavailableOperations(),epoch=0,pending=null,saving=null,timer=null,dirty=false,activeSession=null,bound=false,displayedRevision=null,submitted=null,rechecking=null,recheckReceipt=null;
  const signatures=new WeakMap();
  const form=document.querySelector('[data-port-policy]');
  const field=name=>form?.querySelector('[name="'+name+'"]');
  const node=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
  const current=op=>op.session===state.csrf && op.epoch===epoch;
  const busy=()=>Boolean(saving || rechecking || isScanBusy() || last.job?.state==='running');
  const enabled=()=>last.state==='ready' && !busy() && Boolean(state.csrf) && allowed();
  const scope=createScopeWorkspace({getStatus:()=>last,enabled,apply,notify});
  const listeners=createListenerWorkspace({getStatus:()=>last,enabled,getDraft:()=>form?{tcp:field('tcp').value,udp:field('udp').value,revision:displayedRevision,dirty}:null,writeDraft:value=>{field('tcp').value=value.tcp.join(', ');field('udp').value=value.udp.join(', ');dirty=true;render();},notify,runRecheck,canRecheck:()=>typeof recheck==='function',getSession:()=>state.csrf,getRecheckReceipt:()=>recheckReceipt});
  function button(text,action) {const b=node('button',text,'sc-outline');b.type='button';b.dataset.operationAction='';b.disabled=!enabled();b.addEventListener('click',action);return b;}
  // Passive polls preserve focused controls and replace a list only when its data changes.
  function list(selector,value,build) {
    const element=document.querySelector(selector);if(!element)return;
    const signature=JSON.stringify(value);
    if(signatures.get(element)===signature)return;
    if(last.state==='ready' && element.contains(document.activeElement))return;
    element.replaceChildren();build(element);signatures.set(element,signature);
  }
  function sync() {
    document.querySelectorAll('[data-operation-action],[data-quarantine-id]').forEach(b=>{b.disabled=!enabled() || b.dataset.operationBlocked==='true';});
    form?.querySelectorAll('input,button').forEach(n=>{n.disabled=!enabled();});
    document.querySelectorAll('[data-operation-recheck]').forEach(b=>{b.disabled=!enabled() || typeof recheck!=='function';});
    scope.render();listeners.render();
  }
  function followupJob() {
    if(last.state!=='ready')return null;
    return [last.job,...last.audit].filter(job=>operationRecheckPlan(job)).sort((a,b)=>Date.parse(b.finished_at)-Date.parse(a.finished_at))[0] || null;
  }
  async function runRecheck(job) {
    const plan=operationRecheckPlan(job);
    if(!plan || !enabled() || typeof recheck!=='function')return;
    const op={session:state.csrf,epoch};rechecking=op;render();
    try {
      const receipt=await recheck(plan.action,plan.panel);
      if(!current(op))return;
      if(receipt?.state!=='running' || !/^[a-f0-9]{32}$/.test(receipt.task_id || ''))throw Error('复检未取得有效任务确认，请核对本机检测状态');
      recheckReceipt={id:job.id,taskId:receipt.task_id};
      notify('复检已受理，任务 '+receipt.task_id.slice(0,8)+'；请核对新报告与覆盖范围。');
    } catch(error) {if(current(op))notify(error.message,true);}
    finally {if(rechecking===op){rechecking=null;if(current(op))render();}}
  }
  function render() {
    const ready=last.state==='ready';
    document.querySelectorAll('[data-operation-state]').forEach(n=>{n.textContent=ready?(phases[last.job.state]+' · '+(last.job.reason || '可以配置与处置')):last.reason;});
    if(form) {
      if(ready && !dirty && !form.contains(document.activeElement)) {
        field('tcp').value=last.policy.tcp.join(', ');field('udp').value=last.policy.udp.join(', ');displayedRevision=last.policy.revision;
      }
      form.querySelectorAll('input,button').forEach(n=>{n.disabled=!enabled();});
      const conflict=ready && dirty && displayedRevision!==last.policy.revision;
      form.querySelector('[data-port-policy-state]').textContent=!ready?'等待本机处置服务':conflict?'策略已被其他操作修改，请重新加载后编辑':dirty?'有未保存修改':'已加载本机检测白名单';
    }
    document.querySelectorAll('[data-operations-refresh]').forEach(n=>{n.disabled=Boolean(pending || saving) || !state.csrf;});
    const label=document.querySelector('[data-risk-state]'),detail=document.querySelector('[data-risk-detail]');
    if(label)label.textContent=ready?last.risks.length+' 项复核项':'服务未就绪';
    if(detail)detail.textContent=ready?'环境证据：'+({current:'当前',historical:'历史',unavailable:'缺失'}[last.sources.environment])+' · 引擎证据：'+({current:'当前',historical:'历史',unavailable:'缺失'}[last.sources.engines])+' · 能力覆盖 '+last.sources.engine_coverage+(last.sources.truncated?' · 结果超出展示预算，请查看完整记录':''):'尚未取得可核验的风险与处置数据，不能据此判断安全。';
    list('[data-risk-list]',ready?last.risks:null,element=>{
      if(!ready)return;
      for(const risk of last.risks) {
        const li=node('li',undefined,'ic-risk-item');li.dataset.state=risk.severity==='critical'||risk.severity==='high'?'finding':'warning';
        const head=node('div',undefined,'ic-risk-heading');head.append(node('strong',risk.title),node('span',states[risk.review.status]+(risk.fresh?'':' · 历史证据'),'ic-tag'));
        li.append(head,node('p',risk.detail),node('small',risk.target+' · '+new Date(risk.observed_at).toLocaleString()));
        if(risk.review.reason)li.append(node('p','处理说明：'+risk.review.reason,'sc-muted'));
        const actions=node('div',undefined,'ic-action-row');
        for(const [status,title] of [['investigating','开始处理'],['accepted','接受风险'],['open','重新打开']]) {
          const b=button(title,()=>{const reason=window.prompt('填写处理原因（4–240字）。接受风险保留原检测结论。',risk.review.reason);if(reason!==null)void apply({action:'review',id:risk.id,evidence:risk.evidence,status,reason});});
          b.dataset.operationBlocked=String(!risk.fresh || risk.review.status===status);actions.append(b);
        }
        li.append(actions);element.append(li);
      }
      if(!last.risks.length)element.append(node('li','当前可核验报告没有列出风险；证据缺失的检测范围仍需补齐。','sc-empty-row'));
    });
    const qs=document.querySelector('[data-recovery-state]');
    if(qs)qs.textContent=ready?(last.quarantine.state==='unavailable'?'隔离记录无法核验':last.quarantine.count+' 项记录 · '+last.quarantine.pending+' 项中断待核查 · 页面展示 '+last.quarantine.items.length+' 项'):'等待本机处置服务';
    list('[data-recovery-records]',ready?last.quarantine:null,element=>{
      if(!ready)return;
      for(const item of last.quarantine.items) {
        const row=node('li',undefined,'ic-risk-item');row.append(node('strong',quarantineLabels[item.state]),node('p',item.path),node('small',item.signature+' · '+item.size+' 字节'));
        if(['quarantined','restoring'].includes(item.state))row.append(button('取回原始隔离内容',()=>{if(window.confirm('这会恢复原来被隔离的内容，可能仍有恶意代码。不会覆盖已有文件，恢复文件为 root:0600，并保留隔离副本。确认取回？'))void apply({action:'restore',id:item.id,confirm:'restore-original'});}));
        element.append(row);
      }
      if(last.quarantine.state==='empty')element.append(node('li','暂无隔离记录。','sc-empty-row'));
    });
    list('[data-operation-audit]',ready?last.audit:null,element=>{
      if(!ready)return;
      for(const job of [...last.audit].reverse()) {const row=node('li',undefined,'ic-risk-item');row.append(node('strong',({ports:'端口策略',review:'风险受理',quarantine:'文件隔离',restore:'原始内容取回',discover:'发现保护范围',enroll:'启用保护范围'}[job.action])+' · '+phases[job.state]),node('p',job.reason),node('small',job.target+' · '+new Date(job.finished_at).toLocaleString()));element.append(row);}
      if(!last.audit.length)element.append(node('li','暂无网页处置记录。','sc-empty-row'));
    });
    const followup=followupJob(),plan=operationRecheckPlan(followup);
    for(const selector of ['[data-risk-followup]','[data-recovery-followup]'])list(selector,[ready,followup,Boolean(rechecking),recheckReceipt],element=>{
      if(!ready){element.append(node('p','等待可核验的本机处置记录。','sc-muted'));return;}
      if(!followup){element.append(node('p','端口策略、保护范围、隔离或原内容取回成功后，可从这里发起对应复检。','sc-muted'));return;}
      const actionName={ports:'端口策略',enroll:'保护范围',quarantine:'文件隔离',restore:'原内容取回'}[followup.action];
      element.append(node('p',actionName+'已完成 · '+new Date(followup.finished_at).toLocaleString()),node('p',followup.reason,'sc-muted'));
      if(recheckReceipt?.id===followup.id)element.append(node('p','复检任务 '+recheckReceipt.taskId.slice(0,8)+' 已受理；结果请查看检测页，不代表风险已消除。','sc-muted'));
      const start=button(rechecking?'正在提交复检…':plan.label,()=>void runRecheck(followup));start.dataset.operationRecheck='';element.append(start);
    });
    sync();
  }
  function schedule(op) {if(!current(op))return;clearTimeout(timer);timer=setTimeout(()=>{if(current(op))void refresh();},last.job?.state==='running'?2000:15000);}
  async function refresh() {
    if(!state.csrf || pending || saving)return;clearTimeout(timer);const op={session:state.csrf,epoch};pending=op;render();
    try {
      const v=await request('/api/operations');if(current(op)) {
        last=sanitizeOperations(v);
        if(submitted && last.state==='ready' && last.job.id===submitted.id && last.job.state!=='running') {
          if(last.job.state==='complete' && submitted.action==='ports')dirty=false;
          if(last.job.state==='complete' && submitted.action==='enroll')scope.complete();
          submitted=null;
        }
      }
    } catch {if(current(op))last=unavailableOperations();}
    finally {if(pending===op){pending=null;if(current(op)){render();schedule(op);}}}
  }
  async function apply(input) {
    if(!enabled())return;
    let value;try{value=validateOperation(input);}catch(error){notify(error.message,true);return;}
    const op={session:state.csrf,epoch:++epoch};pending=null;saving=op;clearTimeout(timer);render();
    try {
      const result=sanitizeOperations(await request('/api/operations',{method:'POST',body:value}));
      if(current(op)){if(result.state!=='running' || result.job.action!==value.action)throw Error('任务受理结果与提交操作不一致，请刷新核对。');submitted={id:result.job.id,action:value.action};last={...last,job:result.job};notify('操作已受理，完成后请重新检查验证。');}
    } catch(error){if(current(op))notify(error.message,true);}
    finally {if(saving===op){saving=null;if(current(op)){render();void refresh();}}}
  }
  function reset() {
    epoch++;activeSession=state.csrf;pending=saving=submitted=rechecking=recheckReceipt=null;displayedRevision=null;dirty=false;clearTimeout(timer);last=unavailableOperations();scope.reset();listeners.reset();
    if(form){field('tcp').value='';field('udp').value='';}render();if(state.csrf)void refresh();
  }
  function bind() {
    if(bound)return;bound=true;scope.bind();
    form?.addEventListener('input',()=>{dirty=true;render();});
    form?.addEventListener('submit',event=>{
      event.preventDefault();if(last.state!=='ready')return;
      if(displayedRevision!==last.policy.revision){notify('策略版本已变化，请重新加载后编辑。',true);return;}
      try {
        const ports=parsePortDraft(field('tcp').value,field('udp').value);
        void apply({action:'ports',revision:displayedRevision,...ports});
      }catch(error){notify(error.message,true);}
    });
    document.querySelectorAll('[data-operations-refresh]').forEach(n=>n.addEventListener('click',()=>{void refresh();}));
    document.querySelector('[data-port-policy-reset]')?.addEventListener('click',()=>{dirty=false;displayedRevision=null;document.activeElement?.blur();render();void refresh();});
    document.addEventListener('focusout',()=>queueMicrotask(()=>render()));
    document.addEventListener('ironcurtain-session-cleared',reset);
    document.addEventListener('click',event=>{const b=event.target.closest?.('[data-quarantine-id]');if(!b || b.disabled)return;if(window.confirm('确认隔离命中文件？系统会核对当前证据和内容，保存副本后移除路径。已有进程可能继续运行，请完成后复核。'))void apply({action:'quarantine',id:b.dataset.quarantineId,confirm:'quarantine'});});
  }
  return Object.freeze({bind,start(){if(activeSession!==state.csrf)reset();},refresh,sync,observeListeners:listeners.observe});
}
