import {sanitizeInventory} from '/contracts/protection-status.js';
import {validatePorts} from '/contracts/operations-status.js';

// A bounded observation can propose a detection policy, never approve a process or close a port.
export function listenerObservation(report, trusted, now=Date.now()) {
  const inventory=sanitizeInventory(report?.inventory), stamp=Date.parse(inventory.observed_at);
  const fresh=Boolean(inventory.schema && Number.isFinite(stamp) && stamp<=now+30000 && stamp>=now-900000);
  return {inventory:inventory.schema?inventory:null,editable:trusted===true && fresh && inventory.listener_state==='complete',fresh};
}
export function parsePortDraft(tcp,udp) {
  const parse=text=>validatePorts(text.trim()?text.trim().split(/[,，\s]+/).map(v=>/^\d+$/.test(v)?Number(v):NaN):[]);
  return {tcp:parse(tcp),udp:parse(udp)};
}
const identity=(inventory,row)=>JSON.stringify([inventory.observed_at,row.protocol,row.address,row.port,row.processes]);
export function createListenerWorkspace({getStatus,enabled,getDraft,writeDraft,notify,runRecheck,canRecheck,getSession,getRecheckReceipt=()=>null}) {
  let report=null,trusted=false,observationSession=null,signature=null;
  const body=document.querySelector('[data-host-table="listeners"]');
  const label=document.querySelector('[data-listener-policy-state]');
  const followup=document.querySelector('[data-port-followup]');
  const node=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n;};
  function draft() {
    const status=getStatus(),value=getDraft();
    if(!enabled() || status.state!=='ready' || !value || value.revision!==status.policy.revision)return null;
    try{return {...parsePortDraft(value.tcp,value.udp),revision:value.revision,dirty:value.dirty};}catch{return null;}
  }
  function observation(){return listenerObservation(report,trusted && observationSession===getSession());}
  function canEdit(){return Boolean(observation().editable && draft());}
  function edit(key,row,adding) {
    const view=observation(),value=draft();
    if(!view.editable || !value || !view.inventory.listeners.some(item=>identity(view.inventory,item)===key)) {
      notify('监听观测或策略已变化，请重新检查并加载当前策略。',true);return;
    }
    const ports=value[row.protocol];
    // A focused old button must never invert a newer draft or operate on a replaced row.
    if(ports.includes(row.port)===adding){notify('端口草稿已变化，请查看当前允许清单。',true);return;}
    try {
      value[row.protocol]=validatePorts(adding?[...ports,row.port]:ports.filter(port=>port!==row.port));
      writeDraft(value);
      notify(row.protocol.toUpperCase()+' '+row.port+(adding?' 已加入':' 已移出')+'允许清单草稿；保存后复检。');
    }catch(error){notify(error.message,true);}
  }
  function portJob(){const status=getStatus();return status.state==='ready'?[status.job,...status.audit].filter(job=>job?.state==='complete' && job.action==='ports').sort((a,b)=>Date.parse(b.finished_at)-Date.parse(a.finished_at))[0]:null;}
  function render() {
    const view=observation(),status=getStatus(),value=draft(),editable=canEdit();
    if(label)label.textContent=!view.inventory?'等待可核验的监听观测':!view.editable?'监听观测未完成或已过期，请重新体检':!value?'策略未就绪、草稿无效或正在执行任务':value.dirty?'草稿尚未保存；检测仍使用已保存策略':'显示 '+view.inventory.listeners.length+' / '+view.inventory.listener_count+' 个监听；允许清单按协议与端口匹配';
    const next=JSON.stringify([view.inventory,status.state,status.policy,value,editable]);
    if(body && signature!==next && !(status.state==='ready' && body.contains(document.activeElement))) {
      body.replaceChildren();signature=next;
      for(const row of view.inventory?.listeners||[]) {
        const saved=status.state==='ready'?status.policy[row.protocol].includes(row.port):null;
        const proposed=value?value[row.protocol].includes(row.port):saved;
        const tr=node('tr');
        for(const text of [row.protocol.toUpperCase(),row.port,row.address,row.processes.map(p=>p.name+' ('+p.pid+')').join('、')||'归属未读取',saved===null?'策略未知':saved?'已允许':'未列入允许清单'])tr.append(node('td',String(text)));
        const actions=node('td'),button=node('button',proposed?'移出草稿':'加入草稿');button.type='button';button.className='sc-outline';button.dataset.listenerEdit='';button.disabled=!editable;
        const key=identity(view.inventory,row),adding=!proposed;
        button.addEventListener('click',()=>edit(key,row,adding));actions.append(button);
        if(saved!==proposed)actions.append(node('small',proposed?' 待保存加入':' 待保存移出'));
        tr.append(actions);body.append(tr);
      }
      if(!view.inventory?.listeners.length){const tr=node('tr'),td=node('td',view.inventory?.listener_state==='complete'?'本次清单未观测到监听端口':'尚无完整监听清单');td.colSpan=6;tr.append(td);body.append(tr);}
    }
    body?.querySelectorAll('[data-listener-edit]').forEach(button=>{button.disabled=!editable;});
    if(followup) {
      const job=portJob(),id=job?.id,receipt=getRecheckReceipt(),receiptId=id && receipt?.id===id?receipt.taskId:null;
      const followupKey=JSON.stringify([id||null,receiptId]);
      if(followup.dataset.portJob!==followupKey) {
        followup.replaceChildren();followup.dataset.portJob=followupKey;
        followup.append(node('p',job?'端口允许清单已保存；发起新检测核对实际监听和告警。':'保存允许清单后，从这里复检端口。'));
        if(receiptId)followup.append(node('p','复检任务 '+receiptId.slice(0,8)+' 已受理；请查看新报告，不代表风险已消除。'));
        if(job){const button=node('button','复检端口与环境');button.type='button';button.className='sc-outline';button.dataset.portRecheck='';button.addEventListener('click',()=>{const current=portJob(),currentDraft=draft();if(current?.id===id && currentDraft && !currentDraft.dirty && canRecheck())void runRecheck(current);});followup.append(button);}
      }
      followup.querySelectorAll('[data-port-recheck]').forEach(button=>{button.disabled=!value || value.dirty || !canRecheck();});
    }
  }
  return {render,observe(value,options={}){report=value;trusted=options.trusted===true;observationSession=getSession();render();},reset(){report=null;trusted=false;observationSession=null;signature=null;body?.replaceChildren();followup?.replaceChildren();if(followup)followup.dataset.portJob='';render();}};
}
