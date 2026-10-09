// Enrollment uses only fresh host-issued candidate identifiers; no path editor.
const kinds={program_roots:'程序目录',business_roots:'业务目录',containers:'容器'};
export function createScopeWorkspace({getStatus,enabled,apply,notify}) {
  const form=document.querySelector('[data-scope-form]'),list=document.querySelector('[data-scope-candidates]');
  let view=null,selected=new Set(),signature=null,bound=false;
  const node=(tag,text)=>{const el=document.createElement(tag);if(text!==undefined)el.textContent=text;return el;};
  const current=()=>{
    const last=getStatus(),d=last.scope?.discovery;
    const age=d?.observed_at?Date.now()-Date.parse(d.observed_at):Infinity;
    return last.state==='ready' && d?.state==='ready' && age>=-30000 && age<=120000 && view?.revision===last.policy.revision && view?.inventory===d.revision;
  };
  function reset(){view=null;selected.clear();signature=null;render();}
  function render(){
    if(!form || !list)return;
    const last=getStatus(),scope=last.state==='ready'?last.scope:null,d=scope?.discovery;
    if(!selected.size && !list.contains(document.activeElement))view=scope?{revision:last.policy.revision,inventory:d.revision,observed_at:d.observed_at,candidates:d.candidates}:null;
    const valid=current(),available=enabled(),conflict=selected.size && !valid;
    const summary=document.querySelector('[data-scope-summary]');
    if(summary)summary.textContent=scope?'程序目录 '+scope.program_roots.length+' · 业务目录 '+scope.business_roots.length+' · 容器 '+scope.containers.length+'；'+[...scope.program_roots,...scope.business_roots,...scope.containers].join('、'):'保护范围尚未取得，不能确认扫描覆盖。';
    const state=document.querySelector('[data-scope-state]');
    if(state)state.textContent=!scope?'本机服务尚未提供保护范围，请检查安装与服务版本':conflict?'选择已过期或配置发生变化，已保留选择供核对；请重新发现并重新选择':selected.size?'已选择 '+selected.size+' 项，等待启用保护':!d || d.state==='unavailable'?'点击发现，获取本机可纳管目录和容器':!valid?'发现结果已过期，请重新发现':d.count?'选择需要保护的对象，启用后重新扫描':'未发现可纳管对象，请核对部署位置和发现覆盖说明';
    const issues=document.querySelector('[data-scope-issues]');
    if(issues)issues.textContent=scope?[...d.issues,...(d.truncated?['候选显示达到预算，请分批配置或使用 Linux 菜单']:[])].join('；'):'';
    const candidates=view?.candidates || [],next=JSON.stringify(candidates);
    if(signature!==next && !list.contains(document.activeElement)){
      list.replaceChildren();
      for(const item of candidates){
        const row=node('li'),label=node('label'),input=node('input'),detail=node('span');
        input.type='checkbox';input.dataset.scopeCandidate=item.id;input.checked=selected.has(item.id);
        detail.append(node('strong',kinds[item.kind]+' · '+item.value),node('small',item.origin+(item.enrolled?' · 已纳管':'')));
        label.append(input,detail);row.append(label);list.append(row);
        input.addEventListener('change',()=>{
          if(!availableNow() || item.enrolled){input.checked=selected.has(item.id);return;}
          if(input.checked){if(selected.size>=32){input.checked=false;notify('每次最多选择 32 项，请分批启用。',true);return;}selected.add(item.id);}else selected.delete(item.id);
          render();
        });
      }
      if(!candidates.length)list.append(node('li','尚无保护候选，点击发现获取当前对象。'));
      signature=next;
    }
    function availableNow(){return enabled() && current();}
    for(const input of list.querySelectorAll('[data-scope-candidate]')){
      const item=candidates.find(i=>i.id===input.dataset.scopeCandidate);
      input.disabled=!available || !valid || !item || item.enrolled;
      input.checked=selected.has(input.dataset.scopeCandidate);
      input.parentElement?.setAttribute('data-selected',input.checked?'true':'false');
    }
    const discover=document.querySelector('[data-scope-discover]'),save=document.querySelector('[data-scope-enroll]'),reload=document.querySelector('[data-scope-reset]');
    if(discover){discover.dataset.operationBlocked=String(!scope);discover.disabled=!available || !scope;}
    if(save){save.dataset.operationBlocked=String(!valid || !selected.size);save.disabled=!available || !valid || !selected.size;}
    if(reload)reload.disabled=!selected.size && !view;
  }
  function bind(){
    if(bound || !form)return;bound=true;
    document.querySelector('[data-scope-discover]')?.addEventListener('click',()=>{if(enabled() && getStatus().scope)void apply({action:'discover'});});
    document.querySelector('[data-scope-reset]')?.addEventListener('click',()=>{document.activeElement?.blur();reset();});
    form.addEventListener('submit',event=>{
      event.preventDefault();
      if(!enabled() || !selected.size)return;
      if(!current()){notify('保护候选已过期或配置变化，请重新发现并重新选择。',true);render();return;}
      void apply({action:'enroll',revision:view.revision,inventory:view.inventory,ids:[...selected]});
    });
  }
  return Object.freeze({bind,render,reset,complete(){selected.clear();view=null;signature=null;}});
}
