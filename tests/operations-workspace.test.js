import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
import {sanitizeOperations,unavailableOperations,validatePorts,validateOperation,operationRecheckPlan} from '../src/contracts/operations-status.js';
import {sanitizeInventory} from '../src/contracts/protection-status.js';
import {operationStatus,operationJob,operationScope,revision} from './fixtures/operations.js';

class Element {
 constructor(){this.children=[];this.dataset={};this.handlers=new Map();this.value='';this.disabled=false;this.textContent='';}
 append(...items){for(const item of items){item.parentElement=this;this.children.push(item);}}
 setAttribute(name,value){this[name]=value;}
 blur(){}
 querySelectorAll(selector){const key={'[data-scope-candidate]':'scopeCandidate','[data-listener-edit]':'listenerEdit','[data-port-recheck]':'portRecheck'}[selector];return this.children.flatMap(child=>[...(key && Object.hasOwn(child.dataset,key)?[child]:[]),...child.querySelectorAll(selector)]);}
 replaceChildren(...items){this.children=items;}
 contains(value){return this===value || this.children.some(child=>child.contains?.(value));}
 addEventListener(name,fn){this.handlers.set(name,fn);}
 fire(name,event={}){return this.handlers.get(name)?.({preventDefault(){},...event});}
}
async function harness(options={}){
 const state={csrf:'session-one'},requests=[],messages=[],events=new Map(),timers=new Map();let counter=0;
 const tcp=new Element(),udp=new Element(),save=new Element(),reset=new Element(),label=new Element(),form=new Element();
 form.append(tcp,udp,save,reset,label);
 form.querySelector=selector=>({'[name="tcp"]':tcp,'[name="udp"]':udp,'[data-port-policy-state]':label}[selector]);
 form.querySelectorAll=()=>[tcp,udp,save,reset];
 const map=new Map([['[data-port-policy]',form],['[data-port-policy-reset]',reset]]);
 for(const selector of ['[data-risk-list]','[data-risk-state]','[data-risk-detail]','[data-recovery-state]','[data-recovery-records]','[data-operation-audit]','[data-risk-followup]','[data-recovery-followup]','[data-host-table="listeners"]','[data-listener-policy-state]','[data-port-followup]'])map.set(selector,new Element());
 const scopeForm=new Element(),scopeList=new Element(),scopeSave=new Element(),scopeReset=new Element(),scopeDiscover=new Element(),scopeState=new Element();
 scopeForm.append(scopeList,scopeSave,scopeReset);
 for(const [key,value] of [['form',scopeForm],['candidates',scopeList],['enroll',scopeSave],['reset',scopeReset],['discover',scopeDiscover],['state',scopeState],['summary',new Element()],['issues',new Element()]])map.set('[data-scope-'+key+']',value);
 const refresh=new Element(),status=new Element();
 const document={activeElement:null,createElement:()=>new Element(),querySelector:s=>map.get(s),querySelectorAll:s=>s==='[data-operations-refresh]'?[refresh]:s==='[data-operation-state]'?[status]:s.includes('data-operation-action') || s.includes('data-operation-recheck')?[...map.values()].flatMap(n=>n.children.filter(c=>Object.hasOwn(c.dataset,'operationAction') || Object.hasOwn(c.dataset,'operationRecheck'))):[],addEventListener:(name,fn)=>events.set(name,fn)};
 let source=await readFile(new URL('../src/local/public/assets/portal/operations-workspace.js',import.meta.url),'utf8');
 source=source.replace(/^import[^\n]+\n/gm,'').replace('export function','function');
 source=(await readFile(new URL('../src/local/public/assets/portal/scope-workspace.js',import.meta.url),'utf8')).replace('export function','function')+'\n'+source;
 source=(await readFile(new URL('../src/local/public/assets/portal/listener-workspace.js',import.meta.url),'utf8')).replace(/^import[^\n]+\n/gm,'').replace(/export function/g,'function')+'\n'+source;
 const context=vm.createContext({sanitizeInventory,sanitizeOperations,unavailableOperations,validatePorts,validateOperation,operationRecheckPlan,document,window:{prompt:()=>null,confirm:()=>true},queueMicrotask,Date,setTimeout:fn=>{const id=++counter;timers.set(id,fn);return id;},clearTimeout:id=>timers.delete(id)});
 vm.runInContext(source,context);
 const workspace=context.createOperationsWorkspace({...options,state,notify:(text,error)=>messages.push({text,error}),request:(url,options)=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});requests.push({url,options,resolve,reject});return promise;}});
 workspace.bind();
 const settle=async()=>{await new Promise(resolve=>setImmediate(resolve));};
 const load=async value=>{const wait=workspace.refresh();requests.at(-1).resolve(value || operationStatus());await wait;};
 const submit=()=>form.fire('submit');
 return {state,requests,messages,workspace,document,tcp,udp,form,save,reset,label,map,settle,load,submit,scopeForm,scopeList,scopeSave,scopeReset,scopeDiscover,scopeState,clear:()=>events.get('ironcurtain-session-cleared')()};
}

test('port draft and focused controls survive passive polling; fresh save uses the displayed revision',async()=>{
 const h=await harness();await h.load();assert.equal(h.tcp.value,'22, 443');
 h.tcp.value='443, 8443';h.document.activeElement=h.tcp;h.form.fire('input');
 await h.load({...operationStatus(),policy:{revision,tcp:[80],udp:[53]}});
 assert.equal(h.tcp.value,'443, 8443');assert.equal(h.udp.value,'');assert.match(h.label.textContent,/未保存/);
 h.submit();assert.equal(h.requests.at(-1).options.method,'POST');
 assert.deepEqual(JSON.parse(JSON.stringify(h.requests.at(-1).options.body)),{action:'ports',revision,tcp:[443,8443],udp:[]});
});
test('a newer profile cannot silently accept the old draft; explicit reload replaces it',async()=>{
 const h=await harness();await h.load();h.tcp.value='8443';h.form.fire('input');
 const next={...operationStatus(),policy:{revision:'c'.repeat(64),tcp:[80],udp:[53]}};await h.load(next);
 const count=h.requests.length;h.submit();assert.equal(h.requests.length,count);assert.equal(h.tcp.value,'8443');assert.match(h.messages.at(-1).text,/版本已变化/);
 h.reset.fire('click');h.requests.at(-1).resolve(next);await h.settle();assert.equal(h.tcp.value,'80');assert.equal(h.udp.value,'53');
 h.submit();assert.equal(h.requests.at(-1).options.body.revision,next.policy.revision);
});
test('a failed save retains user input and never reports successful acceptance',async()=>{
 const h=await harness();await h.load();h.tcp.value='8443';h.form.fire('input');h.submit();
 h.requests.at(-1).reject(Error('维护锁被占用'));await h.settle();
 assert.equal(h.messages.at(-1).error,true);h.requests.at(-1).resolve(operationStatus());await h.settle();
 assert.equal(h.tcp.value,'8443');assert.match(h.label.textContent,/未保存/);assert.equal(h.save.disabled,false);
});
test('a pre-submit GET cannot overwrite a POST receipt or release the new operation',async()=>{
 const h=await harness();await h.load();h.tcp.value='8443';h.form.fire('input');
 const get=h.workspace.refresh(),old=h.requests.at(-1);h.submit();const post=h.requests.at(-1);
 old.resolve({...operationStatus(),policy:{revision:'d'.repeat(64),tcp:[80],udp:[]}});await get;
 assert.equal(h.save.disabled,true);assert.equal(h.tcp.value,'8443');assert.equal(h.requests.at(-1),post);
 post.resolve({schema:'ironcurtain-operations/v1',state:'running',job:operationJob()});await h.settle();
 assert.equal(h.messages.at(-1).error,undefined);assert.equal(h.save.disabled,true);
 const completed={...operationStatus(),policy:{revision:'e'.repeat(64),tcp:[8443],udp:[]},job:{...operationJob(),state:'complete',finished_at:'2026-10-09T01:00:01.000Z'}};
 h.requests.at(-1).resolve(completed);await h.settle();assert.equal(h.save.disabled,false);assert.equal(h.tcp.value,'8443');assert.match(h.label.textContent,/已加载/);
});
test('logout and a new session reject stale GET data and POST notifications',async()=>{
 const h=await harness();await h.load();h.tcp.value='8443';h.form.fire('input');h.submit();const post=h.requests.at(-1);
 h.state.csrf=null;h.clear();assert.equal(h.tcp.value,'');assert.equal(h.save.disabled,true);
 h.state.csrf='session-two';h.workspace.start();const get=h.requests.at(-1);
 post.resolve({schema:'ironcurtain-operations/v1',state:'running',job:operationJob()});await h.settle();assert.equal(h.messages.length,0);
 get.resolve({...operationStatus(),policy:{revision:'c'.repeat(64),tcp:[80],udp:[]}});await h.settle();assert.equal(h.tcp.value,'80');assert.equal(h.save.disabled,false);
 const oldLoad=h.workspace.refresh(),old=h.requests.at(-1);h.state.csrf=null;h.clear();old.resolve(operationStatus());await oldLoad;assert.equal(h.tcp.value,'');assert.equal(h.save.disabled,true);
});
test('a receipt for another action is rejected and preserves the draft',async()=>{
 const h=await harness();await h.load();h.tcp.value='8443';h.form.fire('input');h.submit();
 h.requests.at(-1).resolve({schema:'ironcurtain-operations/v1',state:'running',job:{...operationJob(),action:'restore'}});await h.settle();
 assert.equal(h.messages.at(-1).error,true);assert.match(h.messages.at(-1).text,/不一致/);
 h.requests.at(-1).resolve(operationStatus());await h.settle();assert.equal(h.tcp.value,'8443');assert.match(h.label.textContent,/未保存/);
});

const scoped=()=>({...operationStatus(),scope:operationScope()});
const choose=(h,id='1'.repeat(16),checked=true)=>{const input=h.scopeList.querySelectorAll('[data-scope-candidate]').find(i=>i.dataset.scopeCandidate===id);input.checked=checked;input.fire('change');return input;};
test('scope discovery submits fixed action and never supplies user paths',async()=>{
 const h=await harness();await h.load();assert.equal(h.scopeDiscover.disabled,true);
 await h.load(scoped());h.scopeDiscover.fire('click');assert.deepEqual(JSON.parse(JSON.stringify(h.requests.at(-1).options.body)),{action:'discover'});
});
test('scope selections and focus survive polling; enrollment binds both revisions',async()=>{
 const h=await harness(),v=scoped();await h.load(v);const input=choose(h);h.document.activeElement=input;
 await h.load(v);assert.equal(h.scopeList.querySelectorAll('[data-scope-candidate]')[0],input);assert.equal(input.checked,true);assert.equal(h.scopeSave.disabled,false);
 h.scopeForm.fire('submit');assert.deepEqual(JSON.parse(JSON.stringify(h.requests.at(-1).options.body)),{action:'enroll',revision,inventory:v.scope.discovery.revision,ids:['1'.repeat(16)]});
});
test('stale discovery and changed profile keep selection but block enrollment until explicit reset',async()=>{
 for(const change of [v=>v.policy.revision='c'.repeat(64),v=>v.scope.discovery.revision='d'.repeat(64),v=>v.scope.discovery.observed_at=new Date(Date.now()-121000).toISOString()]){
  const h=await harness(),v=scoped();await h.load(v);const input=choose(h);change(v);await h.load(v);
  assert.equal(input.checked,true);assert.equal(h.scopeSave.disabled,true);assert.match(h.scopeState.textContent,/过期|变化/);
  const count=h.requests.length;h.scopeForm.fire('submit');assert.equal(h.requests.length,count);assert.equal(h.messages.at(-1).error,true);
  h.scopeReset.fire('click');assert.equal(h.scopeList.querySelectorAll('[data-scope-candidate]')[0].checked,false);
 }
});
test('failed enrollment retains selection; only matching complete receipt clears it',async()=>{
 const h=await harness(),v=scoped();await h.load(v);choose(h);h.scopeForm.fire('submit');h.requests.at(-1).reject(Error('服务忙'));await h.settle();h.requests.at(-1).resolve(v);await h.settle();assert.equal(h.scopeSave.disabled,false);
 h.scopeForm.fire('submit');const job={...operationJob(),action:'enroll'};h.requests.at(-1).resolve({schema:v.schema,state:'running',job});await h.settle();
 h.requests.at(-1).resolve({...v,job:{...job,state:'complete',finished_at:'2026-10-09T01:00:01.000Z'}});await h.settle();assert.equal(h.scopeList.querySelectorAll('[data-scope-candidate]')[0].checked,false);
});
test('enrolled objects stay disabled, HTML-looking paths are text and logout drops drafts',async()=>{
 const h=await harness(),v=scoped();v.scope.discovery.candidates[1].enrolled=true;v.scope.discovery.candidates[0].value='/srv/<script>alert(1)</script>';
 await h.load(v);assert.equal(h.scopeList.querySelectorAll('[data-scope-candidate]')[1].disabled,true);choose(h);
 h.state.csrf=null;h.clear();assert.equal(h.scopeList.querySelectorAll('[data-scope-candidate]').length,0);assert.equal(h.scopeSave.disabled,true);
 h.state.csrf='new';h.workspace.start();h.requests.at(-1).resolve(v);await h.settle();assert.equal(h.scopeList.querySelectorAll('[data-scope-candidate]')[0].checked,false);
});

const followupButton=h=>h.map.get('[data-risk-followup]').children.find(n=>Object.hasOwn(n.dataset,'operationRecheck'));
test('completed responses expose a fixed recheck and keep acceptance separate from resolution',async()=>{
 const calls=[];let resolve;
 const h=await harness({recheck:(action,panel)=>{calls.push({action,panel});return new Promise(done=>{resolve=done;});}});
 await h.load({...operationStatus(),job:operationJob('complete')});const b=followupButton(h);assert.equal(b.textContent,'复检环境与端口');b.fire('click');b.fire('click');
 assert.deepEqual(calls,[{action:'scan',panel:'environment'}]);assert.equal(h.save.disabled,true);
 resolve({state:'running',task_id:'c'.repeat(32)});await h.settle();assert.equal(h.messages.length,1);assert.match(h.messages[0].text,/已受理/);assert.match(h.map.get('[data-risk-followup]').children.map(n=>n.textContent).join(' '),/不代表风险已消除/);
});
test('only successful persisted actions expose rechecks and file actions select joint checkup',async()=>{
 const calls=[];const h=await harness({recheck:async(action,panel)=>{calls.push({action,panel});return {state:'running',task_id:'d'.repeat(32)};}});
 for(const job of [operationJob('failed'),operationJob('interrupted'),{...operationJob('complete'),action:'review'}]){await h.load({...operationStatus(),job});assert.equal(followupButton(h),undefined);}
 await h.load({...operationStatus(),audit:[{...operationJob('complete'),action:'restore',target:'a'.repeat(64)}]});followupButton(h).fire('click');await h.settle();assert.deepEqual(calls,[{action:'checkup',panel:'scan'}]);
});
test('scan contention, logout and failed confirmations never report a recheck as accepted',async()=>{
 let scanBusy=true,resolve;const calls=[];
 const h=await harness({isScanBusy:()=>scanBusy,recheck:()=>{calls.push(1);return new Promise(done=>{resolve=done;});}});
 await h.load({...operationStatus(),job:operationJob('complete')});assert.equal(followupButton(h).disabled,true);followupButton(h).fire('click');assert.equal(calls.length,0);
 scanBusy=false;h.workspace.sync();assert.equal(followupButton(h).disabled,false);followupButton(h).fire('click');resolve({state:'running',task_id:'wrong'});await h.settle();assert.equal(h.messages.at(-1).error,true);assert.equal(h.messages.some(n=>n.text.includes('已受理')),false);
 followupButton(h).fire('click');h.state.csrf=null;h.clear();h.state.csrf='session-two';h.workspace.start();resolve({state:'running',task_id:'e'.repeat(32)});await h.settle();assert.equal(h.messages.length,1);assert.equal(followupButton(h),undefined);
});

const listenerButtons=h=>h.map.get('[data-host-table="listeners"]').querySelectorAll('[data-listener-edit]');
const portRecheckButton=h=>h.map.get('[data-port-followup]').querySelectorAll('[data-port-recheck]')[0];
function listenerReport(listeners=[{protocol:'tcp',address:'0.0.0.0',port:8080,processes:[{name:'web',pid:42}]}]){
 return {inventory:{schema:'ironcurtain-inventory/v1',observed_at:new Date().toISOString(),container_state:'complete',listener_state:'complete',directory_state:'complete',drift_state:'first-observation',container_count:0,listener_count:listeners.length,candidate_count:0,containers:[],listeners,candidates:[],issues:[],drift:[],truncated:false}};
}
const observe=(h,report=listenerReport(),trusted=true)=>h.workspace.observeListeners(report,{trusted});
test('listener actions edit only the protocol draft; explicit save submits its displayed revision',async()=>{
 const h=await harness();await h.load();const count=h.requests.length;observe(h);const row=h.map.get('[data-host-table="listeners"]').children[0];
 assert.equal(row.children[1].textContent,'8080');assert.equal(row.children[4].textContent,'未列入允许清单');
 listenerButtons(h)[0].fire('click');assert.equal(h.requests.length,count);assert.equal(h.tcp.value,'22, 443, 8080');assert.equal(h.udp.value,'');
 assert.match(h.map.get('[data-listener-policy-state]').textContent,/尚未保存/);assert.match(h.map.get('[data-host-table="listeners"]').children[0].children[5].children[1].textContent,/待保存加入/);
 h.submit();assert.deepEqual(JSON.parse(JSON.stringify(h.requests.at(-1).options.body)),{action:'ports',revision,tcp:[22,443,8080],udp:[]});
});
test('same protocol port is shared across addresses while TCP and UDP drafts stay independent',async()=>{
 const h=await harness();await h.load();observe(h,listenerReport([{protocol:'tcp',address:'0.0.0.0',port:443,processes:[]},{protocol:'tcp',address:'127.0.0.1',port:443,processes:[]},{protocol:'udp',address:'0.0.0.0',port:443,processes:[]}]));
 listenerButtons(h)[0].fire('click');assert.equal(h.tcp.value,'22');assert.equal(h.udp.value,'');
 assert.equal(listenerButtons(h)[1].textContent,'加入草稿');assert.equal(listenerButtons(h)[2].textContent,'加入草稿');
 listenerButtons(h)[2].fire('click');assert.equal(h.udp.value,'443');assert.equal(h.tcp.value,'22');
 assert.equal(h.map.get('[data-host-table="listeners"]').children[0].children[4].textContent,'已允许');
});
test('focused listener controls survive polling but cannot invert a changed draft or edit replaced evidence',async()=>{
 const h=await harness();await h.load();const report=listenerReport();observe(h,report);const old=listenerButtons(h)[0];h.document.activeElement=old;
 observe(h,report);assert.equal(listenerButtons(h)[0],old);old.fire('click');assert.equal(h.tcp.value,'22, 443, 8080');
 old.fire('click');assert.equal(h.tcp.value,'22, 443, 8080');assert.match(h.messages.at(-1).text,/草稿已变化/);
 const next=listenerReport([{...report.inventory.listeners[0],processes:[{name:'replacement',pid:43}]}]);observe(h,next);
 old.fire('click');assert.match(h.messages.at(-1).text,/观测或策略已变化/);assert.equal(h.tcp.value,'22, 443, 8080');
});
test('stale, partial, malformed, untrusted and future listener evidence cannot edit policy',async()=>{
 for(const change of [r=>r.inventory.observed_at=new Date(Date.now()-901000).toISOString(),r=>r.inventory.observed_at=new Date(Date.now()+31000).toISOString(),r=>r.inventory.listener_state='partial',r=>r.inventory.listeners[0].port=0,r=>r.inventory.schema='wrong']){
  const h=await harness();await h.load();const r=listenerReport();change(r);observe(h,r);for(const b of listenerButtons(h)){assert.equal(b.disabled,true);b.fire('click');}assert.equal(h.tcp.value,'22, 443');
 }
 const h=await harness();await h.load();observe(h,listenerReport(),false);assert.equal(listenerButtons(h)[0].disabled,true);listenerButtons(h)[0].fire('click');assert.equal(h.tcp.value,'22, 443');
});
test('old focused listeners reject disconnect, session switch and aging since rendering',async()=>{
 for(const kind of ['disconnect','session','age']){
  const h=await harness();await h.load();const r=listenerReport();observe(h,r);const old=listenerButtons(h)[0];h.document.activeElement=old;
  if(kind==='disconnect')observe(h,null);if(kind==='session')h.state.csrf='other';if(kind==='age')r.inventory.observed_at=new Date(Date.now()-901000).toISOString();
  old.fire('click');assert.equal(h.tcp.value,'22, 443');assert.equal(h.messages.at(-1).error,true);
 }
});
test('invalid draft, revision conflict and active scan or operation block listener edits',async()=>{
 let busy=false;const h=await harness({isScanBusy:()=>busy});await h.load();observe(h);h.tcp.value='abc';h.form.fire('input');assert.equal(listenerButtons(h)[0].disabled,true);listenerButtons(h)[0].fire('click');assert.equal(h.tcp.value,'abc');
 h.tcp.value='22, 443';h.form.fire('input');busy=true;h.workspace.sync();assert.equal(listenerButtons(h)[0].disabled,true);busy=false;
 await h.load({...operationStatus(),policy:{revision:'c'.repeat(64),tcp:[22],udp:[]}});assert.equal(listenerButtons(h)[0].disabled,true);
 h.reset.fire('click');h.requests.at(-1).resolve(operationStatus());await h.settle();await h.load({...operationStatus(),job:operationJob()});assert.equal(listenerButtons(h)[0].disabled,true);
});
test('bounded listener display preserves the actual total and treats process names as text',async()=>{
 const h=await harness();await h.load();const r=listenerReport();r.inventory.listener_count=100;r.inventory.truncated=true;r.inventory.listeners[0].processes[0].name='<script>x</script>';observe(h,r);
 assert.match(h.map.get('[data-listener-policy-state]').textContent,/1 \/ 100/);assert.equal(h.map.get('[data-host-table="listeners"]').children[0].children[3].textContent,'<script>x</script> (42)');
});
test('port-specific recheck selects only completed port jobs and requires a clean draft',async()=>{
 const calls=[];const h=await harness({recheck:async(...args)=>{calls.push(args);return {state:'running',task_id:'c'.repeat(32)};}});
 const ports={...operationJob('complete'),id:'d'.repeat(32),target:'端口策略'},restore={...operationJob('complete'),id:'e'.repeat(32),action:'restore',finished_at:'2026-10-09T02:00:00.000Z',target:'a'.repeat(64)};
 await h.load({...operationStatus(),job:restore,audit:[ports]});assert.ok(portRecheckButton(h));h.tcp.value='8080';h.form.fire('input');assert.equal(portRecheckButton(h).disabled,true);portRecheckButton(h).fire('click');assert.equal(calls.length,0);
 h.reset.fire('click');h.requests.at(-1).resolve({...operationStatus(),job:restore,audit:[ports]});await h.settle();portRecheckButton(h).fire('click');await h.settle();assert.deepEqual(calls,[['scan','environment']]);assert.match(h.messages.at(-1).text,/复检已受理/);
});
test('failed ports, unsupported rechecks and replaced focused port receipts cannot start a check',async()=>{
 const calls=[];const h=await harness({recheck:async()=>{calls.push(1);return {state:'running',task_id:'c'.repeat(32)};}});await h.load({...operationStatus(),job:operationJob('failed')});assert.equal(portRecheckButton(h),undefined);
 await h.load({...operationStatus(),job:operationJob('complete')});const old=portRecheckButton(h);await h.load({...operationStatus(),job:{...operationJob('complete'),id:'d'.repeat(32)}});old.fire('click');assert.equal(calls.length,0);
 const noCapability=await harness();await noCapability.load({...operationStatus(),job:operationJob('complete')});assert.equal(portRecheckButton(noCapability).disabled,true);
});

test('management permission revocation blocks focused listener editing and policy saves',async()=>{
 let allowed=true;const h=await harness({allowed:()=>allowed});await h.load();observe(h);const old=listenerButtons(h)[0];h.document.activeElement=old;allowed=false;h.workspace.sync();assert.equal(old.disabled,true);assert.equal(h.save.disabled,true);
 const count=h.requests.length;old.fire('click');h.submit();assert.equal(h.requests.length,count);assert.equal(h.tcp.value,'22, 443');
});
test('port-specific recheck reports the accepted task without claiming resolution',async()=>{
 const h=await harness({recheck:async()=>({state:'running',task_id:'c'.repeat(32)})});await h.load({...operationStatus(),job:operationJob('complete')});portRecheckButton(h).fire('click');await h.settle();
 assert.match(h.map.get('[data-port-followup]').children.map(n=>n.textContent).join(' '),/cccccccc.*不代表风险已消除/);
});
