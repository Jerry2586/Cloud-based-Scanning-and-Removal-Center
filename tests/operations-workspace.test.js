import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
import {sanitizeOperations,unavailableOperations,validatePorts,validateOperation} from '../src/contracts/operations-status.js';
import {operationStatus,operationJob,revision} from './fixtures/operations.js';

class Element {
 constructor(){this.children=[];this.dataset={};this.handlers=new Map();this.value='';this.disabled=false;this.textContent='';}
 append(...items){this.children.push(...items);}
 replaceChildren(...items){this.children=items;}
 contains(value){return this===value || this.children.some(child=>child.contains?.(value));}
 addEventListener(name,fn){this.handlers.set(name,fn);}
 fire(name,event={}){return this.handlers.get(name)?.({preventDefault(){},...event});}
}
async function harness(){
 const state={csrf:'session-one'},requests=[],messages=[],events=new Map(),timers=new Map();let counter=0;
 const tcp=new Element(),udp=new Element(),save=new Element(),reset=new Element(),label=new Element(),form=new Element();
 form.append(tcp,udp,save,reset,label);
 form.querySelector=selector=>({'[name="tcp"]':tcp,'[name="udp"]':udp,'[data-port-policy-state]':label}[selector]);
 form.querySelectorAll=()=>[tcp,udp,save,reset];
 const map=new Map([['[data-port-policy]',form],['[data-port-policy-reset]',reset]]);
 for(const selector of ['[data-risk-list]','[data-risk-state]','[data-risk-detail]','[data-recovery-state]','[data-recovery-records]','[data-operation-audit]'])map.set(selector,new Element());
 const refresh=new Element(),status=new Element();
 const document={activeElement:null,createElement:()=>new Element(),querySelector:s=>map.get(s),querySelectorAll:s=>s==='[data-operations-refresh]'?[refresh]:s==='[data-operation-state]'?[status]:[],addEventListener:(name,fn)=>events.set(name,fn)};
 let source=await readFile(new URL('../src/local/public/assets/portal/operations-workspace.js',import.meta.url),'utf8');
 source=source.replace(/^import[^\n]+\n/gm,'').replace('export function','function');
 const context=vm.createContext({sanitizeOperations,unavailableOperations,validatePorts,validateOperation,document,window:{prompt:()=>null,confirm:()=>true},queueMicrotask,Date,setTimeout:fn=>{const id=++counter;timers.set(id,fn);return id;},clearTimeout:id=>timers.delete(id)});
 vm.runInContext(source,context);
 const workspace=context.createOperationsWorkspace({state,notify:(text,error)=>messages.push({text,error}),request:(url,options)=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});requests.push({url,options,resolve,reject});return promise;}});
 workspace.bind();
 const settle=async()=>{await new Promise(resolve=>setImmediate(resolve));};
 const load=async value=>{const wait=workspace.refresh();requests.at(-1).resolve(value || operationStatus());await wait;};
 const submit=()=>form.fire('submit');
 return {state,requests,messages,workspace,document,tcp,udp,form,save,reset,label,map,settle,load,submit,clear:()=>events.get('ironcurtain-session-cleared')()};
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
