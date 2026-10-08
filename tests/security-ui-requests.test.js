import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
async function harness(){
 const handlers=new Map(),events=new Map(),requests=[],busy=[],results=[];
 const button={hasAttribute:name=>name==='data-security-full-scan',addEventListener:(name,fn)=>handlers.set(name,fn)};
 const state={csrf:'first'};let allowed=true;
 const pending=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
 const consoleView={bind(){},clear(){busy.push(false);},update(){},setBusy:value=>busy.push(value),requestResult:value=>results.push(value)};
 const widget=()=>({bind(){},start(){}});
 let source=await readFile(new URL('../src/local/public/assets/portal/security-ui.js',import.meta.url),'utf8');
 source=source.replace(/^import[^\n]+\n/gm,'').replace('export function','function');
 const ctx=vm.createContext({Date,document:{hidden:false,getElementById:()=>null,querySelectorAll:selector=>selector.includes('data-security-scan')?[button]:[],addEventListener:(event,fn)=>events.set(event,fn)},window:{addEventListener(){}},createSecurityConsole:()=>consoleView,createCloudIntelligence:widget,createMultiEngine:widget,createEngineReadiness:widget,createScheduleSettings:widget,createUpdateSettings:widget,createDomainSettings:widget,createSecurityPoller:()=>({run(){},stop(){},refresh:async()=>{}}),summarizeLocalSecurity(){},engineDisplayText:value=>value});
 vm.runInContext(source,ctx);
 const ui=ctx.createSecurityUi({state,can:()=>allowed,notify:()=>assert.fail('Stale request notified the new session'),request:(url,options)=>{if(options?.method==='POST'){const p=pending();requests.push({url,...p});return p.promise;}return Promise.resolve({state:'unpaired',connected:false});}});
 ui.bind();
 return {state,busy,results,requests,click:()=>handlers.get('click')(),clear:()=>events.get('ironcurtain-session-cleared')(),permission:value=>{allowed=value;}};
}
test('credential rotation during a scan request releases busy state and permits the next scan',async()=>{
 const h=await harness(),first=h.click();assert.equal(h.requests.length,1);h.state.csrf='rotated';h.requests[0].resolve({task_id:'old'});await first;
 assert.equal(h.busy.at(-1),false);assert.equal(h.results.length,0);
 const second=h.click();assert.equal(h.requests.length,2);h.requests[1].resolve({task_id:'new'});await second;
 assert.equal(h.results.length,1);assert.equal(h.results[0].task_id,'new');assert.equal(h.busy.at(-1),false);
});
test('permission revocation settles old requests, blocks submission until permission returns',async()=>{
 const h=await harness(),first=h.click();h.permission(false);h.requests[0].reject(new Error('stale failure'));await first;
 assert.equal(h.busy.at(-1),false);assert.equal(h.results.length,0);await h.click();assert.equal(h.requests.length,1);
 h.permission(true);const next=h.click();assert.equal(h.requests.length,2);h.requests[1].resolve({});await next;
});
test('a completed old-session request cannot clear a new session request lock',async()=>{
 const h=await harness(),old=h.click();h.state.csrf=null;h.clear();h.state.csrf='new-session';const next=h.click();assert.equal(h.requests.length,2);
 h.requests[0].resolve({});await old;assert.equal(h.busy.at(-1),true);await h.click();assert.equal(h.requests.length,2);
 h.requests[1].resolve({});await next;assert.equal(h.busy.at(-1),false);
});
