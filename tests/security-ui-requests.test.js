import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
async function harness(options={}){
 const handlers=new Map(),events=new Map(),requests=[],busy=[],results=[],messages=[],opened=[],external=[],observations=[];let operations,poller,multiParams;let multiBusy=false;
 const button={hasAttribute:name=>name==='data-security-full-scan',addEventListener:(name,fn)=>handlers.set(name,fn)};
 const state={csrf:'first'};let allowed=true;
 const pending=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
 const consoleView={bind(){},clear(){busy.push(false);},update(){},setExternalBusy:value=>external.push(value),setBusy:value=>busy.push(value),open:(...args)=>opened.push(args),requestResult:value=>results.push(value)};
 const widget=()=>({bind(){},start(){},sync(){},refresh(){},observeListeners:(...args)=>observations.push(args)});
 let source=await readFile(new URL('../src/local/public/assets/portal/security-ui.js',import.meta.url),'utf8');
 source=source.replace(/^import[^\n]+\n/gm,'').replace('export function','function');
 const ctx=vm.createContext({Date,document:{hidden:false,getElementById:id=>options.reportDom && ['security-local-state','security-local-time','security-local-checks'].includes(id)?{dataset:{},replaceChildren(){},append(){}}:null,querySelectorAll:selector=>selector.includes('data-security-scan')?[button]:[],addEventListener:(event,fn)=>events.set(event,fn)},window:{addEventListener(){}},createSecurityConsole:()=>consoleView,createCloudIntelligence:widget,createMultiEngine:params=>{multiParams=params;return {...widget(),isBusy:()=>multiBusy};},createEngineReadiness:widget,createEngineMaintenance:widget,createScheduleSettings:widget,createOperationsWorkspace:params=>{operations=params;return widget();},createUpdateSettings:widget,createDomainSettings:widget,createSecurityPoller:params=>{poller=params;return {run(){},stop(){},refresh:async()=>{if(options.reportOnRefresh)poller.render(options.reportOnRefresh);}};},summarizeLocalSecurity(){return {title:'结果',tone:'warning'};},engineDisplayText:value=>value});
 vm.runInContext(source,ctx);
 const ui=ctx.createSecurityUi({state,can:()=>allowed,notify:(text,error)=>messages.push({text,error}),request:(url,options)=>{if(options?.method==='POST'){const p=pending();requests.push({url,options,...p});return p.promise;}return Promise.resolve({state:'unpaired',connected:false});}});
 ui.bind();
 return {state,busy,external,results,observations,requests,messages,opened,operations,poller,click:()=>handlers.get('click')(),clear:()=>events.get('ironcurtain-session-cleared')(),permission:value=>{allowed=value;},joint:{busy:value=>{multiBusy=value;multiParams.onStateChange();},params:()=>multiParams}};
}
test('credential rotation during a scan request releases busy state and permits the next scan',async()=>{
 const h=await harness(),first=h.click();assert.equal(h.requests.length,1);h.state.csrf='rotated';h.requests[0].resolve({state:'running',task_id:'a'.repeat(32)});await first;
 assert.equal(h.busy.at(-1),false);assert.equal(h.results.length,0);assert.equal(h.messages.length,0);
 const second=h.click();assert.equal(h.requests.length,2);h.requests[1].resolve({state:'running',task_id:'b'.repeat(32)});await second;
 assert.equal(h.results.length,1);assert.equal(h.results[0].task_id,'b'.repeat(32));assert.equal(h.busy.at(-1),false);
});
test('permission revocation settles old requests, blocks submission until permission returns',async()=>{
 const h=await harness(),first=h.click();h.permission(false);h.requests[0].reject(new Error('stale failure'));await first;
 assert.equal(h.busy.at(-1),false);assert.equal(h.results.length,0);assert.equal(h.messages.length,0);await h.click();assert.equal(h.requests.length,1);
 h.permission(true);const next=h.click();assert.equal(h.requests.length,2);h.requests[1].resolve({state:'running',task_id:'b'.repeat(32)});await next;
});
test('a completed old-session request cannot clear a new session request lock',async()=>{
 const h=await harness(),old=h.click();h.state.csrf=null;h.clear();h.state.csrf='new-session';const next=h.click();assert.equal(h.requests.length,2);
 h.requests[0].resolve({state:'running',task_id:'b'.repeat(32)});await old;assert.equal(h.messages.length,0);assert.equal(h.busy.at(-1),true);await h.click();assert.equal(h.requests.length,2);
 h.requests[1].resolve({state:'running',task_id:'b'.repeat(32)});await next;assert.equal(h.busy.at(-1),false);
});

test('response recheck and scan buttons share one request lock and navigate only after confirmation',async()=>{
 const h=await harness();const recheck=h.operations.recheck('checkup','scan');assert.equal(h.requests[0].url,'/api/checkup');assert.equal(h.operations.isScanBusy(),true);await h.click();assert.equal(h.requests.length,1);assert.equal(h.opened.length,0);
 h.requests[0].resolve({state:'running',task_id:'c'.repeat(32)});assert.equal((await recheck).task_id,'c'.repeat(32));assert.deepEqual(h.opened,[['scan',true]]);assert.equal(h.operations.isScanBusy(),true);await h.click();assert.equal(h.requests.length,1);
 h.poller.render({state:'finished',checkup:{state:'finished',task_id:'c'.repeat(32)},rules:{state:'unavailable'}});assert.equal(h.operations.isScanBusy(),false);
});
test('invalid acceptance cannot navigate, and engine maintenance requires a task identity',async()=>{
 const h=await harness();const failed=h.operations.recheck('scan','environment');const check=assert.rejects(failed,/有效检测任务/);h.requests[0].resolve({state:'running',task_id:'x'});await check;assert.equal(h.opened.length,0);assert.equal(h.operations.isScanBusy(),false);
 const scan=h.click();h.requests[1].reject(Error('代理不可用'));await scan;assert.equal(h.messages.length,1);assert.equal(h.messages[0].error,true);
 const update=h.operations.recheck('engine-update','scan');h.requests[2].resolve({state:'running',task_id:'f'.repeat(32)});await update;assert.equal(h.requests[2].url,'/api/engine/update');
});
test('recheck late responses cannot navigate into a changed session or unlock its active request',async()=>{
 const h=await harness();const old=h.operations.recheck('scan','environment'),failed=assert.rejects(old,/登录状态/);h.state.csrf=null;h.clear();h.state.csrf='second';const next=h.click();
 h.requests[0].resolve({state:'running',task_id:'d'.repeat(32)});await failed;assert.equal(h.opened.length,0);assert.equal(h.messages.length,0);assert.equal(h.operations.isScanBusy(),true);
 h.requests[1].resolve({state:'running',task_id:'e'.repeat(32)});await next;assert.equal(h.operations.isScanBusy(),true);h.poller.render({state:'finished',full_scan:{state:'finished',task_id:'e'.repeat(32)},rules:{state:'unavailable'}});assert.equal(h.operations.isScanBusy(),false);
});
test('observed running tasks and missing permissions block both entry points without a request',async()=>{
 const h=await harness();h.poller.render({state:'running',rules:{state:'unavailable'}});await assert.rejects(h.operations.recheck('scan','environment'),/已有检测任务/);await h.click();assert.equal(h.requests.length,0);
 h.poller.onError(Error('代理不可用'));h.permission(false);await assert.rejects(h.operations.recheck('scan','environment'),/请登录/);await h.click();assert.equal(h.requests.length,0);
 await assert.rejects(h.operations.recheck('shell','scan'),/不支持/);
});

test('a fresh terminal report releases the accepted-task lock, while an active report keeps it',async()=>{
 const h=await harness({reportOnRefresh:{state:'finished',task_id:'f'.repeat(32),rules:{state:'unavailable'}}});const check=h.operations.recheck('scan','environment');h.requests[0].resolve({state:'running',task_id:'f'.repeat(32)});await check;assert.equal(h.operations.isScanBusy(),false);
 const next=h.click();h.requests[1].resolve({state:'running',task_id:'a'.repeat(32)});await next;assert.equal(h.requests.length,2);
 h.poller.render({state:'finished',checkup:{state:'running'},rules:{state:'unavailable'}});assert.equal(h.operations.isScanBusy(),true);await h.click();assert.equal(h.requests.length,2);
});

test('joint scanning blocks every local scan and response recheck, then a confirmed finish releases them',async()=>{
 const h=await harness();h.joint.busy(true);assert.equal(h.operations.isScanBusy(),true);await h.click();await assert.rejects(h.operations.recheck('scan','environment'),/已有检测/);assert.equal(h.requests.length,0);
 h.joint.busy(false);const request=h.click();assert.equal(h.joint.params().isScanBusy(),true);h.requests[0].resolve({state:'running',task_id:'a'.repeat(32)});await request;
 h.poller.onError(Error('连接断开'));assert.equal(h.joint.params().isScanBusy(),true);await h.click();assert.equal(h.requests.length,1);
 h.poller.render({state:'finished',full_scan:{state:'finished',task_id:'a'.repeat(32)},rules:{state:'unavailable'}});assert.equal(h.joint.params().isScanBusy(),false);
 h.permission(false);assert.equal(h.joint.params().allowed(),false);
});

test('old terminal and malformed reports cannot unlock a newly accepted task, including a failed poll',async()=>{
 const h=await harness({reportOnRefresh:{state:'finished',task_id:'a'.repeat(32)}});const run=h.operations.recheck('full-scan','scan');h.requests[0].resolve({state:'running',task_id:'b'.repeat(32)});await run;assert.equal(h.operations.isScanBusy(),true);assert.equal(h.external.at(-1),true);
 h.poller.onError(Error('连接断开'));assert.equal(h.external.at(-1),true);await h.click();assert.equal(h.requests.length,1);
 h.poller.render({state:'unavailable'});assert.equal(h.operations.isScanBusy(),true);h.poller.render({state:'finished',task_id:'b'.repeat(32),full_scan:{state:'scanning',task_id:'b'.repeat(32)}});assert.equal(h.operations.isScanBusy(),true);
 h.poller.render({state:'finished',full_scan:{state:'failed',task_id:'b'.repeat(32)}});assert.equal(h.operations.isScanBusy(),false);assert.equal(h.external.at(-1),false);
});

test('an engine update stays locked through old scans and unavailable polls until its own terminal report',async()=>{
 const h=await harness({reportOnRefresh:{state:'finished',task_id:'a'.repeat(32)}});const update=h.operations.recheck('engine-update','scan');h.requests[0].resolve({state:'running',task_id:'b'.repeat(32)});await update;
 assert.equal(h.operations.isScanBusy(),true);h.poller.onError(Error('断线'));assert.equal(h.external.at(-1),true);
 h.poller.render({state:'finished',engine_update:{state:'finished',task_id:'a'.repeat(32)}});assert.equal(h.operations.isScanBusy(),true);
 h.poller.render({state:'finished',engine_update:{state:'running',task_id:'b'.repeat(32)}});assert.equal(h.operations.isScanBusy(),true);
 h.poller.render({state:'finished',engine_update:{state:'finished',task_id:'b'.repeat(32)}});assert.equal(h.operations.isScanBusy(),false);
});
test('engine update acceptance without an identity cannot start a confirmed task',async()=>{
 const h=await harness();const task=h.operations.recheck('engine-update','scan'),failed=assert.rejects(task,/有效检测任务/);h.requests[0].resolve({state:'running'});await failed;assert.equal(h.opened.length,0);assert.equal(h.operations.isScanBusy(),false);
});

test('new local detection invalidates editable listener evidence even if request fails',async()=>{
 const h=await harness();const run=h.click();assert.equal(h.observations.length,1);assert.equal(h.observations[0][0],null);h.requests[0].reject(Error('请求超时'));await run;
 assert.equal(h.observations.at(-1)[0],null);assert.equal(h.results.at(-1).error,'请求超时');
 h.poller.onError(Error('断线'));assert.equal(h.observations.at(-1)[0],null);
});
test('operations use the shared management permission gate and revoked reports are view-only',async()=>{
 const h=await harness({reportDom:true});assert.equal(h.operations.allowed(),true);h.permission(false);assert.equal(h.operations.allowed(),false);
 h.poller.render({state:'finished',rules:{state:'unavailable'}});assert.equal(h.observations.at(-1)[1].trusted,false);
});
