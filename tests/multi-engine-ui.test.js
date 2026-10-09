import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
import {ENGINE_IDS,ENGINE_META,sanitizeMultiEngine} from '../src/contracts/multi-engine-status.js';
import {engineDisplayText} from '../src/local/public/assets/portal/engine-labels.js';
const job=(id='a',state='finished')=>({schema:'ironcurtain-multi-engine/v1',job_id:id.repeat(64),profile_digest:'b'.repeat(64),state,started_at:'2026-10-06T01:00:00.000Z',updated_at:'2026-10-06T01:00:01.000Z',...(state==='running'?{}:{finished_at:'2026-10-06T01:00:01.000Z'}),completed:4,total:4,coverage:4,engines:ENGINE_IDS.map(id=>({id,state:'complete',detail:'observed',completed:1,total:1,finding_total:0,findings:[]}))});
async function fixture(options={}){
 class Element{constructor(){this.children=[];this.dataset={};this.handlers={};this.textContent='';this.disabled=false;}append(...x){this.children.push(...x);}replaceChildren(...x){this.children=x;}addEventListener(k,f){this.handlers[k]=f;}setAttribute(k,v){this[k]=v;}contains(node){return this.children.some(child=>child===node || child.contains(node));}}
 const ids=['panel','percent','completed','coverage','state','detail','progress','list','findings','start','evidence'];const elements=Object.fromEntries(ids.map(x=>['multi-engine-'+x,new Element()]));elements.containerStart=new Element();elements.containerLabel=new Element();let tid=0;const timers=new Map(),pending=[],notices=[],state={csrf:'first'};
 let source=await readFile(new URL('../src/local/public/assets/portal/multi-engine.js',import.meta.url),'utf8');source=source.replace(/^import[^\n]+\n/gm,'').replace('export function','function');
 const context=vm.createContext({ENGINE_IDS,ENGINE_META,sanitizeMultiEngine,engineDisplayText,document:{activeElement:null,getElementById:id=>elements[id],createElement:()=>new Element(),querySelectorAll:selector=>selector==='[data-security-container-scan]'?[elements.containerStart]:selector==='[data-container-scan-button]'?[elements.containerLabel]:[]},setTimeout:fn=>{timers.set(++tid,fn);return tid;},clearTimeout:id=>timers.delete(id),Date});vm.runInContext(source,context);
 const ui=context.createMultiEngine({state,request:(path,options)=>new Promise((resolve,reject)=>pending.push({path,options,resolve,reject})),notify:(...x)=>notices.push(x),...options});ui.bind();ui.start();
 const flush=async()=>{for(let i=0;i<6;i++)await Promise.resolve();};
 return {elements,pending,timers,notices,state,ui,context,flush,click:()=>elements['multi-engine-start'].handlers.click(),poll:()=>{const fn=timers.values().next().value;timers.clear();fn();}};
}
test('rejected new multi-engine requests cannot display historical 100 percent',async()=>{
 const f=await fixture();f.pending.shift().resolve(job());await f.flush();assert.equal(f.elements['multi-engine-percent'].textContent,'100%');
 for(const reason of ['已有检测正在运行','请求过于频繁']){
  const click=f.click();assert.equal(f.elements['multi-engine-percent'].textContent,'—');assert.equal(f.elements['multi-engine-start'].disabled,true);
  f.pending.shift().reject(new Error(reason));await click;assert.equal(f.elements['multi-engine-start'].disabled,false);assert.equal(f.elements['multi-engine-percent'].textContent,'—');assert.equal(f.elements['multi-engine-detail'].textContent,reason);
  f.pending.shift().resolve(job());await f.flush();assert.equal(f.elements['multi-engine-percent'].textContent,'—');assert.equal(f.elements['multi-engine-detail'].textContent,reason);
 }
 assert.equal(f.notices.length,2);
});
test('running multi-engine completion waits for terminal report and binds the accepted job',async()=>{
 const f=await fixture();f.pending.shift().resolve(job());await f.flush();const click=f.click();f.pending.shift().resolve(job('c','running'));await click;
 assert.equal(f.elements['multi-engine-percent'].textContent,'99%');assert.equal(f.elements['multi-engine-progress'].value,99);
 f.pending.shift().resolve(job());await f.flush();assert.equal(f.elements['multi-engine-percent'].textContent,'—');assert.match(f.elements['multi-engine-detail'].textContent,/旧报告不代表/);
 f.poll();f.pending.shift().resolve(job('c'));await f.flush();assert.equal(f.elements['multi-engine-percent'].textContent,'100%');assert.equal(f.elements['multi-engine-start'].disabled,false);
 f.poll();f.state.csrf=null;f.ui.start();f.pending.shift().resolve(job('c'));await f.flush();assert.equal(f.elements['multi-engine-percent'].textContent,'—');assert.match(f.elements['multi-engine-detail'].textContent,/登录/);assert.equal(f.timers.size,0);
});

test('container entry starts the same authenticated joint task and blocks a second submission',async()=>{
 const f=await fixture();f.pending.shift().resolve(job());await f.flush();
 const run=f.elements.containerStart.handlers.click();const request=f.pending.shift();assert.equal(request.path,'/api/multi-engine');assert.equal(request.options.method,'POST');assert.equal(f.ui.isBusy(),true);assert.equal(f.elements.containerStart.disabled,true);
 await f.click();assert.equal(f.pending.length,0);request.resolve(job('c','running'));await run;
 assert.equal(f.ui.isBusy(),true);assert.equal(f.elements['multi-engine-start'].disabled,true);
 f.pending.shift().resolve(job('c'));await f.flush();assert.equal(f.ui.isBusy(),false);assert.equal(f.elements.containerStart.disabled,false);
});
test('unit progress uses verified counts while queued and empty scopes never report full coverage percent',async()=>{
 const f=await fixture(),report=job('c','running');report.completed=0;report.coverage=0;
 report.engines=ENGINE_IDS.map(id=>({id,state:'queued',detail:'waiting',completed:0,total:0,finding_total:0,findings:[]}));
 report.engines[0]={...report.engines[0],state:'running',completed:5,total:10};report.engines[1]={...report.engines[1],state:'running',completed:1,total:2};
 f.pending.shift().resolve(report);await f.flush();const rows=f.elements['multi-engine-list'].children;
 assert.equal(rows[0].children[4].value,50);assert.match(rows[0].children[6].textContent,/5 \/ 10 文件/);assert.equal(rows[1].children[4].value,50);
 assert.equal(rows[2].children[4].value,0);assert.equal(rows[2].children[5].textContent,'进度尚不可核验');assert.equal(f.elements['multi-engine-percent'].textContent,'0%');
 f.poll();f.pending.shift().resolve({...job('c'),engines:job('c').engines.map(e=>({...e,completed:0,total:0}))});await f.flush();
 for(const row of f.elements['multi-engine-list'].children){assert.equal(row.children[4].value,0);assert.match(row.children[5].textContent,/空范围/);}
});
test('a confirmed running task remains busy across failed polls and historical terminal reports',async()=>{
 const f=await fixture();f.pending.shift().resolve(job('c','running'));await f.flush();assert.equal(f.ui.isBusy(),true);
 f.poll();f.pending.shift().reject(Error('连接断开'));await f.flush();assert.equal(f.ui.isBusy(),true);assert.equal(f.elements['multi-engine-start'].disabled,true);assert.match(f.elements['multi-engine-detail'].textContent,/终态尚未确认/);
 f.poll();f.pending.shift().resolve({...job('a'),started_at:'2026-10-06T00:00:00.000Z',updated_at:'2026-10-06T00:00:01.000Z',finished_at:'2026-10-06T00:00:01.000Z'});await f.flush();assert.equal(f.ui.isBusy(),true);assert.equal(f.elements['multi-engine-percent'].textContent,'—');
 f.poll();f.pending.shift().resolve(job('c'));await f.flush();assert.equal(f.ui.isBusy(),false);assert.equal(f.elements['multi-engine-percent'].textContent,'100%');
});
test('other local scans and permission checks block joint starts before the network request',async()=>{
 let busy=true,allowed=true;const f=await fixture({isScanBusy:()=>busy,allowed:()=>allowed});f.pending.shift().resolve(job());await f.flush();
 assert.equal(f.elements.containerStart.disabled,true);await assert.rejects(f.ui.run(),/已有检测/);assert.equal(f.pending.length,0);
 busy=false;f.ui.sync();assert.equal(f.elements.containerStart.disabled,false);allowed=false;f.ui.sync();await assert.rejects(f.ui.run(),/请登录/);assert.equal(f.pending.length,0);
});
test('verified completion refreshes file evidence once and routes findings to relevant workspaces',async()=>{
 const finished=[];const f=await fixture({onFinished:value=>finished.push(value.job_id)}),report=job();
 report.file_evidence={state:'ready',reason:'bound'};
 report.engines.forEach((e,index)=>{e.finding_total=1;e.findings=[{kind:ENGINE_META[e.id].kind,severity:'high',target:'/srv/fixture',rule:'evidence',detail:'verified'}];});
 f.pending.shift().resolve(report);await f.flush();assert.equal(finished.length,1);
 const rows=f.elements['multi-engine-findings'].children;assert.deepEqual(rows.map(row=>row.children[3].href),['#quarantine','#environment','#environment','#environment']);
 const oldLink=rows[0].children[3];f.context.document.activeElement=oldLink;
 f.poll();f.pending.shift().resolve({...report,updated_at:'2026-10-06T01:00:02.000Z'});await f.flush();assert.equal(finished.length,1);assert.equal(f.elements['multi-engine-findings'].children[0].children[3],oldLink);
});
test('logout and a new session prevent late joint acceptance from modifying the new task',async()=>{
 const f=await fixture();f.pending.shift().resolve(job());await f.flush();const old=f.click();const oldRequest=f.pending.shift();
 f.state.csrf=null;f.ui.start();assert.equal(f.ui.isBusy(),false);f.state.csrf='second';f.ui.start();const newPoll=f.pending.shift();
 const current=f.click(),currentRequest=f.pending.shift();oldRequest.resolve(job('c','running'));await old;assert.equal(f.ui.isBusy(),true);
 currentRequest.resolve(job('d','running'));await current;assert.equal(f.ui.isBusy(),true);newPoll.resolve(job());await f.flush();
 const currentPoll=f.pending.shift();currentPoll.resolve(job('d'));await f.flush();assert.equal(f.ui.isBusy(),false);assert.equal(f.elements['multi-engine-percent'].textContent,'100%');
});

test('terminal reports cannot regress to a stale running state, while a newer scheduled task is observed',async()=>{
 const f=await fixture();f.pending.shift().resolve(job('c'));await f.flush();assert.equal(f.ui.isBusy(),false);
 f.poll();f.pending.shift().resolve(job('c','running'));await f.flush();assert.equal(f.ui.isBusy(),false);assert.equal(f.elements['multi-engine-percent'].textContent,'—');
 const newer={...job('d','running'),started_at:'2026-10-06T02:00:00.000Z',updated_at:'2026-10-06T02:00:01.000Z'};
 f.poll();f.pending.shift().resolve(newer);await f.flush();assert.equal(f.ui.isBusy(),true);assert.equal(f.elements.containerStart.disabled,true);
 f.poll();f.pending.shift().resolve({...newer,completed:5});await f.flush();assert.equal(f.ui.isBusy(),true);assert.equal(f.elements['multi-engine-percent'].textContent,'—');
});
test('unknown running scope is indeterminate and a partial terminal report exposes coverage gaps',async()=>{
 const f=await fixture(),report=job('c','running');report.completed=3;report.coverage=3;report.engines[0]={...report.engines[0],state:'running',completed:0,total:0};
 f.pending.shift().resolve(report);await f.flush();const row=f.elements['multi-engine-list'].children[0];assert.equal(row.children[4].value,undefined);assert.match(row.children[5].textContent,/核验范围与数量/);
 const partial={...job('c','partial'),coverage:3};partial.engines[0]={...partial.engines[0],state:'unavailable',completed:0,total:0};
 f.poll();f.pending.shift().resolve(partial);await f.flush();assert.equal(f.ui.isBusy(),false);assert.equal(f.elements['multi-engine-percent'].textContent,'100%');assert.equal(f.elements['multi-engine-coverage'].textContent,'3 / 4');assert.match(f.elements['multi-engine-state'].textContent,/覆盖缺口/);assert.equal(f.elements['multi-engine-list'].children[0].children[4].value,0);
});

test('session changes immediately clear old findings even while the next request is pending',async()=>{
 const f=await fixture(),report=job();report.engines[0].findings=[{kind:'malware',severity:'high',rule:'infected',target:'/secret/file',detail:'evidence'}];report.engines[0].finding_total=1;f.pending.shift().resolve(report);await f.flush();assert.equal(f.elements['multi-engine-findings'].children.length,1);
 f.context.document.activeElement=f.elements['multi-engine-findings'].children[0].children.at(-1);f.state.csrf='new';f.ui.start();assert.equal(f.elements['multi-engine-findings'].children.length,0);assert.equal(f.elements['multi-engine-percent'].textContent,'—');
 f.state.csrf=null;f.ui.start();assert.equal(f.elements['multi-engine-list'].children[0].children[3].textContent,'尚未取得检测证据');f.pending.shift().resolve(report);await f.flush();assert.equal(f.elements['multi-engine-findings'].children.length,0);
});
test('permission revocation invalidates pending reads and restoring the same session restarts polling',async()=>{
 let allowed=true;const f=await fixture({allowed:()=>allowed});const old=f.pending.shift();allowed=false;f.ui.start();old.resolve(job());await f.flush();assert.equal(f.elements['multi-engine-percent'].textContent,'—');assert.equal(f.elements['multi-engine-start'].disabled,true);assert.equal(f.timers.size,0);
 allowed=true;f.ui.start();assert.equal(f.pending.length,1);f.pending.shift().resolve(job('c','running'));await f.flush();assert.equal(f.ui.isBusy(),true);allowed=false;f.ui.start();assert.equal(f.ui.isBusy(),true);assert.equal(f.elements['multi-engine-percent'].textContent,'—');
 allowed=true;f.ui.start();assert.equal(f.pending.length,1);f.pending.shift().resolve(job('c'));await f.flush();assert.equal(f.ui.isBusy(),false);assert.equal(f.timers.size,1);
});
