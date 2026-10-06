import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import vm from 'node:vm';
import {CAPABILITY_NAMES,engineDisplayText} from '../src/local/public/assets/portal/engine-labels.js';
import {sanitizeEngineReadiness,unavailableReadiness,ENGINE_IDS} from '../src/contracts/engine-readiness.js';
import {localEngineReadiness} from '../src/local/engine-readiness-client.js';
const make=(now=Date.now())=>({schema:'ironcurtain-engine-readiness/v1',state:'checked',checked_at:new Date(now).toISOString(),reason:'dependencies only',ready_count:3,engines:[
 {id:'clamav',state:'ready',detail:'metadata configured',version:'1.4.3.vendor',source:'official-direct',database_at:new Date(now-3600000).toISOString()},
 {id:'trivy',state:'ready',detail:'local database',version:'0.65.0',database_at:new Date(now-3600000).toISOString(),next_update:new Date(now+3600000).toISOString()},
 {id:'osquery',state:'ready',detail:'query passed',version:'5.19.0'},
 {id:'falco',state:'partial',detail:'events are not live coverage'}]});
test('readiness requires fresh evidence, exact order and truthful engine coverage',()=>{
 const now=Date.now();assert.equal(sanitizeEngineReadiness(make(now),now).ready_count,3);
 for(const edit of [v=>v.ready_count=4,v=>v.engines.reverse(),v=>v.engines[3].state='ready',v=>v.checked_at=new Date(now-121000).toISOString(),v=>v.engines[1].next_update=new Date(now).toISOString(),v=>delete v.engines[0].source,v=>delete v.engines[1].version,v=>v.engines[2].version='shell SECRET',v=>v.engines[1].database_at='2026-02-31T00:00:00Z',v=>v.engines[1].next_update=new Date(now+50*3600000).toISOString(),v=>v.state='checking']){
  const v=make(now);edit(v);assert.equal(sanitizeEngineReadiness(v,now).state,'unavailable');
 }
 const v=make(now);v.secret='SECRET';v.engines[1].command='rm';const clean=sanitizeEngineReadiness(v,now);assert.equal(clean.secret,undefined);assert.equal(clean.engines[1].command,undefined);
});
test('fixed client fails closed for missing agent and unknown action',async()=>{
 assert.throws(()=>localEngineReadiness('install'),/Unknown/);
 const r=await localEngineReadiness('status',{IRONCURTAIN_SCAN_SOCKET:join(tmpdir(),'missing-readiness-'+process.pid+'.sock')});assert.equal(r.state,'unavailable');assert.equal(r.response_status,503);
});
test('Unix readiness API validates response budgets and empty fixed commands',{skip:process.platform==='win32'},async t=>{
 const dir=await mkdtemp(join(tmpdir(),'readiness-'));t.after(()=>rm(dir,{recursive:true,force:true}));const socket=join(dir,'agent.sock');let code=200,value=make(),oversize=false;const calls=[];
 const server=createServer((req,res)=>{const chunks=[];req.on('data',x=>chunks.push(x));req.on('end',()=>{calls.push({method:req.method,path:req.url,body:Buffer.concat(chunks).toString(),length:req.headers['content-length']});res.writeHead(code);res.end(oversize?'x'.repeat(16385):JSON.stringify(value));});});await new Promise(r=>server.listen(socket,r));t.after(()=>new Promise(r=>server.close(r)));
 const env={IRONCURTAIN_SCAN_SOCKET:socket};assert.equal((await localEngineReadiness('status',env)).state,'checked');
 code=202;value={...unavailableReadiness(),state:'checking'};assert.equal((await localEngineReadiness('check',env)).response_status,202);assert.deepEqual(calls[1],{method:'POST',path:'/engines',body:'',length:'0'});
 code=200;assert.equal((await localEngineReadiness('check',env)).response_status,503);code=503;assert.equal((await localEngineReadiness('status',env)).state,'unavailable');code=200;oversize=true;assert.equal((await localEngineReadiness('status',env)).state,'unavailable');
});
test('readiness UI recovers failed buttons and discards pre-logout responses',async()=>{
 class Element{constructor(){this.children=[];this.dataset={};this.handlers={};this.disabled=false;this.textContent='';}append(...n){this.children.push(...n);}replaceChildren(...n){this.children=n;}addEventListener(k,fn){this.handlers[k]=fn;}}
 const elements=Object.fromEntries(['state','detail','list','check'].map(x=>['engine-readiness-'+x,new Element()]));let tid=0;const timers=new Map();const state={csrf:'first'},pending=[];const notices=[];
 let source=await readFile(new URL('../src/local/public/assets/portal/engine-readiness.js',import.meta.url),'utf8');source=source.replace(/^import[^\n]+\n/gm,'').replace('export function','function');
 const context=vm.createContext({CAPABILITY_NAMES,engineDisplayText,sanitizeEngineReadiness,unavailableReadiness,ENGINE_IDS,document:{getElementById:id=>elements[id],createElement:()=>new Element()},setTimeout:fn=>{timers.set(++tid,fn);return tid;},clearTimeout:id=>timers.delete(id),Date});vm.runInContext(source,context);
 const ui=context.createEngineReadiness({state,request:(path,options)=>new Promise((resolve,reject)=>pending.push({path,options,resolve,reject})),notify:(...x)=>notices.push(x)});ui.bind();ui.start();
 const flush=async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();};
 pending.shift().resolve(make());await flush();assert.equal(elements['engine-readiness-list'].children.length,4);
 const click=elements['engine-readiness-check'].handlers.click();assert.equal(elements['engine-readiness-check'].disabled,true);assert.deepEqual({...pending[0].options.body},{});pending.shift().reject(new Error('temporarily unavailable'));await flush();await click;assert.equal(elements['engine-readiness-check'].disabled,false);assert.equal(notices.length,1);
 state.csrf=null;ui.start();pending.shift().resolve(make());await flush();assert.match(elements['engine-readiness-detail'].textContent,/登录/);assert.equal(elements['engine-readiness-check'].disabled,true);assert.equal(timers.size,0);
});
