import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';import {join} from 'node:path';import vm from 'node:vm';
import {sanitizeEngineMaintenance,unavailableMaintenance,ENGINE_MAINTENANCE_SCHEMA} from '../src/contracts/engine-maintenance.js';
import {localEngineMaintenance} from '../src/local/engine-maintenance-client.js';
const make=(state='queued',code='queued')=>({schema:ENGINE_MAINTENANCE_SCHEMA,state,code,id:'a'.repeat(32),requested_at:new Date().toISOString(),reason:'untrusted raw log'});
test('maintenance contract rejects fabricated success and strips raw logs',()=>{
 const v=make();assert.equal(sanitizeEngineMaintenance(v).state,'queued');assert.doesNotMatch(sanitizeEngineMaintenance(v).reason,/raw log/);
 for(const bad of [{...v,id:'evil'},{...v,state:'finished',code:'finished'},{...v,requested_at:'invalid'},{...v,schema:'other'},{...v,code:'shell'}])assert.equal(sanitizeEngineMaintenance(bad).state,'unavailable');
 const finished={...make('finished','finished'),finished_at:new Date().toISOString(),command:'curl evil',token:'secret'};assert.equal(sanitizeEngineMaintenance(finished).state,'finished');assert.equal(sanitizeEngineMaintenance(finished).token,undefined);
});
test('maintenance Unix client uses only a fixed bodyless operation',{skip:process.platform==='win32'},async t=>{
 const dir=await mkdtemp(join(tmpdir(),'ic-engine-'));t.after(()=>rm(dir,{recursive:true,force:true}));const path=join(dir,'scan.sock');let status=202,value=make();let seen=[];
 const server=createServer((req,res)=>{seen.push([req.method,req.url,req.headers['content-length']]);res.writeHead(status,{'content-type':'application/json'});res.end(typeof value==='string'?value:JSON.stringify(value));});await new Promise(r=>server.listen(path,r));t.after(()=>new Promise(r=>server.close(r)));const env={IRONCURTAIN_SCAN_SOCKET:path};
 assert.equal((await localEngineMaintenance('install',env)).response_status,202);assert.deepEqual(seen[0],['POST','/engine-maintenance','0']);
 status=200;assert.equal((await localEngineMaintenance('status',env)).state,'queued');assert.deepEqual(seen[1],['GET','/engine-maintenance',undefined]);
 status=202;value={...make('finished','finished'),finished_at:new Date().toISOString()};assert.equal((await localEngineMaintenance('install',env)).response_status,503);
 value='x'.repeat(5000);assert.equal((await localEngineMaintenance('install',env)).response_status,503);assert.throws(()=>localEngineMaintenance('shell',env),TypeError);
});
test('maintenance UI recovers failed submission and ignores responses after logout',async()=>{
 class E{constructor(){this.handlers={};this.textContent='';this.disabled=false;}addEventListener(k,f){this.handlers[k]=f;}}
 const elements=Object.fromEntries(['state','detail','install'].map(x=>['engine-maintenance-'+x,new E()]));let tid=0;const timers=new Map(),state={csrf:'first'},pending=[],notices=[];let finished=0;
 let src=await readFile(new URL('../src/local/public/assets/portal/engine-maintenance.js',import.meta.url),'utf8');src=src.replace(/^import[^\n]+\n/gm,'').replace('export function','function');
 // Source imports are line based; retain no module syntax in the VM fixture.
 src=src.split('\n').filter(x=>!x.startsWith('import ')).join('\n');
 const ctx=vm.createContext({sanitizeEngineMaintenance,unavailableMaintenance,document:{getElementById:id=>elements[id]},setTimeout:f=>{timers.set(++tid,f);return tid;},clearTimeout:id=>timers.delete(id),Date});vm.runInContext(src,ctx);
 const ui=ctx.createEngineMaintenance({state,request:(path,options)=>new Promise((resolve,reject)=>pending.push({path,options,resolve,reject})),notify:(...x)=>notices.push(x),onFinished:()=>finished++});ui.bind();ui.start();const flush=async()=>{for(let i=0;i<5;i++)await Promise.resolve();};
 pending.shift().resolve({schema:ENGINE_MAINTENANCE_SCHEMA,state:'idle',code:'idle'});await flush();assert.equal(elements['engine-maintenance-install'].disabled,false);
 const click=elements['engine-maintenance-install'].handlers.click();assert.equal(elements['engine-maintenance-install'].disabled,true);assert.equal(pending[0].path,'/api/engines/install');assert.deepEqual({...pending[0].options.body},{});pending.shift().reject(Error('busy'));await click;assert.equal(notices.length,1);assert.equal(elements['engine-maintenance-install'].disabled,false);
 state.csrf=null;ui.start();pending.shift().resolve({...make('finished','finished'),finished_at:new Date().toISOString()});await flush();assert.equal(finished,0);assert.equal(elements['engine-maintenance-install'].disabled,true);assert.equal(timers.size,0);
});
