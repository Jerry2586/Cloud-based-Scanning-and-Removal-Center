import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {mkdtemp, rm, readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {SCHEDULE_IDS, validateScheduleConfig, sanitizeSchedule} from '../src/contracts/schedule.js';
import {localSchedule} from '../src/local/schedule-client.js';
const at='2026-10-07T12:00:00Z';
function ready(revision=1) {
  return {schema:'ironcurtain-schedule/v1',state:'ready',config:{revision,jobs:{quick:{enabled:true,interval_seconds:300},files:{enabled:false,interval_seconds:86400},engines:{enabled:false,interval_seconds:21600}}},records:Object.fromEntries(SCHEDULE_IDS.map(id=>[id,{state:'idle',task_id:null,attempts:0,next_at:id==='quick'?at:null,last_attempt_at:null,last_started_at:null,last_finished_at:null}]))};
}
test('strict schedule contract admits task-bound states and rejects invented completion',()=>{
  assert.deepEqual(sanitizeSchedule(ready()),ready());
  for (const state of ['dispatching','running','complete','partial','failed','unavailable','deferred','interrupted']) {
    const value=ready(), task=['running','complete','partial','failed'].includes(state);
    Object.assign(value.records.quick,{state,attempts:1,last_attempt_at:at,last_started_at:task?at:null,task_id:task?'a'.repeat(32):null,last_finished_at:['dispatching','running'].includes(state)?null:at,next_at:['dispatching','running'].includes(state)?null:at});
    assert.equal(sanitizeSchedule(value).state,'ready',state);
  }
  for (const mutate of [v=>v.command='shell',v=>v.records.quick.state='running',v=>v.records.quick.attempts=1,v=>v.records.quick.last_attempt_at=at,v=>v.records.quick.next_at='2026-02-30T12:00:00Z',v=>v.records.quick.next_at='2026-10-07T12:00:00.000Z',v=>v.records.files.next_at=at]) {
    const value=ready();mutate(value);assert.equal(sanitizeSchedule(value).state,'unavailable');
  }
  const terminal=ready();Object.assign(terminal.records.quick,{state:'complete',attempts:1,last_attempt_at:at,last_finished_at:at});assert.equal(sanitizeSchedule(terminal).state,'unavailable');
  terminal.records.quick.task_id='a'.repeat(32);terminal.records.quick.last_started_at=at;assert.equal(sanitizeSchedule(terminal).state,'ready');
  terminal.records.quick.last_finished_at='2026-10-06T12:00:00Z';assert.equal(sanitizeSchedule(terminal).state,'unavailable');
});
test('schedule config is exact, bounded and independent from its input',()=>{
  const value=ready().config,clean=validateScheduleConfig(value);value.jobs.quick.enabled=false;assert.equal(clean.jobs.quick.enabled,true);
  for (const change of [v=>v.revision=true,v=>v.revision=0,v=>v.jobs.quick.enabled=1,v=>v.jobs.quick.interval_seconds=299,v=>v.jobs.files.interval_seconds=604801,v=>v.jobs.engines.command='bad']) {
    const v=ready().config;change(v);assert.throws(()=>validateScheduleConfig(v),TypeError);
  }
});
async function unixFixture(t, handler) {
  const dir=await mkdtemp(join(tmpdir(),'ironcurtain-schedule-'));
  const socket=process.platform==='win32'?'\\\\.\\pipe\\ironcurtain-schedule-'+crypto.randomUUID():join(dir,'agent.sock');
  const server=http.createServer(handler);await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(socket,resolve);});
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));await rm(dir,{recursive:true,force:true});});
  return {IRONCURTAIN_SCAN_SOCKET:socket};
}
test('Unix client validates real responses and saves exact fixed config',async t=>{
  const env=await unixFixture(t,(req,res)=>{assert.equal(req.url,'/schedule');if(req.method==='POST'){assert.equal(req.headers['content-type'],'application/json');let body='';req.on('data',c=>body+=c);req.on('end',()=>{assert.deepEqual(JSON.parse(body),ready().config);res.end(JSON.stringify(ready(2)));});}else res.end(JSON.stringify(ready()));});
  assert.equal((await localSchedule('status',null,env)).response_status,200);
  assert.equal((await localSchedule('save',ready().config,env)).config.revision,2);
  assert.throws(()=>localSchedule('execute',null,env),TypeError);
});
for(const mode of ['oversize','truncated','invalid','conflict']) test('Unix client fails closed: '+mode,async t=>{
  const env=await unixFixture(t,(_req,res)=>{if(mode==='oversize')res.end('x'.repeat(16385));else if(mode==='truncated'){res.writeHead(200,{'Content-Length':2000});res.end('{');}else if(mode==='conflict'){res.statusCode=409;res.end('{"state":"unavailable"}');}else res.end(JSON.stringify({...ready(),command:'bad'}));});
  const result=await localSchedule(mode==='conflict'?'save':'status',ready().config,env);assert.equal(result.state,'unavailable');assert.equal(result.response_status,mode==='conflict'?409:503);
});
test('Unix client enforces an absolute deadline despite continuing response bytes',async t=>{
  const env=await unixFixture(t,(_req,res)=>{res.writeHead(200);res.write('{');const pulse=setInterval(()=>res.write(' '),100);res.once('close',()=>clearInterval(pulse));});
  const before=performance.now(),result=await localSchedule('status',null,env),elapsed=performance.now()-before;
  assert.equal(result.response_status,503);assert.match(result.reason,/超时/);assert.ok(elapsed>=4500&&elapsed<6500,String(elapsed));
});
function element(){return {disabled:false,checked:false,value:'',textContent:'',listeners:{},addEventListener(name,fn){this.listeners[name]=fn;}};}
async function uiFixture(t) {
  const controls=new Map(), form=element(), events={};
  for(const selector of ['[data-schedule-state]','[data-schedule-save]','[data-schedule-refresh]'])controls.set(selector,element());
  for(const id of SCHEDULE_IDS)for(const kind of ['enabled','interval','record'])controls.set('[data-schedule-'+kind+'="'+id+'"]',element());
  const panel={querySelector(selector){return selector==='form'?form:controls.get(selector);}};
  const previous=globalThis.document;globalThis.document={querySelector(){return panel;},addEventListener(name,fn){events[name]=fn;}};
  const text=(await readFile(new URL('../src/local/public/assets/portal/schedule-settings.js',import.meta.url),'utf8')).replace("'/contracts/schedule.js'",JSON.stringify(new URL('../src/contracts/schedule.js',import.meta.url).href));
  const {createScheduleSettings}=await import('data:text/javascript;base64,'+Buffer.from(text).toString('base64'));
  const calls=[],notes=[],state={csrf:'session-a'},request=(url,options)=>new Promise((resolve,reject)=>calls.push({url,options,resolve,reject}));
  const ui=createScheduleSettings({state,request,notify:(...args)=>notes.push(args)});ui.bind();ui.start();
  t.after(()=>{state.csrf=null;events['ironcurtain-session-cleared']();globalThis.document=previous;});
  const flush=()=>new Promise(resolve=>setImmediate(resolve));
  return {ui,state,calls,notes,controls,form,events,flush};
}
test('setting refresh from an old login cannot overwrite a newer session or unlock its pending form',async t=>{
  const f=await uiFixture(t);assert.equal(f.calls.length,1);
  f.state.csrf='session-b';f.events['ironcurtain-session-cleared']();assert.equal(f.calls.length,2);
  f.calls[0].resolve(ready(99));await f.flush();assert.equal(f.controls.get('[data-schedule-save]').disabled,true);
  f.calls[1].resolve(ready(2));await f.flush();assert.match(f.controls.get('[data-schedule-state]').textContent,/版本 2/);
  assert.doesNotMatch(f.controls.get('[data-schedule-state]').textContent,/99/);assert.equal(f.controls.get('[data-schedule-save]').disabled,false);
});
test('old save completion cannot claim success or clear a new pending refresh',async t=>{
  const f=await uiFixture(t);f.calls[0].resolve(ready());await f.flush();
  const pendingSave=f.form.listeners.submit({preventDefault(){}});assert.equal(f.calls[1].options.method,'POST');
  f.state.csrf='session-b';f.events['ironcurtain-session-cleared']();assert.equal(f.calls.length,3);
  f.calls[1].resolve(ready(99));await pendingSave;assert.deepEqual(f.notes,[]);assert.equal(f.controls.get('[data-schedule-save]').disabled,true);
  f.calls[2].resolve(ready(3));await f.flush();assert.match(f.controls.get('[data-schedule-state]').textContent,/版本 3/);
});
test('running tasks disable edits and programmatic submit also refuses a save',async t=>{
  const f=await uiFixture(t),v=ready();Object.assign(v.records.quick,{state:'running',attempts:1,task_id:'a'.repeat(32),last_attempt_at:at,last_started_at:at,next_at:null});
  f.calls[0].resolve(v);await f.flush();assert.equal(f.controls.get('[data-schedule-save]').disabled,true);
  await f.form.listeners.submit({preventDefault(){}});assert.equal(f.calls.length,1);
  for(const id of SCHEDULE_IDS)assert.equal(f.controls.get('[data-schedule-enabled="'+id+'"]').disabled,true);
});
