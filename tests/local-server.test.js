import {createCloudControl} from '../src/cloud/control.js';
import { request as httpRequest } from 'node:http';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLocalServer } from '../src/local/server.js';
import { createCloudLink } from '../src/local/cloud-client.js';
import { passwordRecord, loadCredentials, verifyPassword, createSessions } from '../src/local/auth.js';
const password = 'fixture-independent-password-only';
async function fixture(t, scanResult, updates, cloudStatus, extra = {}) {
  let invoked = 0;
  const actions = [];
  const server = createLocalServer({ ...extra, credentials: passwordRecord(password), origin: 'http://127.0.0.1:8791', ...(updates ? {updates} : {}), ...(cloudStatus ? {cloudStatus} : {}), scan: async action => { invoked++; actions.push(action); return scanResult || { state: ['scan','full-scan','checkup','engine-update'].includes(action) ? 'running' : 'idle', checks: [] }; } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = 'http://127.0.0.1:' + server.address().port;
  const request = (pathname, options = {}) => new Promise((resolve, reject) => {
    const req = httpRequest(base + pathname, { method: options.method || 'GET', headers: { host: '127.0.0.1:8791', ...options.headers } }, response => {
      const chunks = []; response.on('data', chunk => chunks.push(chunk)); response.on('end', () => resolve(new Response(Buffer.concat(chunks), { status: response.statusCode, headers: response.headers })));
    }); req.on('error', reject); req.end(options.body);
  });
  const post = (pathname, value, headers = {}) => request(pathname, { method: 'POST', headers: { origin: 'http://127.0.0.1:8791', 'content-type': 'application/json', ...headers }, body: JSON.stringify(value) });
  const login = async () => { const response = await post('/api/login', { username: 'admin', password }); assert.equal(response.status, 200); return { cookie: response.headers.get('set-cookie').split(';')[0], csrf: (await response.json()).csrf }; };
  return { request, post, login, invoked: () => invoked, actions: () => [...actions] };
}
test('standalone session owns scan authorization and rejects shell/path inputs', async t => {
  const f = await fixture(t);
  assert.equal((await f.request('/api/scan')).status, 401);
  assert.equal((await f.post('/api/login', { username: 'admin', password }, { origin: 'https://untrusted.invalid' })).status, 403);
  const identity = await f.login();
  assert.equal((await f.post('/api/scan', {}, { cookie: identity.cookie })).status, 403);
  const headers = { cookie: identity.cookie, 'x-csrf-token': identity.csrf };
  assert.equal((await f.post('/api/scan', { path: '/etc/shadow', command: 'bad' }, headers)).status, 400);
  assert.equal(f.invoked(), 0);
  const started = await f.post('/api/scan', {}, headers); assert.equal(started.status, 202); assert.equal((await started.json()).state, 'running');
  assert.equal(f.invoked(), 1);
  assert.equal((await f.request('/web/admin/security/status', { headers })).status, 404);
  await f.post('/api/logout', {}, headers);
  assert.equal((await f.request('/api/scan', { headers })).status, 401);
});
test('authenticated status refresh stays read-only and never starts a scan', async t => {
  const f = await fixture(t);
  const identity = await f.login();
  const headers = { cookie: identity.cookie };
  for (let n = 0; n < 2; n++) {
    const response = await f.request('/api/scan', { headers });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).state, 'idle');
  }
  assert.deepEqual(f.actions(), ['status', 'status']);
  const started = await f.post('/api/scan', {}, { ...headers, 'x-csrf-token': identity.csrf });
  assert.equal(started.status, 202);
  assert.deepEqual(f.actions(), ['status', 'status', 'scan']);
});
test('panel has independent entry and fixed static whitelist with no APPGOG dependency', async t => {
  const f = await fixture(t);
  const response = await f.request('/'); const html = await response.text(); assert.equal(response.status, 200);
  assert.match(html, /铁幕安全/); assert.match(html, /data-security-scan/);
  assert.match(html, /data-task-progress/);
  assert.match(html, /<form id="login-form" method="post">/);
  for(const [url,type] of [['/assets/workbench.css','text/css'],['/assets/portal/engine-labels.js','text/javascript'],['/contracts/local-workbench.js','text/javascript']]){
    const asset=await f.request(url);assert.equal(asset.status,200);assert.ok(asset.headers.get('content-type').startsWith(type));
  }
  assert.doesNotMatch(html, /admin-portal|data-page-target|APPGOG DEFENDER/);
  assert.equal((await f.request('/assets/../../panel-auth.json')).status, 401);
  assert.equal((await f.request('/api/session')).status, 200);
  assert.match(response.headers.get('content-security-policy'), /frame-ancestors 'none'/);
});
test('login rate limit and host validation fail closed', async t => {
  const f = await fixture(t);
  for (let n = 0; n < 5; n++) assert.equal((await f.post('/api/login', { username: 'admin', password: 'bad' })).status, 401);
  assert.equal((await f.post('/api/login', { username: 'admin', password })).status, 429);
  assert.equal((await f.request('/healthz', { headers: { host: 'untrusted.invalid' } })).status, 421);
  assert.throws(() => createLocalServer({ origin: 'http://0.0.0.0:8791' }), /HTTPS/);
});
test('credential initialization preserves identity on restart and rejects damaged existing record', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ironcurtain-auth-'));
  try {
    const first = await loadCredentials(dir, password); const second = await loadCredentials(dir, 'some-other-valid-password');
    assert.deepEqual(second, first); assert.equal(verifyPassword(second, password), true);
    assert.equal((await readFile(join(dir, 'panel-auth.json'), 'utf8')).includes(password), false);
    assert.equal(verifyPassword(second, 'incorrect'), false);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
test('sessions expire and maximum does not evict active sessions', () => {
  let time = 0; const sessions = createSessions({ now: () => time, ttl: 10, maximum: 1 });
  const first = sessions.create(); assert.equal(sessions.create(), null); assert.ok(sessions.get(first.id)); time = 11;
  assert.equal(sessions.get(first.id), undefined); assert.ok(sessions.create());
});

test('full scan is a fixed session/CSRF action without supplied paths or commands',async t=>{
 const f=await fixture(t);assert.equal((await f.post('/api/full-scan',{})).status,401);
 const identity=await f.login();const headers={cookie:identity.cookie,'x-csrf-token':identity.csrf};
 assert.equal((await f.post('/api/full-scan',{}, {cookie:identity.cookie})).status,403);
 assert.equal((await f.post('/api/full-scan',{path:'/etc',command:'sh'},headers)).status,400);
 assert.equal(f.invoked(),0);
 const result=await f.post('/api/full-scan',{},headers);assert.equal(result.status,202);assert.equal((await result.json()).state,'running');assert.equal(f.invoked(),1);
});

test('scan endpoints preserve busy, cooldown and unavailable responses', async t => {
  const cases = [
    ['accepted', { state: 'running', response_status: 202 }, 202],
    ['existing quick scan', { state: 'running', response_status: 409 }, 202],
    ['busy with another scan', { state: 'unavailable', response_status: 409, reason: '已有扫描正在进行，请等待当前任务' }, 409],
    ['cooldown', { state: 'unavailable', response_status: 429, reason: '扫描请求过于频繁，请稍后重试' }, 429],
    ['not ready', { state: 'unavailable', response_status: 503, reason: '请先在 Linux 菜单配置扫描目录与病毒引擎' }, 503],
    ['missing agent', { state: 'unavailable', reason: '本机检查代理未接入或超时' }, 503],
    ['unexpected status', { state: 'unavailable', response_status: 500, reason: '本机检查代理返回异常' }, 503],
  ];
  for (const endpoint of ['/api/scan', '/api/full-scan', '/api/checkup', '/api/engine/update']) {
    for (const [name, result, expectedStatus] of cases) {
      await t.test(endpoint + ': ' + name, async t => {
        const f = await fixture(t, result);
        const identity = await f.login();
        const response = await f.post(endpoint, {}, { cookie: identity.cookie, 'x-csrf-token': identity.csrf });
        assert.equal(response.status, expectedStatus);
        assert.deepEqual(await response.json(), result);
        assert.equal(f.invoked(), 1);
      });
    }
  }
});

 test('program update endpoints require session, origin, CSRF and an empty body',async t=>{
  const f=await fixture(t);
  assert.equal((await f.request('/api/updates')).status,401);
  const identity=await f.login(),headers={cookie:identity.cookie,'x-csrf-token':identity.csrf};
  for(const route of ['/api/updates/check','/api/updates/install']){
   assert.equal((await f.post(route,{},{})).status,401);
   assert.equal((await f.post(route,{},{cookie:identity.cookie})).status,403);
   assert.equal((await f.post(route,{}, {...headers,origin:'https://untrusted.invalid'})).status,403);
   assert.equal((await f.post(route,{version:'99.0.0',command:'sh'},headers)).status,400);
  }
  const value=await (await f.request('/api/updates',{headers})).json();
  assert.match(value.running_version,/^\d+\.\d+\.\d+$/);
  assert.equal(value.installed_version,null);assert.equal(value.check.state,'unavailable');
 });

test('real update callbacks preserve accepted, busy, throttled and failed status without leaking commands',async t=>{
 for(const status of [202,409,429,503]){
  const actions=[],f=await fixture(t,null,async action=>{actions.push(action);return {state:status===202||status===409?'running':'unavailable',response_status:status,reason:'PRIVATE_TOKEN',command:'sh'};});
  const identity=await f.login(),headers={cookie:identity.cookie,'x-csrf-token':identity.csrf};
  for(const [route,action] of [['/api/updates/check','check'],['/api/updates/install','install']]){
   const response=await f.post(route,{},headers);assert.equal(response.status,status);
   const data=await response.json();assert.ok(data.reason);assert.doesNotMatch(JSON.stringify(data),/PRIVATE_TOKEN|command/);assert.equal(actions.at(-1),action);
  }
 }
});

test('unpaired cloud does not gate local checkup, scan or official updater', async t => {
 const dir=await mkdtemp(join(tmpdir(),'ic-unpaired-')); const cloud=createCloudLink({directory:join(dir,'identity')});
 t.after(async()=>{cloud.close();await rm(dir,{recursive:true,force:true});});
 const f=await fixture(t,undefined,undefined,()=>cloud.status()); const identity=await f.login();
 const headers={cookie:identity.cookie,'x-csrf-token':identity.csrf};
 const status=await (await f.request('/api/cloud/status',{headers})).json();
 assert.equal(status.state,'unpaired');assert.equal(status.connected,false);
 for(const route of ['/api/checkup','/api/engine/update']) {
  assert.equal((await f.post(route,{})).status,401);
  assert.equal((await f.post(route,{},{cookie:identity.cookie})).status,403);
  assert.equal((await f.post(route,{}, {...headers,origin:'https://untrusted.invalid'})).status,403);
  assert.equal((await f.post(route,{command:'sh',url:'https://untrusted.invalid'},headers)).status,400);
 }
 assert.equal(f.invoked(),0);
 for(const route of ['/api/scan','/api/full-scan','/api/checkup','/api/engine/update']) {
  const response=await f.post(route,{},headers);assert.equal(response.status,202);assert.equal((await response.json()).state,'running');
 }
 assert.equal(f.invoked(),4);assert.equal((await f.request('/api/report',{headers})).status,404);
});

test('multi engine start enforces session, Origin, CSRF and server-selected targets',async t=>{
 const calls=[];const f=await fixture(t,undefined,undefined,undefined,{multi:async action=>{calls.push(action);return {state:action==='status'?'idle':'unavailable',response_status:503};}});
 assert.equal((await f.request('/api/multi-engine')).status,401);
 const identity=await f.login();const headers={cookie:identity.cookie,'x-csrf-token':identity.csrf};
 assert.equal((await f.post('/api/multi-engine',{}, {cookie:identity.cookie})).status,403);
 assert.equal((await f.post('/api/multi-engine',{}, {...headers,origin:'https://evil.invalid'})).status,403);
 assert.equal((await f.post('/api/multi-engine',{images:['attacker/image']},headers)).status,400);
 assert.deepEqual(calls,[]);
 assert.equal((await f.request('/api/multi-engine',{headers})).status,200);assert.deepEqual(calls,['status']);
 assert.equal((await f.post('/api/multi-engine',{},headers)).status,503);assert.deepEqual(calls,['status','start']);
 const asset=await f.request('/assets/portal/multi-engine.js');assert.equal(asset.status,200);
});
test('cloud admin never launches a local Go detection job',async t=>{
 let calls=0;const f=await fixture(t,undefined,undefined,undefined,{role:'cloud',multi:async()=>{calls++;return {state:'idle'};}});
 const identity=await f.login();const headers={cookie:identity.cookie,'x-csrf-token':identity.csrf};
 assert.equal((await f.request('/api/multi-engine',{headers})).status,404);assert.equal((await f.post('/api/multi-engine',{},headers)).status,404);assert.equal(calls,0);
});

test('readiness routes require local role, session, CSRF, Origin and no custom arguments',async t=>{
 const {unavailableReadiness}=await import('../src/contracts/engine-readiness.js');const calls=[];
 const f=await fixture(t,undefined,undefined,undefined,{engines:async action=>{calls.push(action);return {...unavailableReadiness(),state:action==='check'?'checking':'unavailable',...(action==='check'?{response_status:202}:{})};}});
 assert.equal((await f.request('/api/engines')).status,401);assert.equal((await f.post('/api/engines/check',{})).status,401);
 const id=await f.login(),headers={cookie:id.cookie,'x-csrf-token':id.csrf};
 assert.equal((await f.post('/api/engines/check',{}, {cookie:id.cookie})).status,403);
 assert.equal((await f.post('/api/engines/check',{}, {...headers,origin:'https://evil.invalid'})).status,403);
 assert.equal((await f.post('/api/engines/check',{engine:'custom',command:'sh'},headers)).status,400);assert.deepEqual(calls,[]);
 assert.equal((await f.request('/api/engines',{headers})).status,200);assert.equal((await f.post('/api/engines/check',{},headers)).status,202);assert.deepEqual(calls,['status','check']);
 for(const asset of ['/contracts/engine-readiness.js','/assets/portal/engine-readiness.js'])assert.equal((await f.request(asset)).status,200);
 const cloud=await fixture(t,undefined,undefined,undefined,{role:'cloud',engines:async()=>{throw new Error('must not invoke');}});const cid=await cloud.login(),ch={cookie:cid.cookie,'x-csrf-token':cid.csrf};
 assert.equal((await cloud.request('/api/engines',{headers:ch})).status,404);assert.equal((await cloud.post('/api/engines/check',{},ch)).status,404);
});

test('cloud control requires admin session, matching Origin and CSRF, and remains absent from local role',async t=>{
  const control=createCloudControl({file:':memory:',sources:()=>({}),schedule:false});t.after(()=>control.close());
  const f=await fixture(t,undefined,undefined,()=>({nodes:{}}),{role:'cloud',control});
  assert.equal((await f.request('/api/control')).status,401);
  const identity=await f.login(),headers={cookie:identity.cookie,'x-csrf-token':identity.csrf};
  assert.equal((await f.request('/api/control',{headers})).status,200);
  const value={revision:1,malicious_threshold:4,external_hash_lookup:false};
  assert.equal((await f.post('/api/policy',value,{cookie:identity.cookie})).status,403);
  assert.equal((await f.post('/api/policy',value,{...headers,origin:'https://untrusted.invalid'})).status,403);
  assert.equal((await f.post('/api/policy',value,headers)).status,200);
  assert.equal((await f.post('/api/policy',value,headers)).status,409);
  const input={sha256:'a'.repeat(64),request_key:'11111111-1111-4111-8111-111111111111'};
  const submitted=await f.post('/api/intelligence',input,headers);assert.equal(submitted.status,202);const job=await submitted.json();
  assert.equal((await f.request('/api/intelligence/'+job.id,{headers})).status,200);
  assert.equal((await f.post('/api/plugins',{id:'remote-command',action:'install'},headers)).status,400);
  const local=await fixture(t,undefined,undefined,undefined,{control});const localIdentity=await local.login();
  const localHeaders={cookie:localIdentity.cookie,'x-csrf-token':localIdentity.csrf};
  assert.equal((await local.request('/api/control',{headers:localHeaders})).status,404);
  assert.equal((await local.post('/api/intelligence',input,localHeaders)).status,400);
  assert.equal(control.snapshot().jobs.length,1);
});


test('local cloud tasks require session, Origin and CSRF, validate hash-only bodies and keep local scanning independent',async t=>{
 const {randomUUID}=await import('node:crypto');let calls=0;const id=randomUUID(),hash='a'.repeat(64),at=new Date().toISOString();
 const job={id,sha256:hash,requester:'node/node-one',state:'queued',created_at:at,updated_at:at,attempts:0,policy:{revision:1,malicious_threshold:3,external_hash_lookup:false},providers:[],result:null};
 const f=await fixture(t,undefined,undefined,undefined,{cloudTasks:{nodeId:async()=> 'node-one',submitHash:async v=>{calls++;assert.equal(v.sha256,hash);return job;},hashJob:async value=>{calls++;assert.equal(value,id);return job;}}});
 const value={sha256:hash,request_key:randomUUID()};assert.equal((await f.post('/api/intelligence',value)).status,401);
 const login=await f.login(),headers={cookie:login.cookie,'x-csrf-token':login.csrf};
 assert.equal((await f.post('/api/intelligence',value,{cookie:login.cookie})).status,403);
 assert.equal((await f.post('/api/intelligence',value,{...headers,origin:'https://wrong.invalid'})).status,403);
 assert.equal((await f.post('/api/intelligence',{...value,command:'id'},headers)).status,400);
 assert.equal((await f.post('/api/intelligence',{...value,sha256:[hash]},headers)).status,400);assert.equal(calls,0);
 assert.equal((await f.post('/api/intelligence',value,headers)).status,202);
 assert.equal((await f.request('/api/intelligence/'+id,{headers})).status,200);assert.equal(calls,2);
 for(const url of ['/assets/portal/cloud-intelligence.js','/contracts/hash-intelligence.js'])assert.equal((await f.request(url)).status,200);
 await f.post('/api/logout',{},headers);assert.equal((await f.request('/api/intelligence/'+id,{headers})).status,401);
});
test('cloud authentication rejection is not a local logout; local scan survives an unpaired or malformed cloud',async t=>{
 const {randomUUID}=await import('node:crypto');const value={sha256:'a'.repeat(64),request_key:randomUUID()};
 const f=await fixture(t,undefined,undefined,undefined,{cloudTasks:{nodeId:async()=> 'node-one',submitHash:async()=>{throw Object.assign(Error('CLOUD_AUTH_REJECTED'),{status:503});},hashJob:async()=>({state:'safe',command:'bad'})}});
 const login=await f.login(),headers={cookie:login.cookie,'x-csrf-token':login.csrf};
 assert.equal((await f.post('/api/intelligence',value,headers)).status,503);
 assert.equal((await f.request('/api/session',{headers})).status,200);
 assert.equal((await f.request('/api/intelligence/'+randomUUID(),{headers})).status,503);
 assert.equal((await f.post('/api/scan',{},headers)).status,202);
});


test('hash API boundaries reject foreign nodes and strip storage-only fields',async t=>{
 const {randomUUID}=await import('node:crypto');const id=randomUUID(),at=new Date().toISOString(),sha256='a'.repeat(64);
 let job={id,sha256,requester:'node/node-two',state:'queued',created_at:at,updated_at:at,attempts:0,policy:{revision:1,malicious_threshold:3,external_hash_lookup:false},providers:[],result:null,command:'never expose'};
 const local=await fixture(t,undefined,undefined,undefined,{cloudTasks:{nodeId:async()=> 'node-one',submitHash:async()=>job,hashJob:async()=>job}});
 const auth=await local.login(),headers={cookie:auth.cookie,'x-csrf-token':auth.csrf};
 assert.equal((await local.post('/api/intelligence',{sha256,request_key:randomUUID()},headers)).status,503);
 assert.equal((await local.request('/api/intelligence/'+id,{headers})).status,503);
 job={...job,requester:'node/node-one'};
 const valid=await local.request('/api/intelligence/'+id,{headers});assert.equal(valid.status,200);assert.equal((await valid.json()).command,undefined);
 let enqueueCalls=0;const control={enqueue:()=>{enqueueCalls++;return {...job,requester:'admin'};},job:()=>job};
 const cloud=await fixture(t,undefined,undefined,undefined,{role:'cloud',control});const ca=await cloud.login(),ch={cookie:ca.cookie,'x-csrf-token':ca.csrf};
 for(const input of [{sha256,request_key:randomUUID(),path:'/etc/shadow'},{sha256:'bad',request_key:randomUUID()},{sha256,request_key:'bad'}])assert.equal((await cloud.post('/api/intelligence',input,ch)).status,400);
 assert.equal(enqueueCalls,0);
 const submitted=await cloud.post('/api/intelligence',{sha256,request_key:randomUUID()},ch);assert.equal(submitted.status,202);assert.equal((await submitted.json()).command,undefined);
 const fetched=await cloud.request('/api/intelligence/'+id,{headers:ch});assert.equal(fetched.status,200);assert.equal((await fetched.json()).command,undefined);
 job={...job,result:{verdict:'safe'}};assert.equal((await cloud.request('/api/intelligence/'+id,{headers:ch})).status,503);
});

function scheduleFixture(revision=1) {
  return {schema:'ironcurtain-schedule/v1',state:'ready',response_status:200,config:{revision,jobs:{quick:{enabled:true,interval_seconds:300},files:{enabled:false,interval_seconds:86400},engines:{enabled:false,interval_seconds:21600}}},records:Object.fromEntries(['quick','files','engines'].map(id=>[id,{state:'idle',task_id:null,attempts:0,next_at:id==='quick'?'2026-10-07T12:00:00Z':null,last_attempt_at:null,last_started_at:null,last_finished_at:null}]))};
}
test('schedule API requires login, same Origin and CSRF, reads are side-effect free, logout revokes access',async t=>{
  const actions=[],f=await fixture(t,null,null,null,{schedule:async(action,config)=>{actions.push({action,config});return scheduleFixture(action==='save'?2:1);}});
  assert.equal((await f.request('/api/schedule')).status,401);assert.deepEqual(actions,[]);
  const identity=await f.login(),headers={cookie:identity.cookie,'x-csrf-token':identity.csrf},config=scheduleFixture().config;
  assert.equal((await f.request('/api/schedule',{headers})).status,200);assert.deepEqual(actions.map(x=>x.action),['status']);
  assert.equal((await f.post('/api/schedule',config,{cookie:identity.cookie})).status,403);
  assert.equal((await f.post('/api/schedule',config,{...headers,origin:'https://untrusted.invalid'})).status,403);
  assert.equal((await f.post('/api/schedule',{...config,command:'shell'},headers)).status,400);assert.equal(actions.length,1);
  const save=await f.post('/api/schedule',config,headers);assert.equal(save.status,200);assert.equal((await save.json()).config.revision,2);assert.deepEqual(actions[1],{action:'save',config});
  await f.post('/api/logout',{},headers);assert.equal((await f.request('/api/schedule',{headers})).status,401);assert.equal((await f.post('/api/schedule',config,headers)).status,401);assert.equal(actions.length,2);
});
test('cloud role never exposes host schedule controls',async t=>{
  let calls=0;const f=await fixture(t,null,null,null,{role:'cloud',schedule:async()=>{calls++;return scheduleFixture();}}),identity=await f.login(),headers={cookie:identity.cookie,'x-csrf-token':identity.csrf};
  assert.equal((await f.request('/api/schedule',{headers})).status,404);assert.equal((await f.post('/api/schedule',{},headers)).status,404);assert.equal(calls,0);
});
test('schedule API rejects malformed host success and retains revision conflict',async t=>{
  let broken=true;const f=await fixture(t,null,null,null,{schedule:async()=>broken?{...scheduleFixture(),records:{}}:{state:'unavailable',response_status:409}}),identity=await f.login(),headers={cookie:identity.cookie,'x-csrf-token':identity.csrf};
  assert.equal((await f.request('/api/schedule',{headers})).status,503);assert.equal((await f.post('/api/schedule',scheduleFixture().config,headers)).status,503);
  broken=false;assert.equal((await f.post('/api/schedule',scheduleFixture().config,headers)).status,409);
});

test('cloud signed web updates enforce authentication and never accept installer arguments',async t=>{
 const calls=[],f=await fixture(t,undefined,async action=>{calls.push(action);return action==='status'?{schema:'ironcurtain-update-status/v1',installed_version:'0.6.6',check:{state:'unavailable'},job:{state:'idle'}}:{state:'running',response_status:202};},undefined,{role:'cloud'});
 assert.equal((await f.request('/api/updates')).status,401);
 const id=await f.login(),headers={cookie:id.cookie,'x-csrf-token':id.csrf};
 for(const route of ['/api/updates/check','/api/updates/install']){
  assert.equal((await f.post(route,{})).status,401);
  assert.equal((await f.post(route,{},{cookie:id.cookie})).status,403);
  assert.equal((await f.post(route,{},{...headers,origin:'https://untrusted.invalid'})).status,403);
  assert.equal((await f.post(route,{version:'99.0.0',role:'local',command:'sh'},headers)).status,400);
 }
 assert.deepEqual(calls,[]);
 const status=await(await f.request('/api/updates',{headers})).json();assert.equal(status.installed_version,'0.6.6');assert.equal(status.check.state,'unavailable');
 for(const route of ['/api/updates/check','/api/updates/install'])assert.equal((await f.post(route,{},headers)).status,202);
 assert.deepEqual(calls,['status','check','install']);assert.equal(f.invoked(),0);
});


test('active host detection has an actionable update conflict without claiming an update started',async t=>{
 const f=await fixture(t,undefined,async()=>({state:'unavailable',response_status:409,conflict:'management-active',reason:'secret',command:'secret'}));
 const identity=await f.login(),headers={cookie:identity.cookie,'x-csrf-token':identity.csrf};
 const response=await f.post('/api/updates/install',{},headers);
 assert.equal(response.status,409);
 assert.deepEqual(await response.json(),{state:'unavailable',reason:'本机检测或管理任务正在运行，程序更新尚未启动。请等待当前任务结束后重试。'});
});


test('local operations requires session, origin, CSRF and fixed evidence-bound fields',async t=>{
 const {operationStatus,operationJob,revision}=await import('./fixtures/operations.js');
 const calls=[];const f=await fixture(t,null,null,null,{operations:async(action,value)=>{calls.push({action,value});return action==='status'?operationStatus():{schema:'ironcurtain-operations/v1',state:'running',job:operationJob(),response_status:202};}});
 assert.equal((await f.request('/api/operations')).status,401);
 const identity=await f.login(),headers={cookie:identity.cookie,'x-csrf-token':identity.csrf};
 const input={action:'ports',revision,tcp:[443,22],udp:[]};
 assert.equal((await f.post('/api/operations',input,{cookie:identity.cookie})).status,403);
 assert.equal((await f.post('/api/operations',input,{...headers,origin:'https://invalid.example'})).status,403);
 assert.equal((await f.post('/api/operations',{...input,command:'sh'},headers)).status,400);
 assert.equal((await f.post('/api/operations',{action:'quarantine',id:revision,confirm:'yes'},headers)).status,400);
 assert.equal(calls.length,0);
 assert.equal((await f.request('/api/operations',{headers})).status,200);
 assert.equal((await f.post('/api/operations',input,headers)).status,202);
 assert.deepEqual(calls,[{action:'status',value:undefined},{action:'apply',value:{...input,tcp:[22,443]}}]);
 await f.post('/api/logout',{},headers);
 assert.equal((await f.post('/api/operations',input,headers)).status,401);assert.equal(calls.length,2);
});
test('cloud panel cannot access the local operations controller',async t=>{
 const f=await fixture(t,null,null,null,{role:'cloud',operations:async()=>assert.fail('cloud must not call local controller')});
 const identity=await f.login(),headers={cookie:identity.cookie,'x-csrf-token':identity.csrf};
 assert.equal((await f.request('/api/operations',{headers})).status,404);
 assert.equal((await f.post('/api/operations',{},headers)).status,404);
});
test('operations rejects malformed status and an acknowledgement for a different action',async t=>{
 const {operationJob,revision}=await import('./fixtures/operations.js');
 const f=await fixture(t,null,null,null,{operations:async action=>action==='status'?{state:'ready'}:{schema:'ironcurtain-operations/v1',state:'running',job:{...operationJob(),action:'restore'},response_status:202}});
 const identity=await f.login(),headers={cookie:identity.cookie,'x-csrf-token':identity.csrf};
 assert.equal((await f.request('/api/operations',{headers})).status,503);
 const res=await f.post('/api/operations',{action:'ports',revision,tcp:[],udp:[]},headers);
 assert.equal(res.status,503);assert.ok((await res.json()).error);
});
