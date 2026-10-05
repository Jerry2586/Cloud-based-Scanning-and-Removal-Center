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
async function fixture(t, scanResult, updates, cloudStatus) {
  let invoked = 0;
  const server = createLocalServer({ credentials: passwordRecord(password), origin: 'http://127.0.0.1:8791', ...(updates ? {updates} : {}), ...(cloudStatus ? {cloudStatus} : {}), scan: async action => { invoked++; return scanResult || { state: ['scan','full-scan','checkup','engine-update'].includes(action) ? 'running' : 'idle', checks: [] }; } });
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
  return { request, post, login, invoked: () => invoked };
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
test('panel has independent entry and fixed static whitelist with no APPGOG dependency', async t => {
  const f = await fixture(t);
  const response = await f.request('/'); const html = await response.text(); assert.equal(response.status, 200);
  assert.match(html, /铁幕安全/); assert.match(html, /data-security-scan/);
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
 const dir=await mkdtemp(join(tmpdir(),'ic-unpaired-')); const cloud=createCloudLink({directory:dir});
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
