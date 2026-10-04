import { request as httpRequest } from 'node:http';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createLocalServer } from '../src/local/server.js';
import { passwordRecord, loadCredentials, verifyPassword, createSessions } from '../src/local/auth.js';
const password = 'fixture-independent-password-only';
async function fixture(t) {
  let invoked = 0;
  const server = createLocalServer({ credentials: passwordRecord(password), origin: 'http://127.0.0.1:8791', scan: async action => { invoked++; return { state: action === 'scan' ? 'running' : 'idle', checks: [] }; } });
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
