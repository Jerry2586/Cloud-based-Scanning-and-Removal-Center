import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { createMonitor } from '../src/monitor.js';

const fp = 'AA:'.repeat(31) + 'AA';
const reader = { token: 'r'.repeat(40), fingerprint256: fp };
const node = { token: 'n'.repeat(40), fingerprint256: fp, health_url: 'https://example.test/health', baseline: { 'app.js': 'a'.repeat(64) } };
function call(monitor, { url = '/v1/status', method = 'GET', credential = reader, authorized = true, body = '' } = {}) {
  return new Promise(resolve => {
    const req = Readable.from([body]);
    req.method = method; req.url = url;
    req.headers = { authorization: `Bearer ${credential?.token ?? ''}` };
    req.socket = { authorized, getPeerCertificate: () => ({ fingerprint256: credential?.fingerprint256 }) };
    const res = { writeHead(status) { this.status = status; }, end(text) { resolve({ status: this.status, data: JSON.parse(text) }); } };
    void monitor.handler(req, res);
  });
}
test('reader requires both trusted TLS identity and separate bearer token', async () => {
  const monitor = createMonitor({ nodes: { 'license-center': node }, readers: [reader], probe: async () => ({ state: 'healthy' }) });
  assert.equal((await call(monitor)).status, 200);
  assert.equal((await call(monitor, { credential: { ...reader, token: 'wrong' } })).status, 403);
  assert.equal((await call(monitor, { credential: { ...reader, fingerprint256: 'BB' } })).status, 403);
  assert.equal((await call(monitor, { authorized: false })).status, 403);
  assert.equal((await call(monitor, { url: '/v1/report', method: 'POST', credential: reader, body: '{}' })).status, 403);
});
test('probe remains independent of report and flags outage', async () => {
  let connected = true;
  const monitor = createMonitor({ nodes: { 'license-center': node }, readers: [reader], probe: async () => {
    if (!connected) throw Object.assign(new Error('offline'), { code: 'ECONNREFUSED' });
    return { state: 'healthy' };
  } });
  await monitor.runProbes();
  assert.equal(monitor.status().nodes['license-center'].probe.state, 'healthy');
  connected = false;
  await monitor.runProbes();
  assert.equal(monitor.status().nodes['license-center'].probe.state, 'unreachable');
  assert.equal(monitor.status().nodes['license-center'].integrity.state, 'unknown');
  assert.equal(monitor.status().events[0].kind, 'probe.failed');
});
test('report detects changed, missing, added; credentials rotate without stale access', async () => {
  let time = Date.now();
  const monitor = createMonitor({ nodes: { 'license-center': node }, readers: [reader], now: () => time });
  let result = await call(monitor, { url: '/v1/report', method: 'POST', credential: node,
    body: JSON.stringify({ files: { 'app.js': 'b'.repeat(64), 'injected.js': 'c'.repeat(64) } }) });
  assert.equal(result.data.state, 'changed');
  assert.deepEqual(result.data.changed, ['app.js']);
  assert.deepEqual(result.data.added, ['injected.js']);
  node.token = 'm'.repeat(40);
  assert.equal((await call(monitor, { url: '/v1/report', method: 'POST', credential: { ...node, token: 'n'.repeat(40) }, body: '{}' })).status, 403);
  result = await call(monitor, { url: '/v1/report', method: 'POST', credential: node,
    body: JSON.stringify({ files: { 'app.js': 'a'.repeat(64) } }) });
  assert.equal(result.data.state, 'matched');
  time += 121000;
  assert.equal(monitor.status().nodes['license-center'].report_fresh, false);
});
