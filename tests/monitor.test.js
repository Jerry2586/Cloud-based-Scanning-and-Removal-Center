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

test('cloud records missing, stale and resumed node reports once per transition', async () => {
  let time = Date.now();
  const monitor = createMonitor({ nodes: { 'license-center': node }, readers: [reader], now: () => time,
    probe: async () => ({ state: 'healthy' }) });
  await monitor.runProbes();
  await monitor.runProbes();
  assert.equal(monitor.status().events.filter(event => event.kind === 'report.stale').length, 1);
  const report = () => call(monitor, { url: '/v1/report', method: 'POST', credential: node,
    body: JSON.stringify({ files: { 'app.js': 'a'.repeat(64) } }) });
  assert.equal((await report()).status, 200);
  assert.equal(monitor.status().events.filter(event => event.kind === 'report.resumed').length, 1);
  time += 121000;
  await monitor.runProbes();
  await monitor.runProbes();
  assert.equal(monitor.status().nodes['license-center'].report_fresh, false);
  assert.equal(monitor.status().events.filter(event => event.kind === 'report.stale').length, 2);
  assert.equal((await report()).status, 200);
  assert.equal(monitor.status().events.filter(event => event.kind === 'report.resumed').length, 2);
  assert.equal(monitor.status().nodes['license-center'].report_fresh, true);
});

test('host self-report rejects malformed evidence, signals transitions and expires independently of new reports', async () => {
  let time = Date.now();
  const monitor = createMonitor({ nodes: { 'license-center': node }, readers: [reader], now: () => time,
    probe: async () => ({ state: 'healthy' }) });
  const submit = host_scan => call(monitor, { url: '/v1/report', method: 'POST', credential: node,
    body: JSON.stringify({ files: { 'app.js': 'a'.repeat(64) }, host_scan }) });
  const counts = { ok: 6, warning: 0, finding: 0, unavailable: 0 };
  assert.equal((await submit({ state: 'ok', checked_at: 'bad', counts })).status, 400);
  assert.equal((await submit({ state: 'ok', checked_at: new Date(time + 120000).toISOString(), counts })).status, 400);
  assert.equal((await submit({ state: 'ok', checked_at: new Date(time).toISOString(), counts: { ...counts, finding: -1 } })).status, 400);
  assert.equal(monitor.status().nodes['license-center'].integrity.state, 'unknown');
  assert.equal((await submit({ state: 'ok', checked_at: new Date(time).toISOString(), counts })).status, 200);
  assert.equal(monitor.status().nodes['license-center'].host_scan.state, 'ok');
  assert.equal(monitor.status().nodes['license-center'].host_scan.source, 'node-self-report');
  assert.equal((await submit({ state: 'finding', checked_at: new Date(time).toISOString(), counts: { ...counts, ok: 5, finding: 1 } })).status, 200);
  assert.equal((await submit({ state: 'finding', checked_at: new Date(time).toISOString(), counts: { ...counts, ok: 5, finding: 1 } })).status, 200);
  assert.equal(monitor.status().events.filter(event => event.kind === 'host.finding').length, 1);
  time += 901000;
  // A freshly authenticated report cannot turn an old host scan into fresh evidence.
  assert.equal((await submit({ state: 'finding', checked_at: new Date(time - 901000).toISOString(), counts: { ...counts, ok: 5, finding: 1 } })).status, 200);
  assert.equal(monitor.status().nodes['license-center'].host_scan.state, 'stale');
  await monitor.runProbes();
  assert.equal(monitor.status().events.filter(event => event.kind === 'host.stale').length, 1);
  assert.equal((await submit({ state: 'ok', checked_at: new Date(time).toISOString(), counts })).status, 200);
  assert.equal(monitor.status().nodes['license-center'].host_scan.state, 'ok');
  assert.equal(monitor.status().events.filter(event => event.kind === 'host.resumed').length, 1);
});
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test('existing persisted state upgrades without host fields or trusted host result', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'cloud-state-'));
  try {
    const stateFile = join(dir, 'state.json');
    writeFileSync(stateFile, JSON.stringify({ probes: {}, reports: {}, reportFreshness: {}, events: [] }));
    const monitor = createMonitor({ nodes: { 'license-center': node }, readers: [reader], stateFile,
      probe: async () => ({ state: 'healthy' }) });
    assert.equal(monitor.status().nodes['license-center'].host_scan.state, 'unavailable');
    await monitor.runProbes();
    assert.equal((await call(monitor, { url: '/v1/report', method: 'POST', credential: node,
      body: JSON.stringify({ files: { 'app.js': 'a'.repeat(64) } }) })).status, 200);
    assert.equal(monitor.status().nodes['license-center'].host_scan.state, 'unavailable');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
