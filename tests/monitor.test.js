import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { createMonitor, validateConfiguration } from '../src/monitor.js';

const fp = 'AA:'.repeat(31) + 'AA';
const reader = { token: 'r'.repeat(40), fingerprint256: fp };
const node = { token: 'n'.repeat(40), fingerprint256: fp, health_url: 'https://example.test/health', baseline: { 'app.js': 'a'.repeat(64) } };
function callRaw(monitor, { url = '/v1/status', method = 'GET', credential = reader, authorized = true, body = '', authorization } = {}) {
  return new Promise(resolve => {
    const req = Readable.from([body]);
    req.method = method; req.url = url;
    req.headers = { authorization: authorization ?? `Bearer ${credential?.token ?? ''}` };
    req.socket = { authorized, getPeerCertificate: () => ({ fingerprint256: credential?.fingerprint256 }) };
    const res = {
      writeHead(status, headers = {}) { this.status = status; this.headers = headers; },
      end(text = '') { resolve({ status: this.status, headers: this.headers ?? {}, text }); },
    };
    void monitor.handler(req, res);
  });
}
async function call(monitor, options) {
  const result = await callRaw(monitor, options);
  return { ...result, data: JSON.parse(result.text) };
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
  const rotatingNode = { ...node };
  const monitor = createMonitor({ nodes: { 'license-center': rotatingNode }, readers: [reader], now: () => time });
  let result = await call(monitor, { url: '/v1/report', method: 'POST', credential: rotatingNode,
    body: JSON.stringify({ files: { 'app.js': 'b'.repeat(64), 'injected.js': 'c'.repeat(64) } }) });
  assert.equal(result.data.state, 'changed');
  assert.deepEqual(result.data.changed, ['app.js']);
  assert.deepEqual(result.data.added, ['injected.js']);
  assert.deepEqual(monitor.status().events.find(event => event.kind === 'integrity.changed').details,
    { missing: 0, changed: 1, added: 1 });
  rotatingNode.token = 'm'.repeat(40);
  assert.equal((await call(monitor, { url: '/v1/report', method: 'POST', credential: { ...rotatingNode, token: 'n'.repeat(40) }, body: '{}' })).status, 403);
  result = await call(monitor, { url: '/v1/report', method: 'POST', credential: rotatingNode,
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

test('persisted state rejects malformed field shapes and ignores unrecognized fields', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cloud-state-invalid-'));
  try {
    const stateFile = join(dir, 'state.json');
    for (const invalid of [null, [], { reports: [] }, { events: {} }, { hostReportState: 'unsafe' }]) {
      writeFileSync(stateFile, JSON.stringify(invalid));
      assert.throws(() => createMonitor({ nodes: { 'license-center': node }, readers: [reader], stateFile }),
        /Invalid persisted security state/);
    }
    writeFileSync(stateFile, JSON.stringify({ probes: {}, reports: {}, reportFreshness: {}, events: [],
      hostReports: {}, hostReportState: {}, handler: 'untrusted', policy: { allow_cloud_push: true } }));
    const monitor = createMonitor({ nodes: { 'license-center': node }, readers: [reader], stateFile });
    assert.equal(typeof monitor.handler, 'function');
    assert.deepEqual(monitor.audit().events, []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('report limit is enforced by UTF-8 bytes before JSON parsing', async () => {
  const monitor = createMonitor({ nodes: { 'license-center': node }, readers: [reader] });
  const result = await call(monitor, { url: '/v1/report', method: 'POST', credential: node,
    body: '界'.repeat(90000) });
  assert.equal(result.status, 413);
  assert.equal(result.data.error, 'REPORT_TOO_LARGE');
});

test('audit strings are length bounded', async () => {
  const monitor = createMonitor({ nodes: { 'license-center': node }, readers: [reader],
    probe: async () => ({ state: 'unhealthy', reason: 'x'.repeat(1000) }) });
  await monitor.runProbes();
  const finding = monitor.status().events.find(event => event.kind === 'probe.failed');
  assert.equal(finding.details.length, 512);
});

test('status fails closed and identity, audit and pull-only policy never expose credentials', async () => {
  let time = Date.parse('2026-10-02T00:00:00Z');
  const readerIdentity = { token: 'r'.repeat(40), fingerprint256: fp,
    status: 'active', cert_not_after: new Date(time + 90 * 86400000).toISOString() };
  const nodeIdentity = { token: 'n'.repeat(40), fingerprint256: 'BB:'.repeat(31) + 'BB',
    status: 'active', cert_not_after: new Date(time + 90 * 86400000).toISOString() };
  const configuredNode = { role: 'license-center', identities: [nodeIdentity],
    health_url: 'https://example.test/health', baseline: { 'app.js': 'a'.repeat(64) } };
  const monitor = createMonitor({ nodes: { 'license-center': configuredNode },
    readers: [{ role: 'reader', identities: [readerIdentity] }], now: () => time,
    probe: async () => ({ state: 'healthy' }) });
  await monitor.runProbes();
  assert.equal(monitor.status().summary_state, 'unavailable');
  const counts = { ok: 6, warning: 0, finding: 0, unavailable: 0 };
  assert.equal((await call(monitor, { url: '/v1/report', method: 'POST', credential: nodeIdentity,
    body: JSON.stringify({ files: { 'app.js': 'a'.repeat(64) },
      host_scan: { state: 'ok', checked_at: new Date(time).toISOString(), counts } }) })).status, 200);
  assert.equal(monitor.status().summary_state, 'ok');
  assert.equal(monitor.status().nodes['license-center'].summary_state, 'ok');

  const identities = await call(monitor, { url: '/v1/identity', credential: readerIdentity });
  assert.equal(identities.status, 200);
  assert.equal(identities.data.roles.reader.rotation_state, 'active');
  assert.equal(identities.data.roles['license-center'].certificate_state, 'healthy');
  assert.equal(identities.data.roles['license-center'].revocation_state, 'enforced');
  assert.equal(identities.text.includes(readerIdentity.token), false);
  assert.equal(identities.text.includes(nodeIdentity.token), false);
  assert.equal((await call(monitor, { url: '/v1/identity', credential: nodeIdentity })).status, 403);

  const policy = await call(monitor, { url: '/v1/policy', credential: nodeIdentity });
  assert.equal(policy.status, 200);
  assert.equal(policy.data.delivery, 'pull-only');
  assert.equal(policy.data.remote_execution, false);
  const audit = await call(monitor, { url: '/v1/audit', credential: readerIdentity });
  assert.equal(audit.status, 200);
  assert.equal(audit.data.summary_state, 'ok');
  assert.ok(audit.data.events.every(entry => !JSON.stringify(entry).includes(readerIdentity.token)));

  assert.equal((await call(monitor, { url: '/v1/report', method: 'POST', credential: nodeIdentity,
    body: JSON.stringify({ files: { 'app.js': 'b'.repeat(64) },
      host_scan: { state: 'finding', checked_at: new Date(time).toISOString(),
        counts: { ...counts, ok: 5, finding: 1 } } }) })).status, 200);
  assert.equal(monitor.status().summary_state, 'finding');
});

test('dashboard is server-rendered behind reader mTLS plus Basic token and security headers', async () => {
  const monitor = createMonitor({ nodes: {}, readers: [reader] });
  const status = monitor.status();
  assert.equal(status.deployment.state, 'not-enrolled');
  assert.deepEqual(status.deployment.configured_roles, []);
  const authorization = `Basic ${Buffer.from(`reader:${reader.token}`).toString('base64')}`;
  const page = await callRaw(monitor, { url: '/dashboard', credential: reader, authorization });
  assert.equal(page.status, 200);
  assert.match(page.headers['content-type'], /^text\/html/);
  assert.match(page.headers['content-security-policy'], /default-src 'none'/);
  assert.match(page.text, /APPGOG 云端安全监测中心/);
  assert.match(page.text, /授权中心/);
  assert.match(page.text, /打包中心/);
  assert.match(page.text, /等待在 Linux 管理菜单中注册/);
  assert.match(page.text, /双机总架构/);
  assert.match(page.text, /三机总架构/);
  assert.match(page.text, /首次对接进度/);
  assert.match(page.text, /云端服务已安装/);
  assert.match(page.text, /当前步骤/);
  assert.match(page.text, /sudo appgog-security/);
  assert.equal(page.text.includes(reader.token), false);
  for (const secret of ['ca.key', 'reader.key', '/etc/appgog-security', 'private key']) {
    assert.equal(page.text.includes(secret), false);
  }
  const denied = await callRaw(monitor, { url: '/dashboard', credential: reader,
    authorization: `Basic ${Buffer.from('reader:wrong').toString('base64')}` });
  assert.equal(denied.status, 401);
  assert.match(denied.headers['www-authenticate'], /^Basic /);
});

test('dashboard quick-start reaches complete only after both business roles report', async () => {
  const license = { ...node, token: 'l'.repeat(40), status: 'active', cert_not_after: '2027-10-02T00:00:00Z' };
  const build = { ...node, token: 'b'.repeat(40), status: 'active', cert_not_after: '2027-10-02T00:00:00Z' };
  const monitor = createMonitor({ nodes: { 'license-center': license, 'build-center': build }, readers: [reader],
    probe: async () => ({ state: 'healthy' }) });
  const host_scan = { state: 'ok', checked_at: new Date().toISOString(),
    counts: { ok: 6, warning: 0, finding: 0, unavailable: 0 } };
  await monitor.runProbes();
  for (const credential of [license, build]) {
    const result = await call(monitor, { url: '/v1/report', method: 'POST', credential,
      body: JSON.stringify({ files: { 'app.js': 'a'.repeat(64) }, host_scan }) });
    assert.equal(result.status, 200);
  }
  const authorization = `Basic ${Buffer.from(`reader:${reader.token}`).toString('base64')}`;
  const page = await callRaw(monitor, { url: '/dashboard', credential: reader, authorization });
  assert.match(page.text, /首次对接已完成/);
  assert.match(page.text, /两个业务角色均已通过 mTLS 认证并开始上报/);
});

test('deployment and pairing states cover enrollment, authenticated connection, staleness and findings', async () => {
  let current = Date.parse('2026-10-02T00:00:00Z');
  const pairedNode = { ...node, status: 'active', cert_not_after: '2027-10-02T00:00:00Z' };
  const monitor = createMonitor({ nodes: { 'license-center': pairedNode }, readers: [reader], now: () => current,
    probe: async () => ({ state: 'healthy' }) });
  let snapshot = monitor.status();
  assert.equal(snapshot.deployment.state, 'partial');
  assert.deepEqual(snapshot.deployment.configured_roles, ['license-center']);
  assert.equal(snapshot.nodes['license-center'].pairing_state, 'waiting-first-report');

  await monitor.runProbes();
  const hostScan = { state: 'ok', checked_at: new Date(current).toISOString(),
    counts: { ok: 6, warning: 0, finding: 0, unavailable: 0 } };
  await call(monitor, { url: '/v1/report', method: 'POST', credential: pairedNode,
    body: JSON.stringify({ files: { 'app.js': 'a'.repeat(64) }, host_scan: hostScan }) });
  snapshot = monitor.status();
  assert.equal(snapshot.nodes['license-center'].pairing_state, 'connected');
  assert.deepEqual(snapshot.deployment.connected_roles, ['license-center']);

  current += 121000;
  assert.equal(monitor.status().nodes['license-center'].pairing_state, 'stale');
  await call(monitor, { url: '/v1/report', method: 'POST', credential: pairedNode,
    body: JSON.stringify({ files: { 'app.js': 'b'.repeat(64) },
      host_scan: { ...hostScan, checked_at: new Date(current).toISOString() } }) });
  assert.equal(monitor.status().nodes['license-center'].pairing_state, 'attention-required');
});

test('identity posture warns on staged or unknown certificates and fails on expiration', () => {
  const current = Date.parse('2026-10-02T00:00:00Z');
  const healthy = { token: 'a'.repeat(40), fingerprint256: fp,
    cert_not_after: '2027-01-02T00:00:00Z', status: 'active' };
  const staged = { token: 'b'.repeat(40), fingerprint256: 'CC:'.repeat(31) + 'CC',
    cert_not_after: '2027-01-02T00:00:00Z', status: 'staged' };
  let monitor = createMonitor({ nodes: {}, readers: [{ identities: [healthy, staged] }], now: () => current });
  assert.equal(monitor.identityStatus().summary_state, 'warning');
  assert.equal(monitor.identityStatus().roles.reader.revocation_state, 'pending-old-identity');
  monitor = createMonitor({ nodes: {}, readers: [{ identities: [{ ...healthy, cert_not_after: '2026-10-01T00:00:00Z' }] }],
    now: () => current });
  assert.equal(monitor.identityStatus().summary_state, 'finding');
  assert.equal(monitor.status().summary_state, 'finding');
});

test('public policy exposes only the fixed fail-closed contract', async () => {
  const monitor = createMonitor({ nodes: { 'license-center': node }, readers: [reader],
    policy: { version: '7', rules: { require_signed_updates: true, allow_remote_commands: false,
      allow_cloud_push: false, internal_value: 'must-not-leak' } } });
  const result = await call(monitor, { url: '/v1/policy', credential: node });
  assert.equal(result.status, 200);
  assert.deepEqual(result.data.rules,
    { require_signed_updates: true, allow_remote_commands: false, allow_cloud_push: false });
  assert.equal(result.text.includes('internal_value'), false);
  assert.equal(result.text.includes('must-not-leak'), false);
});

test('reports reject every non-lowercase SHA-256 file digest', async () => {
  const monitor = createMonitor({ nodes: { 'license-center': node }, readers: [reader] });
  for (const digest of ['A'.repeat(64), '0'.repeat(63), 'not-a-digest', null]) {
    const result = await call(monitor, { url: '/v1/report', method: 'POST', credential: node,
      body: JSON.stringify({ files: { 'app.js': digest } }) });
    assert.equal(result.status, 400);
  }
  assert.equal(monitor.status().nodes['license-center'].integrity.state, 'unknown');
});

const configuredIdentity = (character, byte) => ({
  token: character.repeat(40), fingerprint256: `${byte}:`.repeat(31) + byte, status: 'active',
});

const validConfiguration = () => ({
  nodes: { 'license-center': {
    role: 'license-center', health_url: 'https://service.example.test/health',
    identities: [configuredIdentity('n', 'BB')], baseline: { 'app.js': 'a'.repeat(64) },
  } },
  readers: [{ role: 'reader', identities: [configuredIdentity('r', 'AA')] }],
  policy: { version: '1', rules: {
    require_signed_updates: true, allow_remote_commands: false, allow_cloud_push: false,
  } },
});

test('configuration accepts the fail-closed identity and policy contract', () => {
  const config = validConfiguration();
  assert.equal(validateConfiguration(config), config);
});

test('configuration rejects missing readers and unknown roles', () => {
  const noReader = validConfiguration();
  noReader.readers = [];
  assert.throws(() => validateConfiguration(noReader), /Exactly one reader/);

  const extraReader = validConfiguration();
  extraReader.readers.push(structuredClone(extraReader.readers[0]));
  assert.throws(() => validateConfiguration(extraReader), /Exactly one reader/);

  const unknownRole = validConfiguration();
  unknownRole.nodes['database-center'] = unknownRole.nodes['license-center'];
  delete unknownRole.nodes['license-center'];
  assert.throws(() => validateConfiguration(unknownRole), /Unsupported node role/);
});

test('configuration rejects credential-bearing health URLs', () => {
  const config = validConfiguration();
  const health = new URL(config.nodes['license-center'].health_url);
  health.username = ['embedded'].join('');
  config.nodes['license-center'].health_url = health.href;
  assert.throws(() => validateConfiguration(config), /Invalid HTTPS health URL/);
});

test('configuration rejects reused tokens and certificate fingerprints', () => {
  const duplicateToken = validConfiguration();
  duplicateToken.nodes['build-center'] = {
    role: 'build-center', health_url: 'https://build.example.test/health',
    identities: [{ ...configuredIdentity('b', 'CC'), token: duplicateToken.nodes['license-center'].identities[0].token }],
    baseline: { 'worker.js': 'b'.repeat(64) },
  };
  assert.throws(() => validateConfiguration(duplicateToken), /must be unique/);

  const duplicateFingerprint = validConfiguration();
  duplicateFingerprint.nodes['build-center'] = {
    role: 'build-center', health_url: 'https://build.example.test/health',
    identities: [{ ...configuredIdentity('b', 'CC'),
      fingerprint256: duplicateFingerprint.nodes['license-center'].identities[0].fingerprint256 }],
    baseline: { 'worker.js': 'b'.repeat(64) },
  };
  assert.throws(() => validateConfiguration(duplicateFingerprint), /must be unique/);
});

test('configuration rejects invalid identity rotation state', () => {
  const revoked = validConfiguration();
  revoked.readers[0].identities[0].status = 'revoked';
  assert.throws(() => validateConfiguration(revoked), /active or staged/);

  const twoActive = validConfiguration();
  twoActive.readers[0].identities.push(configuredIdentity('s', 'CC'));
  assert.throws(() => validateConfiguration(twoActive), /one active identity/);

  const stagedOnly = validConfiguration();
  stagedOnly.readers[0].identities[0].status = 'staged';
  assert.throws(() => validateConfiguration(stagedOnly), /one active identity/);
});

test('configuration rejects malformed digests, fingerprints and tokens', () => {
  for (const digest of ['A'.repeat(64), '0'.repeat(63)]) {
    const config = validConfiguration();
    config.nodes['license-center'].baseline['app.js'] = digest;
    assert.throws(() => validateConfiguration(config), /Invalid SHA-256 baseline/);
  }

  const lowercaseFingerprint = validConfiguration();
  lowercaseFingerprint.readers[0].identities[0].fingerprint256 = fp.toLowerCase();
  assert.throws(() => validateConfiguration(lowercaseFingerprint), /SHA-256 client certificate fingerprint/);

  for (const token of ['short', `${'x'.repeat(32)} invalid`]) {
    const config = validConfiguration();
    config.readers[0].identities[0].token = token;
    assert.throws(() => validateConfiguration(config), /32[+] character token/);
  }
});

test('configuration rejects any policy that permits unsafe update or control paths', () => {
  for (const [name, value] of [
    ['require_signed_updates', false],
    ['allow_remote_commands', true],
    ['allow_cloud_push', true],
  ]) {
    const config = validConfiguration();
    config.policy.rules[name] = value;
    assert.throws(() => validateConfiguration(config), /Unsafe policy configuration/);
  }
});
