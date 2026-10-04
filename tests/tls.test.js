import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createServer, request as httpsRequest } from 'node:https';
import { createHash, randomUUID, X509Certificate } from 'node:crypto';
import { createMonitor } from '../src/monitor.js';

const binary = process.platform === 'win32' ? 'C:/Program Files/Git/usr/bin/openssl.exe' : 'openssl';
const available = spawnSync(binary, ['version']).status === 0;
const tokenDigest = value => createHash('sha256').update(value).digest('hex');
const openssl = (cwd, ...args) => {
  const result = spawnSync(binary, args, { cwd, encoding: 'utf8' });
  if (result.status !== 0) throw Error(result.stderr);
};
function request(port, { ca, cert, key, token, path = '/v1/status', body }) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify({ observed_at: new Date().toISOString(), report_id: randomUUID(), ...body }) : undefined;
    const req = httpsRequest(`https://localhost:${port}${path}`, { ca, cert, key, method: body ? 'POST' : 'GET', rejectUnauthorized: true,
      headers: { authorization: `Bearer ${token}` } }, res => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, data: JSON.parse(data) }));
    });
    req.on('error', reject);
    req.end(payload);
  });
}
test('actual mutual TLS: valid identity, wrong token, missing certificate, wrong CA and rotation', { skip: !available }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'cloud-tls-'));
  let server;
  try {
    openssl(dir, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '1', '-subj', '/CN=Security Test CA');
    openssl(dir, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=localhost');
    writeFileSync(join(dir, 'server.ext'), 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n');
    openssl(dir, 'x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.crt', '-days', '1', '-extfile', 'server.ext');
  } catch (error) {
    rmSync(dir, { recursive: true, force: true });
    throw error;
  }
  try {
    openssl(dir, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'client.key', '-out', 'client.csr', '-subj', '/CN=license-center');
    openssl(dir, 'x509', '-req', '-in', 'client.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'client.crt', '-days', '1');
    const ca = readFileSync(join(dir, 'ca.crt'));
    const cert = readFileSync(join(dir, 'client.crt'));
    const key = readFileSync(join(dir, 'client.key'));
    let readerToken = 'r'.repeat(40);
    const reader = { token_sha256: tokenDigest(readerToken), fingerprint256: new X509Certificate(cert).fingerprint256 };
    const monitor = createMonitor({ nodes: {}, readers: [reader] });
    server = createServer({ key: readFileSync(join(dir, 'server.key')), cert: readFileSync(join(dir, 'server.crt')),
      ca, requestCert: true, rejectUnauthorized: true }, monitor.handler);
    await new Promise(resolve => server.listen(0, resolve));
    const port = server.address().port;
    assert.equal((await request(port, { ca, cert, key, token: readerToken })).status, 200);
    const ipStatus = await new Promise((resolve, reject) => {
      const req = httpsRequest(`https://127.0.0.1:${port}/v1/status`, { ca, cert, key,
        headers: { authorization: `Bearer ${readerToken}` } }, res => {
        res.resume(); res.on('end', () => resolve(res.statusCode));
      });
      req.on('error', reject); req.end();
    });
    assert.equal(ipStatus, 200);
    assert.equal((await request(port, { ca, cert, key, token: 'invalid' })).status, 403);
    await assert.rejects(request(port, { ca, token: readerToken }), /certificate|alert|handshake/i);
    await assert.rejects(request(port, { ca: cert, cert, key, token: readerToken }), /certificate|verify|issuer/i);
    await assert.rejects(new Promise((resolve, reject) => {
      const req = httpsRequest(`https://localhost:${port}/v1/status`, { ca, cert, key, servername: 'wrong.example', headers: { authorization: `Bearer ${readerToken}` } }, resolve);
      req.on('error', reject); req.end();
    }), /altname|hostname|ip address/i);
    readerToken = 's'.repeat(40);
    reader.token_sha256 = tokenDigest(readerToken);
    assert.equal((await request(port, { ca, cert, key, token: 'r'.repeat(40) })).status, 403);
    assert.equal((await request(port, { ca, cert, key, token: readerToken })).status, 200);

    openssl(dir, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'rotated.key', '-out', 'rotated.csr', '-subj', '/CN=rotated-reader');
    openssl(dir, 'x509', '-req', '-in', 'rotated.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'rotated.crt', '-days', '1');
    const rotatedCert = readFileSync(join(dir, 'rotated.crt'));
    const rotatedKey = readFileSync(join(dir, 'rotated.key'));
    const rotatedToken = 'rotated'.repeat(8);
    reader.identities = [{ fingerprint256: reader.fingerprint256, token_sha256: tokenDigest(readerToken) },
      { fingerprint256: new X509Certificate(rotatedCert).fingerprint256, token_sha256: tokenDigest(rotatedToken) }];
    assert.equal((await request(port, { ca, cert, key, token: readerToken })).status, 200);

    assert.equal((await request(port, { ca, cert: rotatedCert, key: rotatedKey, token: rotatedToken })).status, 200);
    reader.identities.shift();
    assert.equal((await request(port, { ca, cert, key, token: readerToken })).status, 403);
    assert.equal((await request(port, { ca, cert: rotatedCert, key: rotatedKey, token: rotatedToken })).status, 200);
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});


test('reader and two reporting nodes cannot impersonate each other across TLS identities', { skip: !available }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'cloud-three-identities-'));
  let server;
  try {
    openssl(dir, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '1', '-subj', '/CN=Security Test CA');
    openssl(dir, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=localhost');
    writeFileSync(join(dir, 'server.ext'), 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n');
    openssl(dir, 'x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.crt', '-days', '1', '-extfile', 'server.ext');
    const ca = readFileSync(join(dir, 'ca.crt'));
    const identities = {};
    for (const name of ['reader', 'license-center', 'build-center']) {
      openssl(dir, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', `/CN=${name}`);
      openssl(dir, 'x509', '-req', '-in', `${name}.csr`, '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', `${name}.crt`, '-days', '1');
      const cert = readFileSync(join(dir, `${name}.crt`));
      identities[name] = { ca, cert, key: readFileSync(join(dir, `${name}.key`)), token: name.repeat(8), fingerprint256: new X509Certificate(cert).fingerprint256 };
    }
    const nodes = {};
    for (const name of ['license-center', 'build-center']) {
      nodes[name] = { fingerprint256: identities[name].fingerprint256, token_sha256: tokenDigest(identities[name].token),
        baseline: { 'apps/app.js': 'a'.repeat(64) } };
    }
    const monitor = createMonitor({ nodes, readers: [{ fingerprint256: identities.reader.fingerprint256,
      token_sha256: tokenDigest(identities.reader.token) }] });
    server = createServer({ key: readFileSync(join(dir, 'server.key')), cert: readFileSync(join(dir, 'server.crt')),
      ca, requestCert: true, rejectUnauthorized: true }, monitor.handler);
    await new Promise(resolve => server.listen(0, resolve));
    const port = server.address().port;
    for (const name of ['reader', 'license-center', 'build-center']) {
      const result = await request(port, { ...identities[name], path: '/v1/connectivity' });
      assert.equal(result.status, 200);
      assert.equal(result.data.identity, name);
    }
    assert.equal((await request(port, { ...identities.reader, token: identities['license-center'].token,
      path: '/v1/connectivity' })).status, 403);
    assert.equal((await request(port, { ...identities['build-center'], token: 'invalid'.repeat(8),
      path: '/v1/connectivity' })).status, 403);
    const report = { path: '/v1/report', body: { files: { 'apps/app.js': 'a'.repeat(64) } } };
    assert.equal((await request(port, { ...identities.reader, ...report })).status, 403);
    assert.equal((await request(port, identities['license-center'])).status, 403);
    assert.equal((await request(port, { ...identities['license-center'], token: identities['build-center'].token, ...report })).status, 403);
    assert.equal((await request(port, { ...identities['license-center'], ...report })).status, 200);
    assert.equal((await request(port, { ...identities['build-center'], ...report })).status, 200);
    const status = await request(port, identities.reader);
    assert.equal(status.status, 200);
    assert.equal(status.data.nodes['license-center'].integrity.state, 'matched');
    assert.equal(status.data.nodes['build-center'].integrity.state, 'matched');
    if (process.env.APPGOG_BUSINESS_ROOT) {
      const business = process.env.APPGOG_BUSINESS_ROOT;
      const { inventory, sendReport } = await import(pathToFileURL(join(business, 'scripts/security-agent.js')).href);
      const { cloudSecurityStatus } = await import(pathToFileURL(join(business,
        'apps/license-api/src/modules/operations/security-status.js')).href);
      mkdirSync(join(dir, 'apps'));
      writeFileSync(join(dir, 'apps', 'app.js'), 'verified release source');
      for (const name of ['license-center', 'build-center']) nodes[name].baseline = inventory(dir);
      const common = { SECURITY_CLOUD_URL: `https://localhost:${port}`, SECURITY_CLOUD_CA: join(dir, 'ca.crt'),
        SECURITY_SCAN_ROOT: dir };
      const envFor = name => ({ ...common, SECURITY_CLOUD_TOKEN: identities[name].token,
        SECURITY_CLOUD_CLIENT_CERT: join(dir, `${name}.crt`), SECURITY_CLOUD_CLIENT_KEY: join(dir, `${name}.key`) });
      assert.equal((await cloudSecurityStatus(envFor('reader'))).connected, true);
      assert.equal((await cloudSecurityStatus(envFor('license-center'))).connected, false);
      assert.equal((await sendReport(envFor('license-center'))).state, 'matched');
      assert.equal((await sendReport(envFor('build-center'))).state, 'matched');
      assert.equal(monitor.status().nodes['license-center'].report_fresh, true);
      assert.equal(monitor.status().nodes['build-center'].report_fresh, true);
      await assert.rejects(sendReport(envFor('reader')), /403/);
      await assert.rejects(sendReport({ ...envFor('license-center'), SECURITY_CLOUD_TOKEN: identities['build-center'].token }), /403/);
      await assert.rejects(sendReport({ ...envFor('build-center'), SECURITY_CLOUD_CA: identities.reader.cert }),
        /certificate|verify|issuer/i);
      await new Promise(resolve => server.close(resolve));
      server = null;
      assert.equal((await cloudSecurityStatus(envFor('reader'))).connected, false);
      await assert.rejects(sendReport(envFor('license-center')));
      server = createServer({ key: readFileSync(join(dir, 'server.key')), cert: readFileSync(join(dir, 'server.crt')),
        ca, requestCert: true, rejectUnauthorized: true }, monitor.handler);
      await new Promise(resolve => server.listen(port, 'localhost', resolve));
      assert.equal((await cloudSecurityStatus(envFor('reader'))).connected, true);
      assert.equal((await sendReport(envFor('build-center'))).state, 'matched');
    }
    const rotatedLicenseToken = 'rotated-license-token-'.repeat(3);
    nodes['license-center'].token_sha256 = tokenDigest(rotatedLicenseToken);
    assert.equal((await request(port, { ...identities['license-center'], ...report })).status, 403);
    assert.equal((await request(port, { ...identities['license-center'], token: rotatedLicenseToken, ...report })).status, 200);
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});
