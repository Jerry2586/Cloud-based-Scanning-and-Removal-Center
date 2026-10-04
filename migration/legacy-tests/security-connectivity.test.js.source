import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:https';
import { X509Certificate } from 'node:crypto';
import { sendReport } from '../scripts/security-agent.js';
import { cloudSecurityStatus } from '../apps/license-api/src/modules/operations/security-status.js';

const opensslBin = process.platform === 'win32' ? 'C:/Program Files/Git/usr/bin/openssl.exe' : 'openssl';
const hasOpenSSL = spawnSync(opensslBin, ['version']).status === 0;
function openssl(cwd, ...args) {
  const result = spawnSync(opensslBin, args, { cwd, encoding: 'utf8' });
  if (result.status !== 0) throw Error(result.stderr);
}

test('modeled business layouts: three mTLS identities, wrong credentials and outage', { skip: !hasOpenSSL }, async t => {
  for (const topology of ['same-host-business', 'separate-business-hosts']) {
    await t.test(topology, async () => {
      const dir = mkdtempSync(join(tmpdir(), 'appgog-security-'));
      let server;
      try {
        openssl(dir, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '1', '-subj', '/CN=test CA');
        openssl(dir, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=localhost');
        writeFileSync(join(dir, 'server.ext'), 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
        openssl(dir, 'x509', '-req', '-in', 'server.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.crt', '-days', '1', '-extfile', 'server.ext');
        const ids = {};
        for (const role of ['reader', 'license', 'build']) {
          openssl(dir, 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${role}.key`, '-out', `${role}.csr`, '-subj', `/CN=${role}`);
          openssl(dir, 'x509', '-req', '-in', `${role}.csr`, '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', `${role}.crt`, '-days', '1');
          ids[role] = { cert: join(dir, `${role}.crt`), key: join(dir, `${role}.key`),
            token: role.repeat(10), fingerprint: new X509Certificate(readFileSync(join(dir, `${role}.crt`))).fingerprint256 };
        }
        const reports = [];
        server = createServer({ key: readFileSync(join(dir, 'server.key')), cert: readFileSync(join(dir, 'server.crt')),
          ca: readFileSync(join(dir, 'ca.crt')), requestCert: true, rejectUnauthorized: true }, async (req, res) => {
          const actor = Object.entries(ids).find(([, id]) => req.socket.getPeerCertificate()?.fingerprint256 === id.fingerprint
            && req.headers.authorization === `Bearer ${id.token}`)?.[0];
          const allowed = req.url === '/v1/status' ? actor === 'reader' : actor === 'license' || actor === 'build';
          if (!allowed) { res.writeHead(403); res.end('{}'); return; }
          if (req.url === '/v1/report') {
            let body = '';
            for await (const chunk of req) body += chunk;
            reports.push({ actor, ...JSON.parse(body) });
            res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"state":"matched"}');
          } else {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ generated_at: new Date().toISOString(), nodes: {}, events: [] }));
          }
        });
        await new Promise(resolve => server.listen(0, 'localhost', resolve));
        const common = { SECURITY_CLOUD_URL: `https://localhost:${server.address().port}`, SECURITY_CLOUD_CA: join(dir, 'ca.crt') };
        const envFor = role => ({ ...common, SECURITY_CLOUD_CLIENT_CERT: ids[role].cert,
          SECURITY_CLOUD_CLIENT_KEY: ids[role].key, SECURITY_CLOUD_TOKEN: ids[role].token, SECURITY_SCAN_ROOT: dir,
          SECURITY_REPORT_HOST: 'true', SECURITY_HOST_SCAN_SOCKET: join(dir, 'missing.sock') });
        mkdirSync(join(dir, 'apps'));
        writeFileSync(join(dir, 'apps', 'app.js'), 'trusted');
        assert.equal((await cloudSecurityStatus(envFor('reader'))).connected, true);
        assert.equal((await cloudSecurityStatus(envFor('license'))).connected, false);
        assert.equal((await sendReport(envFor('license'))).state, 'matched');
        assert.equal((await sendReport(envFor('build'))).state, 'matched');
        await assert.rejects(sendReport(envFor('reader')), /403/);
        await assert.rejects(sendReport({ ...envFor('license'), SECURITY_CLOUD_TOKEN: 'wrong'.repeat(10) }), /403/);
        assert.equal((await cloudSecurityStatus({ ...envFor('reader'), SECURITY_CLOUD_CA: ids.reader.cert })).connected, false);
        assert.deepEqual(reports.map(report => report.actor), ['license', 'build']);
        assert.deepEqual(reports.map(report => report.host_scan), [
          { state: 'unavailable', checked_at: null }, { state: 'unavailable', checked_at: null }]);
        assert.ok(reports.every(report => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(report.observed_at)));
        assert.ok(reports.every(report => /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(report.report_id)));
        assert.notEqual(reports[0].report_id, reports[1].report_id);
        assert.equal(reports[0].files['apps/app.js'], reports[1].files['apps/app.js']);
        await new Promise(resolve => server.close(resolve)); server = null;
        assert.equal((await cloudSecurityStatus(envFor('reader'))).connected, false);
        await assert.rejects(sendReport(envFor('license')));
      } finally {
        if (server) await new Promise(resolve => server.close(resolve));
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }
});
