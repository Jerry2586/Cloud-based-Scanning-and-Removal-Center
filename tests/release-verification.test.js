import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, copyFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { independentContract, legacyContract } from '../src/release-contract.js';
import { runHeader, verifyRelease } from '../src/release-verification.js';
import { verifyPublishedRelease } from '../scripts/verify-published-release.js';
const keys = generateKeyPairSync('ed25519');
const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' });
const version = '0.2.0', commit = 'a'.repeat(40), tag = 'v' + version;
const contract = { ...legacyContract, independent: independentContract };

function tar(entries) {
  const parts = [];
  for (const [name, content, type = '0'] of entries) {
    const data = Buffer.from(content), header = Buffer.alloc(512);
    header.write(name, 0, 100); header.write('0000600\0', 100); header.write('0000000\0', 108); header.write('0000000\0', 116);
    header.write(data.length.toString(8).padStart(11, '0') + '\0', 124); header.write('00000000000\0', 136);
    header.fill(32, 148, 156); header.write(type, 156); header.write('ustar\0', 257); header.write('00', 263);
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148);
    parts.push(header, data, Buffer.alloc((512 - data.length % 512) % 512));
  }
  return gzipSync(Buffer.concat([...parts, Buffer.alloc(1024)]));
}
function fixture(t, options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'ironcurtain-verify-test-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const prefix = 'APPGOG-Cloud-Security-Center-' + version;
  const archive = tar([
    ['./package.json', JSON.stringify({ name: legacyContract.product, version: options.packageVersion || version })],
    ['./release-contract.json', JSON.stringify(contract)],
    ...(options.entries || []),
  ]);
  const run = Buffer.concat([Buffer.from(options.header || runHeader), options.otherArchive || archive]);
  const hash = data => createHash('sha256').update(data).digest('hex');
  const manifest = { schema: 1, product: legacyContract.product, version, tar_name: prefix + '.tar.gz',
    tar_sha256: hash(archive), run_name: prefix + '.run', run_sha256: hash(run), environment: contract };
  for (const [name, data] of [[manifest.tar_name, archive], [manifest.run_name, run]]) {
    writeFileSync(join(directory, name), data);
    writeFileSync(join(directory, name + '.sha256'), hash(data) + '  ' + name + '\n');
  }
  const bytes = Buffer.from(JSON.stringify(manifest));
  writeFileSync(join(directory, 'release-manifest.json'), bytes);
  writeFileSync(join(directory, 'release-manifest.json.sig'), sign(null, bytes, keys.privateKey));
  return directory;
}
const verify = directory => verifyRelease({ directory, publicKey, expectedVersion: version });

test('valid signed six-asset release verifies TAR, RUN and packaged identity', t => {
  const result = verify(fixture(t)); assert.equal(result.version, version); assert.equal(result.assets.length, 6);
});
test('re-signed installer script or embedded payload replacement is rejected', t => {
  assert.throws(() => verify(fixture(t, { header: runHeader.replace('exit $?','echo injected; exit $?') })), /header/);
  assert.throws(() => verify(fixture(t, { otherArchive: tar([['evil', 'bad']]) })), /embedded TAR/);
});
test('re-signed wrong package version and unsafe archive paths are rejected', t => {
  assert.throws(() => verify(fixture(t, { packageVersion: '0.1.6' })), /identity/);
  for (const name of ['./..' + '/escape', '/absolute', './duplicate']) {
    const entries = name === './duplicate' ? [[name,'one'],[name,'two']] : [[name,'bad']];
    assert.throws(() => verify(fixture(t, { entries })), /unsafe|duplicated/);
  }
  assert.throws(() => verify(fixture(t, { entries: [['./link', '', '2']] })), /links|special/);
});
test('corrupt checksum attachment, signature and extra asset fail verification', t => {
  let dir = fixture(t); writeFileSync(join(dir, 'extra.txt'), 'unexpected'); assert.throws(() => verify(dir), /six/);
  dir = fixture(t); writeFileSync(join(dir, 'APPGOG-Cloud-Security-Center-0.2.0.run.sha256'), 'bad'); assert.throws(() => verify(dir), /checksum/);
  dir = fixture(t); writeFileSync(join(dir, 'release-manifest.json.sig'), Buffer.alloc(64)); assert.throws(() => verify(dir), /signature/);
});
function apiFixture(source, options = {}) {
  const assets = readdirSync(source).map(name => ({ name, state: 'uploaded', size: readFileSync(join(source,name)).length }));
  const release = { id: 1, tag_name: tag, draft: false, prerelease: false, assets, ...options.release };
  const calls = [];
  const run = args => {
    calls.push(args);
    if (args[0] === 'api') {
      const endpoint = args[1];
      if (endpoint.includes('/git/ref/')) return JSON.stringify({ object: options.object || { type: 'commit', sha: commit } });
      if (endpoint.includes('/git/tags/')) return JSON.stringify({ object: { type: 'commit', sha: commit } });
      if (endpoint.endsWith('/latest')) return JSON.stringify(options.latest || release);
      return JSON.stringify(release);
    }
    assert.equal(args[0], 'release'); assert.equal(args[1], 'download');
    const destination = args[args.indexOf('--dir') + 1];
    for (const name of readdirSync(source)) copyFileSync(join(source,name),join(destination,name));
    return '';
  };
  return { run, calls };
}
test('published verifier accepts exact commit and downloads authenticated six assets', t => {
  const source = fixture(t), client = apiFixture(source);
  const result = verifyPublishedRelease({ tag, expectedCommit: commit, publicKey, run: client.run });
  assert.equal(result.commit, commit); assert.equal(result.assets.length, 6);
  assert.equal(client.calls.filter(args => args[0] === 'release').length, 1);
  const annotated = apiFixture(source, { object: { type: 'tag', sha: 'b'.repeat(40) } });
  assert.equal(verifyPublishedRelease({ tag, expectedCommit: commit, publicKey, run: annotated.run }).commit,commit);
});
test('wrong commit, draft, prerelease, Latest or asset list rejects before downloading', t => {
  const source = fixture(t);
  for (const options of [
    { object: { type: 'commit', sha: 'b'.repeat(40) } },
    { release: { draft: true } }, { release: { prerelease: true } },
    { latest: { id: 2, tag_name: 'v0.1.6' } },
    { release: { assets: [] } },
  ]) {
    const client = apiFixture(source,options);
    assert.throws(() => verifyPublishedRelease({ tag, expectedCommit: commit, publicKey, run: client.run }));
    assert.equal(client.calls.filter(args => args[0] === 'release').length, 0);
  }
});
