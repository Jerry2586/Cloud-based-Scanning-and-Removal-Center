import assert from 'node:assert/strict';
import { copyFileSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const script = resolve(import.meta.dirname, '../scripts/security-connect.sh');
const linux = process.platform === 'linux';

function command(program, args, options = {}) {
  const result = spawnSync(program, args, { encoding: 'utf8', ...options });
  assert.equal(result.error, undefined, result.error?.message);
  return result;
}

function certificate(directory, name) {
  const certificatePath = join(directory, `${name}.crt`);
  const key = join(directory, `${name}.key`);
  const generated = command('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
    '-subj', `/CN=${name}`, '-keyout', key, '-out', certificatePath]);
  assert.equal(generated.status, 0, generated.stderr);
  const fingerprint = command('openssl', ['x509', '-in', certificatePath, '-noout', '-fingerprint', '-sha256']);
  assert.equal(fingerprint.status, 0, fingerprint.stderr);
  return { certificatePath, fingerprint: fingerprint.stdout.trim().split('=')[1].replaceAll(':', '').toLowerCase() };
}

function setup(t) {
  const temp = mkdtempSync(join(tmpdir(), 'appgog-security-pair-'));
  t.after(() => rmSync(temp, { recursive: true, force: true }));
  const install = join(temp, 'install');
  const shared = join(install, 'shared');
  const bundle = join(temp, 'bundle');
  const bin = join(temp, 'bin');
  mkdirSync(shared, { recursive: true });
  mkdirSync(join(install, 'current'), { recursive: true });
  mkdirSync(bundle);
  mkdirSync(bin);
  writeFileSync(join(shared, '.env'), 'APPGOG_DEPLOYMENT_ROLE=license\nEXISTING_SETTING=keep\n');
  writeFileSync(join(install, 'current', 'compose.license.yaml'), 'services: {}\n');
  mkdirSync(join(install, 'current', 'scripts', 'lib'), { recursive: true });
  copyFileSync(resolve(import.meta.dirname, '../scripts/lib/deployment-role.sh'), join(install, 'current', 'scripts', 'lib', 'deployment-role.sh'));
  for (const [name, contents] of Object.entries({
    id: '#!/bin/sh\nprintf "0\\n"\n',
    docker: '#!/bin/sh\nexit 0\n',
    curl: '#!/bin/sh\nexit 99\n',
    jq: '#!/bin/sh\nexit 99\n',
  })) writeFileSync(join(bin, name), contents, { mode: 0o755 });
  const env = { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH}` };
  const run = (pin = null) => command('/bin/sh', [script, '--cloud-url', 'https://cloud.example.com:9443',
    '--bundle-dir', bundle, '--install-dir', install, ...(pin === null ? [] : ['--ca-sha256', pin])], { env });
  return { temp, install, shared, bundle, run };
}

// The script rejects untrusted CA material before it stages credentials or restarts Docker.
test('first pairing refuses missing or mismatched independent CA fingerprint without changing deployment', { skip: !linux }, t => {
  const { temp, shared, bundle, run } = setup(t);
  const ca = certificate(temp, 'proposed');
  writeFileSync(join(bundle, 'ca.crt'), readFileSync(ca.certificatePath));
  for (const [pin, expected] of [[null, 'First pairing requires'], ['0'.repeat(64), 'fingerprint mismatch']]) {
    const result = run(pin);
    assert.notEqual(result.status, 0, result.stderr);
    assert.match(result.stderr, new RegExp(expected));
    assert.equal(readFileSync(join(shared, '.env'), 'utf8'), 'APPGOG_DEPLOYMENT_ROLE=license\nEXISTING_SETTING=keep\n');
    assert.equal(command('/bin/sh', ['-c', 'test ! -e "$1" && test ! -e "$2"', '_',
      join(shared, 'security'), join(shared, '.security-stage')]).status, 0);
  }
});

test('re-pairing refuses an unexpected CA change even if its new fingerprint is supplied', { skip: !linux }, t => {
  const { temp, shared, bundle, run } = setup(t);
  const old = certificate(temp, 'pinned');
  const changed = certificate(temp, 'changed');
  mkdirSync(join(shared, 'security'));
  writeFileSync(join(shared, 'security', 'ca.crt'), readFileSync(old.certificatePath));
  writeFileSync(join(bundle, 'ca.crt'), readFileSync(changed.certificatePath));
  const result = run(changed.fingerprint);
  assert.notEqual(result.status, 0, result.stderr);
  assert.match(result.stderr, /Cloud CA changed/);
  assert.deepEqual(readFileSync(join(shared, 'security', 'ca.crt')), readFileSync(old.certificatePath));
  assert.equal(readFileSync(join(shared, '.env'), 'utf8'), 'APPGOG_DEPLOYMENT_ROLE=license\nEXISTING_SETTING=keep\n');
});