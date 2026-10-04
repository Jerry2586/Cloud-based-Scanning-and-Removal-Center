import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, mkdtemp, chmod, rm, symlink, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
const root = fileURLToPath(new URL('../', import.meta.url));
const entry = await readFile(join(root, 'scripts/git-install-entry.sh'), 'utf8');
const shortEntry = await readFile(join(root, 'scripts/git-install-short.sh'), 'utf8');
const pin = 'ebceaf3a7a7aabd749f185f43c9b0c02deeadc62';
const hash = '5852387ff3f35d7499be3e7e52fdaec4f90f703d80a32949965de150fc4cabc4';
const linux = process.platform === 'linux';
test('online entry pins an accepted immutable installer and matching digest', async () => {
  const pinned = await readFile(join(root, 'install.sh'));
  assert.equal(createHash('sha256').update(pinned).digest('hex'), hash);
  assert.ok(entry.includes('ref=' + pin)); assert.ok(entry.includes(hash)); assert.ok(!entry.includes('ref=main'));
});
test('entry never supplies tokens as URL/arguments or disables transport checks', () => {
  assert.match(entry, /curl -q --proto '=https' --tlsv1\.2/);
  assert.match(entry, /fetch -H @"\$work\/headers"/);
  assert.match(entry, /unset token/);
  assert.doesNotMatch(entry, /--location|--insecure|curl[^\n]* -[Lk]\b/);
  assert.doesNotMatch(entry, /fetch[^\n]*\$token[" ]/);
});
test('README online commands are generated from the tested entry', () => {
  const result = spawnSync(process.execPath, ['scripts/render-git-install.js', '--check'], { cwd: root, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});
async function run(options = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'ironcurtain-online-test-'));
  const bin = join(dir, 'bin'), tokenDir = join(dir, 'etc-ironcurtain');
  await mkdir(bin); await mkdir(tokenDir);
  const tokenFile = join(tokenDir, 'github-release.token');
  const payload = '#!/bin/sh\nprintf "%s\n" "$@" > "$TEST_RECEIPT"\nexit "$TEST_INSTALL_EXIT"\n';
  const payloadFile = join(dir, 'fixture.sh'); await writeFile(payloadFile, payload);
  const payloadHash = createHash('sha256').update(payload).digest('hex');
  const mocks = {
    id: '#!/bin/sh\necho "$TEST_UID"\n',
    uname: '#!/bin/sh\necho "$TEST_OS"\n',
    stat: '#!/bin/sh\ncase "$2" in %u) echo "$TEST_TOKEN_UID" ;; %a) if [ "$3" = "$TEST_TOKEN_FILE" ]; then echo "$TEST_TOKEN_MODE"; else echo "$TEST_PARENT_MODE"; fi ;; *) exit 1 ;; esac\n',
    curl: '#!/bin/sh\nprintf "%s\n" "$@" >> "$TEST_REQUESTS"\ndest=; auth=; header=\nwhile [ "$#" -gt 0 ]; do case "$1" in -o) dest=$2; shift ;; --user) auth=yes; shift ;; -H) case "$2" in @*) header=$2; auth=yes ;; esac; shift ;; esac; shift; done\nif [ "$TEST_DOWNLOAD" = failure ]; then printf 000; exit 7; fi\nif [ "$TEST_DOWNLOAD" = rate_limit ]; then printf 403; exit 22; fi\nif [ "$TEST_DOWNLOAD" = upstream ]; then printf 500; exit 22; fi\nif [ "$TEST_DOWNLOAD" = private ] && [ -z "$auth" ]; then printf 404; exit 22; fi\nprintf 200\ncp "$TEST_PAYLOAD" "$dest"\nif [ "$TEST_DOWNLOAD" = tampered ]; then printf "\n#evil\n" >> "$dest"; fi\n',
    'apt-get': '#!/bin/sh\nprintf "%s\n" "$@" >> "$TEST_PACKAGES"\n[ "$TEST_PACKAGES_FAIL" != 1 ] || exit 1\n'
  };
  for (const [name, body] of Object.entries(mocks)) {
    await writeFile(join(bin, name), body); await chmod(join(bin, name), 0o755);
  }
  if (options.token) await writeFile(tokenFile, options.token);
  if (options.tokenSymlink) {
    await writeFile(join(dir, 'other-token'), 'test_readonly_token'); await symlink(join(dir, 'other-token'), tokenFile);
  }
  const ca = join(dir, 'ca.crt'); await writeFile(ca, 'fixture CA');
  const osRelease = join(dir, 'os-release'); await writeFile(osRelease, 'ID=ubuntu\n');
  const body = (options.short ? shortEntry : entry).replaceAll(hash, options.hashMismatch ? '0'.repeat(64) : payloadHash)
    .replace('token_file=/etc/ironcurtain/github-release.token', 'token_file=' + tokenFile)
    .replace('for parent in /etc/ironcurtain /etc; do', 'for parent in "' + tokenDir + '" "' + dir + '"; do')
    .replace('mktemp -d /tmp/ironcurtain-online.XXXXXXXX', 'mktemp -d "' + dir + '/work.XXXXXXXX"')
    .replace('for ca in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do', 'for ca in "' + ca + '"; do')
    .replaceAll('/etc/os-release', osRelease);
  if (options.missingCa) {
    await rm(ca); await writeFile(join(bin, 'apt-get'), mocks['apt-get'] + 'printf "CA\n" > "' + ca + '"\n');
  }
  const script = join(dir, 'entry.sh'); await writeFile(script, body);
  const requests = join(dir, 'requests'), receipt = join(dir, 'receipt'), packages = join(dir, 'packages');
  const env = { ...process.env, PATH: bin + ':' + process.env.PATH,
    TEST_RECEIPT: receipt, TEST_REQUESTS: requests, TEST_PACKAGES: packages,
    TEST_PAYLOAD: payloadFile, TEST_TOKEN_FILE: tokenFile, TEST_INSTALL_EXIT: '0',
    TEST_UID: '0', TEST_OS: 'Linux', TEST_TOKEN_UID: '0', TEST_TOKEN_MODE: '600', TEST_PARENT_MODE: '700',
    TEST_DOWNLOAD: options.download ?? 'public', TEST_PACKAGES_FAIL: options.packagesFail ? '1' : '0', ...options.env };
  const result = options.readmeCommand
    ? spawnSync('sh', ['-s', '--', options.role ?? 'local'], { input: body, encoding: 'utf8', env })
    : spawnSync('sh', [script, options.role ?? 'local'], { encoding: 'utf8', env });
  const read = async path => { try { return await readFile(path, 'utf8'); } catch { return ''; } };
  const output = { ...result, requests: await read(requests), receipt: await read(receipt), packages: await read(packages), tmpLeft: (await readdir(dir)).filter(name => name.startsWith('work.')) };
  await rm(dir, { recursive: true, force: true }); return output;
}
test('empty-server command downloads and launches only verified local installer', { skip: !linux }, async () => {
  const r = await run({ readmeCommand: true }); assert.equal(r.status, 0, r.stderr);
  assert.match(r.receipt, /^--role\nlocal\n--token-file\n/); assert.deepEqual(r.tmpLeft, []); assert.doesNotMatch(r.requests, /--user/);
});
test('cloud command passes a separate cloud role', { skip: !linux }, async () => {
  const r = await run({ role: 'cloud' }); assert.equal(r.status, 0, r.stderr); assert.match(r.receipt, /--role\ncloud\n/);
});
test('private first fetch retries with hidden curl credential input and no secret argument', { skip: !linux }, async () => {
  const r = await run({ download: 'private' }); assert.equal(r.status, 0, r.stderr);
  assert.match(r.requests, /--user\nJerry2586\n/); assert.match(r.stderr, /不是服务器或 GitHub 登录密码/);
});
test('repeat fetch reuses protected token without leaking it', { skip: !linux }, async () => {
  const secret = 'test_readonly_token', r = await run({ token: secret, download: 'private' });
  assert.equal(r.status, 0, r.stderr); assert.doesNotMatch(r.requests, /--user/);
  assert.ok(![r.requests, r.stdout, r.stderr, r.receipt].some(value => value.includes(secret)));
});
for (const [label, options] of [
  ['tampered response', { download: 'tampered' }], ['wrong expected hash', { hashMismatch: true }],
  ['download failure', { download: 'failure' }], ['package source failure', { missingCa: true, packagesFail: true }], ['world-readable token', { token: 'token', env: { TEST_TOKEN_MODE: '644' } }],
  ['non-root token', { token: 'token', env: { TEST_TOKEN_UID: '1000' } }], ['writable token directory', { token: 'token', env: { TEST_PARENT_MODE: '777' } }],
  ['token symlink', { tokenSymlink: true }], ['header injection token', { token: 'good\nbad header' }],
  ['unsupported role', { role: 'other' }], ['non-root caller', { env: { TEST_UID: '1000' } }], ['non-Linux caller', { env: { TEST_OS: 'Darwin' } }]
]) test(label + ' refuses execution', { skip: !linux }, async () => {
  const r = await run(options); assert.notEqual(r.status, 0); assert.equal(r.receipt, ''); assert.deepEqual(r.tmpLeft, []);
});
test('missing CA triggers bounded package preparation before fetching', { skip: !linux }, async () => {
  const r = await run({ missingCa: true }); assert.equal(r.status, 0, r.stderr); assert.match(r.packages, /update\n/); assert.match(r.packages, /--no-remove/);
});
test('installer failure propagates and cleans up', { skip: !linux }, async () => {
  const r = await run({ env: { TEST_INSTALL_EXIT: '42' } }); assert.equal(r.status, 42); assert.deepEqual(r.tmpLeft, []);
});

for (const download of ['failure', 'rate_limit', 'upstream']) {
  test(download + ' does not request credentials', { skip: !linux }, async () => {
    const r = await run({ download });
    assert.notEqual(r.status, 0); assert.doesNotMatch(r.requests, /--user/); assert.match(r.stderr, /不需要输入 Token/);
  });
}


test('short entry retains pinned download and is materially smaller', () => {
  assert.ok(shortEntry.includes('ref=' + pin)); assert.ok(shortEntry.includes(hash));
  assert.ok(shortEntry.length < entry.length * 0.6);
  assert.match(shortEntry, /curl -q --proto '=https' --tlsv1\.2/);
  assert.doesNotMatch(shortEntry, /--location|--insecure|ref=main/);
});
for (const role of ['local', 'cloud']) test('short README command launches verified ' + role, { skip: !linux }, async () => {
  const r = await run({ short: true, role, readmeCommand: true });
  assert.equal(r.status, 0, r.stderr); assert.equal(r.receipt, '--role\n' + role + '\n');
  assert.deepEqual(r.tmpLeft, []); assert.doesNotMatch(r.requests, /--user/);
});
test('short private entry requests Token without secret arguments', { skip: !linux }, async () => {
  const r = await run({ short: true, download: 'private', readmeCommand: true });
  assert.equal(r.status, 0, r.stderr); assert.match(r.requests, /--user\nJerry2586\n/);
  assert.match(r.stderr, /GitHub 只读 Token/); assert.deepEqual(r.tmpLeft, []);
});
for (const [label, options] of [
  ['tampering', { download: 'tampered' }], ['wrong checksum', { hashMismatch: true }],
  ['package failure', { missingCa: true, packagesFail: true }], ['bad role', { role: 'other' }],
  ['non-root', { env: { TEST_UID: '1000' } }], ['non-Linux', { env: { TEST_OS: 'Darwin' } }]
]) test('short ' + label + ' never launches installer', { skip: !linux }, async () => {
  const r = await run({ ...options, short: true });
  assert.notEqual(r.status, 0); assert.equal(r.receipt, ''); assert.deepEqual(r.tmpLeft, []);
});
for (const download of ['failure', 'rate_limit', 'upstream']) test('short ' + download + ' does not request credentials', { skip: !linux }, async () => {
  const r = await run({ short: true, download });
  assert.notEqual(r.status, 0); assert.equal(r.receipt, ''); assert.doesNotMatch(r.requests, /--user/);
  assert.deepEqual(r.tmpLeft, []);
});
test('short missing CA prepares tools before downloading', { skip: !linux }, async () => {
  const r = await run({ short: true, missingCa: true });
  assert.equal(r.status, 0, r.stderr); assert.match(r.packages, /--no-remove/);
});
test('short installer failure propagates and cleans up', { skip: !linux }, async () => {
  const r = await run({ short: true, env: { TEST_INSTALL_EXIT: '42' } });
  assert.equal(r.status, 42); assert.deepEqual(r.tmpLeft, []);
});
