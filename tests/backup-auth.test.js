import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import test from 'node:test';

const helper = fileURLToPath(new URL('../scripts/backup-auth.js', import.meta.url));
const run = (...args) => spawnSync(process.execPath, [helper, ...args], { encoding: 'utf8' });

test('backup authentication creates and verifies HMAC and rejects every modified input', () => {
  const dir = mkdtempSync(join(tmpdir(), 'appgog-backup-auth-'));
  try {
    const key = join(dir, 'mac.key');
    const input = join(dir, 'backup.enc');
    const tag = join(dir, 'backup.enc.hmac');
    writeFileSync(key, Buffer.alloc(48, 0x41));
    writeFileSync(input, Buffer.from('APPGOG-BACKUP-V2\ntrusted ciphertext'));
    const created = run('create', key, input);
    assert.equal(created.status, 0, created.stderr);
    assert.match(created.stdout, /^[0-9a-f]{64}\n$/);
    writeFileSync(tag, created.stdout);
    assert.equal(run('verify', key, input, tag).status, 0);

    writeFileSync(input, Buffer.from('APPGOG-BACKUP-V2\ntampered ciphertext'));
    assert.notEqual(run('verify', key, input, tag).status, 0);
    writeFileSync(input, Buffer.from('APPGOG-BACKUP-V2\ntrusted ciphertext'));
    writeFileSync(tag, `${'0'.repeat(64)}\n`);
    assert.notEqual(run('verify', key, input, tag).status, 0);
    writeFileSync(tag, 'not-a-tag\n');
    assert.notEqual(run('verify', key, input, tag).status, 0);
    writeFileSync(key, readFileSync(key).subarray(0, 16));
    assert.notEqual(run('create', key, input).status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('derived encryption password covers every key byte including NUL and newlines', () => {
  const dir = mkdtempSync(join(tmpdir(), 'appgog-backup-derive-'));
  try {
    const key = join(dir, 'backup.key');
    const bytes = Buffer.concat([Buffer.from('first-line\nsecond-line\0'), Buffer.alloc(48, 0xa5)]);
    writeFileSync(key, bytes);
    const derived = run('derive', key);
    assert.equal(derived.status, 0, derived.stderr);
    const expected = createHash('sha256').update(bytes).digest('base64url');
    assert.equal(derived.stdout, `${expected}\n`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('V3 pack and verify-extract reject header, ciphertext, and key tampering without output', () => {
  const dir = mkdtempSync(join(tmpdir(), 'appgog-backup-v3-'));
  try {
    const key = join(dir, 'mac.key');
    const wrongKey = join(dir, 'wrong.key');
    const ciphertext = join(dir, 'ciphertext');
    const backup = join(dir, 'backup.enc');
    const extracted = join(dir, 'extracted');
    writeFileSync(key, Buffer.alloc(48, 0x41));
    writeFileSync(wrongKey, Buffer.alloc(48, 0x42));
    writeFileSync(ciphertext, Buffer.from('ciphertext\0with\nall bytes'));

    const packed = run('pack', key, ciphertext, backup);
    assert.equal(packed.status, 0, packed.stderr);
    assert.match(readFileSync(backup, 'utf8'), /^APPGOG-BACKUP-V3\n[0-9a-f]{64}\n/);
    const verified = run('verify-extract', key, backup, extracted);
    assert.equal(verified.status, 0, verified.stderr);
    assert.deepEqual(readFileSync(extracted), readFileSync(ciphertext));

    const original = readFileSync(backup);
    const formatTampered = Buffer.from(original);
    formatTampered[15] ^= 1;
    const hmacTampered = Buffer.from(original);
    hmacTampered[18] = hmacTampered[18] === 0x30 ? 0x31 : 0x30;
    const ciphertextTampered = Buffer.from(original);
    ciphertextTampered[ciphertextTampered.length - 1] ^= 1;
    const truncated = original.subarray(0, original.length - 1);
    const incompleteHeader = Buffer.from('APPGOG-BACKUP-V3\n');
    const missingCiphertext = Buffer.from(`APPGOG-BACKUP-V3\n${'0'.repeat(64)}\n`);
    const cases = [
      ['wrong-key', wrongKey, original],
      ['format-header', key, formatTampered],
      ['hmac-header', key, hmacTampered],
      ['ciphertext', key, ciphertextTampered],
      ['truncated', key, truncated],
      ['incomplete-header', key, incompleteHeader],
      ['missing-ciphertext', key, missingCiphertext],
    ];
    for (const [name, selectedKey, content] of cases) {
      const candidate = join(dir, `${name}.enc`);
      const output = `${candidate}.out`;
      writeFileSync(candidate, content);
      assert.notEqual(run('verify-extract', selectedKey, candidate, output).status, 0, name);
      assert.equal(existsSync(output), false, `${name} left unauthenticated output`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('V3 pack rejects empty ciphertext and removes a partially reserved output', () => {
  const dir = mkdtempSync(join(tmpdir(), 'appgog-backup-empty-'));
  try {
    const key = join(dir, 'mac.key');
    const ciphertext = join(dir, 'ciphertext');
    const backup = join(dir, 'backup.enc');
    writeFileSync(key, Buffer.alloc(48, 0x41));
    writeFileSync(ciphertext, Buffer.alloc(0));

    const packed = run('pack', key, ciphertext, backup);
    assert.notEqual(packed.status, 0);
    assert.equal(existsSync(backup), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
