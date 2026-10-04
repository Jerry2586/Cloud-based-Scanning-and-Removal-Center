#!/usr/bin/env node
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { createReadStream, createWriteStream, openSync, closeSync, fstatSync, readFileSync, readSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { pipeline } from 'node:stream/promises';

const FORMAT = 'APPGOG-BACKUP-V3';
const [command, keyPath, inputPath, outputPath] = process.argv.slice(2);
if (!['create', 'verify', 'derive', 'pack', 'verify-extract'].includes(command)
  || !keyPath || (command !== 'derive' && !inputPath)
  || (['verify', 'pack', 'verify-extract'].includes(command) && !outputPath)) {
  console.error('Usage: backup-auth.js create KEY INPUT | verify KEY INPUT TAG | derive KEY | pack KEY CIPHERTEXT OUTPUT | verify-extract KEY BACKUP OUTPUT');
  process.exit(2);
}

const key = readFileSync(keyPath);
if (key.length < 32) throw Error('Backup authentication key must contain at least 32 bytes');

if (command === 'derive') {
  process.stdout.write(`${createHash('sha256').update(key).digest('base64url')}\n`);
  process.exit(0);
}

async function digestFile(path, start = 0, prefix = Buffer.alloc(0)) {
  return await new Promise((resolve, reject) => {
    const hmac = createHmac('sha256', key);
    hmac.update(prefix);
    const input = createReadStream(path, { start });
    input.on('data', chunk => hmac.update(chunk));
    input.on('error', reject);
    input.on('end', () => resolve(hmac.digest('hex')));
  });
}

function authenticatedHeader(path) {
  const descriptor = openSync(path, 'r');
  try {
    const buffer = Buffer.alloc(256);
    const bytes = readSync(descriptor, buffer, 0, buffer.length, 0);
    const first = buffer.subarray(0, bytes).indexOf(0x0a);
    const second = first < 0 ? -1 : buffer.subarray(first + 1, bytes).indexOf(0x0a);
    if (first < 0 || second < 0) throw Error('Authenticated backup header is incomplete');
    const tagEnd = first + 1 + second;
    const format = buffer.subarray(0, first).toString('utf8');
    const tag = buffer.subarray(first + 1, tagEnd).toString('utf8');
    if (format !== FORMAT || !/^[0-9a-f]{64}$/.test(tag)) throw Error('Authenticated backup header is invalid');
    if (tagEnd + 1 >= fstatSync(descriptor).size) throw Error('Authenticated backup ciphertext is empty');
    return { tag, offset: tagEnd + 1 };
  } finally {
    closeSync(descriptor);
  }
}

if (command === 'pack') {
  try {
    if (statSync(inputPath).size === 0) throw Error('Authenticated backup ciphertext is empty');
    const digest = await digestFile(inputPath, 0, Buffer.from(`${FORMAT}\n`));
    writeFileSync(outputPath, `${FORMAT}\n${digest}\n`, { mode: 0o600, flag: 'wx' });
    await pipeline(createReadStream(inputPath), createWriteStream(outputPath, { flags: 'a', mode: 0o600 }));
  } catch (error) {
    try { unlinkSync(outputPath); } catch {}
    throw error;
  }
  process.exit(0);
}

if (command === 'verify-extract') {
  const { tag, offset } = authenticatedHeader(inputPath);
  try {
    const digest = await digestFile(inputPath, offset, Buffer.from(`${FORMAT}\n`));
    if (!timingSafeEqual(Buffer.from(digest, 'hex'), Buffer.from(tag, 'hex'))) throw Error('Backup authentication failed');
    await pipeline(createReadStream(inputPath, { start: offset }), createWriteStream(outputPath, { mode: 0o600, flag: 'wx' }));
  } catch (error) {
    try { unlinkSync(outputPath); } catch {}
    throw error;
  }
  process.exit(0);
}

const digest = await digestFile(inputPath);

if (command === 'create') {
  process.stdout.write(`${digest}\n`);
} else {
  const expected = readFileSync(outputPath, 'utf8').trim();
  if (!/^[0-9a-f]{64}$/.test(expected)
    || !timingSafeEqual(Buffer.from(digest, 'hex'), Buffer.from(expected, 'hex'))) {
    console.error('Backup authentication failed');
    process.exit(1);
  }
}
