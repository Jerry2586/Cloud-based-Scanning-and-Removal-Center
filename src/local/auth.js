import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, writeFile, lstat } from 'node:fs/promises';
import { join } from 'node:path';

export function passwordRecord(password) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 256) throw Error('密码须为 12–256 个字符');
  const salt = randomBytes(32).toString('hex');
  return { schema: 1, username: 'admin', salt, hash: scryptSync(password, salt, 64).toString('hex') };
}
export function validCredentials(value) {
  return value?.schema === 1 && value.username === 'admin' && /^[a-f0-9]{64}$/.test(value.salt) && /^[a-f0-9]{128}$/.test(value.hash);
}
export function verifyPassword(record, password) {
  if (!validCredentials(record) || typeof password !== 'string' || password.length > 256) return false;
  return timingSafeEqual(scryptSync(password, record.salt, 64), Buffer.from(record.hash, 'hex'));
}
export async function readCredentials(directory) {
  const file = join(directory, 'panel-auth.json');
  const meta = await lstat(file);
  if (!meta.isFile() || meta.isSymbolicLink() || (process.platform !== 'win32' && (meta.mode & 0o077))) throw Error('面板凭据权限不安全');
  const value = JSON.parse(await readFile(file, 'utf8'));
  if (!validCredentials(value)) throw Error('面板凭据无效；拒绝重置既有身份');
  return value;
}
export async function loadCredentials(directory, initialPassword) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const file = join(directory, 'panel-auth.json');
  try {
    return await readCredentials(directory);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const password = initialPassword || randomBytes(24).toString('base64url');
  const record = passwordRecord(password);
  await writeFile(file, JSON.stringify(record) + '\n', { mode: 0o600, flag: 'wx' });
  await writeFile(join(directory, 'initial-credentials.txt'), 'admin\n' + password + '\n', { mode: 0o600, flag: 'wx' });
  return record;
}
export function createSessions({ now = Date.now, ttl = 1800000, maximum = 128 } = {}) {
  const entries = new Map();
  const prune = () => { for (const [id, value] of entries) if (value.expires <= now()) entries.delete(id); };
  return Object.freeze({
    create() {
      prune();
      if (entries.size >= maximum) return null;
      const id = randomBytes(32).toString('hex');
      const session = { csrf: randomBytes(32).toString('hex'), expires: now() + ttl };
      entries.set(id, session); return { id, ...session };
    },
    get(id) { prune(); return entries.get(id); },
    remove(id) { entries.delete(id); },
    clear() { entries.clear(); },
  });
}
export function equalSecret(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length > 128 || b.length > 128) return false;
  const left=Buffer.from(a), right=Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left,right);
}
