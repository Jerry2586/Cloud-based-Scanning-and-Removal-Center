import http from 'node:http';
import https from 'node:https';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { createSessions, equalSecret, loadCredentials, verifyPassword } from './auth.js';
import { createCloudLink } from './cloud-client.js';
import { localSecurityScan, localCloudSnapshot } from './scan-client.js';
import { localUpdate } from './update-client.js';
import { sanitizeUpdateStatus } from '../contracts/update-status.js';
const RUNNING_VERSION = JSON.parse(await readFile(new URL('../../package.json', import.meta.url))).version;

const PUBLIC = new URL('./public/', import.meta.url);
const ASSETS = new Map([
  ['/contracts/antivirus-status.js', [new URL('../contracts/antivirus-status.js', import.meta.url), 'text/javascript; charset=utf-8']],
  ['/contracts/checkup-status.js', [new URL('../contracts/checkup-status.js', import.meta.url), 'text/javascript; charset=utf-8']],
  ['/contracts/update-status.js', [new URL('../contracts/update-status.js', import.meta.url), 'text/javascript; charset=utf-8']],
  ['/contracts/host-scan-contract.js', [new URL('../contracts/host-scan-contract.js', import.meta.url), 'text/javascript; charset=utf-8']],
  ['/contracts/environment-status.js', [new URL('../contracts/environment-status.js', import.meta.url), 'text/javascript; charset=utf-8']],
  ['/contracts/protection-status.js', [new URL('../contracts/protection-status.js', import.meta.url), 'text/javascript; charset=utf-8']],
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/assets/local.css', ['assets/local.css', 'text/css; charset=utf-8']],
  ['/assets/security-preview.css', ['assets/security-preview.css', 'text/css; charset=utf-8']],
  ['/assets/ironcurtain-shield.webp', ['assets/ironcurtain-shield.webp', 'image/webp']],
  ...['app', 'security-ui', 'security-console', 'security-poller','host-workspace','update-settings'].map(name => ['/assets/portal/' + name + '.js', ['assets/portal/' + name + '.js', 'text/javascript; charset=utf-8']]),
]);
function json(res, code, data) { res.writeHead(code, { 'content-type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(data)); }
async function body(req) {
  if (!/^application\/json(?:;.*)?$/.test(req.headers['content-type'] || '')) throw Object.assign(Error('请求须为 JSON'), { status: 415 });
  const chunks = []; let size = 0;
  for await (const chunk of req) { size += chunk.length; if (size > 1024) throw Object.assign(Error('请求过大'), { status: 413 }); chunks.push(chunk); }
  try { const value = JSON.parse(Buffer.concat(chunks)); if (!value || Array.isArray(value) || typeof value !== 'object') throw Error(); return value; }
  catch { throw Object.assign(Error('请求格式无效'), { status: 400 }); }
}
export function createLocalServer({ credentials, origin, tls, scan = localSecurityScan, updates = localUpdate,
  cloudStatus = async () => ({ state: 'unpaired', connected: false, reason: '玄武引擎尚未配对' }), now = Date.now } = {}) {
  const target = new URL(origin);
  if (!['http:', 'https:'].includes(target.protocol) || target.pathname !== '/' || target.search || target.hash || target.username || target.password) throw Error('面板来源配置无效');
  const secure = target.protocol === 'https:';
  if (!secure && !['127.0.0.1', '[::1]', 'localhost'].includes(target.hostname)) throw Error('公网面板必须启用 HTTPS');
  const sessions = createSessions({ now }); const attempts = new Map();
  const cookie = id => 'ironcurtain_session=' + id + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=1800' + (secure ? '; Secure' : '');
  async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer'); res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    if (secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    try {
      if (req.headers.host !== target.host) return json(res, 421, { error: '面板地址不匹配' });
      const url = new URL(req.url, target.origin);
      if (url.origin !== target.origin) return json(res, 400, { error: '地址无效' });
      if (req.method === 'GET' && url.pathname === '/healthz') return json(res, 200, { service: 'ironcurtain-local', ready: true });
      if (req.method === 'GET' && ASSETS.has(url.pathname)) {
        const [file, type] = ASSETS.get(url.pathname); const data = await readFile(new URL(file, PUBLIC));
        res.writeHead(200, { 'content-type': type }); return res.end(data);
      }
      if (!['GET', 'POST'].includes(req.method)) return json(res, 405, { error: '方法不支持' });
      if (req.method === 'POST' && req.headers.origin !== target.origin) return json(res, 403, { error: '来源验证失败' });
      const match = /(?:^|;\s*)ironcurtain_session=([a-f0-9]{64})(?:;|$)/.exec(req.headers.cookie || '');
      const sessionId = match?.[1]; const session = sessions.get(sessionId);
      if (req.method === 'POST' && url.pathname === '/api/login') {
        const ip = req.socket.remoteAddress || 'unknown'; const time = now();
        for (const [key, item] of attempts) if (item.until <= time) attempts.delete(key);
        const entry = attempts.get(ip) || { count: 0, until: time + 600000 };
        if (entry.count >= 5 || (!attempts.has(ip) && attempts.size >= 1024)) return json(res, 429, { error: '登录过于频繁，请稍后重试' });
        const value = await body(req); entry.count++; attempts.set(ip, entry);
        if (Object.keys(value).some(key => !['username', 'password'].includes(key)) || value.username !== 'admin' || !verifyPassword(credentials, value.password)) return json(res, 401, { error: '账号或密码错误' });
        const created = sessions.create(); if (!created) return json(res, 503, { error: '会话数已达上限' });
        attempts.delete(ip); res.setHeader('Set-Cookie', cookie(created.id)); return json(res, 200, { authenticated: true, csrf: created.csrf, username: 'admin' });
      }
      if (req.method === 'GET' && url.pathname === '/api/session') return json(res, 200, session ? { authenticated: true, username: 'admin', csrf: session.csrf } : { authenticated: false });
      if (!session) return json(res, 401, { error: '请登录铁幕安全' });
      if (req.method === 'POST') {
        if (!equalSecret(req.headers['x-csrf-token'], session.csrf)) return json(res, 403, { error: '会话验证失败' });
        const value = await body(req);
        if (Object.keys(value).length !== 0) return json(res, 400, { error: '此操作不接受路径或命令参数' });
        if (url.pathname === '/api/logout') { sessions.remove(sessionId); res.setHeader('Set-Cookie', 'ironcurtain_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0' + (secure ? '; Secure' : '')); return json(res, 200, { authenticated: false }); }
        if (['/api/updates/check','/api/updates/install'].includes(url.pathname)) { const result = await updates(url.pathname.endsWith('/check') ? 'check' : 'install'); return json(res, [202,409,429,503].includes(result.response_status) ? result.response_status : 503, { state: result.state === 'running' ? 'running' : 'unavailable', reason: result.response_status === 409 ? '已有版本任务正在执行，请等待完成。' : result.response_status === 429 ? '请求过于频繁，请稍后再试。' : result.response_status === 202 ? '版本任务已受理。' : '版本任务无法启动，请在 Linux 菜单检查服务。' }); }
        if (['/api/scan','/api/full-scan','/api/checkup','/api/engine/update'].includes(url.pathname)) { const result = await scan(url.pathname === '/api/engine/update' ? 'engine-update' : url.pathname === '/api/checkup' ? 'checkup' : url.pathname === '/api/full-scan' ? 'full-scan' : 'scan'); return json(res, result.state === 'running' ? 202 : [409,429,503].includes(result.response_status) ? result.response_status : 503, result); }
      }
      if (req.method === 'GET' && url.pathname === '/api/updates') return json(res, 200, { ...sanitizeUpdateStatus(await updates('status')), running_version: RUNNING_VERSION });
      if (req.method === 'GET' && url.pathname === '/api/scan') return json(res, 200, await scan('status'));
      if (req.method === 'GET' && url.pathname === '/api/cloud/status') return json(res, 200, await cloudStatus());
      return json(res, 404, { error: '接口不存在' });
    } catch (error) { if (!res.headersSent) json(res, error.status || 503, { error: error.status ? error.message : '本地服务暂不可用' }); else res.destroy(); }
  }
  const server = tls ? https.createServer(tls, handler) : http.createServer(handler);
  server.requestTimeout = 10000; server.headersTimeout = 10000; server.maxHeadersCount = 32;
  server.on('clientError', (_error, socket) => socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'));
  return server;
}
export async function startLocal(env = process.env) {
  const host = env.IRONCURTAIN_LISTEN_HOST || '127.0.0.1'; const port = Number(env.IRONCURTAIN_PORT || 8790);
  const origin = env.IRONCURTAIN_PUBLIC_ORIGIN || 'http://127.0.0.1:' + port;
  const tls = env.IRONCURTAIN_TLS_CERT && env.IRONCURTAIN_TLS_KEY ? { cert: await readFile(env.IRONCURTAIN_TLS_CERT), key: await readFile(env.IRONCURTAIN_TLS_KEY) } : undefined;
  if (!tls && !['127.0.0.1', '::1'].includes(host)) throw Error('公网监听必须配置独立面板 TLS 证书');
  const credentials = await loadCredentials(env.IRONCURTAIN_CONFIG_DIR || '/etc/ironcurtain', env.IRONCURTAIN_INITIAL_PASSWORD);
  const cloud = createCloudLink({ directory: env.IRONCURTAIN_CLOUD_DIR || '/etc/ironcurtain/cloud', snapshot: () => localCloudSnapshot(env) });
  const server = createLocalServer({ credentials, origin, tls, scan: action => localSecurityScan(action, env), updates: action => localUpdate(action, env), cloudStatus: () => cloud.status() });
  server.once('close', () => cloud.close());
  await new Promise((resolveStart, reject) => { server.once('error', reject); server.listen(port, host, resolveStart); });
  console.log('铁幕安全独立面板已启动：' + origin);
  return server;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await startLocal();
