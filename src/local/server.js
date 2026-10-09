import {localOperations} from './operations-client.js';
import {validateOperation,sanitizeOperations} from '../contracts/operations-status.js';
import {localSchedule} from './schedule-client.js';
import {validateScheduleConfig, sanitizeSchedule} from '../contracts/schedule.js';
import { validateHashRequest, validateHashJob } from '../contracts/hash-intelligence.js';
import {localEngineReadiness} from './engine-readiness-client.js';
import {sanitizeEngineReadiness} from '../contracts/engine-readiness.js';
import {accountPassword} from './account-client.js';
import http from 'node:http';
import https from 'node:https';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { createSessions, equalSecret, loadCredentials, readCredentials, verifyPassword } from './auth.js';
import { createCloudLink } from './cloud-client.js';
import { localSecurityScan, localCloudSnapshot } from './scan-client.js';
import { localMultiEngine } from './multi-engine-client.js';
import { sanitizeMultiEngine } from '../contracts/multi-engine-status.js';
import { localUpdate } from './update-client.js';
import { domainRequest, domainConfiguration, domainTls, domainChallenge } from './domain-client.js';
import { sanitizeUpdateStatus } from '../contracts/update-status.js';
const RUNNING_VERSION = JSON.parse(await readFile(new URL('../../package.json', import.meta.url))).version;

const PUBLIC = new URL('./public/', import.meta.url);
const ASSETS = new Map([
  ['/contracts/operations-status.js',[new URL('../contracts/operations-status.js',import.meta.url),'text/javascript; charset=utf-8']],
  ['/contracts/schedule.js', [new URL('../contracts/schedule.js', import.meta.url), 'text/javascript; charset=utf-8']],
  ['/contracts/hash-intelligence.js', [new URL('../contracts/hash-intelligence.js', import.meta.url), 'text/javascript; charset=utf-8']],
 ['/contracts/engine-readiness.js',[new URL('../contracts/engine-readiness.js',import.meta.url),'text/javascript; charset=utf-8']],
  ['/contracts/multi-engine-status.js', [new URL('../contracts/multi-engine-status.js', import.meta.url), 'text/javascript; charset=utf-8']],
  ['/contracts/antivirus-status.js', [new URL('../contracts/antivirus-status.js', import.meta.url), 'text/javascript; charset=utf-8']],
  ['/contracts/local-workbench.js', [new URL('../contracts/local-workbench.js', import.meta.url), 'text/javascript; charset=utf-8']],
  ['/contracts/checkup-status.js', [new URL('../contracts/checkup-status.js', import.meta.url), 'text/javascript; charset=utf-8']],
  ['/contracts/update-status.js', [new URL('../contracts/update-status.js', import.meta.url), 'text/javascript; charset=utf-8']],
  ['/contracts/host-scan-contract.js', [new URL('../contracts/host-scan-contract.js', import.meta.url), 'text/javascript; charset=utf-8']],
  ['/contracts/environment-status.js', [new URL('../contracts/environment-status.js', import.meta.url), 'text/javascript; charset=utf-8']],
  ['/contracts/protection-status.js', [new URL('../contracts/protection-status.js', import.meta.url), 'text/javascript; charset=utf-8']],
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/assets/theme.js', ['assets/theme.js', 'text/javascript; charset=utf-8']],
  ['/assets/theme.css', ['assets/theme.css', 'text/css; charset=utf-8']],
  ['/assets/workbench.css', ['assets/workbench.css', 'text/css; charset=utf-8']],
  ['/assets/local.css', ['assets/local.css', 'text/css; charset=utf-8']],
  ['/assets/security-preview.css', ['assets/security-preview.css', 'text/css; charset=utf-8']],
  ['/assets/ironcurtain-shield.webp', ['assets/ironcurtain-shield.webp', 'image/webp']],
  ...['app', 'security-ui', 'security-console', 'security-poller','host-workspace','operations-workspace','update-settings','schedule-settings','domain-settings','multi-engine','engine-readiness','engine-labels','cloud-intelligence'].map(name => ['/assets/portal/' + name + '.js', ['assets/portal/' + name + '.js', 'text/javascript; charset=utf-8']]),
]);
function json(res, code, data) { res.writeHead(code, { 'content-type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(data)); }
async function body(req) {
  if (!/^application\/json(?:;.*)?$/.test(req.headers['content-type'] || '')) throw Object.assign(Error('请求须为 JSON'), { status: 415 });
  const chunks = []; let size = 0;
  for await (const chunk of req) { size += chunk.length; if (size > 4096) throw Object.assign(Error('请求过大'), { status: 413 }); chunks.push(chunk); }
  try { const value = JSON.parse(Buffer.concat(chunks)); if (!value || Array.isArray(value) || typeof value !== 'object') throw Error(); return value; }
  catch { throw Object.assign(Error('请求格式无效'), { status: 400 }); }
}
export function createLocalServer({ credentials, origin, tls, scan = localSecurityScan, updates = localUpdate, multi = localMultiEngine, engines = localEngineReadiness, schedule = localSchedule, operations = localOperations,
  domains = domainRequest, credentialDirectory, changePassword = accountPassword, domainDirectory, panelPort, role = 'local', control, cloudTasks, cloudStatus = async () => ({ state: 'unpaired', connected: false, reason: '玄武引擎尚未配对' }), assets = ASSETS, publicDirectory = PUBLIC, now = Date.now } = {}) {
  let credentialRead = Promise.resolve();
  const refreshCredentials = () => {
    const next = credentialRead.then(async () => {
      if (!credentialDirectory) return;
      const latest = await readCredentials(credentialDirectory);
      if (latest.hash !== credentials.hash || latest.salt !== credentials.salt) {credentials = latest; sessions.clear();}
    });
    credentialRead = next.catch(() => {});
    return next;
  };
  const target = new URL(origin);
  if (!['http:', 'https:'].includes(target.protocol) || target.pathname !== '/' || target.search || target.hash || target.username || target.password) throw Error('面板来源配置无效');
  const secure = target.protocol === 'https:';
  if (!secure && !['127.0.0.1', '[::1]', 'localhost'].includes(target.hostname)) throw Error('公网面板必须启用 HTTPS');
  const sessions = createSessions({ now }); const attempts = new Map();
  const cookie = id => 'ironcurtain_session=' + id + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=1800' + (secure ? '; Secure' : '');
  async function taskNodeId() {
    const id=await cloudTasks?.nodeId?.();
    if(typeof id!=='string' || !/^(?:node-[a-z0-9][a-z0-9-]{0,63}|license-center|build-center)$/.test(id)) throw Error('INVALID_CLOUD_NODE_ID');
    return id;
  }
  async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer'); res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    if (secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    try {
      const configured = domainDirectory ? domainConfiguration(domainDirectory) : null;
      const hosts = new Map([[target.host, target.origin]]);
      if (configured) {
        hosts.set(configured.domain, configured.origin);
        hosts.set(configured.domain + ':' + (panelPort || target.port || (role === 'cloud' ? 8791 : 8790)), configured.origin + ':' + (panelPort || target.port || (role === 'cloud' ? 8791 : 8790)));
      }
      const effectiveOrigin = hosts.get(req.headers.host);
      if (req.method === 'GET' && domainDirectory) {
        const challenge = domainChallenge(domainDirectory, req.headers.host, req.url, target.host);
        if (challenge) { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end(challenge); }
      }
      if (!effectiveOrigin) return json(res, 421, { error: '面板地址不匹配' });
      const url = new URL(req.url, effectiveOrigin);
      if (url.origin !== effectiveOrigin) return json(res, 400, { error: '地址无效' });
      if (req.method === 'GET' && url.pathname === '/healthz') return json(res, 200, { service: role === 'cloud' ? 'xuanwu-admin' : 'ironcurtain-local', ready: true });
      if (req.method === 'GET' && assets.has(url.pathname)) {
        const [file, type] = assets.get(url.pathname); const data = await readFile(new URL(file, publicDirectory));
        res.writeHead(200, { 'content-type': type }); return res.end(data);
      }
      if (!['GET', 'POST'].includes(req.method)) return json(res, 405, { error: '方法不支持' });
      if (req.method === 'POST' && req.headers.origin !== effectiveOrigin) return json(res, 403, { error: '来源验证失败' });
      await refreshCredentials();
      const match = /(?:^|;\s*)ironcurtain_session=([a-f0-9]{64})(?:;|$)/.exec(req.headers.cookie || '');
      const sessionId = match?.[1]; const session = sessions.get(sessionId);
      if (req.method === 'POST' && url.pathname === '/api/login') {
        const ip = req.socket.remoteAddress || 'unknown'; const time = now();
        for (const [key, item] of attempts) if (item.until <= time) attempts.delete(key);
        const entry = attempts.get(ip) || { count: 0, until: time + 600000 };
        if (entry.count >= 5 || (!attempts.has(ip) && attempts.size >= 1024)) return json(res, 429, { error: '登录过于频繁，请稍后重试' });
        const value = await body(req); await refreshCredentials(); entry.count++; attempts.set(ip, entry);
        if (Object.keys(value).some(key => !['username', 'password'].includes(key)) || value.username !== 'admin' || !verifyPassword(credentials, value.password)) return json(res, 401, { error: '账号或密码错误' });
        const created = sessions.create(); if (!created) return json(res, 503, { error: '会话数已达上限' });
        attempts.delete(ip); res.setHeader('Set-Cookie', cookie(created.id)); return json(res, 200, { authenticated: true, csrf: created.csrf, username: 'admin' });
      }
      if (req.method === 'GET' && url.pathname === '/api/session') return json(res, 200, session ? { authenticated: true, username: 'admin', csrf: session.csrf } : { authenticated: false });
      if (!session) return json(res, 401, { error: role === 'cloud' ? '请登录玄武引擎' : '请登录铁幕安全' });
      if (req.method === 'POST') {
        if (!equalSecret(req.headers['x-csrf-token'], session.csrf)) return json(res, 403, { error: '会话验证失败' });
        const value = await body(req);
        await refreshCredentials();
        if (sessions.get(sessionId) !== session) return json(res,401,{error:'登录已失效，请重新登录'});
        if (url.pathname === '/api/account/password') {
          const key = 'password:' + sessionId; const at = now();
          for (const [id, entry] of attempts) if (entry.until <= at) attempts.delete(id);
          const entry = attempts.get(key) || {count:0, until:at+600000};
          if (entry.count >= 5 || (!attempts.has(key) && attempts.size >= 1024)) return json(res,429,{error:'密码验证过于频繁，请稍后重试'});
          if (Object.keys(value).length !== 2 || !Object.hasOwn(value,'current_password') || !Object.hasOwn(value,'new_password') ||
            typeof value.new_password !== 'string' || value.new_password.length < 12 || value.new_password.length > 256 || /[\r\n\0]/.test(value.new_password)) return json(res,400,{error:'新密码须为 12–256 个字符，且不能包含换行或空字符'});
          entry.count++; attempts.set(key,entry);
          if (!verifyPassword(credentials,value.current_password)) return json(res,400,{error:'当前密码错误'});
          if (verifyPassword(credentials,value.new_password)) return json(res,400,{error:'新密码不能与当前密码相同'});
          const result = await changePassword(value);
          if (result.response_status !== 200 || result.changed !== true) return json(res,[400,403,409,503].includes(result.response_status)?result.response_status:503,{error:result.error || '密码更改未完成'});
          // Reload on subsequent requests, invalidating every existing session on both CLI and web changes.
          sessions.clear(); attempts.delete(key);
          await refreshCredentials();
          res.setHeader('Set-Cookie','ironcurtain_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0' + (secure?'; Secure':''));
          return json(res,200,{changed:true,authenticated:false});
        }
        if (role === 'cloud' && control) {
          if (url.pathname === '/api/plugins') return json(res, 200, control.pluginAction('admin', value));
          if (url.pathname === '/api/policy') return json(res, 200, control.setPolicy('admin', value));
          if (url.pathname === '/api/intelligence') { const input=validateHashRequest(value); return json(res,202,validateHashJob(control.enqueue('admin',input),{requester:'admin',sha256:input.sha256})); }
        }
        if (role === 'local' && cloudTasks && url.pathname === '/api/intelligence') { const request=validateHashRequest(value); return json(res,202,validateHashJob(await cloudTasks.submitHash(request),{nodeId:await taskNodeId(),sha256:request.sha256})); };
        if (role === 'local' && url.pathname === '/api/schedule') {
          let config; try { config = validateScheduleConfig(value); } catch (error) { return json(res, 400, {error: error.message}); }
          const result = await schedule('save', config);
          if (result.response_status === 200) {
            const clean = sanitizeSchedule(result.state === 'ready' ? {schema:result.schema,state:result.state,config:result.config,records:result.records} : result);
            return json(res, clean.state === 'ready' ? 200 : 503, clean);
          }
          return json(res, [400,409,503].includes(result.response_status) ? result.response_status : 503, {error: result.response_status === 409 ? '配置已变化或检测正在运行，请刷新后再保存' : '本机周期配置无法保存'});
        }
        if (role === 'local' && url.pathname === '/api/operations') {
          let input;try {input=validateOperation(value);}catch(error){return json(res,400,{error:error.message});}
          const result=await operations('apply',input);const clean=sanitizeOperations(result);
          const accepted=result.response_status===202 && clean.state==='running' && clean.job.action===input.action;
          return json(res,accepted?202:[400,409].includes(result.response_status)?result.response_status:503,accepted?clean:{error:result.reason || '处置任务无法启动'});
        }
        if (url.pathname === '/api/domain') { const result = await domains('save', value); return json(res, result.response_status || 503, result); }
        if (Object.keys(value).length !== 0) return json(res, 400, { error: '此操作不接受路径或命令参数' });
        if (url.pathname === '/api/logout') { sessions.remove(sessionId); res.setHeader('Set-Cookie', 'ironcurtain_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0' + (secure ? '; Secure' : '')); return json(res, 200, { authenticated: false }); }
        if (['/api/updates/check','/api/updates/install'].includes(url.pathname)) { const result = await updates(url.pathname.endsWith('/check') ? 'check' : 'install'); return json(res, [202,409,429,503].includes(result.response_status) ? result.response_status : 503, { state: result.state === 'running' ? 'running' : 'unavailable', reason: result.response_status === 409 ? result.conflict === 'management-active' ? '本机检测或管理任务正在运行，程序更新尚未启动。请等待当前任务结束后重试。' : '已有版本任务正在执行，请等待完成。' : result.response_status === 429 ? '请求过于频繁，请稍后再试。' : result.response_status === 202 ? '版本任务已受理。' : '版本任务无法启动，请在 Linux 菜单检查服务。' }); }
        if (role === 'local' && url.pathname === '/api/engines/check') { const result=sanitizeEngineReadiness(await engines('check')); return json(res,[202,409,429,503].includes(result.response_status)?result.response_status:503,result); }
        if (role === 'local' && url.pathname === '/api/multi-engine') { const result = sanitizeMultiEngine(await multi('start')); return json(res, [202,409,429,503].includes(result.response_status) ? result.response_status : 503, result); }
        if (role === 'local' && ['/api/scan','/api/full-scan','/api/checkup','/api/engine/update'].includes(url.pathname)) { const result = await scan(url.pathname === '/api/engine/update' ? 'engine-update' : url.pathname === '/api/checkup' ? 'checkup' : url.pathname === '/api/full-scan' ? 'full-scan' : 'scan'); return json(res, result.state === 'running' ? 202 : [409,429,503].includes(result.response_status) ? result.response_status : 503, result); }
      }
      if (role === 'cloud' && control && req.method === 'GET') {
        if (url.pathname === '/api/control') return json(res, 200, { ...control.snapshot(), running_version: RUNNING_VERSION });
        const task = /^\/api\/intelligence\/([a-f0-9-]{36})$/.exec(url.pathname);
        if (task) return json(res, 200, validateHashJob(control.job('admin', task[1]),{id:task[1]}));
      }
      if (role === 'local' && cloudTasks && req.method === 'GET') {
        const task=/^\/api\/intelligence\/([a-f0-9-]{36})$/.exec(url.pathname);
        if(task) return json(res,200,validateHashJob(await cloudTasks.hashJob(task[1]),{nodeId:await taskNodeId(),id:task[1]}));
      }
      if (role === 'local' && req.method === 'GET' && url.pathname === '/api/operations') {const clean=sanitizeOperations(await operations('status'));return json(res,clean.state==='ready'?200:503,clean);}
      if (role === 'local' && req.method === 'GET' && url.pathname === '/api/schedule') {
        const result = await schedule('status');
        const clean = sanitizeSchedule(result.state === 'ready' ? {schema:result.schema,state:result.state,config:result.config,records:result.records} : result);
        return json(res, clean.state === 'ready' ? 200 : 503, clean);
      }
      if (req.method === 'GET' && url.pathname === '/api/domain') { const result = await domains('status'); return json(res, result.response_status || 503, result); }
      if (req.method === 'GET' && url.pathname === '/api/updates') return json(res, 200, { ...sanitizeUpdateStatus(await updates('status')), running_version: RUNNING_VERSION });
      if (role === 'local' && req.method === 'GET' && url.pathname === '/api/engines') return json(res,200,sanitizeEngineReadiness(await engines('status')));
      if (role === 'local' && req.method === 'GET' && url.pathname === '/api/multi-engine') return json(res, 200, sanitizeMultiEngine(await multi('status')));
      if (role === 'local' && req.method === 'GET' && url.pathname === '/api/scan') return json(res, 200, await scan('status'));
      if (req.method === 'GET' && url.pathname === '/api/cloud/status') return json(res, 200, await cloudStatus());
      return json(res, 404, { error: '接口不存在' });
    } catch (error) { if (!res.headersSent) json(res, error.status || 503, { error: error.status ? error.message : '本地服务暂不可用' }); else res.destroy(); }
  }
  const server = tls ? https.createServer(domainDirectory ? domainTls(domainDirectory, tls, target.hostname) : tls, handler) : http.createServer(handler);
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
  const server = createLocalServer({ credentials, credentialDirectory: env.IRONCURTAIN_CONFIG_DIR || '/etc/ironcurtain', changePassword: value => accountPassword(value, env), origin, tls, panelPort: port, scan: action => localSecurityScan(action, env), multi: action => localMultiEngine(action, env), engines: action => localEngineReadiness(action, env), operations: (action, value) => localOperations(action, value, env), schedule: (action, value) => localSchedule(action, value, env), updates: action => localUpdate(action, env), cloudStatus: () => cloud.status(), cloudTasks: cloud, domainDirectory: env.IRONCURTAIN_CONFIG_DIR || '/etc/ironcurtain', domains: (action, value) => domainRequest(action, value, env) });
  server.once('close', () => cloud.close());
  await new Promise((resolveStart, reject) => {const ready=()=>{server.off('error',reject);resolveStart();};server.once('error',reject);server.listen(port,host,ready);});
  console.log('铁幕安全独立面板已启动：' + origin);
  return server;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await startLocal();
