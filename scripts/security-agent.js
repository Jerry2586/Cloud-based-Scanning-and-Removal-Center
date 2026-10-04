import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { resolve, relative, sep } from 'node:path';
import { request as httpsRequest } from 'node:https';
import { completeHostScan, freshHostScan } from '../src/contracts/host-scan-contract.js';
import { localSecurityScan } from '../src/local/scan-client.js';

const EXCLUDED = new Set(['.git', 'node_modules', 'var', '.codex', '.codex-tmp']);
export function inventory(root, paths = ['apps', 'packages', 'scripts', 'Dockerfile', 'compose.yaml', 'compose.license.yaml', 'compose.build.yaml']) {
  const base = resolve(root);
  const files = {};
  function walk(name) {
    const full = resolve(base, name);
    if (full !== base && !full.startsWith(base + sep)) throw Error('扫描路径越界');
    let entry;
    try { entry = lstatSync(full); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
    if (entry.isSymbolicLink()) { files[name.replaceAll('\\', '/')] = 'SYMLINK'; return; }
    if (entry.isDirectory()) {
      for (const child of readdirSync(full, { withFileTypes: true })) {
        if (EXCLUDED.has(child.name)) continue;
        walk(relative(base, resolve(full, child.name)));
      }
    } else if (entry.isFile()) {
      files[name.replaceAll('\\', '/')] = createHash('sha256').update(readFileSync(full)).digest('hex');
    }
    if (Object.keys(files).length > 3000) throw Error('文件数量超出上报上限');
  }
  for (const path of paths) walk(path);
  return files;
}
export function summarizeHostScan(report, now = Date.now()) {
  if (!report) return { state: 'unavailable', checked_at: null };
  if (report.state !== 'finished') return { state: report.state === 'running' || report.state === 'idle' ? report.state : 'unavailable', checked_at: null };
  if (!completeHostScan(report)) return { state: 'unavailable', checked_at: null };
  const checkedAt = report.checked_at;
  const states = report.checks.map(item => item.state);
  const state = states.includes('finding') ? 'finding' : !freshHostScan(report, now) ||
    !Array.isArray(report.history) || !['ok', 'truncated'].includes(report.history_state) || states.includes('unavailable') ? 'unavailable'
    : states.includes('warning') ? 'warning' : 'ok';
  return { state, checked_at: checkedAt, counts: Object.fromEntries(['ok', 'warning', 'finding', 'unavailable']
    .map(kind => [kind, states.filter(value => value === kind).length])) };
}
export async function sendReport(env = process.env) {
  const target = new URL('/v1/report', env.SECURITY_CLOUD_URL);
  if (target.protocol !== 'https:' || !env.SECURITY_CLOUD_TOKEN || env.SECURITY_CLOUD_TOKEN.length < 32) {
    throw Error('安全中心连接配置无效');
  }
  const report = { observed_at: new Date().toISOString(), report_id: randomUUID(),
    files: inventory(env.SECURITY_SCAN_ROOT ?? process.cwd()) };
  if (env.SECURITY_REPORT_HOST === 'true') {
    const local = await localSecurityScan('status', { APPGOG_HOST_SCAN_SOCKET: env.SECURITY_HOST_SCAN_SOCKET });
    report.host_scan = summarizeHostScan(local);
  }
  const payload = JSON.stringify(report);
  if (payload.length > 262144) throw Error('上报文件过多，请缩小监测范围');
  return new Promise((resolve, reject) => {
    const req = httpsRequest(target, { method: 'POST', timeout: 10000, rejectUnauthorized: true,
      ca: readFileSync(env.SECURITY_CLOUD_CA), cert: readFileSync(env.SECURITY_CLOUD_CLIENT_CERT),
      key: readFileSync(env.SECURITY_CLOUD_CLIENT_KEY),
      headers: { authorization: `Bearer ${env.SECURITY_CLOUD_TOKEN}`, 'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload) } }, res => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { data += chunk; if (data.length > 32768) req.destroy(Error('响应过大')); });
      res.on('end', () => {
        if (res.statusCode !== 200) return reject(Error(`云端拒绝上报 (${res.statusCode})`));
        try { resolve(JSON.parse(data)); } catch { reject(Error('云端响应无效')); }
      });
    });
    req.on('timeout', () => req.destroy(Error('云端超时')));
    req.on('error', reject);
    req.end(payload);
  });
}
if (process.argv[1] && resolve(process.argv[1]) === new URL(import.meta.url).pathname.replace(/^\/(\w:)/, '$1').replaceAll('/', sep)) {
  const run = async () => {
    try { const result = await sendReport(); console.log(new Date().toISOString(), result.state); }
    catch (error) { console.error(new Date().toISOString(), error.message); process.exitCode = 1; }
  };
  await run();
  if (process.argv.includes('--watch')) setInterval(() => { void run(); }, 30000);
}
