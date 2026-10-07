import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { mkdirSync, lstatSync, chmodSync } from 'node:fs';
import { dirname, resolve, parse } from 'node:path';

const HASH = /^[a-f0-9]{64}$/;
const ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const defaults = { revision: 1, malicious_threshold: 3, external_hash_lookup: false };
export const PLUGINS = Object.freeze([
  { id: 'signed-rules', name: '文件特征规则', kind: 'rules', capability: 'hash-analysis', source: '项目独立签名规则', license: '发布清单中的来源许可', version: '1' },
  { id: 'official-database', name: '文件查杀病毒库', kind: 'database', capability: 'file-scan', source: 'ClamAV / Cisco Talos', license: '参见官方数据库授权与分发条款', version: '1' },
  { id: 'hash-intelligence', name: '云端哈希情报', kind: 'connector', capability: 'hash-analysis', source: 'VirusTotal API', license: '商业使用须具备对应订阅授权；免费 Public API 不可用于商业产品。仅查询 SHA-256', version: '1' },
]);
const fail = (message, status = 400) => { throw Object.assign(Error(message), { status }); };
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === [...fields].sort().join(',');

// One database, one writer, transactional state and audit. Engine readiness is recomputed from trusted sources.
export function createCloudControl({ file, sources, now = Date.now, intelligence, schedule = true } = {}) {
  if (!file || !sources) throw Error('Cloud control requires durable storage and trusted sources');
  if (file !== ':memory:') {
    file = resolve(file);
    // A non-root user must not control any traversed directory. Sticky /tmp is
    // allowed only above a privately owned leaf; repeat after mkdir to catch a
    // directory created by another UID between validation and creation.
    function validateDirectories(allowMissing) {
      for (let parent = dirname(file);; parent = dirname(parent)) {
        try {
          const info = lstatSync(parent);
          const linux = process.platform !== 'win32';
          const stickyRoot = parent !== dirname(file) && info.uid === 0 && Boolean(info.mode & 0o1000);
          if (!info.isDirectory() || info.isSymbolicLink() || (linux &&
              ((info.uid !== 0 && info.uid !== process.getuid()) || ((info.mode & 0o022) && !stickyRoot)))) throw Error('Unsafe control directory');
        } catch (error) { if (!allowMissing || error.code !== 'ENOENT') throw error; }
        if (parent === parse(parent).root) break;
      }
    }
    validateDirectories(true);
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    validateDirectories(false);
    for (const name of [file, file + '-wal', file + '-shm']) {
      try { const info = lstatSync(name); if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (process.platform !== 'win32' && info.uid !== process.getuid())) throw Error('Unsafe control database'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    }
  }
  const db = new DatabaseSync(file);
  try {
  if (file !== ':memory:') chmodSync(file, 0o600);
  db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=3000;');
  if (db.prepare('PRAGMA user_version').get().user_version > 1) { throw Error('Cloud control database is newer than this program'); }
  db.exec(`CREATE TABLE IF NOT EXISTS plugins (id TEXT PRIMARY KEY, enabled INTEGER NOT NULL, installed_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS settings (id TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, requester TEXT NOT NULL, request_key TEXT NOT NULL, sha256 TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, policy TEXT NOT NULL, providers TEXT NOT NULL, result TEXT, UNIQUE(requester, request_key));
    CREATE TABLE IF NOT EXISTS audit (sequence INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS jobs_state ON jobs(state, created_at);
    CREATE INDEX IF NOT EXISTS jobs_hash ON jobs(requester, sha256, created_at);
    PRAGMA user_version=1;`);
  db.prepare('INSERT OR IGNORE INTO settings VALUES (?,?)').run('policy', JSON.stringify(defaults));
  } catch (error) { db.close(); throw error; }
  let closed = false, pumping = false, again = false, workerError = null, closePromise, workerPromise, retryTimer, retryDelay = 1000;
  const controllers = new Set();
  const stamp = () => new Date(now()).toISOString();
  function transaction(fn) { db.exec('BEGIN IMMEDIATE'); try { const result = fn(); db.exec('COMMIT'); return result; } catch (e) { db.exec('ROLLBACK'); throw e; } }
  const log = (actor, action, subject) => { db.prepare('INSERT INTO audit(at,actor,action,subject) VALUES (?,?,?,?)').run(stamp(), actor, action, subject); db.exec('DELETE FROM audit WHERE sequence <= (SELECT COALESCE(MAX(sequence),0)-5000 FROM audit)'); };
  const policy = () => JSON.parse(db.prepare('SELECT value FROM settings WHERE id=?').get('policy').value);
  const installed = () => new Map(db.prepare('SELECT * FROM plugins').all().map(p => [p.id, p]));
  function readiness(id) {
    try {
      const data = sources();
      if (id === 'signed-rules') {
        const r = data.rules;
        return r && !r.error ? { state: 'ready', version: r.value.version, count: r.value.indicators.length, expires_at: new Date(r.value.expires_at * 1000).toISOString(), digest: r.digest } : { state: 'unavailable', reason: '缺少有效、未过期且验签通过的特征规则' };
      }
      if (id === 'official-database') {
        const r = data.virus_databases;
        return r?.state === 'ready' ? { ...r, state: 'ready' } : { state: 'unavailable', reason: '尚未导入独立签名和官方验签通过的病毒库' };
      }
      return intelligence ? { state: 'ready', version: 'v3', reason: '仅查询哈希；调用受账户配额限制' } : { state: 'unavailable', reason: '尚未配置情报服务只读 API 凭据' };
    } catch { return { state: 'unavailable', reason: '可信来源检查失败' }; }
  }
  const plugins = () => { const rows = installed(); return PLUGINS.map(p => ({ ...p, installed: rows.has(p.id), enabled: !!rows.get(p.id)?.enabled, installed_at: rows.get(p.id)?.installed_at ?? null, readiness: readiness(p.id) })); };
  function pluginAction(actor, value) {
    if (!exact(value, ['id', 'action']) || !PLUGINS.some(p => p.id === value.id) || !['install','enable','pause','remove','check'].includes(value.action)) fail('插件操作无效');
    const exists = installed().has(value.id);
    if (value.action === 'check') return { plugin: plugins().find(p => p.id === value.id) };
    if (['install','enable'].includes(value.action) && readiness(value.id).state !== 'ready') fail('插件来源尚未就绪，请先配置并验证可信数据源', 409);
    if (!exists && value.action !== 'install') fail('插件尚未安装', 409);
    transaction(() => {
      if (value.action === 'install') db.prepare('INSERT INTO plugins VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET enabled=1').run(value.id, 1, stamp());
      if (value.action === 'enable' || value.action === 'pause') db.prepare('UPDATE plugins SET enabled=? WHERE id=?').run(value.action === 'enable' ? 1 : 0, value.id);
      if (value.action === 'remove') db.prepare('DELETE FROM plugins WHERE id=?').run(value.id);
      log(actor, 'plugin.' + value.action, value.id);
    });
    return { plugin: plugins().find(p => p.id === value.id) };
  }
  function setPolicy(actor, value) {
    if (!exact(value, ['revision','malicious_threshold','external_hash_lookup']) || !Number.isSafeInteger(value.malicious_threshold) || value.malicious_threshold < 1 || value.malicious_threshold > 20 || typeof value.external_hash_lookup !== 'boolean') fail('策略格式无效');
    return transaction(() => {
      const current = policy(); if (value.revision !== current.revision) fail('策略已更新，请刷新后重试', 409);
      const next = { ...value, revision: current.revision + 1 };
      db.prepare('UPDATE settings SET value=? WHERE id=?').run(JSON.stringify(next), 'policy'); log(actor, 'policy.update', String(next.revision)); return next;
    });
  }
  const decodeJob = row => row ? { id: row.id, requester: row.requester, sha256: row.sha256, state: row.state, created_at: row.created_at, updated_at: row.updated_at, attempts: row.attempts, policy: JSON.parse(row.policy), providers: JSON.parse(row.providers), result: row.result ? JSON.parse(row.result) : null } : null;
  function job(actor, id) { if (typeof id !== 'string' || !ID.test(id)) fail('任务编号无效'); const row = db.prepare('SELECT * FROM jobs WHERE id=?').get(id); if (!row || (actor !== 'admin' && row.requester !== actor)) fail('任务不存在', 404); return decodeJob(row); }
  function enqueue(actor, value) {
    if (!exact(value, ['sha256','request_key']) || typeof value.sha256 !== 'string' || !HASH.test(value.sha256) || typeof value.request_key !== 'string' || !ID.test(value.request_key)) fail('仅支持 SHA-256 与唯一请求编号');
    const existing = db.prepare('SELECT * FROM jobs WHERE requester=? AND request_key=?').get(actor, value.request_key);
    if (existing) { if (existing.sha256 !== value.sha256) fail('请求编号已经用于其他对象', 409); return decodeJob(existing); }
    const result = transaction(() => {
      if (db.prepare("SELECT COUNT(*) AS n FROM jobs WHERE state IN ('queued','running')").get().n >= 256 || db.prepare("SELECT COUNT(*) AS n FROM jobs WHERE requester=? AND state IN ('queued','running')").get(actor).n >= 32) fail('检测队列已满，请稍后重试', 429);
      // Bounded history; never evict outstanding work.
      db.exec("DELETE FROM jobs WHERE id IN (SELECT id FROM jobs WHERE state NOT IN ('queued','running') ORDER BY created_at DESC LIMIT -1 OFFSET 2000)");
      const id = randomUUID(), at = stamp(), p = policy();
      const selected = plugins().filter(x => x.enabled && x.capability === 'hash-analysis' && (x.id !== 'hash-intelligence' || p.external_hash_lookup)).map(x => x.id);
      db.prepare('INSERT INTO jobs(id,requester,request_key,sha256,state,created_at,updated_at,policy,providers) VALUES (?,?,?,?,?,?,?,?,?)').run(id, actor, value.request_key, value.sha256, 'queued', at, at, JSON.stringify(p), JSON.stringify(selected));
      log(actor, 'job.enqueue', id); return job(actor, id);
    });
    if (schedule) queueMicrotask(startWorker); return result;
  }
  // Only authenticated, complete baseline-change reports call this entry. Hashes never authorize actions.
  function enqueueReport(actor, { report_id, hashes } = {}) {
    if (!/^node\/(?:node-[a-z0-9][a-z0-9-]{0,63}|license-center|build-center)$/.test(actor) || typeof report_id !== 'string' || !ID.test(report_id) || !Array.isArray(hashes) || hashes.length > 8 || hashes.some(h => typeof h !== 'string' || !HASH.test(h))) fail('上报调度参数无效');
    const p = policy();
    const selected = plugins().filter(x => x.enabled && x.capability === 'hash-analysis' && (x.id !== 'hash-intelligence' || p.external_hash_lookup)).map(x => x.id);
    const usable = plugins().some(x => x.enabled && x.capability === 'hash-analysis' && x.readiness.state === 'ready' && (x.id !== 'hash-intelligence' || p.external_hash_lookup));
    if (!usable) return { state: 'unavailable', jobs: [], reason: '没有就绪且启用的摘要分析插件' };
    const jobs = [], cutoff = new Date(now() - 600000).toISOString();
    let deferred = 0;
    for (const hash of new Set(hashes)) {
      const existing = db.prepare("SELECT * FROM jobs WHERE requester=? AND sha256=? AND created_at>? AND policy=? AND providers=? AND state!='failed' ORDER BY created_at DESC LIMIT 1").get(actor, hash, cutoff, JSON.stringify(p), JSON.stringify(selected));
      if (existing) { jobs.push({ id: existing.id, sha256: hash, reused: true }); continue; }
      try {
        const task = enqueue(actor, { sha256: hash, request_key: randomUUID() });
        transaction(() => log(actor, 'report.hash-analysis', report_id + '/' + task.id));
        jobs.push({ id: task.id, sha256: hash, reused: false });
      } catch (error) { if (error.status !== 429) throw error; deferred++; }
    }
    return { state: deferred ? 'partial' : 'scheduled', jobs, deferred, automatic_remediation: false, reason: '认证节点自报摘要；文件完整性变化不等于恶意证据' };
  }
  async function evaluate(id, hash, controller) {
    const entry = installed().get(id);
    if (!entry?.enabled) return { provider: id, state: 'unavailable', reason: '插件已暂停或移除' };
    if (id === 'signed-rules') {
      const r = sources().rules;
      if (!r || r.error) return { provider: id, state: 'unavailable', reason: '规则未就绪或已过期' };
      const hit = r.value.indicators.find(x => x.sha256 === hash);
      return { provider: id, state: hit ? 'malicious' : 'unknown', reason: hit ? '命中验签特征' : '未命中特征；不代表文件安全', version: r.value.version, digest: r.digest, ...(hit ? { indicator: hit.id, label: hit.label } : {}) };
    }
    if (!policy().external_hash_lookup || !intelligence) return { provider: id, state: 'unavailable', reason: '外部哈希查询已关闭' };
    try {
      const result = await intelligence(hash, controller.signal);
      if (!result || !['known','unknown'].includes(result.state) || (result.state === 'known' && !['malicious','suspicious','undetected','harmless'].every(k => Number.isSafeInteger(result[k]) && result[k] >= 0 && result[k] <= 1000))) throw Error('invalid provider data');
      return result.state === 'known' ? { provider: id, state: result.state, malicious: result.malicious, suspicious: result.suspicious, undetected: result.undetected, harmless: result.harmless, analyzed_at: result.analyzed_at ?? null } : { provider: id, state: 'unknown' };
    } catch { return { provider: id, state: 'unavailable', reason: '情报接口超时、限流或不可用' }; }
  }
  async function run(row) {
    const controller = new AbortController(); controllers.add(controller);
    const deadline = setTimeout(() => controller.abort(), 8000); deadline.unref();
    try {
      const selected = JSON.parse(row.providers), p = JSON.parse(row.policy);
      const evidence = await Promise.all(selected.map(id => new Promise(resolve => {
        let settled = false;
        const finish = value => { if (settled) return; settled = true; controller.signal.removeEventListener('abort', aborted); resolve(value); };
        const aborted = () => finish({ provider: id, state: 'unavailable', reason: '检测超过资源预算' });
        controller.signal.addEventListener('abort', aborted, { once: true });
        if (controller.signal.aborted) return aborted();
        void evaluate(id, row.sha256, controller).then(finish, () => finish({ provider: id, state: 'unavailable', reason: '检测来源不可用' }));
      })));
      const malicious = evidence.some(x => x.state === 'malicious' || (x.state === 'known' && x.malicious >= p.malicious_threshold));
      const suspicious = evidence.some(x => x.state === 'known' && (x.malicious > 0 || x.suspicious > 0));
      const result = { verdict: malicious ? 'malicious' : suspicious ? 'suspicious' : 'unknown', evidence, policy_revision: p.revision, automatic_remediation: false, reason: selected.length ? '哈希分析不证明全文件、内存或行为安全' : '没有启用适用的检测插件' };
      const state = evidence.length && evidence.every(x => x.state !== 'unavailable') ? 'complete' : 'partial';
      if (!closed) transaction(() => { db.prepare('UPDATE jobs SET state=?, result=?, updated_at=? WHERE id=?').run(state, JSON.stringify(result), stamp(), row.id); log('worker', 'job.' + state, row.id); });
    } finally { clearTimeout(deadline); controllers.delete(controller); }
  }
  function startWorker() {
    if (closed || retryTimer) return;
    if (workerPromise) { again = true; return; }
    workerPromise = pump().catch(() => {
      if (closed) return;
      workerError = '检测存储暂时不可用，工作进程正在重试';
      retryTimer = setTimeout(() => { retryTimer = undefined; startWorker(); }, retryDelay);
      retryTimer.unref(); retryDelay = Math.min(retryDelay * 2, 30000);
    }).finally(() => {
      workerPromise = undefined;
      if (!closed && !retryTimer && again) queueMicrotask(startWorker);
    });
  }
  function recoverInterrupted() {
    transaction(() => {
      for (const row of db.prepare("SELECT id FROM jobs WHERE state='running'").all()) {
        db.prepare("UPDATE jobs SET state='queued',updated_at=? WHERE id=?").run(stamp(), row.id);
        log('worker', 'job.recovered', row.id);
      }
    });
  }
  async function pump() {
    if (closed) return; if (pumping) { again = true; return; } pumping = true;
    try {
      recoverInterrupted();
      do {
        again = false; const rows = transaction(() => { const work = db.prepare("SELECT * FROM jobs WHERE state='queued' ORDER BY created_at LIMIT 2").all(); for (const row of work) db.prepare("UPDATE jobs SET state='running', attempts=attempts+1, updated_at=? WHERE id=?").run(stamp(), row.id); return work; });
        if (!rows.length) break;
        const outcomes = await Promise.allSettled(rows.map(row => run(row)));
        // A persistence failure leaves the row running for the next recovery.
        // Wait for both providers before allowing any retry to avoid duplicate work.
        if (outcomes.some(result => result.status === 'rejected')) throw Error('Cloud worker persistence failed');
        if (closed) break; again = true;
      } while (again);
      workerError = null; retryDelay = 1000;
    } finally { pumping = false; }
  }
  try { recoverInterrupted(); } catch (error) { db.close(); throw error; }
  if (schedule) queueMicrotask(startWorker);
  function snapshot() {
    const counts = Object.fromEntries(db.prepare('SELECT state,COUNT(*) AS n FROM jobs GROUP BY state').all().map(r => [r.state,r.n]));
    return { schema: 'xuanwu-control/v1', generated_at: stamp(), plugins: plugins(), policy: policy(), jobs: db.prepare('SELECT * FROM jobs ORDER BY created_at DESC LIMIT 100').all().map(decodeJob), counts, audit: db.prepare('SELECT * FROM audit ORDER BY sequence DESC LIMIT 100').all(), capabilities: { hash_analysis: true, arbitrary_plugin_upload: false, remote_shell: false, ai_maintenance: false }, running: pumping, worker_error: workerError };
  }
  return { snapshot, plugins, policy, setPolicy, pluginAction, enqueue, enqueueReport, job, pump, close() { if (!closePromise) closePromise = (async () => { closed = true; clearTimeout(retryTimer); for (const controller of controllers) controller.abort(); while (pumping) await new Promise(resolve => setTimeout(resolve, 10)); db.close(); })(); return closePromise; } };
}
