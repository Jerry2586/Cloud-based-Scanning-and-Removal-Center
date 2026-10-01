import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createServer } from 'node:https';

const sha256 = value => createHash('sha256').update(value).digest('hex');
const equal = (left, right) => {
  const a = Buffer.from(sha256(String(left ?? '')), 'hex');
  const b = Buffer.from(sha256(String(right ?? '')), 'hex');
  return timingSafeEqual(a, b);
};
const reply = (res, status, payload) => {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store',
    'x-content-type-options': 'nosniff' });
  res.end(JSON.stringify(payload));
};
const token = req => /^Bearer (\S+)$/.exec(req.headers.authorization ?? '')?.[1] ?? '';

export function createMonitor({ nodes, readers, stateFile, now = () => Date.now(), probe = defaultProbe }) {
  const state = { probes: {}, reports: {}, reportFreshness: {}, hostReports: {}, hostReportState: {}, events: [] };
  if (stateFile) {
    try { Object.assign(state, JSON.parse(readFileSync(stateFile, 'utf8'))); } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  // Older state files predate host scan reporting.
  state.hostReports ??= {};
  state.hostReportState ??= {};
  const persist = () => {
    if (!stateFile) return;
    mkdirSync(dirname(stateFile), { recursive: true });
    const temp = `${stateFile}.${process.pid}.tmp`;
    writeFileSync(temp, JSON.stringify(state), { mode: 0o600 });
    renameSync(temp, stateFile);
  };
  const event = (kind, node, details) => {
    state.events.unshift({ at: new Date(now()).toISOString(), kind, node, details });
    state.events = state.events.slice(0, 300);
  };
  const identity = (req, subject) => {
    const cert = req.socket.getPeerCertificate?.();
    return req.socket.authorized === true && Boolean(cert?.fingerprint256)
      && (subject.identities ?? [subject]).some(candidate =>
        equal(cert.fingerprint256, candidate.fingerprint256) && equal(token(req), candidate.token));
  };
  const hostSnapshot = name => {
    const report = state.hostReports[name];
    const reportAt = Date.parse(state.reports[name]?.at ?? '');
    const checkedAt = Date.parse(report?.checked_at ?? '');
    const reportFresh = Number.isFinite(reportAt) && now() >= reportAt && now() - reportAt < 120000;
    const scanFresh = Number.isFinite(checkedAt) && now() >= checkedAt && now() - checkedAt < 900000;
    const current = Boolean(report && reportFresh && (scanFresh || report.state === 'unavailable'));
    const assessed = !report ? 'unavailable' : !reportFresh ? 'stale'
      : report.state === 'unavailable' || report.state === 'running' || report.state === 'idle' ? 'unavailable'
      : scanFresh ? report.state : 'stale';
    return { state: assessed,
      checked_at: report?.checked_at ?? null, fresh: current, source: 'node-self-report',
      counts: report?.counts ?? null };
  };
  const status = () => ({
    generated_at: new Date(now()).toISOString(),
    nodes: Object.fromEntries(Object.entries(nodes).map(([name, config]) => [name, {
      probe: state.probes[name] ?? { state: 'unknown' },
      integrity: state.reports[name] ?? { state: 'unknown' },
      last_report_at: state.reports[name]?.at ?? null,
      report_fresh: Boolean(state.reports[name]?.at && now() >= Date.parse(state.reports[name].at)
        && now() - Date.parse(state.reports[name].at) < 120000),
      baseline_files: Object.keys(config.baseline ?? {}).length,
      host_scan: hostSnapshot(name),
    }])),
    events: state.events.slice(0, 40),
  });
  const validateHostScan = (value) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)
      || !['ok', 'warning', 'finding', 'unavailable', 'running', 'idle'].includes(value.state)) throw Error('INVALID_HOST');
    if (value.checked_at !== null && value.checked_at !== undefined) {
      if (typeof value.checked_at !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|\+00:00)$/.test(value.checked_at)
        || !Number.isFinite(Date.parse(value.checked_at)) || Date.parse(value.checked_at) > now() + 60000) throw Error('INVALID_HOST_TIME');
    }
    if (value.counts !== undefined) {
      if (!value.counts || typeof value.counts !== 'object' || Array.isArray(value.counts)
        || Object.keys(value.counts).sort().join(',') !== 'finding,ok,unavailable,warning'
        || Object.values(value.counts).some(count => !Number.isSafeInteger(count) || count < 0 || count > 20)
        || Object.values(value.counts).reduce((a, b) => a + b, 0) > 20) throw Error('INVALID_HOST_COUNTS');
    }
    if (['ok', 'warning', 'finding'].includes(value.state) && (!value.checked_at || !value.counts)) throw Error('INCOMPLETE_HOST');
    return { state: value.state, checked_at: value.checked_at ?? null, counts: value.counts ?? null };
  };
  async function runProbes() {
    await Promise.all(Object.entries(nodes).map(async ([name, config]) => {
      let result;
      try { result = await probe(config.health_url); }
      catch (error) { result = { state: 'unreachable', reason: String(error.code ?? 'NETWORK_ERROR') }; }
      const previous = state.probes[name]?.state;
      state.probes[name] = { ...result, at: new Date(now()).toISOString() };
      if (result.state !== 'healthy' && (previous !== result.state || previous === undefined)) event('probe.failed', name, result.reason ?? 'unreachable');
    }));
    for (const name of Object.keys(nodes)) {
      const at = Date.parse(state.reports[name]?.at ?? '');
      const fresh = Number.isFinite(at) && now() - at < 120000 && now() >= at;
      if (!fresh && state.reportFreshness[name] !== 'stale') {
        event('report.stale', name, state.reports[name]?.at ? 'report expired' : 'no report received');
      }
      state.reportFreshness[name] = fresh ? 'fresh' : 'stale';
      const hostState = hostSnapshot(name).state;
      if (hostState !== state.hostReportState[name]) {
        event('host.' + hostState, name, 'node self-reported host scan no longer fresh');
        state.hostReportState[name] = hostState;
      }
    }
    persist();
    return status();
  }
  async function handler(req, res) {
    if (req.method === 'GET' && req.url === '/health') return reply(res, 200, { ok: true });
    if (req.method === 'GET' && req.url === '/v1/connectivity') {
      const actor = readers.some(reader => identity(req, reader)) ? 'reader'
        : Object.entries(nodes).find(([, config]) => identity(req, config))?.[0];
      if (!actor) return reply(res, 403, { error: 'AUTH_REQUIRED' });
      return reply(res, 200, { identity: actor });
    }
    if (req.method === 'GET' && req.url === '/v1/status') {
      if (!readers.some(reader => identity(req, reader))) return reply(res, 403, { error: 'AUTH_REQUIRED' });
      return reply(res, 200, status());
    }
    if (req.method === 'POST' && req.url === '/v1/report') {
      const entry = Object.entries(nodes).find(([, config]) => identity(req, config));
      if (!entry) return reply(res, 403, { error: 'AUTH_REQUIRED' });
      const [name, config] = entry;
      let text = '';
      try {
        for await (const chunk of req) {
          text += chunk;
          if (text.length > 262144) return reply(res, 413, { error: 'REPORT_TOO_LARGE' });
        }
        const data = JSON.parse(text);
        if (!data || typeof data.files !== 'object' || Array.isArray(data.files)) throw Error('INVALID');
        const host = data.host_scan === undefined ? { state: 'unavailable', checked_at: null, counts: null }
          : validateHostScan(data.host_scan);
        const baseline = config.baseline ?? {};
        const missing = Object.keys(baseline).filter(path => !Object.hasOwn(data.files, path));
        const changed = Object.keys(baseline).filter(path => Object.hasOwn(data.files, path) && data.files[path] !== baseline[path]);
        const added = Object.keys(data.files).filter(path => !Object.hasOwn(baseline, path));
        const check = { state: Object.keys(baseline).length ? (missing.length || changed.length || added.length ? 'changed' : 'matched') : 'unconfigured',
          at: new Date(now()).toISOString(), missing, changed, added };
        state.reports[name] = check;
        state.hostReports[name] = host;
        const hostState = hostSnapshot(name).state;
        if (hostState !== state.hostReportState[name]) {
          if (hostState === 'finding' || hostState === 'warning' || hostState === 'unavailable' || hostState === 'stale') {
            event('host.' + hostState, name, 'node self-reported host scan; independent verification required');
          } else if (state.hostReportState[name] && hostState === 'ok') {
            event('host.resumed', name, 'node self-reported host scan recovered');
          }
          state.hostReportState[name] = hostState;
        }
        if (state.reportFreshness[name] === 'stale') event('report.resumed', name, 'authenticated report received');
        state.reportFreshness[name] = 'fresh';
        if (check.state === 'changed') event('integrity.changed', name, { missing, changed, added });
        persist();
        return reply(res, 200, check);
      } catch { return reply(res, 400, { error: 'INVALID_REPORT' }); }
    }
    return reply(res, 404, { error: 'NOT_FOUND' });
  }
  return { handler, runProbes, status };
}

export async function defaultProbe(url) {
  if (!url || new URL(url).protocol !== 'https:') return { state: 'unconfigured' };
  const response = await fetch(url, { signal: AbortSignal.timeout(5000), redirect: 'error' });
  if (!response.ok) return { state: 'unhealthy', reason: `HTTP_${response.status}` };
  const body = await response.json();
  return body.ok === true ? { state: 'healthy' } : { state: 'unhealthy', reason: 'HEALTH_REJECTED' };
}

export function startFromEnvironment(env = process.env) {
  for (const field of ['SECURITY_TLS_KEY', 'SECURITY_TLS_CERT', 'SECURITY_CLIENT_CA', 'SECURITY_CONFIG']) {
    if (!env[field]) throw Error(`${field} is required`);
  }
  const config = JSON.parse(readFileSync(env.SECURITY_CONFIG, 'utf8'));
  for (const subject of [...Object.values(config.nodes ?? {}), ...(config.readers ?? [])]) {
    const identities = subject.identities ?? [subject];
    if (!Array.isArray(identities) || identities.length < 1 || identities.length > 2 || identities.some(identity =>
      !identity.token || identity.token.length < 32 || !/^(?:[A-Fa-f0-9]{2}:){31}[A-Fa-f0-9]{2}$/.test(identity.fingerprint256 ?? ''))) {
      throw Error('Every identity requires a 32+ character token and SHA-256 client certificate fingerprint');
    }
  }
  const monitor = createMonitor({ nodes: config.nodes ?? {}, readers: config.readers ?? [], stateFile: env.SECURITY_STATE_FILE ?? './var/state.json' });
  const server = createServer({ key: readFileSync(env.SECURITY_TLS_KEY), cert: readFileSync(env.SECURITY_TLS_CERT),
    ca: readFileSync(env.SECURITY_CLIENT_CA), requestCert: true, rejectUnauthorized: true }, monitor.handler);
  server.listen(Number(env.SECURITY_PORT ?? 9443), env.SECURITY_HOST ?? '0.0.0.0');
  const timer = setInterval(() => { void monitor.runProbes().catch(error => console.error('probe error:', error)); }, 30000);
  timer.unref();
  void monitor.runProbes().catch(error => console.error('probe error:', error));
  return { server, monitor };
}
