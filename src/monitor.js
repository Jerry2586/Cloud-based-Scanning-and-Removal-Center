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
  const state = { probes: {}, reports: {}, events: [] };
  if (stateFile) {
    try { Object.assign(state, JSON.parse(readFileSync(stateFile, 'utf8'))); } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
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
  const status = () => ({
    generated_at: new Date(now()).toISOString(),
    nodes: Object.fromEntries(Object.entries(nodes).map(([name, config]) => [name, {
      probe: state.probes[name] ?? { state: 'unknown' },
      integrity: state.reports[name] ?? { state: 'unknown' },
      last_report_at: state.reports[name]?.at ?? null,
      report_fresh: Boolean(state.reports[name]?.at && now() - Date.parse(state.reports[name].at) < 120000),
      baseline_files: Object.keys(config.baseline ?? {}).length,
    }])),
    events: state.events.slice(0, 40),
  });
  async function runProbes() {
    await Promise.all(Object.entries(nodes).map(async ([name, config]) => {
      let result;
      try { result = await probe(config.health_url); }
      catch (error) { result = { state: 'unreachable', reason: String(error.code ?? 'NETWORK_ERROR') }; }
      const previous = state.probes[name]?.state;
      state.probes[name] = { ...result, at: new Date(now()).toISOString() };
      if (result.state !== 'healthy' && (previous !== result.state || previous === undefined)) event('probe.failed', name, result.reason ?? 'unreachable');
    }));
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
        const baseline = config.baseline ?? {};
        const missing = Object.keys(baseline).filter(path => !Object.hasOwn(data.files, path));
        const changed = Object.keys(baseline).filter(path => Object.hasOwn(data.files, path) && data.files[path] !== baseline[path]);
        const added = Object.keys(data.files).filter(path => !Object.hasOwn(baseline, path));
        const check = { state: Object.keys(baseline).length ? (missing.length || changed.length || added.length ? 'changed' : 'matched') : 'unconfigured',
          at: new Date(now()).toISOString(), missing, changed, added };
        state.reports[name] = check;
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
