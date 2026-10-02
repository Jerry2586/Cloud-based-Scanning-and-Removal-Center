import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createServer } from 'node:https';
import { renderDashboard } from './dashboard.js';

const sha256 = value => createHash('sha256').update(value).digest('hex');
const equal = (left, right) => {
  const a = Buffer.from(sha256(String(left ?? '')), 'hex');
  const b = Buffer.from(sha256(String(right ?? '')), 'hex');
  return timingSafeEqual(a, b);
};
const securityHeaders = { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()' };
const reply = (res, status, payload, headers = {}) => {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...securityHeaders, ...headers });
  res.end(JSON.stringify(payload));
};
const html = (res, status, payload, headers = {}) => {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', ...securityHeaders,
    'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    ...headers });
  res.end(payload);
};
const token = req => /^Bearer (\S+)$/.exec(req.headers.authorization ?? '')?.[1] ?? '';
const basicToken = req => {
  const encoded = /^Basic (\S+)$/.exec(req.headers.authorization ?? '')?.[1];
  if (!encoded) return '';
  try {
    const value = Buffer.from(encoded, 'base64').toString('utf8');
    return value.startsWith('reader:') ? value.slice(7) : '';
  } catch { return ''; }
};
const rank = { ok: 0, stale: 1, warning: 2, unavailable: 3, finding: 4 };
const worst = values => values.reduce((result, value) => (rank[value] ?? rank.unavailable) > rank[result] ? value : result, 'ok');
const certificateState = (identities, now) => {
  const expiries = identities.map(identity => Date.parse(identity.cert_not_after ?? '')).filter(Number.isFinite);
  if (!expiries.length) return { state: 'unknown', not_after: null };
  const nearest = Math.min(...expiries);
  return { state: nearest <= now ? 'expired' : nearest - now <= 30 * 86400000 ? 'expiring' : 'healthy',
    not_after: new Date(nearest).toISOString() };
};
const fingerprintPattern = /^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/;
const digestPattern = /^[0-9a-f]{64}$/;
const allowedNodeRoles = new Set(['license-center', 'build-center']);
const publicPolicy = policy => ({ version: String(policy?.version ?? '1'), delivery: 'pull-only', remote_execution: false,
  remediation: 'local-agent-only', report_max_age_seconds: 120, host_scan_max_age_seconds: 900,
  rules: { require_signed_updates: true, allow_remote_commands: false, allow_cloud_push: false } });
const plainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value)
  && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
const stateObjectFields = ['probes', 'reports', 'reportFreshness', 'hostReports', 'hostReportState'];
const normalizePersistedState = value => {
  if (!plainObject(value)) throw Error('persisted state root must be an object');
  const normalized = { probes: {}, reports: {}, reportFreshness: {}, hostReports: {}, hostReportState: {}, events: [] };
  for (const field of stateObjectFields) {
    if (value[field] === undefined) continue;
    if (!plainObject(value[field])) throw Error(`persisted state ${field} must be an object`);
    normalized[field] = value[field];
  }
  if (value.events !== undefined) {
    if (!Array.isArray(value.events)) throw Error('persisted state events must be an array');
    normalized.events = value.events;
  }
  return normalized;
};

export function validateConfiguration(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) throw Error('Configuration must be an object');
  const nodes = config.nodes ?? {};
  const readers = config.readers ?? [];
  if (!nodes || typeof nodes !== 'object' || Array.isArray(nodes)) throw Error('Nodes must be an object');
  if (!Array.isArray(readers) || readers.length !== 1) throw Error('Exactly one reader subject is required');
  const fingerprints = new Set();
  const tokens = new Set();
  const validateSubject = (subject, expectedRole) => {
    if (!subject || typeof subject !== 'object' || Array.isArray(subject)
      || (subject.role ?? expectedRole) !== expectedRole) throw Error(`Invalid identity subject for ${expectedRole}`);
    const identities = subject.identities ?? [subject];
    if (!Array.isArray(identities) || identities.length < 1 || identities.length > 2) {
      throw Error('Every identity subject requires one or two identities');
    }
    const statuses = [];
    for (const identity of identities) {
      if (!identity || typeof identity !== 'object' || Array.isArray(identity)
        || typeof identity.token !== 'string' || !/^\S{32,}$/.test(identity.token)
        || !fingerprintPattern.test(identity.fingerprint256 ?? '')) {
        throw Error('Every identity requires a 32+ character token and SHA-256 client certificate fingerprint');
      }
      const status = identity.status ?? 'active';
      if (status !== 'active' && status !== 'staged') throw Error('Identity status must be active or staged');
      statuses.push(status);
      if (tokens.has(identity.token) || fingerprints.has(identity.fingerprint256)) {
        throw Error('Identity tokens and certificate fingerprints must be unique');
      }
      tokens.add(identity.token);
      fingerprints.add(identity.fingerprint256);
    }
    if (statuses.filter(status => status === 'active').length !== 1
      || (statuses.length === 2 && statuses.filter(status => status === 'staged').length !== 1)) {
      throw Error('Identity rotation requires one active identity and at most one staged identity');
    }
  };
  validateSubject(readers[0], 'reader');
  for (const [name, subject] of Object.entries(nodes)) {
    if (!allowedNodeRoles.has(name)) throw Error(`Unsupported node role: ${name}`);
    validateSubject(subject, name);
    let health;
    try { health = new URL(subject.health_url); } catch { throw Error(`Invalid HTTPS health URL for ${name}`); }
    if (health.protocol !== 'https:' || health.username || health.password) throw Error(`Invalid HTTPS health URL for ${name}`);
    if (!subject.baseline || typeof subject.baseline !== 'object' || Array.isArray(subject.baseline)
      || Object.values(subject.baseline).some(value => typeof value !== 'string' || !digestPattern.test(value))) {
      throw Error(`Invalid SHA-256 baseline for ${name}`);
    }
  }
  const rules = config.policy?.rules;
  if (!rules || typeof rules !== 'object' || Array.isArray(rules)
    || rules.require_signed_updates !== true || rules.allow_remote_commands !== false
    || rules.allow_cloud_push !== false) throw Error('Unsafe policy configuration');
  return config;
}

export function createMonitor({ nodes, readers, policy, stateFile, now = () => Date.now(), probe = defaultProbe }) {
  const state = { probes: {}, reports: {}, reportFreshness: {}, hostReports: {}, hostReportState: {}, events: [] };
  if (stateFile) {
    try { Object.assign(state, normalizePersistedState(JSON.parse(readFileSync(stateFile, 'utf8')))); } catch (error) {
      if (error.code !== 'ENOENT') throw Error(`Invalid persisted security state: ${error.message}`, { cause: error });
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
    const safeDetails = typeof details === 'string' ? details.slice(0, 512) : details;
    state.events.unshift({ at: new Date(now()).toISOString(), kind: String(kind).slice(0, 64),
      node: String(node).slice(0, 128), details: safeDetails });
    state.events = state.events.slice(0, 300);
  };
  const identity = (req, subject, secret = token(req)) => {
    const cert = req.socket.getPeerCertificate?.();
    return req.socket.authorized === true && Boolean(cert?.fingerprint256)
      && (subject.identities ?? [subject]).some(candidate =>
        equal(cert.fingerprint256, candidate.fingerprint256) && equal(secret, candidate.token));
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
  const nodeSnapshot = (name, config) => {
    const probeState = state.probes[name] ?? { state: 'unknown' };
    const integrity = state.reports[name] ?? { state: 'unknown' };
    const reportFresh = Boolean(state.reports[name]?.at && now() >= Date.parse(state.reports[name].at)
      && now() - Date.parse(state.reports[name].at) < 120000);
    const hostScan = hostSnapshot(name);
    const summaryState = worst([
      integrity.state === 'changed' ? 'finding' : integrity.state === 'matched' ? 'ok' : 'unavailable',
      probeState.state === 'healthy' ? 'ok' : 'unavailable', reportFresh ? 'ok' : (integrity.state === 'unknown' ? 'unavailable' : 'stale'),
      ['ok', 'warning', 'finding', 'stale'].includes(hostScan.state) ? hostScan.state : 'unavailable',
    ]);
    return {
      role: config.role ?? name, summary_state: summaryState,
      probe: state.probes[name] ?? { state: 'unknown' },
      integrity,
      last_report_at: state.reports[name]?.at ?? null,
      report_fresh: reportFresh,
      baseline_files: Object.keys(config.baseline ?? {}).length,
      host_scan: hostScan,
    };
  };
  const identityStatus = () => {
    const readerSubject = readers.length ? { role: 'reader', identities: readers.flatMap(subject => subject.identities ?? [subject]) } : null;
    const entries = [['reader', readerSubject], ...Object.entries(nodes)].filter(([, subject]) => subject);
    const roles = Object.fromEntries(entries.map(([name, subject]) => {
      const identities = subject.identities ?? [subject];
      const certificate = certificateState(identities, now());
      return [name, { role: subject.role ?? name, identity_count: identities.length,
        rotation_state: identities.length > 1 ? 'staged' : 'active', certificate_state: certificate.state,
        certificate_not_after: certificate.not_after,
        revocation_state: identities.length > 1 ? 'pending-old-identity' : 'enforced' }];
    }));
    const summaryState = worst(Object.values(roles).map(role => role.certificate_state === 'expired' ? 'finding'
      : role.certificate_state === 'healthy' && role.rotation_state === 'active' ? 'ok' : 'warning'));
    return { generated_at: new Date(now()).toISOString(), summary_state: summaryState, roles };
  };
  const status = () => {
    const nodeStatuses = Object.fromEntries(Object.entries(nodes).map(([name, config]) => [name, nodeSnapshot(name, config)]));
    const nodeStates = Object.values(nodeStatuses).map(node => node.summary_state);
    const operationalState = nodeStates.length ? worst(nodeStates) : 'unavailable';
    return {
    generated_at: new Date(now()).toISOString(),
    summary_state: worst([operationalState, identityStatus().summary_state]),
    identity_state: identityStatus().summary_state,
    nodes: nodeStatuses,
    events: state.events.slice(0, 40),
  }; };
  const audit = () => {
    const snapshot = status();
    const counts = { finding: 0, unavailable: 0, warning: 0, stale: 0, ok: 0 };
    for (const node of Object.values(snapshot.nodes)) counts[node.summary_state] += 1;
    return { generated_at: snapshot.generated_at, summary_state: snapshot.summary_state,
      identity_state: snapshot.identity_state, counts, events: state.events.slice(0, 100) };
  };
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
    const path = new URL(req.url, 'https://localhost').pathname;
    if (req.method === 'GET' && path === '/health') return reply(res, 200, { ok: true });
    if (req.method === 'GET' && path === '/v1/connectivity') {
      const actor = readers.some(reader => identity(req, reader)) ? 'reader'
        : Object.entries(nodes).find(([, config]) => identity(req, config))?.[0];
      if (!actor) return reply(res, 403, { error: 'AUTH_REQUIRED' });
      return reply(res, 200, { identity: actor });
    }
    if (req.method === 'GET' && path === '/v1/status') {
      if (!readers.some(reader => identity(req, reader))) return reply(res, 403, { error: 'AUTH_REQUIRED' });
      return reply(res, 200, status());
    }
    if (req.method === 'GET' && path === '/v1/identity') {
      if (!readers.some(reader => identity(req, reader))) return reply(res, 403, { error: 'AUTH_REQUIRED' });
      return reply(res, 200, identityStatus());
    }
    if (req.method === 'GET' && path === '/v1/audit') {
      if (!readers.some(reader => identity(req, reader))) return reply(res, 403, { error: 'AUTH_REQUIRED' });
      return reply(res, 200, audit());
    }
    if (req.method === 'GET' && path === '/v1/policy') {
      const actor = readers.some(reader => identity(req, reader)) || Object.values(nodes).some(config => identity(req, config));
      if (!actor) return reply(res, 403, { error: 'AUTH_REQUIRED' });
      return reply(res, 200, publicPolicy(policy));
    }
    if (req.method === 'GET' && (path === '/' || path === '/dashboard')) {
      const authorized = readers.some(reader => identity(req, reader, basicToken(req)));
      if (!authorized) return html(res, 401, '<!doctype html><title>Authentication required</title>',
        { 'www-authenticate': 'Basic realm="APPGOG Security Dashboard", charset="UTF-8"' });
      return html(res, 200, renderDashboard({ status: status(), identities: identityStatus(), policy: publicPolicy(policy) }));
    }
    if (req.method === 'POST' && path === '/v1/report') {
      const entry = Object.entries(nodes).find(([, config]) => identity(req, config));
      if (!entry) return reply(res, 403, { error: 'AUTH_REQUIRED' });
      const [name, config] = entry;
      let text = '';
      let bytes = 0;
      try {
        for await (const chunk of req) {
          bytes += Buffer.byteLength(chunk);
          if (bytes > 262144) return reply(res, 413, { error: 'REPORT_TOO_LARGE' });
          text += chunk;
        }
        const data = JSON.parse(text);
        if (!data || typeof data.files !== 'object' || Array.isArray(data.files)
          || Object.values(data.files).some(value => typeof value !== 'string' || !digestPattern.test(value))) throw Error('INVALID');
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
        if (check.state === 'changed') event('integrity.changed', name,
          { missing: missing.length, changed: changed.length, added: added.length });
        persist();
        return reply(res, 200, check);
      } catch { return reply(res, 400, { error: 'INVALID_REPORT' }); }
    }
    return reply(res, 404, { error: 'NOT_FOUND' });
  }
  return { handler, runProbes, status, identityStatus, audit };
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
  const config = validateConfiguration(JSON.parse(readFileSync(env.SECURITY_CONFIG, 'utf8')));
  const monitor = createMonitor({ nodes: config.nodes ?? {}, readers: config.readers ?? [], policy: config.policy,
    stateFile: env.SECURITY_STATE_FILE ?? './var/state.json' });
  const server = createServer({ key: readFileSync(env.SECURITY_TLS_KEY), cert: readFileSync(env.SECURITY_TLS_CERT),
    ca: readFileSync(env.SECURITY_CLIENT_CA), requestCert: true, rejectUnauthorized: true }, monitor.handler);
  server.listen(Number(env.SECURITY_PORT ?? 9443), env.SECURITY_HOST ?? '0.0.0.0');
  const timer = setInterval(() => { void monitor.runProbes().catch(error => console.error('probe error:', error)); }, 30000);
  timer.unref();
  void monitor.runProbes().catch(error => console.error('probe error:', error));
  return { server, monitor };
}
