import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { ruleSource, ruleSummary } from './rules.js';
import { createServer } from 'node:https';
import { renderDashboard } from './dashboard.js';
import { releaseSource } from './release-store.js';
import { virusDatabaseSource } from './virus-db-store.js';
import { pipeline } from 'node:stream/promises';

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
const reportIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const reportTimestampPattern = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/;
const parseReportTimestamp = value => {
  if (typeof value !== 'string' || !reportTimestampPattern.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : null;
};
const reportMaxAgeMs = 120000;
const reportFutureSkewMs = 60000;
const reportReplayCacheSize = 256;
const allowedNodeRoles = new Set(['license-center', 'build-center']);
const genericNode = name => /^node-[a-z0-9][a-z0-9-]{0,63}$/.test(name);
const publicPolicy = policy => ({ version: String(policy?.version ?? '1'), delivery: 'pull-only', remote_execution: false,
  remediation: 'local-agent-only', report_max_age_seconds: reportMaxAgeMs / 1000, host_scan_max_age_seconds: 900,
  rules: { require_signed_updates: true, allow_remote_commands: false, allow_cloud_push: false } });
const plainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value)
  && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
const stateObjectFields = ['probes', 'reports', 'reportFreshness', 'reportIds', 'hostReports', 'hostReportState'];
const normalizePersistedState = value => {
  if (!plainObject(value)) throw Error('persisted state root must be an object');
  const normalized = { probes: {}, reports: {}, reportFreshness: {}, reportIds: {}, hostReports: {}, hostReportState: {}, events: [] };
  for (const field of stateObjectFields) {
    if (value[field] === undefined) continue;
    if (!plainObject(value[field])) throw Error(`persisted state ${field} must be an object`);
    normalized[field] = value[field];
  }
  for (const [name, identifiers] of Object.entries(normalized.reportIds)) {
    if (!Array.isArray(identifiers) || identifiers.some(identifier => typeof identifier !== 'string' || !reportIdPattern.test(identifier))) {
      throw Error(`persisted state reportIds.${name} must contain UUIDv4 values`);
    }
    normalized.reportIds[name] = identifiers.slice(-reportReplayCacheSize);
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
  const tokenDigests = new Set();
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
        || Object.hasOwn(identity, 'token')
        || typeof identity.token_sha256 !== 'string' || !digestPattern.test(identity.token_sha256)
        || !fingerprintPattern.test(identity.fingerprint256 ?? '')) {
        throw Error('Every identity requires a lowercase SHA-256 token digest and SHA-256 client certificate fingerprint');
      }
      const status = identity.status ?? 'active';
      if (status !== 'active' && status !== 'staged') throw Error('Identity status must be active or staged');
      statuses.push(status);
      if (tokenDigests.has(identity.token_sha256) || fingerprints.has(identity.fingerprint256)) {
        throw Error('Identity token digests and certificate fingerprints must be unique');
      }
      tokenDigests.add(identity.token_sha256);
      fingerprints.add(identity.fingerprint256);
    }
    if (statuses.filter(status => status === 'active').length !== 1
      || (statuses.length === 2 && statuses.filter(status => status === 'staged').length !== 1)) {
      throw Error('Identity rotation requires one active identity and at most one staged identity');
    }
  };
  validateSubject(readers[0], 'reader');
  for (const [name, subject] of Object.entries(nodes)) {
    if (!allowedNodeRoles.has(name) && !genericNode(name)) throw Error(`Unsupported node role: ${name}`);
    validateSubject(subject, genericNode(name) ? 'ironcurtain-node' : name);
    if (subject.health_url !== undefined || !genericNode(name)) {
      let health;
      try { health = new URL(subject.health_url); } catch { throw Error(`Invalid HTTPS health URL for ${name}`); }
      if (health.protocol !== 'https:' || health.username || health.password || health.hash) throw Error(`Invalid HTTPS health URL for ${name}`);
    }
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

export function createMonitor({ nodes, readers, policy, stateFile, now = () => Date.now(), probe = defaultProbe, rules = () => ({error:'RULE_MISSING'}), releases, virusDatabases }) {
  const state = { probes: {}, reports: {}, reportFreshness: {}, reportIds: {}, hostReports: {}, hostReportState: {}, events: [] };
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
        equal(cert.fingerprint256, candidate.fingerprint256)
          && equal(sha256(secret), candidate.token_sha256));
  };
  const hostSnapshot = name => {
    const report = state.hostReports[name];
    const reportAt = Date.parse(state.reports[name]?.at ?? '');
    const checkedAt = Date.parse(report?.checked_at ?? '');
    const reportFresh = Number.isFinite(reportAt) && now() >= reportAt && now() - reportAt < reportMaxAgeMs;
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
      && now() - Date.parse(state.reports[name].at) < reportMaxAgeMs);
    const hostScan = hostSnapshot(name);
    const certificate = certificateState(config.identities ?? [config], now());
    const summaryState = worst([
      integrity.state === 'changed' ? 'finding' : integrity.state === 'matched' ? 'ok' : 'unavailable',
      probeState.state === 'healthy' ? 'ok' : 'unavailable', reportFresh ? 'ok' : (integrity.state === 'unknown' ? 'unavailable' : 'stale'),
      ['ok', 'warning', 'finding', 'stale'].includes(hostScan.state) ? hostScan.state : 'unavailable',
      certificate.state === 'expired' ? 'finding' : certificate.state === 'healthy' ? 'ok' : 'warning',
    ]);
    const pairingState = !state.reports[name] ? 'waiting-first-report'
      : certificate.state === 'expired' || summaryState === 'finding' ? 'attention-required'
        : !reportFresh ? 'stale' : summaryState === 'ok' ? 'connected' : 'attention-required';
    const recommendedAction = pairingState === 'waiting-first-report' ? '将该角色身份包安全导入业务服务器并启动本地上报代理'
      : pairingState === 'stale' ? '检查业务代理、网络与证书，恢复经过认证的定时上报'
        : pairingState === 'attention-required' ? '核对完整性、宿主检查、证书与公网健康探测'
          : '保持本地代理运行并按计划轮换身份';
    return {
      role: config.role ?? name, configured: true, summary_state: summaryState,
      identity_state: 'identity-created', certificate_state: certificate.state,
      certificate_not_after: certificate.not_after, pairing_state: pairingState,
      recommended_action: recommendedAction,
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
    const independent = Object.keys(nodes).some(genericNode);
    const requiredRoles = independent ? Object.keys(nodes) : ['license-center', 'build-center'];
    const configuredRoles = requiredRoles.filter(role => Object.hasOwn(nodeStatuses, role));
    const connectedRoles = configuredRoles.filter(role => nodeStatuses[role].pairing_state === 'connected');
    const deploymentState = configuredRoles.length === 0 ? 'not-enrolled'
      : configuredRoles.length < requiredRoles.length ? 'partial' : 'ready';
    return {
    generated_at: new Date(now()).toISOString(),
    summary_state: worst([operationalState, identityStatus().summary_state]),
    identity_state: identityStatus().summary_state,
    deployment: {
      state: deploymentState,
      mode: independent ? 'independent-endpoints' : configuredRoles.length === requiredRoles.length ? 'combined-or-split' : 'incomplete',
      supported_modes: independent ? ['independent-endpoints'] : ['combined-business', 'split-business'],
      configured_roles: configuredRoles,
      connected_roles: connectedRoles,
      required_roles: requiredRoles,
    },
    nodes: nodeStatuses,
    events: state.events.slice(0, 40),
    rules: rulesStatus(),
    releases: releases?.summary() ?? {state:'missing',delivery:'pull-only',activation:'local-admin'},
    virus_databases: virusDatabases?.summary() ?? {state:'missing',delivery:'pull-only',activation:'local-admin'},
  }; };
  const rulesStatus = () => {const value=rules();return value.error ? {state:value.error==='RULE_MISSING'?'missing':'unavailable',delivery:'pull-only'} : ruleSummary(value);};
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
        || Object.values(value.counts).some(count => !Number.isSafeInteger(count) || count < 0 || count > 25)
        || Object.values(value.counts).reduce((a, b) => a + b, 0) > 25) throw Error('INVALID_HOST_COUNTS');
    }
    if (['ok', 'warning', 'finding'].includes(value.state) && (!value.checked_at || !value.counts)) throw Error('INCOMPLETE_HOST');
    if (value.counts && ((value.counts.finding > 0 && value.state !== 'finding')
      || (value.state === 'ok' && (value.counts.warning || value.counts.unavailable || value.counts.ok === 0))
      || (value.state === 'finding' && value.counts.finding === 0))) throw Error('CONTRADICTORY_HOST_COUNTS');
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
      const fresh = Number.isFinite(at) && now() - at < reportMaxAgeMs && now() >= at;
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
  let releaseTransfers=0, virusTransfers=0;
  async function handler(req, res) {
    const path = new URL(req.url, 'https://localhost').pathname;
    if (req.method === 'GET' && path === '/health') return reply(res, 200, { ok: true });
    if (req.method === 'GET' && path === '/v1/connectivity') {
      const actor = readers.some(reader => identity(req, reader)) ? 'reader'
        : Object.entries(nodes).find(([, config]) => identity(req, config))?.[0];
      if (!actor) return reply(res, 403, { error: 'AUTH_REQUIRED' });
      return reply(res, 200, { identity: actor });
    }
    if (req.method === 'GET' && path === '/v1/rules') {
      if (!readers.some(reader=>identity(req,reader)) && !Object.values(nodes).some(node=>identity(req,node))) return reply(res,403,{error:'AUTH_REQUIRED'});
      const value=rules();
      return value.error ? reply(res,503,{error:'RULE_UNAVAILABLE'}) : reply(res,200,value.envelope);
    }
    if (path.startsWith('/v1/virus-db/')) {
      if (!readers.some(reader=>identity(req,reader)) && !Object.values(nodes).some(node=>identity(req,node))) return reply(res,403,{error:'AUTH_REQUIRED'});
      if(req.method!=='GET'||new URL(req.url,'https://localhost').search)return reply(res,404,{error:'NOT_FOUND'});
      if(!virusDatabases)return reply(res,503,{error:'DB_UNAVAILABLE'});
      if(path==='/v1/virus-db/latest') {
        try{return reply(res,200,virusDatabases.latest());}catch{return reply(res,503,{error:'DB_UNAVAILABLE'});}
      }
      const match=/^\/v1\/virus-db\/([a-f0-9]{64})\/(main|daily|bytecode)\.cvd$/.exec(path);
      if(!match)return reply(res,404,{error:'NOT_FOUND'});
      if(virusTransfers>=2)return reply(res,503,{error:'DB_BUSY'});
      virusTransfers++;let finished=false,stream;
      const finish=()=>{if(!finished){finished=true;virusTransfers--;}};
      res.once('close',()=>{stream?.destroy();finish();});res.once('finish',finish);
      try {
        const asset=virusDatabases.asset(match[1],match[2]+'.cvd');stream=asset.stream;
        res.setTimeout(120000,()=>res.destroy());
        res.writeHead(200,{'content-type':'application/octet-stream','content-length':asset.size,...securityHeaders});
        await pipeline(stream,res);return;
      }catch(error){finish();if(res.headersSent){res.destroy();return;}return reply(res,error.message==='DB_NOT_FOUND'?404:503,{error:'DB_UNAVAILABLE'});}
    }
    if (path.startsWith('/v1/releases/')) {
      if (!readers.some(reader=>identity(req,reader)) && !Object.values(nodes).some(node=>identity(req,node))) return reply(res,403,{error:'AUTH_REQUIRED'});
      if(req.method!=='GET' || new URL(req.url,'https://localhost').search) return reply(res,404,{error:'NOT_FOUND'});
      if(!releases) return reply(res,503,{error:'RELEASE_UNAVAILABLE'});
      if(path==='/v1/releases/latest') {
        try {return reply(res,200,releases.latest());} catch {return reply(res,503,{error:'RELEASE_UNAVAILABLE'});}
      }
      const match=/^\/v1\/releases\/([0-9]+\.[0-9]+\.[0-9]+)\/([A-Za-z0-9.-]+)$/.exec(path);
      if(!match)return reply(res,404,{error:'NOT_FOUND'});
      if(releaseTransfers>=2)return reply(res,503,{error:'RELEASE_BUSY'});
      releaseTransfers++; let finished=false;
      const finish=()=>{if(!finished){finished=true;releaseTransfers--;}};
      res.once('close',finish);res.once('finish',finish);
      try {
        const bytes=releases.asset(match[1],match[2]);
        res.writeHead(200,{'content-type':'application/octet-stream','content-length':bytes.length,...securityHeaders});
        return res.end(bytes);
      } catch(error) {finish();return reply(res,error.message==='RELEASE_NOT_FOUND'?404:503,{error:'RELEASE_UNAVAILABLE'});}
    }
    if (req.method === 'GET' && path === '/v1/node/status') {
      const entry = Object.entries(nodes).find(([, config]) => identity(req, config));
      if (!entry) return reply(res, 403, { error: 'AUTH_REQUIRED' });
      return reply(res, 200, { identity: entry[0], generated_at: new Date(now()).toISOString(), node: nodeSnapshot(...entry), policy: publicPolicy(policy), rules: rulesStatus(), releases: releases?.summary() ?? {state:'missing'}, virus_databases: virusDatabases?.summary() ?? {state:'missing'} });
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
        if (!data || !plainObject(data.files) || typeof data.files !== 'object' || Array.isArray(data.files)
          || Object.values(data.files).some(value => typeof value !== 'string' || !digestPattern.test(value))) throw Error('INVALID');
        const observedAt = parseReportTimestamp(data.observed_at);
        if (observedAt === null || !reportIdPattern.test(data.report_id ?? '')) {
          return reply(res, 400, { error: 'INVALID_REPORT_METADATA' });
        }
        const receivedAt = now();
        if (observedAt > receivedAt + reportFutureSkewMs) return reply(res, 400, { error: 'REPORT_TIME_IN_FUTURE' });
        if (receivedAt - observedAt >= reportMaxAgeMs) return reply(res, 409, { error: 'REPORT_STALE' });
        const seenIds = state.reportIds[name] ?? [];
        if (seenIds.includes(data.report_id)) return reply(res, 409, { error: 'REPORT_REPLAYED' });
        const host = data.host_scan === undefined ? { state: 'unavailable', checked_at: null, counts: null }
          : validateHostScan(data.host_scan);
        const baseline = config.baseline ?? {};
        const missing = Object.keys(baseline).filter(path => !Object.hasOwn(data.files, path));
        const changed = Object.keys(baseline).filter(path => Object.hasOwn(data.files, path) && data.files[path] !== baseline[path]);
        const added = Object.keys(data.files).filter(path => !Object.hasOwn(baseline, path));
        if (data.files_state !== undefined && !['complete','unavailable'].includes(data.files_state)) throw Error('INVALID_FILES_STATE');
        const check = { state: data.files_state === 'unavailable' ? 'unavailable' : Object.keys(baseline).length ? (missing.length || changed.length || added.length ? 'changed' : 'matched') : 'unconfigured',
          at: new Date(observedAt).toISOString(), received_at: new Date(receivedAt).toISOString(), report_id: data.report_id,
          missing: data.files_state === 'unavailable' ? [] : missing, changed: data.files_state === 'unavailable' ? [] : changed, added: data.files_state === 'unavailable' ? [] : added };
        state.reports[name] = check;
        state.reportIds[name] = [...seenIds, data.report_id].slice(-reportReplayCacheSize);
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
    stateFile: env.SECURITY_STATE_FILE ?? './var/state.json',
    rules: ruleSource(join(dirname(env.SECURITY_CONFIG),'rules.json'),readFileSync(new URL('../release-public.pem',import.meta.url))),
    releases: env.SECURITY_RELEASE_DIR ? releaseSource(env.SECURITY_RELEASE_DIR,readFileSync(new URL('../release-public.pem',import.meta.url))) : undefined,
    virusDatabases: env.SECURITY_VIRUS_DB_DIR ? virusDatabaseSource(env.SECURITY_VIRUS_DB_DIR,readFileSync(new URL('../release-public.pem',import.meta.url))) : undefined });
  const server = createServer({ key: readFileSync(env.SECURITY_TLS_KEY), cert: readFileSync(env.SECURITY_TLS_CERT),
    ca: readFileSync(env.SECURITY_CLIENT_CA), requestCert: true, rejectUnauthorized: true }, monitor.handler);
  server.listen(Number(env.SECURITY_PORT ?? 9443), env.SECURITY_HOST ?? '0.0.0.0');
  const timer = setInterval(() => { void monitor.runProbes().catch(error => console.error('probe error:', error)); }, 30000);
  timer.unref();
  void monitor.runProbes().catch(error => console.error('probe error:', error));
  return { server, monitor };
}
