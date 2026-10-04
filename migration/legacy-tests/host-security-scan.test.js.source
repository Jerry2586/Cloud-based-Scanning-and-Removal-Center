import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { localSecurityScan } from '../apps/license-api/src/modules/operations/local-security-scan.js';
import { fullHostReport } from './helpers/host-scan-report.js';
import { HOST_SCAN_IDS } from '../packages/core/src/host-scan-contract.js';
import { handleOperationsHttp } from '../apps/license-api/src/modules/operations/http-routes.js';

function request(body) { return Object.assign(Readable.from([JSON.stringify(body)]), { headers: {} }); }
function route(method, body, allowed = true) {
  const seen = { status: null, result: null, csrf: null, limits: 0, audit: [] };
  const run = handleOperationsHttp({ method,
    url: new URL('https://example.test/web/admin/security/local-scan'),
    request: request(body), response: {},
    portal: { recordLocalSecurityScan: (state, actorId) => seen.audit.push({ state, actorId }) },
    requireSession: (csrf, permission) => {
      seen.csrf = csrf;
      assert.equal(permission, 'system.manage');
      if (!allowed) throw new Error('denied');
      return { actor_id: 'admin-test' };
    },
    rateLimit: () => { seen.limits++; },
    readJson: async req => JSON.parse((await Array.fromAsync(req)).join('')),
    respondJson: (_res, status, result) => { seen.status = status; seen.result = result; },
  }).then(() => seen);
  return run;
}

test('local scan is unavailable without a host agent and never pretends healthy', async () => {
  const report = await localSecurityScan('status', { APPGOG_HOST_SCAN_SOCKET: '/no-such-appgog-agent.sock' });
  assert.equal(report.state, 'unavailable');
  assert.equal(report.checks, undefined);
  assert.throws(() => localSecurityScan('arbitrary-command'), TypeError);
});

test('local scan requires admin permission and CSRF on writes', async () => {
  await assert.rejects(route('POST', {}, false), /denied/);
  const result = await route('POST', {});
  assert.equal(result.csrf, true);
  assert.equal(result.limits, 1);
  assert.equal(result.result.state, 'unavailable');
  assert.deepEqual(result.audit, [{ state: 'unavailable', actorId: 'admin-test' }]);
  const read = await route('GET', {});
  assert.equal(read.csrf, false);
  assert.deepEqual(read.audit, []);
});

test('local scan rejects browser-selected actions or paths', async () => {
  const result = await route('POST', { path: '/etc/shadow', command: 'cat' });
  assert.equal(result.status, 400);
  assert.match(result.result.error, /自定义/);
  assert.deepEqual(result.audit, []);
});

test('local scan exposes only bounded validated evidence fields', async () => {
  const socketPath = process.platform === 'win32'
    ? `\\\\.\\pipe\\appgog-security-${randomUUID()}`
    : join(tmpdir(), `appgog-security-${randomUUID()}.sock`);
  const valid = {
    name: '容器合同', state: 'finding', detail: '检测到偏移', id: 'container.contract',
    category: 'container', severity: 'high', checked_at: '2026-10-02T12:00:00.000Z',
    scope: 'compose project appgog', evidence_digest: 'a'.repeat(64), ignored: 'secret',
  };
  const server = createServer((_req, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify(fullHostReport({checked_at:valid.checked_at, overrides: {'container.contract':valid}})));
  });
  await new Promise((resolve, reject) => server.listen(socketPath, resolve).once('error', reject));
  try {
    const report = await localSecurityScan('status', { APPGOG_HOST_SCAN_SOCKET: socketPath });
    assert.equal(report.checked_at, valid.checked_at);
    const { ignored: _ignored, ...expectedValid } = valid;
    assert.deepEqual(report.checks.find(item => item.id === valid.id), expectedValid);
    assert.equal(report.checks.length, HOST_SCAN_IDS.length);
    assert.equal(report.coverage.complete, true);
  } finally {
    await new Promise(resolve => server.close(resolve));
    if (process.platform !== 'win32') await rm(socketPath, { force: true });
  }
});


async function withAgent(handler, action = 'status') {
  const socketPath = process.platform === 'win32'
    ? '\\\\.\\pipe\\appgog-security-' + randomUUID()
    : join(tmpdir(), 'appgog-security-' + randomUUID() + '.sock');
  const server = createServer(handler);
  await new Promise((resolve, reject) => server.listen(socketPath, resolve).once('error', reject));
  try { return await localSecurityScan(action, { APPGOG_HOST_SCAN_SOCKET: socketPath }); }
  finally { await new Promise(resolve => server.close(resolve)); if (process.platform !== 'win32') await rm(socketPath, { force: true }); }
}
const checkedAt = '2026-10-02T12:00:00.000Z';
const finished = fullHostReport({ checked_at: checkedAt });
const basicCheck = finished.checks[0];
function response(payload, code=200) { return (_req,res)=>{res.writeHead(code);res.end(JSON.stringify(payload));}; }

test('finished reports reject absent, malformed, over-limit or incomplete checks and timestamps',async()=>{
  for (const payload of [null, {}, {...finished, checks:undefined}, {...finished, checks:[]},
    {...finished, checks:[{name:'unsafe', state:'green',detail:'false'}]},
    {...finished, checks:Array(HOST_SCAN_IDS.length + 2).fill(basicCheck)}, {...finished,checked_at:undefined},
    {...finished,checked_at:'not-a-date'}, {...finished,checked_at:'2026'}, {...finished,checked_at:'2026-02-30T12:00:00Z'}]) {
    assert.equal((await withAgent(response(payload))).state,'unavailable');
  }
  assert.equal((await withAgent(response(finished))).state,'finished');
  const maximum = await withAgent(response({...finished, history_state:'unavailable', checks:[...finished.checks,{...basicCheck,id:'host.history',state:'unavailable'}]}));
  assert.equal(maximum.state,'finished');
  assert.equal(maximum.checks.length,HOST_SCAN_IDS.length + 1);
});
test('fixed scan request is bodyless and status codes cannot launder completed reports',async()=>{
  for(const [code,state,expected] of [[202,'running','running'],[409,'running','running'],[429,'unavailable','unavailable'],[200,'finished','unavailable'],[202,'finished','unavailable'],[500,'running','unavailable']]) {
    const result=await withAgent((req,res)=>{
      assert.equal(req.method,'POST');assert.equal(req.url,'/scan');assert.equal(req.headers['content-length'],'0');
      res.writeHead(code);res.end(JSON.stringify({...finished,state}));
    },'scan'); assert.equal(result.state,expected);
  }
  assert.equal((await withAgent(response({...finished,state:'running'},202))).state,'unavailable');
});
test('malformed, interrupted and UTF-8 oversized responses fail closed',async()=>{
  assert.equal((await withAgent((_req,res)=>res.end('{broken'))).state,'unavailable');
  assert.equal((await withAgent(response({...finished,ignored:'中'.repeat(12000)}))).state,'unavailable');
  assert.equal((await withAgent((_req,res)=>{res.writeHead(200,{'Content-Length':'10000'});res.write('{');res.destroy();})).state,'unavailable');
});
test('history filters secret fields, bounds output and reports corrupted evidence as unavailable',async()=>{
  const event={...basicCheck,previous_state:'arbitrary',secret:'never-expose'};
  const report=await withAgent(response({...finished,history:Array(12).fill(event)}));
  assert.equal(report.history.length,8);assert.equal(report.history_state,'truncated');
  for(const item of report.history){assert.equal(item.secret,undefined);assert.equal(item.previous_state,null);}
  for(const history of [[{...event,id:'../bad'}],[{...event,evidence_digest:'junk'}],[{...event,checked_at:'bad'}],'invalid']) {
    const bad=await withAgent(response({...finished,history}));assert.equal(bad.history.length,0);assert.equal(bad.history_state,'unavailable');
  }
});


test('business malware category survives the fixed local API in checks and transition history', async()=>{
  const item={...basicCheck, id:'malware.business', category:'malware', state:'finding', severity:'high'};
  const report=await withAgent(response({...fullHostReport({checked_at:checkedAt,overrides:{'malware.business':item}}), history:[{...item,previous_state:'ok'}]}));
  assert.equal(report.state,'finished');
  assert.equal(report.checks.find(row=>row.id==='malware.business').category,'malware');
  assert.equal(report.history_state,'ok');
  assert.equal(report.history[0].category,'malware');
  assert.equal(report.history[0].previous_state,'ok');
});


test('fixed coverage rejects missing, repeated, foreign IDs and missing evidence at the actual socket', async()=>{
  const invalid = [
    {...finished,checks:[basicCheck]},
    {...finished,checks:finished.checks.slice(1)},
    {...finished,checks:[...finished.checks.slice(1),finished.checks[1]]},
    {...finished,checks:[...finished.checks.slice(1),{...basicCheck,id:'unknown.check'}]},
    {...finished,checks:[...finished.checks,{...basicCheck,id:'host.history',state:'ok'}]},
  ];
  for(const key of ['id','category','severity','checked_at','scope','evidence_digest']) {
    const row={...basicCheck};delete row[key];
    invalid.push({...finished,checks:[row,...finished.checks.slice(1)]});
  }
  for(const patch of [{id:'../bad'}, {category:'arbitrary'}, {severity:'panic'}, {scope:'x'.repeat(121)},
    {checked_at:'2026-02-30T00:00:00Z'}, {checked_at:'2026-10-02T12:03:00Z'}, {evidence_digest:'BAD'}])
    invalid.push({...finished,checks:[{...basicCheck,...patch},...finished.checks.slice(1)]});
  for(const payload of invalid) {
    const report=await withAgent(response(payload));
    assert.equal(report.state,'unavailable');assert.equal(report.coverage,undefined);
  }
  const finding=fullHostReport({checked_at:checkedAt,overrides:{'integrity.program':{state:'finding',severity:'high'}}});
  const report=await withAgent(response(finding));
  assert.equal(report.state,'finished');assert.equal(report.checks[0].state,'finding');assert.equal(report.coverage.complete,true);
});

test('explicit unreadable history remains unavailable when history is truncated', async()=>{
  const report=await withAgent(response({...finished,history:Array(12).fill(basicCheck),history_state:'unavailable'}));
  assert.equal(report.state,'finished');assert.equal(report.history.length,8);assert.equal(report.history_state,'unavailable');
});
