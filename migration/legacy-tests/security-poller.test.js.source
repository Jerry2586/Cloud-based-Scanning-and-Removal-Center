import { fullHostReport } from './helpers/host-scan-report.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createSecurityPoller } from '../apps/web/public/assets/portal/security-poller.js';
function fixture() {
  let identity='session-a', active=true, calls=0;
  const requests=[], rendered=[], errors=[], timers=new Map(); let timerId=0;
  const poller=createSecurityPoller({
    request:()=>{calls++; return new Promise((resolve,reject)=>requests.push({resolve,reject}));},
    render:r=>rendered.push(r), onError:e=>errors.push(e), allowed:()=>active, session:()=>identity,
    schedule:(fn,delay)=>{timers.set(++timerId,{fn,delay});return timerId;}, cancel:id=>timers.delete(id),
  });
  return {poller, requests, rendered, errors, timers, calls:()=>calls,
    session:v=>{identity=v;}, active:v=>{active=v;}};
}
test('logout invalidates pending responses and prevents timer resurrection',async()=>{
  const f=fixture(); const old=f.poller.run(); await Promise.resolve();
  assert.equal(f.poller.run(),old); assert.equal(f.calls(),1);
  f.poller.stop(); f.session(null); f.active(false);
  f.requests[0].resolve({state:'finished'}); await old;
  assert.deepEqual(f.rendered,[]); assert.equal(f.timers.size,0);
  await f.poller.run(); assert.equal(f.calls(),1);
});
test('a new session can poll while old work remains pending; old errors are suppressed',async()=>{
  const f=fixture(); const old=f.poller.run(); await Promise.resolve();
  f.poller.stop(); f.session('session-b'); const next=f.poller.run(); await Promise.resolve();
  f.requests[0].reject(new Error('old')); await old;
  f.requests[1].resolve({state:'running'}); await next;
  assert.deepEqual(f.errors,[]); assert.deepEqual(f.rendered,[{state:'running'}]);
  assert.equal([...f.timers.values()][0].delay,2000);
  f.poller.stop(); assert.equal(f.timers.size,0);
});
test('manual refresh discards the prior snapshot and normal results use a slower interval',async()=>{
  const f=fixture(); const old=f.poller.run(); await Promise.resolve();
  const next=f.poller.refresh(); await Promise.resolve();
  f.requests[0].resolve({state:'finished',old:true}); await old;
  f.requests[1].resolve({state:'finished'}); await next;
  assert.deepEqual(f.rendered,[{state:'finished'}]); assert.equal([...f.timers.values()][0].delay,20000);
  f.active(false); const timer=[...f.timers.values()][0]; timer.fn(); await Promise.resolve();
  assert.equal(f.calls(),2);
});

import { readFileSync } from 'node:fs';

// Execute the real page function with a pending request and a minimal DOM.
function pageSecurityFixture() {
  const source = readFileSync(new URL('../apps/web/public/assets/portal/security-ui.js', import.meta.url), 'utf8');
  const start = source.indexOf('  async function renderSecurity() {');
  const end = source.indexOf('  function bind() {', start);
  assert.ok(start > 0 && end > start);
  const pending = [], nodes = new Map();
  const state = { csrf: 'session-a' }, document = { hidden: false }; let permission = true;
  const $ = id => { if (!nodes.has(id)) nodes.set(id, { textContent: '' }); return nodes.get(id); };
  const construct = new Function('state', 'document', 'can', 'request', '$', 'let securityRenderGeneration = 0;\n' + source.slice(start, end) + '\nreturn {run:renderSecurity, invalidate:()=>securityRenderGeneration++};');
  const control = construct(state, document, () => permission, () => new Promise((resolve, reject) => pending.push({resolve, reject})), $);
  return { ...control, state, document, pending, nodes, permission: value => { permission = value; } };
}
test('page discards cloud-status responses after logout, session switch, hiding or permission loss', async () => {
  for (const mutate of [f => { f.state.csrf = null; f.invalidate(); }, f => { f.state.csrf = 'session-b'; }, f => { f.document.hidden = true; }, f => { f.permission(false); }]) {
    const f = pageSecurityFixture(); const pending = f.run(); mutate(f);
    f.pending[0].resolve({connected:true, nodes:{}, events:[]}); await pending;
    assert.equal(f.nodes.get('security-cloud-state').textContent, '正在核对');
    assert.equal(f.nodes.has('security-event-title'), false);
  }
});
test('page only accepts newest cloud request and discards old failures', async () => {
  const f = pageSecurityFixture(); const old = f.run(), fresh = f.run();
  f.pending[1].resolve({connected:true, nodes:{}, events:[]}); await fresh;
  f.pending[0].reject(new Error('old secret')); await old;
  assert.equal(f.nodes.get('security-cloud-state').textContent, '云端已连接');
  assert.equal([...f.nodes.values()].some(node => node.textContent === 'old secret'), false);
});

function localPageFixture() {
  const source = readFileSync(new URL('../apps/web/public/assets/portal/security-ui.js', import.meta.url), 'utf8');
  const html = readFileSync(new URL('../apps/web/public/admin.html', import.meta.url), 'utf8');
  const node = () => ({ textContent: '', dataset: {}, children: [], replaceChildren(...items) { this.children = items; }, append(item) { this.children.push(item); } });
  const nodes = new Map([...html.matchAll(/id="([^"]+)"/g)].map(match => [match[1], node()]));
  const start = source.indexOf('  const localStateLabels =');
  const end = source.indexOf('  const localSecurityPoller =', start);
  assert.ok(start > 0 && end > start);
  const render = new Function('$', 'document', 'consoleView', 'let localRunning = false; let scanRequested = false;\n' + source.slice(source.indexOf('// Keep this fixed browser'),source.indexOf('export function createSecurityUi')) + source.slice(start, end) + '\nreturn renderLocalReport;')(id => nodes.get(id) ?? null, { createElement: node }, { update() {} });
  return { render, nodes };
}
test('actual admin page IDs render findings and history as plain text', () => {
  const { render, nodes } = localPageFixture();
  const payload = '<img src=x onerror=alert(1)>';
  render({ state: 'finished', checked_at: new Date().toISOString(), history_state: 'ok',
    checks: [{ name: '程序完整性', state: 'finding', detail: payload }],
    history: [{ checked_at: '2026-10-03T00:00:00Z', name: '程序完整性', previous_state: 'ok', state: 'finding', detail: payload }] });
  assert.equal(nodes.get('security-local-state').dataset.state, 'warning');
  assert.match(nodes.get('security-local-state').textContent, /覆盖不完整/);
  assert.equal(nodes.get('security-local-checks').children.length, 1);
  assert.ok(nodes.get('security-local-checks').children[0].textContent.includes(payload));
  assert.equal(nodes.get('security-local-history').children.length, 1);
  assert.match(nodes.get('security-local-history-state').textContent, /八条/);
});
test('actual admin page never shows stale or unavailable scans as healthy', () => {
  for (const report of [
    { state: 'finished', checked_at: '2020-01-01T00:00:00Z', checks: [{ name: '程序完整性', state: 'ok', detail: 'unchanged' }] },
    { state: 'finished', checked_at: new Date().toISOString(), checks: [{ name: '特征库', state: 'unavailable', detail: 'missing' }], history_state: 'unavailable' },
    { state: 'unavailable', reason: 'socket unavailable', checks: [] },
    { state: 'finished', checked_at: new Date().toISOString(), checks: [] },
  ]) {
    const { render, nodes } = localPageFixture(); render(report);
    assert.equal(nodes.get('security-local-state').dataset.state, 'warning');
    assert.doesNotMatch(nodes.get('security-local-state').textContent, /未发现异常/);
    if (report.history_state === 'unavailable') assert.match(nodes.get('security-local-history-state').textContent, /不可用/);
  }
});

test('actual admin page distinguishes unreadable history from a valid empty history', () => {
  for (const report of [
    { state: 'unavailable', reason: 'agent missing' },
    { state: 'failed', checked_at: new Date().toISOString() },
    { state: 'running', checks: [], history: [] },
    { state: 'finished', checked_at: new Date().toISOString(), checks: [], history_state: 'ok' },
  ]) {
    const { render, nodes } = localPageFixture(); render(report);
    assert.match(nodes.get('security-local-history-state').textContent, /不可用/);
    assert.doesNotMatch(nodes.get('security-local-history-state').textContent, /暂无/);
  }
  const { render, nodes } = localPageFixture();
  render({ state: 'finished', checked_at: new Date().toISOString(), checks: [], history: [], history_state: 'ok' });
  assert.match(nodes.get('security-local-history-state').textContent, /暂无状态变化记录/);
});


test('real page only shows green for complete fresh checks and usable history', () => {
  const report=fullHostReport();
  const valid=localPageFixture();valid.render(report);
  assert.equal(valid.nodes.get('security-local-state').dataset.state,'ok');
  assert.match(valid.nodes.get('security-local-state').textContent,/未发现异常/);
  const variants=[
    {...report,checks:[report.checks[0]]},
    {...report,checks:Array(24).fill(report.checks[0])},
    {...report,checks:[{...report.checks[0],id:'foreign.id'},...report.checks.slice(1)]},
    {...report,checks:[{...report.checks[0],evidence_digest:undefined},...report.checks.slice(1)]},
    {...report,checks:[{...report.checks[0],checked_at:'2020-01-01T00:00:00Z'},...report.checks.slice(1)]},
    {...report,checks:[{...report.checks[0],checked_at:new Date(Date.now()+180000).toISOString()},...report.checks.slice(1)]},
    {...report,history_state:'unavailable'}, {...report,history:undefined},
    {...report,coverage:undefined}, {...report,coverage:{...report.coverage,expected:1}},
    {...report,coverage:{...report.coverage,complete:false}},
  ];
  for (const patch of [{category:'foreign'}, {severity:'panic'}, {scope:''}, {scope:'x'.repeat(121)},
    {name:''}, {detail:undefined}, {checked_at:'2026-02-30T00:00:00Z'}, {checked_at:report.checked_at.slice(0,19)},
    {checked_at:report.checked_at.replace('Z','+08:00')}]) {
    variants.push({...report, checks:[{...report.checks[0],...patch},...report.checks.slice(1)]});
  }
  for(const invalid of variants){const f=localPageFixture();f.render(invalid);assert.equal(f.nodes.get('security-local-state').dataset.state,'warning');}
  const finding=fullHostReport({overrides:{'malware.business':{state:'finding'}}});
  const f=localPageFixture();f.render(finding);assert.equal(f.nodes.get('security-local-state').dataset.state,'finding');
});
