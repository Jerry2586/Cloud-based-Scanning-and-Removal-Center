import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {mkdtempSync,rmSync,symlinkSync,mkdirSync,chmodSync,chownSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {DatabaseSync} from 'node:sqlite';
import {createCloudControl} from '../src/cloud/control.js';
const hash='a'.repeat(64);
const envelope=()=>({rules:{value:{version:'1.0.0',expires_at:Math.floor(Date.now()/1000)+3600,indicators:[{id:'fixture',sha256:hash,label:'fixture indicator'}]},digest:'b'.repeat(64)}});
const submission=(sha256=hash)=>({sha256,request_key:randomUUID()});
function fixture(t,extra={}) {const dir=mkdtempSync(join(tmpdir(),'cloud-control-'));const control=createCloudControl({file:join(dir,'control.sqlite'),sources:envelope,schedule:false,...extra});t.after(async()=>{await control.close();rmSync(dir,{recursive:true,force:true});});return control;}
test('plugin readiness, strict schemas, unknown results and audit are real',async t=>{let sources={};const c=fixture(t,{sources:()=>sources});assert.throws(()=>c.pluginAction('admin',{id:'signed-rules',action:'install'}),{status:409});assert.throws(()=>c.enqueue('node/a',{sha256:[hash],request_key:randomUUID()}),{status:400});assert.throws(()=>c.enqueue('node/a',{...submission(),command:'whoami'}),{status:400});assert.throws(()=>c.pluginAction('admin',{id:'custom-url',action:'install'}),{status:400});let j=c.enqueue('node/a',submission());await c.pump();assert.equal(c.job('node/a',j.id).state,'partial');assert.equal(c.job('node/a',j.id).result.verdict,'unknown');sources=envelope();c.pluginAction('admin',{id:'signed-rules',action:'install'});j=c.enqueue('node/a',submission());await c.pump();assert.equal(c.job('node/a',j.id).result.verdict,'malicious');assert.equal(c.job('node/a',j.id).result.evidence[0].digest,'b'.repeat(64));j=c.enqueue('node/a',submission('c'.repeat(64)));await c.pump();assert.equal(c.job('node/a',j.id).result.verdict,'unknown');assert.equal(c.job('node/a',j.id).result.automatic_remediation,false);assert(c.snapshot().audit.some(a=>a.action==='plugin.install'));sources={rules:{error:'expired'}};assert.equal(c.plugins()[0].readiness.state,'unavailable');j=c.enqueue('node/a',submission());await c.pump();assert.equal(c.job('node/a',j.id).state,'partial');});
test('idempotency, identity isolation and queue quotas',async t=>{const c=fixture(t);const input=submission(),j=c.enqueue('node/a',input);assert.equal(c.enqueue('node/a',input).id,j.id);assert.throws(()=>c.enqueue('node/a',{...input,sha256:'c'.repeat(64)}),{status:409});assert.throws(()=>c.job('node/b',j.id),{status:404});assert.equal(c.job('admin',j.id).id,j.id);assert.throws(()=>c.job('node/a','-'.repeat(36)),{status:400});for(let i=1;i<32;i++)c.enqueue('node/a',submission());assert.throws(()=>c.enqueue('node/a',submission()),{status:429});for(let n=0;n<7;n++)for(let i=0;i<32;i++)c.enqueue('node/q'+n,submission());assert.throws(()=>c.enqueue('node/final',submission()),{status:429});});
test('policy revision conflict and revocation stops queued hash egress',async t=>{let requests=0;const c=fixture(t,{intelligence:async()=>{requests++;return{state:'known',malicious:4,suspicious:0,harmless:0,undetected:1,secret:'must-not-return'};}});c.pluginAction('admin',{id:'hash-intelligence',action:'install'});assert.equal(c.policy().external_hash_lookup,false);c.setPolicy('admin',{revision:1,malicious_threshold:3,external_hash_lookup:true});assert.throws(()=>c.setPolicy('admin',{revision:1,malicious_threshold:1,external_hash_lookup:false}),{status:409});let j=c.enqueue('node/a',submission());c.setPolicy('admin',{revision:2,malicious_threshold:3,external_hash_lookup:false});await c.pump();assert.equal(requests,0);assert.equal(c.job('node/a',j.id).state,'partial');c.setPolicy('admin',{revision:3,malicious_threshold:3,external_hash_lookup:true});j=c.enqueue('node/a',submission());await c.pump();assert.equal(requests,1);assert.equal(c.job('node/a',j.id).result.verdict,'malicious');assert(!JSON.stringify(c.snapshot()).includes('must-not-return'));c.pluginAction('admin',{id:'hash-intelligence',action:'pause'});j=c.enqueue('node/a',submission());await c.pump();assert.equal(requests,1);assert.equal(c.job('node/a',j.id).result.verdict,'unknown');});
test('durable settings, completed jobs and interrupted jobs recover after restart',async t=>{const dir=mkdtempSync(join(tmpdir(),'cloud-restart-')),file=join(dir,'control.sqlite');let c=createCloudControl({file,sources:envelope,schedule:false});t.after(async()=>{await c.close();rmSync(dir,{recursive:true,force:true});});c.pluginAction('admin',{id:'signed-rules',action:'install'});c.setPolicy('admin',{revision:1,malicious_threshold:5,external_hash_lookup:false});const j=c.enqueue('node/a',submission());await c.pump();const pending=c.enqueue('node/a',submission());await c.close();const db=new DatabaseSync(file);db.prepare("UPDATE jobs SET state='running' WHERE id=?").run(pending.id);db.close();c=createCloudControl({file,sources:envelope,schedule:false});assert.equal(c.policy().revision,2);assert.equal(c.plugins()[0].enabled,true);assert.equal(c.job('node/a',j.id).state,'complete');assert.equal(c.job('node/a',pending.id).state,'queued');assert(c.snapshot().audit.some(a=>a.action==='job.recovered'));await c.pump();assert.equal(c.job('node/a',pending.id).result.verdict,'malicious');await Promise.all([c.close(),c.close()]);});
test('shutdown cancels a hung provider and resumes its task without false completion',async t=>{let started;const ready=new Promise(r=>started=r);const c=fixture(t,{intelligence:async()=>{started();return new Promise(()=>{});}});c.pluginAction('admin',{id:'hash-intelligence',action:'install'});c.setPolicy('admin',{revision:1,malicious_threshold:3,external_hash_lookup:true});c.enqueue('node/a',submission());const running=c.pump();await ready;await c.close();await running;});
test('database newer schema and symlink sidecars fail closed',async t=>{const dir=mkdtempSync(join(tmpdir(),'cloud-storage-')),file=join(dir,'control.sqlite');t.after(()=>rmSync(dir,{recursive:true,force:true}));const db=new DatabaseSync(file);db.exec('PRAGMA user_version=2');db.close();assert.throws(()=>createCloudControl({file,sources:envelope}),/newer/);if(process.platform!=='win32'){rmSync(file);symlinkSync(join(dir,'outside'),file+'-wal');assert.throws(()=>createCloudControl({file,sources:envelope}),/Unsafe/);}});

test('Linux persistent storage rejects writable and symlink ancestors before directory creation',{skip:process.platform==='win32'},async t=>{const dir=mkdtempSync(join(tmpdir(),'cloud-ancestors-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));mkdirSync(join(dir,'unsafe'));chmodSync(join(dir,'unsafe'),0o777);assert.throws(()=>createCloudControl({file:join(dir,'unsafe','new','control.sqlite'),sources:envelope}),/Unsafe/);mkdirSync(join(dir,'target'));symlinkSync(join(dir,'target'),join(dir,'linked'));assert.throws(()=>createCloudControl({file:join(dir,'linked','new','control.sqlite'),sources:envelope}),/Unsafe/);});


test('authenticated report analysis is bounded, persistent, deduplicated and queue-safe', async t => {
  let at = Date.now(); const c = fixture(t, { now: () => at });
  const actor = 'node/node-one', report = () => ({ report_id: randomUUID(), hashes: [hash] });
  assert.equal(c.enqueueReport(actor, report()).state, 'unavailable');
  assert.equal(c.snapshot().jobs.length, 0);
  c.pluginAction('admin', {id: 'signed-rules', action: 'install'});
  assert.throws(() => c.enqueueReport('admin', report()), {status:400});
  assert.throws(() => c.enqueueReport(actor, {...report(), hashes: Array(9).fill(hash)}), {status:400});
  assert.throws(() => c.enqueueReport(actor, {...report(), hashes: ['bad']}), {status:400});
  const first = c.enqueueReport(actor, {...report(), hashes: [hash, hash]});
  assert.equal(first.jobs.length, 1); assert.equal(first.jobs[0].reused, false);
  assert.equal(c.enqueueReport(actor, report()).jobs[0].id, first.jobs[0].id);
  assert.equal(c.enqueueReport(actor, report()).jobs[0].reused, true);
  await c.pump(); assert.equal(c.job(actor, first.jobs[0].id).result.verdict, 'malicious');
  assert.equal(c.enqueueReport(actor, report()).jobs[0].id, first.jobs[0].id);
  const other = c.enqueueReport('node/node-two', report()); assert.notEqual(other.jobs[0].id, first.jobs[0].id);
  at += 600001; assert.notEqual(c.enqueueReport(actor, report()).jobs[0].id, first.jobs[0].id);
  for(let i=0;i<31;i++) c.enqueue(actor, submission());
  const full = c.enqueueReport(actor, {...report(), hashes: ['d'.repeat(64)]});
  assert.equal(full.state, 'partial'); assert.equal(full.deferred, 1); assert.equal(full.jobs.length, 0);
  assert(c.snapshot().audit.some(a => a.action === 'report.hash-analysis'));
});

test('report deduplication survives a database restart', async t => {
  const dir=mkdtempSync(join(tmpdir(),'report-restart-')), file=join(dir,'control.sqlite');
  let c=createCloudControl({file,sources:envelope,schedule:false});
  t.after(async()=>{await c.close();rmSync(dir,{recursive:true,force:true});});
  c.pluginAction('admin',{id:'signed-rules',action:'install'});
  const first=c.enqueueReport('node/node-one',{report_id:randomUUID(),hashes:[hash]}); await c.pump(); await c.close();
  c=createCloudControl({file,sources:envelope,schedule:false});
  const next=c.enqueueReport('node/node-one',{report_id:randomUUID(),hashes:[hash]});
  assert.equal(next.jobs[0].id,first.jobs[0].id); assert.equal(next.jobs[0].reused,true);
});


test('scheduled worker retries a transient storage failure without a new request', async t => {
  let failNext = false;
  const c = fixture(t, { schedule: true, now: () => {
    if (failNext) { failNext = false; throw Error('injected transient storage failure'); }
    return Date.now();
  }});
  c.pluginAction('admin', {id:'signed-rules',action:'install'});
  const j = c.enqueue('node/a', submission());
  failNext = true;
  await new Promise(resolve => setTimeout(resolve, 30));
  assert(c.snapshot().worker_error);
  assert.equal(c.job('node/a', j.id).state, 'queued');
  const deadline = Date.now() + 4000;
  while (c.job('node/a', j.id).state === 'queued' && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 40));
  assert.equal(c.job('node/a', j.id).state, 'complete');
  assert.equal(c.job('node/a', j.id).result.verdict, 'malicious');
  assert.equal(c.snapshot().worker_error, null);
});

test('private storage rejects a directory owned by a different UID', {skip:process.platform==='win32' || process.getuid()!==0}, t => {
  const dir=mkdtempSync(join(tmpdir(),'cloud-owner-'));
  t.after(()=>rmSync(dir,{recursive:true,force:true}));
  const attacker=join(dir,'attacker'); mkdirSync(attacker,{mode:0o700}); chownSync(attacker,65534,65534);
  assert.throws(()=>createCloudControl({file:join(attacker,'control.sqlite'),sources:envelope}),/Unsafe/);
});
