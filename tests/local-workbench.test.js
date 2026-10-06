import test from 'node:test';
import assert from 'node:assert/strict';
import {HOST_SCAN_IDS} from '../src/contracts/host-scan-contract.js';
import {summarizeLocalSecurity,describeWorkbenchTask} from '../src/contracts/local-workbench.js';
const now=Date.now(),at=n=>new Date(now+n*1000).toISOString();
const check=(id,state='ok')=>({id,name:id,detail:'observed',state,category:'host',severity:state==='finding'?'high':'info',checked_at:at(-10),scope:id,evidence_digest:'a'.repeat(64)});
const scan=()=>({schema:'ironcurtain-full-scan/v1',profile_digest:'a'.repeat(64),state:'finished',started_at:at(-19),updated_at:at(-2),finished_at:at(-2),indexed:2,processed:2,clean:1,infected:1,skipped:0,errors:0,bytes_scanned:50,index_complete:true,scope:'enrolled-directories-only',reasons:[]});
test('observed risks remain visible when stale, incomplete or history is unavailable',()=>{
 const r={state:'finished',checked_at:at(-1000),checks:[check(HOST_SCAN_IDS[0],'finding')]};
 const v=summarizeLocalSecurity(r,{stale:true,historyUnavailable:true,now});
 assert.equal(v.tone,'finding');assert.equal(v.findings,1);assert.equal(v.notes.length,3);
 assert.match(v.detail,/1 项环境风险/);assert.notEqual(v.coverage,'报告完整且有效');
});
test('unknown, invalid and duplicate checks cannot inflate risk totals or hide findings',()=>{
 const c=check(HOST_SCAN_IDS[0],'finding');
 const v=summarizeLocalSecurity({state:'finished',checks:[c,{...c,state:'ok'},check('host.unknown','finding'),{...check(HOST_SCAN_IDS[1],'finding'),evidence_digest:'bad'}]});
 assert.equal(v.findings,1);assert.equal(v.tone,'finding');
});
test('no agent report never claims safe status, installed engine or complete coverage',()=>{
 const v=summarizeLocalSecurity(null,{now});assert.equal(v.tone,'warning');assert.match(v.title,/尚未就绪/);
 assert.match(v.coverage,/不能确认/);assert.ok(!summarizeLocalSecurity(null,{stale:true,now}).notes.some(note=>note.includes('过期')));const task=describeWorkbenchTask(null,{now});assert.equal(task.active,false);assert.equal(task.percent,null);
});
test('safe summary requires full fresh evidence and available history',()=>{
 const r={state:'finished',checks:HOST_SCAN_IDS.map(id=>check(id))};
 assert.equal(summarizeLocalSecurity(r,{coverageComplete:true,stale:false,historyUnavailable:false,now}).tone,'ok');
 for(const option of [{stale:true},{coverageComplete:false},{historyUnavailable:true}])assert.notEqual(summarizeLocalSecurity(r,{coverageComplete:true,historyUnavailable:false,...option,now}).tone,'ok');
 assert.equal(summarizeLocalSecurity({...r,checks:[check(HOST_SCAN_IDS[0],'unavailable')]},{coverageComplete:true,historyUnavailable:false,now}).tone,'warning');
});
test('valid file evidence exposes hits independently from environment coverage',()=>{
 const v=summarizeLocalSecurity({state:'unavailable',full_scan:scan()},{now});assert.equal(v.tone,'finding');assert.equal(v.infected,1);
 const older={...scan(),started_at:at(-1020),updated_at:at(-1000),finished_at:at(-1000)};
 assert.ok(summarizeLocalSecurity({state:'unavailable',full_scan:older},{now}).notes.some(n=>n.includes('历史查杀')));
 assert.equal(summarizeLocalSecurity({state:'finished',full_scan:{...scan(),processed:-1}},{now}).infected,0);
});
test('environment progress counts fixed checks and exposes friendly activity',()=>{
 const r={state:'running',started_at:at(-30),checks:HOST_SCAN_IDS.slice(0,3).map(id=>check(id)),progress:{completed:3,total:25,current:HOST_SCAN_IDS[3]}};
 const task=describeWorkbenchTask(r,{now});assert.equal(task.percent,12);assert.ok(task.detail.includes('3 / 25'));assert.match(task.detail,/容器镜像基线/);
 const stale={...r,started_at:at(-300),checks:r.checks.map(c=>({...c,checked_at:at(-300)}))};
 assert.equal(describeWorkbenchTask(stale,{now}).percent,null);assert.match(describeWorkbenchTask(stale,{now}).title,/过期/);
 assert.equal(describeWorkbenchTask({...r,progress:{...r.progress,total:26}},{now}).percent,null);
});
test('request pending and invalid timestamps never fabricate completion',()=>{
 const v=describeWorkbenchTask({state:'finished',checked_at:'invalid'},{busy:true,action:'checkup',now});assert.equal(v.percent,null);assert.equal(v.active,true);
 assert.equal(describeWorkbenchTask({state:'finished',checked_at:'invalid'},{trusted:true,now}).kind,'idle');
});
test('file scan percentage retains its file denominator and indexing stays unknown',()=>{
 const f={...scan(),state:'scanning',finished_at:undefined,indexed:4,processed:2,index_complete:true};
 const task=describeWorkbenchTask({state:'idle',full_scan:f},{now});assert.equal(task.kind,'full-scan');assert.equal(task.percent,50);assert.equal(task.active,true);
 assert.equal(describeWorkbenchTask({full_scan:{...f,state:'indexing',index_complete:false}},{now}).percent,null);
});

test('rejected and pending requests cannot reuse a previous completed task',()=>{
 const r={state:'finished',task_id:'a'.repeat(32),checked_at:at(-2),checks:HOST_SCAN_IDS.map(id=>check(id)),full_scan:{...scan(),task_id:'a'.repeat(32)}};
 for(const reason of ['已有扫描正在进行','扫描请求过于频繁']){const v=describeWorkbenchTask(r,{now,trusted:true,action:'full-scan',requestIssue:reason});assert.equal(v.percent,null);assert.equal(v.active,false);assert.match(v.detail,new RegExp(reason));}
 const waiting=describeWorkbenchTask(r,{now,trusted:true,action:'full-scan',requestedTaskId:'b'.repeat(32)});assert.equal(waiting.percent,null);assert.equal(waiting.active,true);assert.match(waiting.detail,/旧报告不代表/);
 const active=describeWorkbenchTask({...r,state:'running',started_at:at(-20),progress:{completed:25,total:25,current:null}},{now});assert.equal(active.percent,99);
});
