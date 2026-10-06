import test from 'node:test';
import assert from 'node:assert/strict';
import {HOST_SCAN_IDS} from '../src/contracts/host-scan-contract.js';
import {describeCheckup,sanitizeCheckup} from '../src/contracts/checkup-status.js';
import {describeAntivirus,sanitizeAntivirus} from '../src/contracts/antivirus-status.js';
const now=Date.now(), at=n=>new Date(now+n*1000).toISOString();
function report(){return {profile_digest:'a'.repeat(64),state:'finished',checked_at:at(-20),checks:HOST_SCAN_IDS.map(id=>({id,name:id,detail:'observed',state:id.startsWith('cloudflare.')?'unavailable':'ok',category:'host',severity:'info',checked_at:at(-25),scope:id,evidence_digest:'a'.repeat(64)})),inventory:{container_state:'complete',listener_state:'complete',directory_state:'complete',environment:{system_state:'complete',package_state:'complete',service_state:'complete'}},checkup:{schema:'ironcurtain-checkup/v1',profile_digest:'a'.repeat(64),state:'finished',stage:'complete',started_at:at(-30),environment_at:at(-20),updated_at:at(-1),reasons:[]},full_scan:{schema:'ironcurtain-full-scan/v1',profile_digest:'a'.repeat(64),state:'finished',started_at:at(-19),updated_at:at(-2),finished_at:at(-2),indexed:2,processed:2,clean:1,infected:1,skipped:0,errors:0,bytes_scanned:50,index_complete:true,scope:'enrolled-directories-only',reasons:[]}};}
test('same-task real completion requires environment, asset coverage and file evidence, cloud optional',()=>{
 const value=describeCheckup(report(),{now});assert.equal(value.percent,100);assert.equal(value.state,'finished');
 for(const mutate of [r=>r.profile_digest='b'.repeat(64),r=>r.checkup.profile_digest='b'.repeat(64),r=>r.full_scan.profile_digest='b'.repeat(64),r=>r.checked_at=at(-100),r=>r.checks[0].checked_at=at(-100),r=>r.full_scan.started_at=at(-100),r=>r.full_scan.finished_at=at(5),r=>r.full_scan.finished_at=at(-25),r=>r.full_scan.updated_at=at(-25),r=>r.full_scan.state='partial',r=>r.full_scan.errors=1,r=>r.inventory.container_state='partial',r=>r.checks[0].state='unavailable',r=>r.checks={}]) {
  const r=report();mutate(r);const v=describeCheckup(r,{now});assert.equal(v.percent,null);assert.equal(v.state,'unavailable');
 }
});
test('running progress counts stage evidence; stale, malformed and historical tasks never claim completion',()=>{
 const r=report();r.state='running';r.started_at=at(-30);r.checks=r.checks.slice(0,3);r.checkup={...r.checkup,state:'running',stage:'environment'};r.progress={completed:3,total:25,current:HOST_SCAN_IDS[3]};
 assert.equal(describeCheckup(r,{now}).percent,null);assert.match(describeCheckup(r,{now}).detail,/3 \/ 25/);
 const all={...r,checks:report().checks,progress:{completed:25,total:25,current:null}};assert.equal(describeCheckup(all,{now}).percent,null);assert.equal(describeCheckup(all,{now}).active,true);
 r.checks[2].checked_at=at(-200);assert.equal(describeCheckup(r,{now}).percent,null);
 r.checks={};assert.doesNotThrow(()=>describeCheckup(r,{now}));
 const historical=report();historical.checkup.updated_at=at(-1000);historical.checkup.started_at=at(-2000);historical.checkup.environment_at=at(-1500);assert.equal(describeCheckup(historical,{now}).percent,null);
 for(const value of [{}, {...report().checkup,updated_at:at(-40)},{...report().checkup,reasons:['bad\nreason']},{...report().checkup,stage:'files',environment_at:undefined}]) assert.equal(sanitizeCheckup(value).state,'unavailable');
 assert.equal(describeCheckup(undefined,{now,busy:true}).percent,null);
});
test('local antivirus has independent official updates and honest readiness states',()=>{
 const e={engine:'ClamAV',installed:true,version:'1.4.3',state:'configured',detail:'metadata configured',source:'official-direct',updater:'scheduled',update_state:'idle',database_at:at(-100),database_version:100,signatures:999};
 assert.equal(describeAntivirus(e).can_update,true);assert.match(describeAntivirus(e).source_label,/无需玄武/);
 assert.equal(describeAntivirus({...e,source:'xuanwu-signed'}).can_update,false);
 assert.equal(describeAntivirus({...e,update_state:'running'}).can_update,false);
 for(const modify of [{version:'sh;bad'},{installed:false},{database_at:'bad'},{signatures:0},{source:'any'},{update_state:'success'}]) assert.equal(sanitizeAntivirus({...e,...modify}).state,'unavailable');
 assert.equal(describeAntivirus(undefined).can_update,false);
});

test('missing agent evidence does not claim the engine is uninstalled',()=>{const status=describeAntivirus(undefined);assert.equal(status.installed,null);assert.equal(status.title,'本机病毒引擎尚不可核验');assert.equal(status.update_label,'官方更新器状态尚不可核验');assert.equal(status.can_update,false);const missing=describeAntivirus({engine:'ClamAV',installed:false,state:'unavailable',updater:'unknown',detail:'引擎缺失'});assert.equal(missing.title,'本机病毒引擎未安装');});

test('new checkup identities bind both phases and retain legacy evidence compatibility',()=>{
 const id='a'.repeat(32),r=report();r.task_id=id;r.checkup.task_id=id;r.full_scan.task_id=id;
 assert.equal(describeCheckup(r,{now}).percent,100);
 for(const mutate of [x=>x.task_id='b'.repeat(32),x=>delete x.task_id,x=>x.full_scan.task_id='b'.repeat(32),x=>delete x.full_scan.task_id]){const copy=structuredClone(r);mutate(copy);assert.equal(describeCheckup(copy,{now}).percent,null);assert.equal(describeCheckup(copy,{now}).state,'unavailable');}
 assert.equal(describeCheckup(report(),{now}).percent,100);
 assert.equal(sanitizeCheckup({...r.checkup,task_id:123}).state,'unavailable');
});
