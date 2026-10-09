import test from 'node:test';
import assert from 'node:assert/strict';
import {validateOperation,validatePorts,sanitizeOperations,operationRecheckPlan} from '../src/contracts/operations-status.js';
import {operationJob,operationStatus,operationScope,revision} from './fixtures/operations.js';
test('operations accepts only fixed evidence-bound actions and bounded ports',()=>{
 assert.deepEqual(validateOperation({action:'ports',revision,tcp:[443,22],udp:[]}).tcp,[22,443]);
 assert.deepEqual(validateOperation({action:'review',id:revision,evidence:revision,status:'accepted',reason:' 核对业务需要 '}).reason,'核对业务需要');
 for(const input of [null,[],{action:[]},{action:'__proto__'},{action:'constructor'},{action:'ports',revision,tcp:[22,22],udp:[]},{action:'ports',revision,tcp:[true],udp:[]},{action:'ports',revision,tcp:[0],udp:[]},{action:'ports',revision,tcp:[65536],udp:[]},{action:'ports',revision,tcp:[22],udp:[],command:'sh'},{action:'quarantine',id:revision,confirm:'yes'},{action:'restore',id:revision,confirm:'restore-original',path:'/root/target'},{action:'review',id:revision,evidence:revision,status:'fixed',reason:'实际未修复'},{action:'review',id:revision,evidence:revision,status:'open',reason:'reason\nsecret'}])assert.throws(()=>validateOperation(input));
 assert.throws(()=>validatePorts(Array.from({length:129},(_,i)=>i+1)));
});
test('operation reports strip private fields and preserve missing coverage and accepted risk',()=>{
 const report=operationStatus();report.private='secret';report.policy.token='secret';report.job={...operationJob('complete'),target:'port-policy',private:'secret'};
 report.audit=[{...report.job}];report.risks=[{id:revision,evidence:revision,source:'environment',rule:'network.listeners',target:'host',title:'未批准监听',detail:'检测仍有告警',severity:'medium',observed_at:'2026-10-09T01:00:00.000Z',fresh:true,review:{status:'accepted',reason:'业务临时需要',updated_at:'2026-10-09T01:00:01.000Z'},secret:'secret'}];
 const clean=sanitizeOperations(report);assert.equal(clean.state,'ready');assert.equal(clean.sources.environment,'unavailable');assert.equal(clean.risks[0].review.status,'accepted');assert.equal(clean.risks[0].severity,'medium');assert.ok(!JSON.stringify(clean).includes('secret'));
 assert.deepEqual(sanitizeOperations({schema:report.schema,state:'running',job:operationJob(),private:'secret'}),{schema:report.schema,state:'running',job:operationJob()});
});
test('malformed operation status never becomes successful empty results',()=>{
 for(const mutate of [v=>v.policy.tcp.push(22),v=>v.risks.push({}),v=>v.audit.push(operationJob()),v=>v.quarantine.count=-1,v=>v.job=operationJob('failed')&&{...operationJob('failed'),finished_at:'2026-10-08T01:00:00.000Z'},v=>v.quarantine.items.push({id:revision,path:'bad\npath',signature:'Test',state:'quarantined',size:0}),v=>v.sources.engines='safe',v=>v.state='running']){
  const report=operationStatus();mutate(report);assert.equal(sanitizeOperations(report).state,'unavailable');
 }
});

test('Unicode evidence and review lengths match host codepoint limits',()=>{
 const report=operationStatus(); report.job=operationJob('complete'); report.job.reason='🛡'.repeat(500);
 assert.equal(sanitizeOperations(report).state,'ready');
 assert.equal(validateOperation({action:'review',id:revision,evidence:revision,status:'investigating',reason:'  '+'🛡'.repeat(240)+'  '}).reason,'🛡'.repeat(240));
 for(const reason of ['🛡'.repeat(3),'🛡'.repeat(241)]) assert.throws(()=>validateOperation({action:'review',id:revision,evidence:revision,status:'open',reason}));
 report.job.reason+='🛡'; assert.equal(sanitizeOperations(report).state,'unavailable');
});

test('scope is optional and idempotent, strips private discovery identity fields',()=>{
 const old=sanitizeOperations(operationStatus());assert.equal(old.scope,null);assert.deepEqual(sanitizeOperations(old),old);
 const report={...operationStatus(),scope:operationScope()};report.scope.discovery.candidates[0].device=123;report.scope.secret='secret';
 const clean=sanitizeOperations(report);assert.equal(clean.state,'ready');assert.ok(!JSON.stringify(clean).includes('secret'));assert.equal(clean.scope.discovery.candidates[0].device,undefined);assert.deepEqual(sanitizeOperations(clean),clean);
});
test('scope enrollment accepts only bounded trusted identifiers and rejects malformed coverage',()=>{
 const value={action:'enroll',revision,inventory:'b'.repeat(64),ids:['1'.repeat(16)]};assert.deepEqual(validateOperation(value),value);assert.deepEqual(validateOperation({action:'discover'}),{action:'discover'});
 for(const v of [{...value,ids:[]},{...value,ids:['1'.repeat(16),'1'.repeat(16)]},{...value,ids:Array.from({length:33},(_,i)=>i.toString(16).padStart(16,'0'))},{...value,path:'/root'},{...value,inventory:'bad'},{action:'discover',command:'sh'}])assert.throws(()=>validateOperation(v));
 for(const mutate of [v=>v.scope.discovery.candidates[0].kind='shell',v=>v.scope.discovery.candidates[0].id='x',v=>v.scope.discovery.candidates[0].value='relative',v=>v.scope.discovery.count=0,v=>v.scope.discovery.truncated=true,v=>v.scope.discovery.state='unavailable',v=>v.scope.containers=['app\nsecret'],v=>v.scope.discovery.candidates.push({...v.scope.discovery.candidates[0]})]){const v={...operationStatus(),scope:operationScope()};mutate(v);assert.equal(sanitizeOperations(v).state,'unavailable');}
});

test('follow-up plans require a completed identified operation and select only fixed checks',()=>{
 for(const action of ['ports','enroll'])assert.deepEqual(operationRecheckPlan({...operationJob('complete'),action}),{action:'scan',panel:'environment',label:'复检环境与端口'});
 for(const action of ['quarantine','restore'])assert.deepEqual(operationRecheckPlan({...operationJob('complete'),action}),{action:'checkup',panel:'scan',label:'复检文件与环境'});
 for(const value of [null,{},operationJob(),operationJob('failed'),operationJob('interrupted'),{...operationJob('complete'),action:'review'},{...operationJob('complete'),action:'discover'},{...operationJob('complete'),action:'shell'},{...operationJob('complete'),id:'invalid'},{...operationJob('complete'),finished_at:'invalid'}])assert.equal(operationRecheckPlan(value),null);
});
