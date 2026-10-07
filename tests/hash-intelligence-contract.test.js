import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {validateHashRequest,validateHashJob} from '../src/contracts/hash-intelligence.js';
const hash='a'.repeat(64),id=randomUUID(),at=new Date().toISOString();
const job=()=>({id,requester:'node/node-one',sha256:hash,state:'queued',created_at:at,updated_at:at,attempts:0,policy:{revision:1,malicious_threshold:3,external_hash_lookup:false},providers:[],result:null});
test('hash request rejects executable fields, coercions and malformed identities',()=>{
  assert.deepEqual(validateHashRequest({sha256:hash,request_key:id}),{sha256:hash,request_key:id});
  for(const v of [null,1,'bad',[],{sha256:[hash],request_key:id},{sha256:hash,request_key:id,command:'id'},{sha256:hash,request_key:'../other'}])assert.throws(()=>validateHashRequest(v),e=>e.status===400);
});
test('cloud task contract checks identity, task, hash, states and preserves unknown',()=>{
  assert.equal(validateHashJob(job(),{nodeId:'node-one',id,sha256:hash}).state,'queued');
  for(const options of [{nodeId:'node-two'},{id:randomUUID()},{sha256:'b'.repeat(64)}])assert.throws(()=>validateHashJob(job(),options));
  for(const change of [{state:'safe'},{requester:'root'},{created_at:'yesterday'},{attempts:-1},{providers:['shell']},{providers:['signed-rules','signed-rules']},{result:{verdict:'safe'}}])assert.throws(()=>validateHashJob({...job(),...change}));
  const partial={...job(),state:'partial',result:{verdict:'unknown',policy_revision:1,automatic_remediation:false,evidence:[],reason:'没有启用适用的检测插件'}};
  assert.equal(validateHashJob(partial).result.verdict,'unknown');
  assert.throws(()=>validateHashJob({...partial,state:'complete'}));
});
test('verdict is recomputed from bounded evidence, executable fields never pass through',()=>{
  const evidence={provider:'hash-intelligence',state:'known',malicious:2,suspicious:0,undetected:4,harmless:6,analyzed_at:at};
  const value={...job(),state:'complete',providers:['hash-intelligence'],result:{verdict:'suspicious',policy_revision:1,automatic_remediation:false,evidence:[evidence],reason:'摘要复核',command:'rm',path:'/etc/shadow'},command:'id'};
  const clean=validateHashJob(value);assert.equal(clean.result.verdict,'suspicious');assert(!JSON.stringify(clean).includes('command'));assert(!JSON.stringify(clean).includes('/etc/shadow'));
  for(const change of [{verdict:'malicious'},{verdict:'safe'},{automatic_remediation:true},{policy_revision:2},{evidence:[{...evidence,malicious:-1}]},{evidence:[{...evidence,malicious:1001}]},{evidence:[{...evidence,analyzed_at:'invalid'}]}])assert.throws(()=>validateHashJob({...value,result:{...value.result,...change}}));
  value.result.evidence=[{provider:'signed-rules',state:'malicious',reason:'签名规则命中'}];value.providers=['signed-rules'];value.result.verdict='malicious';assert.equal(validateHashJob(value).result.verdict,'malicious');
});
