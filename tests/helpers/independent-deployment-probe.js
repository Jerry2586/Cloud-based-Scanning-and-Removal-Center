// Deployment probe uses live HTTPS, actual credentials and real scan/socket state.
// It prints no credentials, cookies, private keys or identity tokens.
import https from 'node:https';
import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
const root='/etc/ironcurtain/local';
const origin='https://127.0.0.1:8790';
const ca=readFileSync(root+'/runtime/panel.crt');
const credentials=readFileSync(root+'/credentials/initial-credentials.txt','utf8').trim().split('\n');
let cookie='',csrf='';
function call(path,body,extra={}) {
  return new Promise((resolve,reject)=>{
    const payload=body===undefined?null:Buffer.from(JSON.stringify(body));
    const request=https.request(origin+path,{ca,timeout:10000,method:payload?'POST':'GET',headers:{...(payload?{Origin:origin,'Content-Type':'application/json','Content-Length':payload.length}:{}),...(cookie?{Cookie:cookie}:{}),...(csrf?{'X-CSRF-Token':csrf}:{}),...extra}},response=>{
      let data='';response.on('data',chunk=>{data+=chunk;if(data.length>50000)request.destroy(Error('Response exceeds probe limit'));});
      response.on('error',reject);response.on('end',()=>{try{resolve({status:response.statusCode,headers:response.headers,data:JSON.parse(data)});}catch(error){reject(error);}});
    });request.on('timeout',()=>request.destroy(Error('Deployment request timed out')));request.on('error',reject);request.end(payload);
  });
}
assert.equal((await call('/api/scan')).status,401);
const login=await call('/api/login',{username:credentials[0],password:credentials[1]});
assert.equal(login.status,200);cookie=login.headers['set-cookie'][0].split(';')[0];csrf=login.data.csrf;
assert.ok(csrf);
assert.equal((await call('/api/scan',{}, {'X-CSRF-Token':'invalid'})).status,403);
const initial=await call('/api/scan');
assert.equal(initial.status,200);assert.notEqual(initial.data.state,'unavailable', 'Local scan unavailable: '+(initial.data.reason || 'no reason'));
const started=await call('/api/scan',{});
assert.ok([202,429].includes(started.status), 'Expected scan start or cooldown, got HTTP '+started.status+' state='+started.data.state);
if(started.status===202) assert.equal(started.data.state,'running');
if(started.status===429) {
  assert.equal(started.data.state,'unavailable');
  assert.equal(started.data.response_status,429);
  assert.match(started.data.reason,/频繁/);
}
let finished;
for(let attempt=0;attempt<90;attempt++){
  const value=await call('/api/scan');assert.equal(value.status,200);
  if(value.data.state==='finished'){finished=value.data;break;}
  assert.ok(['running','idle'].includes(value.data.state));
  await new Promise(resolve=>setTimeout(resolve,1000));
}
assert.ok(finished,'Actual host scan must complete');
assert.equal(finished.progress.completed,finished.progress.total);
assert.ok(finished.checks.length>=25);
// Fresh local installation has a readable, empty quarantine journal.
// This check confirms the journal, not process blocking or automatic cleanup.
assert.equal(finished.checks.find(check=>check.id==='response.containment').state,'ok');
assert.deepEqual(finished.quarantine,{state:'empty',items:[],count:0,pending:0});
assert.equal(finished.findings.length,0);
assert.equal(finished.findings_total,0);
if(process.env.IRONCURTAIN_EXPECT_RULE_SEQUENCE){
 const sequence=Number(process.env.IRONCURTAIN_EXPECT_RULE_SEQUENCE);
 assert.equal(finished.rules.state,'ready');assert.equal(finished.rules.sequence,sequence);
 assert.ok(['complete','partial'].includes(finished.rule_hits.state));assert.equal(finished.rule_hits.total,1);
 assert.equal(finished.rule_hits.items[0].path,'/srv/ironcurtain-rule-ci/sample.bin');
 assert.equal(finished.rule_hits.items[0].rule_sequence,sequence);
 assert.equal(finished.checks.find(check=>check.id==='malware.business').state,'finding');
 console.log('Live signed rules and real file-byte hash hit passed.');
}
// Identity imports become visible through the panel's 30-second status refresh.
// Wait for the actual authenticated identity, never accept a stale prior node.
let cloud;
for(let attempt=0;attempt<45;attempt++){
 cloud=await call('/api/cloud/status');assert.equal(cloud.status,200);
 if(cloud.data.connected===true && cloud.data.node_id==='node-ci') break;
 await new Promise(resolve=>setTimeout(resolve,1000));
}
assert.equal(cloud.data.connected,true,'Panel must establish mTLS after identity refresh; state='+cloud.data.state);assert.equal(cloud.data.node_id,'node-ci');
assert.equal(cloud.data.policy.remote_execution,false);
if(process.env.IRONCURTAIN_EXPECT_RELEASE_VERSION){
 assert.equal(cloud.data.releases.state,'ready');
 assert.equal(cloud.data.releases.version,process.env.IRONCURTAIN_EXPECT_RELEASE_VERSION);
 assert.equal(cloud.data.releases.activation,'local-admin');
 console.log('Authenticated live dashboard release metadata passed.');
}
console.log('Live independent HTTPS login, CSRF, host scanning and mTLS node connection passed.');
