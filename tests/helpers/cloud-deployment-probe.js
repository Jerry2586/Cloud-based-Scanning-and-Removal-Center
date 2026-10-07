// Live cloud deployment acceptance: TLS, session boundaries, SQLite and restart persistence.
// Credentials, session cookies and CSRF tokens remain in memory and are never printed.
import https from 'node:https';
import {readFileSync,writeFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import assert from 'node:assert/strict';
const [phase,host,fixtureFile]=process.argv.slice(2);
assert.ok(['seed','verify'].includes(phase));
assert.match(host,/^\d{1,3}(?:\.\d{1,3}){3}$/);
assert.ok(fixtureFile);
const root='/etc/ironcurtain/cloud',origin='https://'+host+':8791';
const ca=readFileSync(root+'/runtime/panel.crt');
const credentials=readFileSync(root+'/credentials/initial-credentials.txt','utf8').trim().split('\n');
let cookie='',csrf='';
function call(route,body,extra={}) {
  return new Promise((resolve,reject)=>{
    const payload=body===undefined?null:Buffer.from(JSON.stringify(body));
    const request=https.request(origin+route,{ca,timeout:10000,method:payload?'POST':'GET',headers:{...(payload?{Origin:origin,'Content-Type':'application/json','Content-Length':payload.length}:{}),...(cookie?{Cookie:cookie}:{}),...(csrf?{'X-CSRF-Token':csrf}:{}),...extra}},response=>{
      let data='';response.on('data',chunk=>{data+=chunk;if(data.length>524288)request.destroy(Error('Cloud response exceeds probe limit'));});
      response.on('error',reject);response.on('end',()=>{try{resolve({status:response.statusCode,headers:response.headers,data:JSON.parse(data)});}catch(error){reject(error);}});
    });
    request.on('timeout',()=>request.destroy(Error('Cloud request timed out')));request.on('error',reject);request.end(payload);
  });
}
assert.equal((await call('/healthz')).data.service,'xuanwu-admin');
assert.equal((await call('/api/control')).status,401);
const login=await call('/api/login',{username:credentials[0],password:credentials[1]});
assert.equal(login.status,200);cookie=login.headers['set-cookie'][0].split(';')[0];csrf=login.data.csrf;assert.ok(csrf);
let fixture;
if(phase==='seed') {
  const initial=await call('/api/control');assert.equal(initial.status,200);
  const policy={revision:initial.data.policy.revision,malicious_threshold:5,external_hash_lookup:false};
  assert.equal((await call('/api/policy',policy,{'X-CSRF-Token':'invalid'})).status,403);
  assert.equal((await call('/api/policy',policy,{Origin:'https://untrusted.invalid'})).status,403);
  const changed=await call('/api/policy',policy);assert.equal(changed.status,200);
  assert.equal((await call('/api/policy',policy)).status,409);
  const request={sha256:'d'.repeat(64),request_key:randomUUID()};
  assert.equal((await call('/api/intelligence',{...request,command:'arbitrary'})).status,400);
  const task=await call('/api/intelligence',request);assert.equal(task.status,202);
  assert.equal((await call('/api/intelligence',request)).data.id,task.data.id);
  assert.equal((await call('/api/intelligence',{...request,sha256:'e'.repeat(64)})).status,409);
  let result;
  for(let attempt=0;attempt<30;attempt++) {
    result=await call('/api/intelligence/'+task.data.id);assert.equal(result.status,200);
    if(!['queued','running'].includes(result.data.state)) break;
    await new Promise(resolve=>setTimeout(resolve,250));
  }
  assert.equal(result.data.state,'partial');assert.equal(result.data.result.verdict,'unknown');
  assert.equal(result.data.result.automatic_remediation,false);
  fixture={id:task.data.id,sha256:request.sha256,policy:changed.data};
  writeFileSync(fixtureFile,JSON.stringify(fixture),{mode:0o600});
} else fixture=JSON.parse(readFileSync(fixtureFile,'utf8'));
const snapshot=await call('/api/control');assert.equal(snapshot.status,200);
assert.deepEqual(snapshot.data.policy,fixture.policy);
assert.ok(snapshot.data.audit.some(a=>a.action==='policy.update'&&a.subject===String(fixture.policy.revision)));
assert.ok(snapshot.data.audit.some(a=>a.action==='job.enqueue'&&a.subject===fixture.id));
assert.ok(snapshot.data.audit.some(a=>a.action==='job.partial'&&a.subject===fixture.id));
assert.equal(snapshot.data.capabilities.remote_shell,false);
const persisted=await call('/api/intelligence/'+fixture.id);assert.equal(persisted.status,200);
assert.equal(persisted.data.sha256,fixture.sha256);assert.equal(persisted.data.requester,'admin');
assert.equal(persisted.data.state,'partial');assert.equal(persisted.data.result.verdict,'unknown');
assert.equal(persisted.data.result.automatic_remediation,false);
assert.equal((await call('/api/logout',{})).status,200);
assert.equal((await call('/api/control')).status,401);
console.log('Live cloud '+phase+' passed: trusted TLS, authentication, strict inputs, unknown verdict, audit and durable policy/task.');
