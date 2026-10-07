import {CloudClient} from '../src/local/cloud-client.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createServer,request} from 'node:https';
import {X509Certificate,createHash,randomUUID} from 'node:crypto';
import {createMonitor} from '../src/monitor.js';
import {createCloudControl} from '../src/cloud/control.js';
const binary=process.platform==='win32'?'C:/Program Files/Git/usr/bin/openssl.exe':'openssl';
const available=spawnSync(binary,['version']).status===0;
test('real mTLS hash tasks require both credentials and enforce per-node result isolation',{skip:!available},async t=>{
  const dir=mkdtempSync(join(tmpdir(),'hash-tls-'));let server,control;t.after(async()=>{if(server){server.closeAllConnections();await new Promise(r=>server.close(r));}if(control)await control.close();rmSync(dir,{recursive:true,force:true});});
  const openssl=(...args)=>{const r=spawnSync(binary,args,{cwd:dir,encoding:'utf8'});assert.equal(r.status,0,r.stderr);};
  openssl('req','-x509','-newkey','ed25519','-nodes','-keyout','ca.key','-out','ca.crt','-days','1','-subj','/CN=Fixture CA');
  const identities={};for(const name of ['server','node-one','node-two','reader']){
    openssl('req','-newkey','ed25519','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+name);
    writeFileSync(join(dir,name+'.ext'),name==='server'?'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n':'extendedKeyUsage=clientAuth\n');
    openssl('x509','-req','-in',name+'.csr','-CA','ca.crt','-CAkey','ca.key','-CAcreateserial','-out',name+'.crt','-days','1','-extfile',name+'.ext');
    const cert=readFileSync(join(dir,name+'.crt')),key=readFileSync(join(dir,name+'.key')),token=name+'-fixture-'+ 'x'.repeat(32);
    identities[name]={cert,key,token,fingerprint256:new X509Certificate(cert).fingerprint256,token_sha256:createHash('sha256').update(token).digest('hex')};
  }
  control=createCloudControl({file:join(dir,'control.sqlite'),sources:()=>({rules:{value:{version:'1.0.0',expires_at:Math.floor(Date.now()/1000)+3600,indicators:[{id:'fixture',sha256:'a'.repeat(64),label:'fixture'}]},digest:'b'.repeat(64)}}),schedule:false});
  const nodeOne={...identities['node-one'],baseline:{'/www/index.js':'e'.repeat(64)}};
  const monitor=createMonitor({nodes:{'node-one':nodeOne,'node-two':identities['node-two']},readers:[identities.reader],control});
  const ca=readFileSync(join(dir,'ca.crt'));server=createServer({ca,key:identities.server.key,cert:identities.server.cert,requestCert:true,rejectUnauthorized:true},monitor.handler);
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const call=(name,path,body,extra={})=>new Promise((resolve,reject)=>{const identity=identities[name]||{};const req=request({hostname:'127.0.0.1',port:server.address().port,path,ca,cert:identity.cert,key:identity.key,rejectUnauthorized:true,agent:false,method:body?'POST':'GET',headers:{authorization:'Bearer '+identity.token,'content-type':'application/json',...extra}},res=>{let data='';res.on('data',c=>data+=c);res.on('end',()=>resolve({status:res.statusCode,data:JSON.parse(data)}));});req.on('error',reject);req.end(body?JSON.stringify(body):undefined);});
  const client=new CloudClient({endpoint:'https://127.0.0.1:'+server.address().port,nodeId:'node-one',ca,...identities['node-one']});
  const direct=await client.submitHash({sha256:'c'.repeat(64),request_key:randomUUID()});await control.pump();assert.equal((await client.hashJob(direct.id)).result.verdict,'unknown');
  const second=new CloudClient({endpoint:'https://127.0.0.1:'+server.address().port,nodeId:'node-two',ca,...identities['node-two']});await assert.rejects(second.hashJob(direct.id),e=>e.status===404);
  const wrong=new CloudClient({endpoint:'https://127.0.0.1:'+server.address().port,nodeId:'node-one',ca,...identities['node-one'],token:identities['node-two'].token});await assert.rejects(wrong.hashJob(direct.id),e=>e.status===503);
  assert.throws(()=>client.call('/v1/intelligence/../../config'));await assert.rejects(client.hashJob('../config'));
  const value={sha256:'a'.repeat(64),request_key:randomUUID()};const submitted=await call('node-one','/v1/intelligence',value);assert.equal(submitted.status,202);
  assert.equal((await call('node-one','/v1/intelligence',value)).data.id,submitted.data.id);
  await control.pump();const endpoint='/v1/intelligence/'+submitted.data.id;
  assert.equal((await call('node-one',endpoint)).data.result.verdict,'unknown');
  assert.equal((await call('node-two',endpoint)).status,404);
  assert.equal((await call('reader','/v1/intelligence',value)).status,403);
  assert.equal((await call('node-one',endpoint,undefined,{authorization:'Bearer '+identities['node-two'].token})).status,403);
  await assert.rejects(call('missing',endpoint));
  assert.equal((await call('node-one','/v1/intelligence',{...value,command:'whoami'})).status,400);
  assert.equal((await call('node-one','/v1/intelligence',value,{'content-type':'text/plain'})).status,415);
  assert.equal((await call('node-one','/v1/intelligence',{payload:'x'.repeat(1100)})).status,413);
  control.pluginAction('admin',{id:'signed-rules',action:'install'});
  const report=(files,files_state='complete')=>({files,files_state,report_id:randomUUID(),observed_at:new Date().toISOString()});
  const normal=await call('node-one','/v1/report',report({'/www/index.js':'e'.repeat(64)}));
  assert.equal(normal.status,200); assert.equal(normal.data.state,'matched'); assert.equal(normal.data.intelligence,undefined);
  const change=await call('node-one','/v1/report',report({'/www/index.js':'a'.repeat(64)}));
  assert.equal(change.status,200); assert.equal(change.data.intelligence.state,'scheduled'); assert.equal(change.data.intelligence.jobs.length,1);
  const taskId=change.data.intelligence.jobs[0].id; await control.pump();
  const found=await client.hashJob(taskId); assert.equal(found.result.verdict,'malicious'); assert.equal(found.result.automatic_remediation,false);
  await assert.rejects(second.hashJob(taskId),e=>e.status===404);
  const repeat=await call('node-one','/v1/report',report({'/www/index.js':'a'.repeat(64)}));
  assert.equal(repeat.data.intelligence.jobs[0].id,taskId);assert.equal(repeat.data.intelligence.jobs[0].reused,true);
  assert.equal((await call('node-two','/v1/report',report({'/www/index.js':'a'.repeat(64)}))).data.intelligence,undefined);
  assert.equal((await call('node-one','/v1/report',report({'/www/index.js':'a'.repeat(64)},'unavailable'))).data.intelligence,undefined);
  const files=Object.fromEntries(Array.from({length:12},(_,i)=>['/www/'+i+'.js',String(i).padStart(64,'0')]));
  const bounded=await call('node-one','/v1/report',report(files));assert.equal(bounded.data.intelligence.jobs.length,8);assert.equal(bounded.data.intelligence.omitted,4);
  const original=control.enqueueReport;control.enqueueReport=()=>{throw Error('storage unavailable');};
  const degraded=await call('node-one','/v1/report',report({'/www/index.js':'f'.repeat(64)}));
  assert.equal(degraded.status,200);assert.equal(degraded.data.state,'changed');assert.equal(degraded.data.intelligence.state,'unavailable');control.enqueueReport=original;

});


test('CloudClient constructor enforces node bearer token format before network access',()=>{
 for(const token of ['',undefined,'short','x'.repeat(257),'x'.repeat(32)+'\n','x'.repeat(32)+' '])assert.throws(()=>new CloudClient({endpoint:'https://example.invalid',nodeId:'node-one',token}),/INVALID_NODE_TOKEN/);
 assert.doesNotThrow(()=>new CloudClient({endpoint:'https://example.invalid',nodeId:'node-one',token:'x'.repeat(32)}));
});
