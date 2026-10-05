import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:https';
import { createHash, X509Certificate } from 'node:crypto';
import { CloudClient, loadCloudClient, createCloudLink } from '../src/local/cloud-client.js';
import { createMonitor, validateConfiguration } from '../src/monitor.js';
import { HOST_SCAN_IDS } from '../src/contracts/host-scan-contract.js';
const binary=process.platform==='win32' ? 'C:/Program Files/Git/usr/bin/openssl.exe' : 'openssl';
const available=spawnSync(binary,['version']).status===0;
const digest=v=>createHash('sha256').update(v).digest('hex');
const snapshot=(state='ok')=>{const checked_at=new Date().toISOString();return {files:{'/srv/site/app.js':'a'.repeat(64)},files_state:'complete',scan:{state:'finished',checked_at,history:[],history_state:'ok',checks:HOST_SCAN_IDS.map(id=>({id,name:id,category:'host',severity:'info',state,checked_at,scope:id,detail:'test evidence',evidence_digest:'a'.repeat(64)}))}};};
test('real local cloud client validates mutual TLS, per-node permissions and honest incomplete snapshots',{skip:!available},async()=>{
 const directory=mkdtempSync(join(tmpdir(),'ironcurtain-cloud-'));let server;
 const run=(...args)=>{const result=spawnSync(binary,args,{cwd:directory,encoding:'utf8'});assert.equal(result.status,0,result.stderr);};
 const read=name=>readFileSync(join(directory,name));
 try {
  run('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout','ca.key','-out','ca.crt','-days','1','-subj','/CN=Cloud Test CA');
  for(const name of ['server','node-a','node-b','reader']){
   run('req','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+name);
   writeFileSync(join(directory,name+'.ext'),name==='server' ? 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' : 'extendedKeyUsage=clientAuth\n');
   run('x509','-req','-in',name+'.csr','-CA','ca.crt','-CAkey','ca.key','-CAcreateserial','-out',name+'.crt','-days','1','-extfile',name+'.ext');
  }
  const subject=name=>({role:name==='reader' ? 'reader' : 'ironcurtain-node',token_sha256:digest(name.padEnd(40,'x')),fingerprint256:new X509Certificate(read(name+'.crt')).fingerprint256,baseline:name==='reader' ? undefined : {'/srv/site/app.js':'a'.repeat(64)}});
  const config={nodes:{'node-a':subject('node-a'),'node-b':subject('node-b')},readers:[subject('reader')],policy:{rules:{require_signed_updates:true,allow_remote_commands:false,allow_cloud_push:false}}};validateConfiguration(config);
  const monitor=createMonitor(config);
  server=createServer({key:read('server.key'),cert:read('server.crt'),ca:read('ca.crt'),requestCert:true,rejectUnauthorized:true},monitor.handler);
  await new Promise(resolve=>server.listen(0,resolve));const endpoint='https://localhost:'+server.address().port;
  const options=name=>({endpoint,nodeId:name,ca:read('ca.crt'),cert:read(name+'.crt'),key:read(name+'.key'),token:name.padEnd(40,'x')});
  const client=new CloudClient(options('node-a'));const other=new CloudClient(options('node-b'));
  assert.equal((await client.status()).node_id,'node-a');
  assert.deepEqual(Object.keys((await client.status()).nodes),['node-a']);
  assert.equal((await other.status()).node_id,'node-b');
  await client.report(snapshot());assert.equal((await client.status()).node.integrity.state,'matched');
  const missing=snapshot('unavailable');missing.files_state='unavailable';missing.files={};await client.report(missing);
  assert.equal((await client.status()).node.integrity.state,'unavailable');
  assert.equal((await other.status()).node.last_report_at,null);
  await assert.rejects(new CloudClient({...options('node-a'),token:'wrong'}).status(),/AUTH_REJECTED/);
  await assert.rejects(new CloudClient({...options('node-a'),cert:read('node-b.crt'),key:read('node-b.key')}).status(),/AUTH_REJECTED/);
  await assert.rejects(new CloudClient({...options('node-a'),ca:read('node-a.crt')}).status());
  await assert.rejects(new CloudClient({...options('node-a'),endpoint:endpoint.replace('localhost','127.0.0.1')}).status(),/altname|hostname|ip address/i);
  assert.throws(()=>client.call('/v1/status'),/INVALID_CLOUD_OPERATION/);
  assert.throws(()=>client.call('/bin/sh',{}),/INVALID_CLOUD_OPERATION/);
  await assert.rejects(client.report({...snapshot(),files_state:undefined}),/INCOMPLETE/);
  const stale=snapshot();stale.scan.checked_at='2020-01-01T00:00:00.000Z';await assert.rejects(client.report(stale),/INCOMPLETE/);
  await assert.rejects(client.report({...snapshot(),files:{'/srv/site/../key':'a'.repeat(64)}}),/INCOMPLETE/);
 } finally {if(server)await new Promise(resolve=>server.close(resolve));rmSync(directory,{recursive:true,force:true});}
});
test('cloud configuration cannot broaden the endpoint into credentials, paths or insecure HTTP',()=>{
 const base={endpoint:'https://security.example',nodeId:'node-a'};
 for(const endpoint of ['http://security.example','https://u:p@security.example','https://security.example/command','https://security.example/?secret=x'])assert.throws(()=>new CloudClient({...base,endpoint}),/INVALID/);
 assert.throws(()=>new CloudClient({...base,nodeId:'arbitrary-project'}),/INVALID/);
});

test('unpaired and invalid or untrusted cloud identity expose disconnected state without stopping the local link',async()=>{
 const workspace=mkdtempSync(join(tmpdir(),'ic-cloud-offline-'));
 const directory=join(workspace,'identity');
 const link=createCloudLink({directory,interval:60000});
 try {
  const unpaired=await link.status();assert.equal(unpaired.state,'unpaired');assert.equal(unpaired.connected,false);
  mkdirSync(directory);writeFileSync(join(directory,'cloud.json'),'{}');
  const invalid=await link.refresh();assert.equal(invalid.state,'unavailable');assert.equal(invalid.connected,false);
  rmSync(directory,{recursive:true});
  const restored=await link.refresh();assert.equal(restored.state,'unpaired');assert.equal(restored.connected,false);
 } finally {link.close();rmSync(workspace,{recursive:true,force:true});}
});
