import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {mkdtempSync,writeFileSync,mkdirSync,chmodSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {verifyVirusManifest,virusDatabaseSource} from '../src/virus-db-store.js';
import {pullVirusDatabase} from '../scripts/virus-db-pull.js';
import {renderDashboard} from '../src/dashboard.js';
import {readFileSync,readdirSync} from 'node:fs';
import {createMonitor} from '../src/monitor.js';
import {deliveryTLS,tlsServer,requestRelease,pairedIdentity} from './helpers/delivery-tls.js';
const publisher=generateKeyPairSync('ed25519'),hash=b=>createHash('sha256').update(b).digest('hex');
const rootOnly=process.platform!=='linux'||process.getuid?.()!==0;
function fixture(t){
  const directory=mkdtempSync(join(tmpdir(),'ic-virus-db-'));chmodSync(directory,0o700);t.after(()=>rmSync(directory,{recursive:true,force:true}));
  // Deliberately synthetic transport fixture: does not claim official ClamAV acceptance.
  const data=Buffer.alloc(512,42),files={};
  for(const name of ['bytecode.cvd','daily.cvd','main.cvd'])files[name]={version:7,signatures:1,functionality:1,timestamp:Math.floor(Date.now()/1000),size:data.length,sha256:hash(data)};
  const value={schema:'ironcurtain-virus-db/v1',files},bytes=Buffer.from(JSON.stringify(value)+'\n'),signature=sign(null,bytes,publisher.privateKey);
  const snapshot=hash(bytes),root=join(directory,snapshot);mkdirSync(root,{mode:0o700});
  writeFileSync(join(root,'manifest.json'),bytes,{mode:0o600});writeFileSync(join(root,'manifest.json.sig'),signature,{mode:0o600});
  for(const name of Object.keys(files))writeFileSync(join(root,name),data,{mode:0o600});
  writeFileSync(join(directory,'active.json'),JSON.stringify({schema:'ironcurtain-virus-db-pointer/v1',snapshot}),{mode:0o600});
  return {directory,root,snapshot,value,bytes,signature,data};
}
test('independent pinned virus database signature, limits, freshness and exact schema',t=>{
  const item=fixture(t);assert.deepEqual(verifyVirusManifest(item.bytes,item.signature,publisher.publicKey),item.value);
  assert.throws(()=>verifyVirusManifest(item.bytes,item.signature,generateKeyPairSync('ed25519').publicKey),/SIGNATURE/);
  assert.throws(()=>verifyVirusManifest(Buffer.from('tampered'),item.signature,publisher.publicKey),/SIGNATURE/);
  for(const alter of [v=>{v.command='rm';},v=>{v.files['main.cld']=v.files['main.cvd'];delete v.files['main.cvd'];},v=>{v.files['daily.cvd'].size=512*1024*1024+1;},v=>{v.files['daily.cvd'].version=-1;},v=>{v.files['daily.cvd'].timestamp+=3600;},v=>{v.files['daily.cvd'].timestamp-=8*86400;}]){
    const v=structuredClone(item.value);alter(v);const b=Buffer.from(JSON.stringify(v)),s=sign(null,b,publisher.privateKey);assert.throws(()=>verifyVirusManifest(b,s,publisher.publicKey));
  }
});
test('protected signed CVD cache uses stable bounded streams and rejects tampering',{skip:rootOnly},async t=>{
  const item=fixture(t),source=virusDatabaseSource(item.directory,publisher.publicKey);
  assert.equal(source.summary().state,'ready');assert.equal(source.latest().snapshot,item.snapshot);
  const asset=source.asset(item.snapshot,'daily.cvd'),chunks=[];for await(const chunk of asset.stream)chunks.push(chunk);assert.deepEqual(Buffer.concat(chunks),item.data);
  assert.throws(()=>source.asset(item.snapshot,'../daily.cvd'),/NOT_FOUND/);
  assert.throws(()=>source.asset('f'.repeat(64),'daily.cvd'),/NOT_FOUND/);
  writeFileSync(join(item.root,'daily.cvd'),Buffer.alloc(512,0));assert.throws(()=>source.asset(item.snapshot,'daily.cvd'),/DIGEST/);
  chmodSync(join(item.root,'daily.cvd'),0o666);assert.throws(()=>source.asset(item.snapshot,'daily.cvd'),/FILE/);
  writeFileSync(join(item.directory,'active.json'),'{}');assert.equal(source.summary().state,'unavailable');
});
test('real mTLS virus database delivery enforces identities, GET-only fixed routes and signed offers',{skip:rootOnly},async t=>{
  const item=fixture(t),source=virusDatabaseSource(item.directory,publisher.publicKey),tls=deliveryTLS(fixture(t).directory);
  const monitor=createMonitor({readers:[],nodes:{'node-ci':{fingerprint256:tls['node-ci'].fingerprint256,token_sha256:hash(tls['node-ci'].token)}},readers:[{fingerprint256:tls.reader.fingerprint256,token_sha256:hash(tls.reader.token)}],virusDatabases:source});
  const {endpoint}=await tlsServer(t,tls.server,monitor.handler);
  const get=(identity=tls['node-ci'],options={})=>requestRelease(endpoint,identity,{path:'/v1/virus-db/latest',...options});
  for(const actor of [tls['node-ci'],tls.reader]){
    const response=await get(actor);assert.equal(response.status,200);const offer=JSON.parse(response.bytes);assert.equal(offer.snapshot,item.snapshot);verifyVirusManifest(Buffer.from(offer.manifest,'base64'),Buffer.from(offer.signature,'base64'),publisher.publicKey);
    const stream=await get(actor,{path:'/v1/virus-db/'+item.snapshot+'/daily.cvd'});assert.equal(stream.status,200);assert.deepEqual(stream.bytes,item.data);
  }
  assert.equal((await get(tls['node-ci'],{token:tls.reader.token})).status,403);
  await assert.rejects(get({ca:tls.server.ca,token:'x'}));
  for(const path of ['/v1/virus-db/latest?x=1','/v1/virus-db/'+item.snapshot+'/daily.cld','/v1/virus-db/'+item.snapshot+'/unknown.cvd','/v1/virus-db/'+'f'.repeat(64)+'/daily.cvd'])assert.equal((await get(tls['node-ci'],{path})).status,404);
  assert.equal((await get(tls['node-ci'],{method:'POST'})).status,404);
  assert.equal(monitor.status().virus_databases.state,'ready');
  writeFileSync(join(item.root,'daily.cvd'),Buffer.alloc(512,0));assert.equal((await get(tls['node-ci'],{path:'/v1/virus-db/'+item.snapshot+'/daily.cvd'})).status,503);
});

test('local mTLS pull streams exactly signed bytes; failures remove the incomplete output',{skip:rootOnly},async t=>{
  const item=fixture(t),source=virusDatabaseSource(item.directory,publisher.publicKey),tls=deliveryTLS(fixture(t).directory);
  const monitor=createMonitor({readers:[],nodes:{'node-ci':{fingerprint256:tls['node-ci'].fingerprint256,token_sha256:hash(tls['node-ci'].token)}},virusDatabases:source});
  const {endpoint}=await tlsServer(t,tls.server,monitor.handler),identity=fixture(t).directory;for(const name of readdirSync(identity))rmSync(join(identity,name),{recursive:true,force:true});
  pairedIdentity(identity,tls['node-ci'],endpoint);
  const empty=()=>{const output=fixture(t).directory;for(const name of readdirSync(output))rmSync(join(output,name),{recursive:true,force:true});return output;};
  const output=empty(),pull=directory=>pullVirusDatabase({identityDirectory:identity,directory,publicKey:publisher.publicKey,timeout:3000});
  assert.equal((await pull(output)).state,'downloaded-verified');
  for(const name of ['main.cvd','daily.cvd','bytecode.cvd'])assert.deepEqual(readFileSync(join(output,name)),item.data);
  const bad=empty();writeFileSync(join(item.root,'bytecode.cvd'),Buffer.alloc(512,0));await assert.rejects(pull(bad));assert.deepEqual(readdirSync(bad),[]);
  const wrong=empty();await assert.rejects(pullVirusDatabase({identityDirectory:identity,directory:wrong,publicKey:generateKeyPairSync('ed25519').publicKey,timeout:3000}),/SIGNATURE/);assert.deepEqual(readdirSync(wrong),[]);
  writeFileSync(join(identity,'token'),'x'.repeat(64));await assert.rejects(pull(empty()));
});
test('cloud dashboard reports missing, failed and verified database states independently',()=>{
  const render=db=>renderDashboard({status:{nodes:{},virus_databases:db},identities:{roles:{}},policy:{}});
  assert.match(render({state:'missing'}),/尚未导入签名病毒库/);
  assert.match(render({state:'unavailable'}),/校验失败或病毒库过期/);
  const page=render({state:'ready',daily_version:123,signatures:456});assert.match(page,/签名分发库已就绪/);assert.match(page,/123/);assert.match(page,/456/);
});
