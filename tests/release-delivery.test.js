import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {readFileSync,writeFileSync,chmodSync,mkdirSync,rmSync,symlinkSync,linkSync,readdirSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {join} from 'node:path';
import {importRelease,releaseSource,compareVersions,readReleaseFile,trustedReleaseDirectory} from '../src/release-store.js';
import {releaseAssetNames} from '../src/release-verification.js';
import {createMonitor} from '../src/monitor.js';
import {pullRelease} from '../scripts/release-pull.js';
import {temporary,signedRelease,publisher,hash} from './helpers/release-fixture.js';
import {deliveryTLS,tlsServer,requestRelease,pairedIdentity} from './helpers/delivery-tls.js';
const rootOnly=process.platform!=='linux' || process.getuid()!==0;

test('signed program storage fails closed outside its supported Linux boundary',{skip:process.platform==='linux'}, t=>{
  const directory=temporary(t);
  assert.throws(()=>trustedReleaseDirectory(directory),/PLATFORM_UNSUPPORTED/);
  assert.equal(releaseSource(directory,publisher.publicKey).summary().state,'unavailable');
});

test('numeric version comparisons reject noncanonical input',()=>{
  assert.equal(compareVersions('0.10.0','0.9.99'),1);assert.equal(compareVersions('0.3.0','0.3.0'),0);
  for(const value of ['00.3.0','0.3','0.3.0-beta','9999999.0.0'])assert.throws(()=>compareVersions(value,'0.3.0'));
});

test('signed release cache preserves publisher authority and rejects unsafe storage',{skip:rootOnly},async t=>{
  const input=signedRelease(t),directory=temporary(t),source=releaseSource(directory,publisher.publicKey);
  await t.test('missing cache is explicit; signed six assets import atomically',()=>{
    assert.equal(source.summary().state,'missing');
    assert.equal(importRelease({input:input.directory,directory,publicKey:publisher.publicKey}).state,'ready');
    const offer=source.latest();assert.equal(offer.version,'0.3.0');
    assert.equal(Buffer.from(offer.manifest,'base64').toString(),readFileSync(join(input.directory,'release-manifest.json'),'utf8'));
    for(const name of releaseAssetNames('0.3.0'))assert.deepEqual(source.asset('0.3.0',name),readFileSync(join(input.directory,name)));
    assert.equal(importRelease({input:input.directory,directory,publicKey:publisher.publicKey}).version,'0.3.0');
  });
  await t.test('downgrade, changed same version and wrong publisher retain active pointer',()=>{
    const pointer=readFileSync(join(directory,'active.json'));
    for(const fixture of [signedRelease(t,{version:'0.2.9'}),signedRelease(t,{content:'different same version'}),signedRelease(t,{version:'0.3.1',keys:generateKeyPairSync('ed25519')})]) {
      assert.throws(()=>importRelease({input:fixture.directory,directory,publicKey:publisher.publicKey}),/DOWNGRADE|SAME_VERSION|signature/);
      assert.deepEqual(readFileSync(join(directory,'active.json')),pointer);
    }
  });
  await t.test('corrupt binaries and checksums cannot be served',()=>{
    for(const name of [input.manifest.run_name,input.manifest.run_name+'.sha256']) {
      const file=join(directory,'0.3.0',name),original=readFileSync(file);writeFileSync(file,'tampered');
      assert.throws(()=>source.asset('0.3.0',name),/DIGEST/);writeFileSync(file,original);
    }
    assert.throws(()=>source.asset('0.2.9',input.manifest.run_name),/NOT_FOUND/);
    assert.throws(()=>source.asset('0.3.0','..'),/NOT_FOUND/);
  });
  await t.test('broken pointer, missing asset and nonexistent store are unavailable',()=>{
    const pointer=readFileSync(join(directory,'active.json'));writeFileSync(join(directory,'active.json'),'{}');
    assert.equal(source.summary().state,'unavailable');writeFileSync(join(directory,'active.json'),pointer);
    const name=input.manifest.run_name,bytes=readFileSync(join(directory,'0.3.0',name));rmSync(join(directory,'0.3.0',name));
    assert.equal(source.summary().state,'unavailable');writeFileSync(join(directory,'0.3.0',name),bytes,{mode:0o640});
    assert.equal(releaseSource(join(directory,'absent'),publisher.publicKey).summary().state,'unavailable');
  });
  await t.test('root Linux rejects writable files, links and writable directory ancestry',{skip:process.platform==='win32'},()=>{
    const parent=temporary(t),file=join(parent,'file');writeFileSync(file,'safe',{mode:0o600});
    chmodSync(file,0o666);assert.throws(()=>readReleaseFile(file),/FILE/);chmodSync(file,0o600);
    const linked=join(parent,'link');symlinkSync(file,linked);assert.throws(()=>readReleaseFile(linked));rmSync(linked);
    linkSync(file,linked);assert.throws(()=>readReleaseFile(file),/FILE/);rmSync(linked);
    chmodSync(parent,0o777);assert.throws(()=>trustedReleaseDirectory(parent),/DIRECTORY/);chmodSync(parent,0o700);
  });
  await t.test('root snapshot copies exactly six bounded files and rejects links',{skip:process.platform==='win32'},()=>{
    const out=temporary(t);execFileSync('python3',['scripts/release-snapshot.py',input.directory,out]);assert.equal(readdirSync(out).length,6);
    const bad=signedRelease(t);rmSync(join(bad.directory,bad.manifest.run_name));symlinkSync(join(input.directory,input.manifest.run_name),join(bad.directory,bad.manifest.run_name));
    assert.throws(()=>execFileSync('python3',['scripts/release-snapshot.py',bad.directory,temporary(t)],{stdio:'pipe'}));
  });
});

test('real mutual TLS release delivery and independent local verification',{skip:rootOnly},async t=>{
  const input=signedRelease(t),directory=temporary(t);importRelease({input:input.directory,directory,publicKey:publisher.publicKey});
  const releases=releaseSource(directory,publisher.publicKey),tls=deliveryTLS(temporary(t));
  const monitor=createMonitor({nodes:{'node-ci':{fingerprint256:tls['node-ci'].fingerprint256,token_sha256:hash(tls['node-ci'].token)}},readers:[{fingerprint256:tls.reader.fingerprint256,token_sha256:hash(tls.reader.token)}],releases});
  const {endpoint}=await tlsServer(t,tls.server,monitor.handler);
  const identityDirectory=temporary(t);pairedIdentity(identityDirectory,tls['node-ci'],endpoint);
  const pull=(overrides={})=>pullRelease({identityDirectory,directory:temporary(t),publicKey:publisher.publicKey,installedVersion:'0.2.1',...overrides});
  await t.test('authenticated node and reader receive fixed assets; wrong token and missing certificate fail',async()=>{
    for(const identity of [tls['node-ci'],tls.reader])assert.equal((await requestRelease(endpoint,identity)).status,200);
    assert.equal((await requestRelease(endpoint,tls['node-ci'],{token:tls.reader.token})).status,403);
    await assert.rejects(requestRelease(endpoint,{ca:tls.server.ca,token:'x'}));
    assert.equal((await requestRelease(endpoint,tls['node-ci'],{method:'POST'})).status,404);
    for(const path of ['/v1/releases/latest?anything=1','/v1/releases/0.3.0/unknown','/v1/releases/0.2.9/'+input.manifest.run_name])assert.equal((await requestRelease(endpoint,tls['node-ci'],{path})).status,404);
    const result=await requestRelease(endpoint,tls['node-ci'],{path:'/v1/releases/0.3.0/'+input.manifest.run_name});
    assert.equal(result.status,200);assert.equal(result.headers['content-type'],'application/octet-stream');assert.equal(hash(result.bytes),input.manifest.run_sha256);
  });
  await t.test('local downloader verifies six files, signature and package before offering activation',async()=>{
    const out=temporary(t),result=await pull({directory:out});
    assert.deepEqual(result,{state:'verified',version:'0.3.0',run_name:input.manifest.run_name,activation:'local-admin'});
    assert.deepEqual(readdirSync(out).sort(),releaseAssetNames('0.3.0'));
  });
  await t.test('wrong publisher and downgrade fail without leaving installable bytes',async()=>{
    for(const overrides of [{publicKey:generateKeyPairSync('ed25519').publicKey},{installedVersion:'0.3.1'}]) {
      const out=temporary(t);await assert.rejects(pull({...overrides,directory:out}),/signature|DOWNGRADE/);assert.deepEqual(readdirSync(out),[]);
    }
  });
  await t.test('tampered cloud file is rejected and staged downloads are cleaned',async()=>{
    const file=join(directory,'0.3.0',input.manifest.run_name),bytes=readFileSync(file);writeFileSync(file,'corrupt');
    const out=temporary(t);await assert.rejects(pull({directory:out}));assert.deepEqual(readdirSync(out),[]);writeFileSync(file,bytes);
  });
  await t.test('compromised cloud cannot redirect, fake publisher or smuggle corrupt payload',async st=>{
    for(const attack of ['redirect','signature','binary','identity']) {
      let binaries=0;
      const {endpoint:badEndpoint}=await tlsServer(st,tls.server,(req,res)=>{
        if(req.url==='/v1/connectivity'){res.writeHead(200,{'content-type':'application/json'});return res.end(JSON.stringify({identity:attack==='identity'?'node-other':'node-ci'}));}
        if(req.url==='/v1/releases/latest'){
          if(attack==='redirect'){res.writeHead(302,{location:endpoint});return res.end();}
          const offer=releases.latest();if(attack==='signature')offer.signature=Buffer.alloc(64).toString('base64');
          res.writeHead(200,{'content-type':'application/json'});return res.end(JSON.stringify(offer));
        }
        binaries++;const name=req.url.split('/').at(-1),bytes=attack==='binary'&&name.endsWith('.run')?Buffer.from('corrupt payload'):releases.asset('0.3.0',name);
        res.writeHead(200,{'content-type':'application/octet-stream','content-length':bytes.length});res.end(bytes);
      });
      const id=temporary(t),out=temporary(t);pairedIdentity(id,tls['node-ci'],badEndpoint);
      await assert.rejects(pull({identityDirectory:id,directory:out}));assert.deepEqual(readdirSync(out),[]);
      if(attack!=='binary')assert.equal(binaries,0);
    }
  });
  await t.test('whole-request deadline aborts an unresponsive cloud',async st=>{
    const {endpoint:slow}=await tlsServer(st,tls.server,()=>{}),id=temporary(t),out=temporary(t);pairedIdentity(id,tls['node-ci'],slow);
    await assert.rejects(pull({identityDirectory:id,directory:out,timeout:100}),/abort|ABORT/i);assert.deepEqual(readdirSync(out),[]);
  });
  await t.test('revoked node cannot fetch release or binaries',async()=>{
    const denied=createMonitor({nodes:{},readers:[],releases});
    const {endpoint:revoked}=await tlsServer(t,tls.server,denied.handler);const id=temporary(t);pairedIdentity(id,tls['node-ci'],revoked);
    await assert.rejects(pull({identityDirectory:id}),/REJECTED/);
  });
});
