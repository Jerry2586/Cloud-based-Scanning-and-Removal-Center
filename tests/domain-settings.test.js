import test from 'node:test';
import assert from 'node:assert/strict';
import {request as httpRequest} from 'node:http';
import {request as httpsRequest} from 'node:https';
import {mkdtemp, mkdir, writeFile, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createLocalServer} from '../src/local/server.js';
import {passwordRecord} from '../src/local/auth.js';
import {domainConfiguration, publicDomainStatus, domainRequest, domainChallenge} from '../src/local/domain-client.js';
import {createDomainSettings} from '../src/local/public/assets/portal/domain-settings.js';
const password='domain-regression-fixture-password';
const generation='a'.repeat(64);
const config={schema:1,domain:'guard.example.com',origin:'https://guard.example.com',gateway:false,generation};
async function fixture(t,role='local') {
 const dir=await mkdtemp(join(tmpdir(),'ic-domain-'));t.after(()=>rm(dir,{recursive:true,force:true}));
 const calls=[];const server=createLocalServer({role,origin:'http://127.0.0.1:8797',panelPort:8797,domainDirectory:dir,credentials:passwordRecord(password),
 domains:async(action,value)=>{calls.push([action,value]);return {response_status:action==='save'?202:200,state:action==='save'?'running':'idle'};}});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
 const request=(route,options={})=>new Promise((resolve,reject)=>{const req=httpRequest({hostname:'127.0.0.1',port:server.address().port,path:route,method:options.method||'GET',headers:{host:'127.0.0.1:8797',...options.headers}},res=>{const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:JSON.parse(Buffer.concat(chunks))}));});req.on('error',reject);req.end(options.body);});
 const post=(route,value,headers={})=>request(route,{method:'POST',headers:{origin:'http://127.0.0.1:8797','content-type':'application/json',...headers},body:JSON.stringify(value)});
 const login=await post('/api/login',{username:'admin',password});assert.equal(login.status,200);
 const headers={cookie:login.headers['set-cookie'][0].split(';')[0],'x-csrf-token':login.body.csrf};
 return {dir,calls,request,post,headers};
}
test('domain API session, CSRF, origin and fixed input boundaries for both roles',async t=>{
 for(const role of ['local','cloud']) await t.test(role,async t=>{
  const f=await fixture(t,role);
  assert.equal((await f.request('/api/domain')).status,401);
  assert.equal((await f.post('/api/domain',{domain:config.domain},{cookie:f.headers.cookie})).status,403);
  assert.equal((await f.post('/api/domain',{domain:config.domain},{...f.headers,origin:'https://evil.example.com'})).status,403);
  assert.equal(f.calls.length,0);
  assert.equal((await f.request('/api/domain',{headers:f.headers})).status,200);
  assert.equal((await f.post('/api/domain',{domain:config.domain},f.headers)).status,202);
  assert.deepEqual(f.calls,[['status',undefined],['save',{domain:config.domain}]]);
  if(role==='cloud') {assert.equal((await f.post('/api/full-scan',{},f.headers)).status,404);assert.equal((await f.request('/healthz')).body.service,'xuanwu-admin');}
 });
});
test('active domain adopts strict Host/Origin on actual configured panel port and preserves IP entry',async t=>{
 const f=await fixture(t);await writeFile(join(f.dir,'domain.json'),JSON.stringify(config));
 for(const host of ['guard.example.com','guard.example.com:8797','127.0.0.1:8797']) assert.equal((await f.request('/healthz',{headers:{host}})).status,200);
 assert.equal((await f.request('/healthz',{headers:{host:'guard.example.com:8790'}})).status,421);
 assert.equal((await f.post('/api/domain',{domain:config.domain},{...f.headers,host:config.domain,origin:config.origin})).status,202);
 assert.equal((await f.post('/api/domain',{domain:config.domain},{...f.headers,host:config.domain})).status,403);
 await writeFile(join(f.dir,'domain.json'),JSON.stringify({...config,generation:'../../bad'}));
 assert.equal(domainConfiguration(f.dir),null);assert.equal((await f.request('/healthz',{headers:{host:config.domain}})).status,421);
 assert.equal((await f.request('/healthz')).status,200);
});
test('status never fabricates a public address before certificate activation; restored old domain remains visible',async()=>{
 assert.equal(publicDomainStatus({state:'running',domain:config.domain}).origin,'');
 assert.equal(publicDomainStatus({state:'failed',domain:config.domain,certificate:'public-ca',requested_domain:'next.example.com'}).origin,config.origin);
 assert.equal((await domainRequest('save',{domain:'https://guard.example.com'})).response_status,400);
 assert.equal((await domainRequest('save',{domain:config.domain,command:'sh'})).response_status,400);
 assert.equal((await domainRequest('status',{}, {IRONCURTAIN_DOMAIN_SOCKET:'/tmp/attacker.sock'})).response_status,503);
});
test('dynamic SNI loads new immutable certificate generation and rejects unknown names',async t=>{
 const binary=process.platform==='win32'?'C:/Program Files/Git/usr/bin/openssl.exe':'openssl';
 if(spawnSync(binary,['version']).status!==0)return t.skip('OpenSSL unavailable');
 const dir=await mkdtemp(join(tmpdir(),'ic-sni-'));t.after(()=>rm(dir,{recursive:true,force:true}));
 async function cert(name,commonName){const key=join(dir,name+'.key'),cert=join(dir,name+'.crt');const r=spawnSync(binary,['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','2','-subj','/CN='+commonName],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);return {key:await readFile(key),cert:await readFile(cert)};}
 const fallback=await cert('fallback','original.example.com'),first=await cert('first',config.domain),second=await cert('second','renewed.example.com');
 async function publish(gen,tls){await mkdir(join(dir,'domain-certificates',gen),{recursive:true});await writeFile(join(dir,'domain-certificates',gen,'cert.pem'),tls.cert);await writeFile(join(dir,'domain-certificates',gen,'key.pem'),tls.key);await writeFile(join(dir,'domain.json'),JSON.stringify({...config,generation:gen}));}
 await publish(generation,first);const server=createLocalServer({tls:fallback,origin:'https://original.example.com:8790',domainDirectory:dir,credentials:passwordRecord(password)});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
 const peer=name=>new Promise((resolve,reject)=>{const req=httpsRequest({host:'127.0.0.1',port:server.address().port,path:'/healthz',servername:name,rejectUnauthorized:false,agent:false,headers:{host:name===config.domain?name:'original.example.com:8790'}},res=>{const cn=res.socket.getPeerCertificate().subject.CN;res.resume();res.on('end',()=>resolve(cn));});req.on('error',reject);req.end();});
 assert.equal(await peer(config.domain),config.domain);assert.equal(await peer('original.example.com'),'original.example.com');
 await publish('b'.repeat(64),second);assert.equal(await peer(config.domain),'renewed.example.com');
 await assert.rejects(peer('unknown.example.com'));
});
test('domain UI keeps Save disabled after a failed poll and blocks duplicate submission',async t=>{
 const previousDoc=globalThis.document;globalThis.document={activeElement:null};t.after(()=>{globalThis.document=previousDoc;});
 const timers=[],originalSet=globalThis.setTimeout,originalClear=globalThis.clearTimeout;
 globalThis.setTimeout=(fn,delay)=>{timers.push({fn,delay});return timers.length;};globalThis.clearTimeout=()=>{};
 t.after(()=>{globalThis.setTimeout=originalSet;globalThis.clearTimeout=originalClear;});
 const nodes=Object.fromEntries(['form','save','input','status','reason','origin','certificate'].map(k=>[k,{value:'guard.example.com',disabled:false,textContent:'',listeners:{},addEventListener(name,fn){this.listeners[name]=fn;},querySelector(){return nodes.input;}}]));
 const scope={querySelectorAll(selector){const k=/data-domain-([a-z]+)/.exec(selector)[1];return nodes[k]?[nodes[k]]:[];},addEventListener(){}};
 let poll=0,posted=0;const ui=createDomainSettings({state:{csrf:'session'},request:async(_url,options)=>{if(options){posted++;return {state:'running'};}if(poll++===0)return {state:'running'};throw Error('network down');},notify(){}},scope);
 ui.bind();ui.start();await new Promise(resolve=>setImmediate(resolve));assert.equal(nodes.save.disabled,true);assert.equal(timers.at(-1).delay,2000);
 await timers.at(-1).fn();assert.equal(nodes.save.disabled,true);assert.match(nodes.status.textContent,/无法确认/);
 await nodes.form.listeners.submit({preventDefault(){},currentTarget:nodes.form});assert.equal(posted,0);ui.stop();
});

test('ACME Host is case-insensitive but never admits another host or port', async t => {
 const dir=await mkdtemp(join(tmpdir(),'ic-challenge-'));t.after(()=>rm(dir,{recursive:true,force:true}));
 const token='a'.repeat(32),url='/.well-known/acme-challenge/'+token;
 await writeFile(join(dir,'domain-pending.json'),JSON.stringify({domain:config.domain}));
 await mkdir(join(dir,'acme-challenge','.well-known','acme-challenge'),{recursive:true});
 await writeFile(join(dir,'acme-challenge','.well-known','acme-challenge',token),'challenge-proof');
 assert.equal(domainChallenge(dir,'GUARD.EXAMPLE.COM',url,'original.example.com')?.toString(),'challenge-proof');
 assert.equal(domainChallenge(dir,'ORIGINAL.EXAMPLE.COM',url,'original.example.com')?.toString(),'challenge-proof');
 for(const host of ['guard.example.com.evil.test','guard.example.com:443','evil.example.com',null]) assert.equal(domainChallenge(dir,host,url,'original.example.com'),null);
});
