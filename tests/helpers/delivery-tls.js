import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync,chmodSync} from 'node:fs';
import {join} from 'node:path';
import {X509Certificate} from 'node:crypto';
import {createServer,request} from 'node:https';
export function deliveryTLS(directory) {
  const openssl=process.platform==='win32'?'C:/Program Files/Git/usr/bin/openssl.exe':'openssl';
  const run=(...args)=>execFileSync(openssl,args,{cwd:directory,stdio:'pipe'});
  run('req','-x509','-newkey','ed25519','-nodes','-keyout','ca.key','-out','ca.crt','-subj','/CN=Delivery-test-CA','-days','1');
  for(const name of ['server','node-ci','reader']) {
    run('req','-newkey','ed25519','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN='+name);
    writeFileSync(join(directory,name+'.ext'),name==='server'?'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n':'extendedKeyUsage=clientAuth\n');
    run('x509','-req','-in',name+'.csr','-CA','ca.crt','-CAkey','ca.key','-CAcreateserial','-out',name+'.crt','-days','1','-extfile',name+'.ext');
  }
  const ca=readFileSync(join(directory,'ca.crt')),values={};
  for(const name of ['server','node-ci','reader']) {
    const cert=readFileSync(join(directory,name+'.crt'));
    values[name]={ca,cert,key:readFileSync(join(directory,name+'.key')),token:name==='reader'?'r'.repeat(64):'n'.repeat(64),fingerprint256:new X509Certificate(cert).fingerprint256};
  }
  return values;
}
export async function tlsServer(t,identity,handler) {
  const server=createServer({...identity,requestCert:true,rejectUnauthorized:true},handler);
  await new Promise(resolve=>server.listen(0,'localhost',resolve));
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
  return {server,endpoint:'https://localhost:'+server.address().port+'/'};
}
export function requestRelease(endpoint,identity,{path='/v1/releases/latest',method='GET',token=identity.token}={}) {
  return new Promise((resolve,reject)=>{
    const req=request(new URL(path,endpoint),{...identity,method,agent:false,headers:{authorization:'Bearer '+token}},res=>{
      const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('error',reject);
      res.on('end',()=>resolve({status:res.statusCode,bytes:Buffer.concat(chunks),headers:res.headers}));
    });req.on('error',reject);req.setTimeout(3000,()=>req.destroy(Error('TEST_TIMEOUT')));req.end();
  });
}
export function pairedIdentity(directory,identity,endpoint) {
  for(const [name,bytes] of [['ca.crt',identity.ca],['client.crt',identity.cert],['client.key',identity.key],['token',identity.token],['cloud.json',JSON.stringify({schema:'ironcurtain-cloud/v1',node_id:'node-ci',endpoint})]]) {
    writeFileSync(join(directory,name),bytes,{mode:0o600});chmodSync(join(directory,name),0o600);
  }
}
