import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {localUpdate} from '../src/local/update-client.js';

async function endpoint(t,reply){
 const dir=await mkdtemp(join(tmpdir(),'ic-update-')),path=join(dir,'control.sock'),calls=[];
 const server=createServer((req,res)=>{calls.push({method:req.method,path:req.url,length:req.headers['content-length']});reply(req,res);});
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(path,resolve);});
 t.after(async()=>{await new Promise(resolve=>server.close(resolve));await rm(dir,{recursive:true,force:true});});
 return {path,calls};
}

test('role-specific fixed update client uses only its assigned Unix socket',{skip:process.platform==='win32'},async t=>{
 for(const role of ['local','cloud']){
  const f=await endpoint(t,(req,res)=>{res.writeHead(req.method==='GET'?200:req.url==='/update-check'?202:409,{'Content-Type':'application/json'});res.end(JSON.stringify(req.method==='GET'?{schema:'ironcurtain-update-status/v1',installed_version:'0.6.6',check:{state:'unavailable'},job:{state:'idle'}}:{state:'running',command:'secret'}));});
  const env={IRONCURTAIN_ROLE:role,IRONCURTAIN_SCAN_SOCKET:role==='local'?f.path:join(tmpdir(),'not-the-cloud-socket'),IRONCURTAIN_UPDATE_SOCKET:role==='cloud'?f.path:join(tmpdir(),'not-the-local-socket')};
  assert.equal((await localUpdate('status',env)).installed_version,'0.6.6');
  assert.deepEqual(await localUpdate('check',env),{state:'running',response_status:202});
  assert.deepEqual(await localUpdate('install',env),{state:'running',response_status:409});
  assert.deepEqual(await localUpdate('arbitrary-command',env),{state:'unavailable',response_status:400});
  assert.deepEqual(f.calls,[{method:'GET',path:'/update-status',length:'0'},{method:'POST',path:'/update-check',length:'0'},{method:'POST',path:'/update',length:'0'}]);
 }
});

test('cloud update client refuses failed, oversized and malformed controller results',{skip:process.platform==='win32'},async t=>{
 for(const scenario of ['error','malformed','oversized']){
  const f=await endpoint(t,(_req,res)=>{res.writeHead(scenario==='error'?500:200);res.end(scenario==='oversized'?'x'.repeat(16385):scenario==='malformed'?'not json':JSON.stringify({state:'running',private:'secret'}));});
  const env={IRONCURTAIN_ROLE:'cloud',IRONCURTAIN_UPDATE_SOCKET:f.path};
  assert.equal((await localUpdate('status',env)).installed_version,null);
  assert.deepEqual(await localUpdate('check',env),{state:'unavailable',response_status:503});
 }
});
