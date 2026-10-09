import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {localSecurityScan} from '../src/local/scan-client.js';
for(const reason of ['management operation active','maintenance active','file scan in progress','untrusted reason']) {
 test('scan rejection preserves maintenance meaning: '+reason,{skip:process.platform==='win32'},async t=>{
  const dir=await mkdtemp(join(tmpdir(),'ic-maint-')),socket=join(dir,'scan.sock');
  const server=http.createServer((req,res)=>{assert.equal(req.url,'/scan');assert.equal(req.method,'POST');res.writeHead(409,{'Content-Type':'application/json'});res.end(JSON.stringify({state:'unavailable',reason,history:[]}));});
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(socket,resolve);});
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));await rm(dir,{recursive:true,force:true});});
  const result=await localSecurityScan('scan',{IRONCURTAIN_SCAN_SOCKET:socket});
  assert.equal(result.response_status,409);assert.equal(result.state,'unavailable');
  assert.equal(result.reason,['management operation active','maintenance active'].includes(reason)?'本机维护正在进行，请稍后重试':'已有扫描正在进行，请等待当前任务');
 });
}

for (const acceptedId of ['a'.repeat(32), undefined, 'invalid']) {
 test('engine update Unix bridge validates receipt: '+String(acceptedId), {skip:process.platform==='win32'}, async t=>{
  const dir=await mkdtemp(join(tmpdir(),'ic-update-')),socket=join(dir,'scan.sock');
  const task={schema:'ironcurtain-engine-update/v1',state:'finished',task_id:'a'.repeat(32),started_at:'2026-10-09T12:00:00.000Z',updated_at:'2026-10-09T12:01:00.000Z',finished_at:'2026-10-09T12:01:00.000Z',detail:'更新器执行完成',private_path:'/private'};
  const server=http.createServer((req,res)=>{
   assert.equal(req.headers['content-length'],req.url==='/engine-update'?'0':undefined);
   assert.ok(['/engine-update','/status'].includes(req.url));
   res.writeHead(req.url==='/engine-update'?202:200,{'Content-Type':'application/json'});
   res.end(JSON.stringify(req.url==='/engine-update'?{state:'running',task_id:acceptedId}:{state:'idle',history:[],engine_update:task}));
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(socket,resolve);});
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));await rm(dir,{recursive:true,force:true});});
  const env={IRONCURTAIN_SCAN_SOCKET:socket};
  const receipt=await localSecurityScan('engine-update',env);
  assert.equal(receipt.state,acceptedId==='a'.repeat(32)?'running':'unavailable');
  if(receipt.state==='running')assert.equal(receipt.task_id,acceptedId);
  const status=await localSecurityScan('status',env);
  assert.equal(status.engine_update.task_id,task.task_id);
  assert.equal(status.engine_update.state,'finished');
  assert.equal(status.engine_update.private_path,undefined);
 });
}
