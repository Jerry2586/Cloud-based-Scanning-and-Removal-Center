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
