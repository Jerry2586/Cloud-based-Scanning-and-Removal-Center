import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {localOperations} from '../src/local/operations-client.js';
import {operationJob,operationStatus,revision} from './fixtures/operations.js';

async function endpoint(t,respond) {
 const folder=await mkdtemp(join(tmpdir(),'ic-operations-'));
 const socketPath=process.platform==='win32'?String.raw`\\.\pipe\ic-operations-${process.pid}-${Math.random().toString(16).slice(2)}`:join(folder,'control.sock');
 const requests=[];
 const server=createServer(async(req,res)=>{
  const parts=[];for await(const part of req)parts.push(part);
  requests.push({url:req.url,method:req.method,body:Buffer.concat(parts).toString(),type:req.headers['content-type']});
  respond(req,res);
 });
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(socketPath,resolve);});
 t.after(async()=>{await new Promise(resolve=>server.close(resolve));await rm(folder,{recursive:true,force:true});});
 return {requests,call:(action,value)=>localOperations(action,value,{IRONCURTAIN_OPERATIONS_SOCKET:socketPath})};
}
function json(res,status,value){res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(value));}
test('local operations sends only fixed methods and canonical validated action fields',async t=>{
 const f=await endpoint(t,(req,res)=>json(res,req.method==='GET'?200:202,req.method==='GET'?operationStatus():{schema:'ironcurtain-operations/v1',state:'running',job:operationJob()}));
 assert.equal((await f.call('status')).state,'ready');
 assert.equal((await f.call('apply',{action:'ports',revision,tcp:[443,22],udp:[]})).response_status,202);
 assert.deepEqual(f.requests.map(r=>[r.url,r.method]),[['/operations','GET'],['/operations','POST']]);
 assert.equal(f.requests[0].body,'');assert.deepEqual(JSON.parse(f.requests[1].body),{action:'ports',revision,tcp:[22,443],udp:[]});
 assert.throws(()=>f.call('delete',{command:'sh'}));assert.throws(()=>f.call('apply',{action:'ports',revision,tcp:[],udp:[],command:'sh'}));assert.equal(f.requests.length,2);
});
test('malformed, mismatched, oversized and interrupted responses stay unavailable',async t=>{
 for(const reply of [
  res=>json(res,200,{...operationStatus(),risks:[{}]}),
  res=>json(res,202,{schema:'ironcurtain-operations/v1',state:'running',job:operationJob()}),
  res=>{res.writeHead(200,{'content-type':'text/html'});res.end(JSON.stringify(operationStatus()));},
  res=>{res.writeHead(200,{'content-type':'application/json'});res.end('bad json');},
  res=>{res.writeHead(200,{'content-type':'application/json'});res.end('x'.repeat(262145));},
  res=>{res.writeHead(200,{'content-type':'application/json','content-length':'1000'});res.write('{');res.destroy();}
 ]) {
  const f=await endpoint(t,(_req,res)=>reply(res));const result=await f.call('status');assert.equal(result.state,'unavailable');assert.equal(result.response_status,503);
 }
 const f=await endpoint(t,(_req,res)=>json(res,202,{schema:'ironcurtain-operations/v1',state:'running',job:{...operationJob(),action:'restore'}}));
 assert.equal((await f.call('apply',{action:'ports',revision,tcp:[],udp:[]})).state,'unavailable');
});
test('exclusive management contention is surfaced as a conflict without a successful job',async t=>{
 const f=await endpoint(t,(_req,res)=>json(res,409,{error:'locked'}));
 const result=await f.call('apply',{action:'ports',revision,tcp:[],udp:[]});
 assert.equal(result.response_status,409);assert.equal(result.state,'unavailable');assert.equal(result.job,undefined);
});
