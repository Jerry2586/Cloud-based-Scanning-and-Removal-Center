import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {sanitizeMultiEngine,ENGINE_IDS} from '../src/contracts/multi-engine-status.js';
import {localMultiEngine} from '../src/local/multi-engine-client.js';
const make=()=>({schema:'ironcurtain-multi-engine/v1',job_id:'a'.repeat(64),profile_digest:'b'.repeat(64),state:'running',started_at:'2026-10-06T01:00:00.000Z',updated_at:'2026-10-06T01:00:00.000Z',completed:0,total:4,coverage:0,engines:ENGINE_IDS.map(id=>({id,state:'queued',detail:'queued',completed:0,total:0,finding_total:0,findings:[]}))});
test('multi engine contract rejects counterfeit completeness, counts and finding classes',()=>{
 assert.equal(sanitizeMultiEngine(make()).state,'running');
 for(const edit of [v=>v.coverage=4,v=>v.completed=1,v=>v.engines.reverse(),v=>v.profile_digest='wrong',v=>v.updated_at='2026-13-01T01:00:00.000Z',v=>v.engines[0].finding_total=-1,v=>v.engines[0].findings=[{kind:'asset'}],v=>v.state='finished']){const v=make();edit(v);assert.equal(sanitizeMultiEngine(v).state,'unavailable');}
 const v=make();v.secret='private';v.engines[0].raw_output='private';assert.equal(sanitizeMultiEngine(v).secret,undefined);assert.equal(sanitizeMultiEngine(v).engines[0].raw_output,undefined);
});
test('observed CVEs survive partial completion and assets are independently categorized',()=>{
 const v=make();v.state='partial';v.completed=4;v.coverage=1;v.finished_at=v.updated_at;
 for(const e of v.engines)e.state='unavailable';v.engines[1].state='complete';v.engines[1].total=v.engines[1].completed=1;v.engines[1].finding_total=1;v.engines[1].findings=[{kind:'vulnerability',severity:'high',target:'sha256:'+ 'a'.repeat(64),rule:'CVE-2026-fixture',detail:'fixed in fixture'}];
 assert.equal(sanitizeMultiEngine(v).engines[1].findings.length,1);
 v.engines[2].findings=[{kind:'malware',severity:'high',target:'port',rule:'bad',detail:''}];v.engines[2].finding_total=1;assert.equal(sanitizeMultiEngine(v).state,'unavailable');
});
test('host client exposes only a fixed Unix action and rejects missing agent',async()=>{
 assert.throws(()=>localMultiEngine('shell'),/Unknown/);
 const value=await localMultiEngine('status',{IRONCURTAIN_SCAN_SOCKET:join(tmpdir(),'missing-ironcurtain-'+process.pid+'.sock')});assert.equal(value.state,'unavailable');assert.equal(value.response_status,503);
});
test('Unix bridge validates HTTP status, empty command body and response budget',{skip:process.platform==='win32'},async t=>{
 const dir=await mkdtemp(join(tmpdir(),'multi-client-'));t.after(()=>rm(dir,{recursive:true,force:true}));const socket=join(dir,'agent.sock');let code=200,value=make(),oversize=false;const requests=[];
 const server=createServer((req,res)=>{const chunks=[];req.on('data',x=>chunks.push(x));req.on('end',()=>{requests.push({method:req.method,path:req.url,body:Buffer.concat(chunks).toString()});res.writeHead(code);res.end(oversize?'x'.repeat(65537):JSON.stringify(value));});});await new Promise(r=>server.listen(socket,r));t.after(()=>new Promise(r=>server.close(r)));
 const env={IRONCURTAIN_SCAN_SOCKET:socket};assert.equal((await localMultiEngine('status',env)).state,'running');code=202;assert.equal((await localMultiEngine('start',env)).response_status,202);assert.deepEqual(requests[1],{method:'POST',path:'/multi-engine',body:''});code=200;assert.equal((await localMultiEngine('start',env)).response_status,503);oversize=true;assert.equal((await localMultiEngine('status',env)).state,'unavailable');
});
