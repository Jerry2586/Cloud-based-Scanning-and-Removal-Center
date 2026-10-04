import test from 'node:test';
import assert from 'node:assert/strict';
import {sanitizeFindings,sanitizeQuarantine} from '../src/local/scan-client.js';
const item=()=>({id:'a'.repeat(64),path:'/opt/site/suspect.js',signature:'Test.Signature',sha256:'b'.repeat(64),size:23,observed_at:new Date().toISOString(),command:'never-forward',uid:0});
const report=()=>({findings:[item()],findings_state:'complete',findings_total:1});
test('findings forward only bounded text evidence and never private identity/commands',()=>{
  const clean=sanitizeFindings(report());assert.equal(clean.findings.length,1);assert.equal('command' in clean.findings[0],false);assert.equal('uid' in clean.findings[0],false);
});
test('malformed, duplicated and unbounded findings become unavailable',()=>{
  for(const mutation of [v=>v.findings.push(v.findings[0]),v=>v.findings_total=0,v=>v.findings[0].path='/opt/../secret',v=>v.findings[0].path+="\n",v=>v.findings[0].size=67108865,v=>v.findings[0].observed_at='wrong',v=>v.findings[0].id='short',v=>v.findings_state='safe']){
    const v=report();mutation(v);assert.equal(sanitizeFindings(v).findings_state,'unavailable');
  }
});
test('partial scan and more hits than visible evidence remain explicit',()=>{
  const v=report();v.findings_state='partial';v.findings_total=15;assert.equal(sanitizeFindings(v).findings_state,'partial');assert.equal(sanitizeFindings(v).findings_total,15);
});

const quarantineReport=()=>({state:'recorded',count:1,pending:1,items:[{...item(),state:'captured'}]});
test('quarantine journal exposes bounded states without execution authority',()=>{
  const clean=sanitizeQuarantine(quarantineReport());assert.equal(clean.pending,1);assert.equal(clean.items[0].state,'captured');assert.equal('command' in clean.items[0],false);
  assert.deepEqual(sanitizeQuarantine({state:'empty',count:0,pending:0,items:[]}),{state:'empty',count:0,pending:0,items:[]});
});
test('quarantine refuses malformed signatures, duplicates and contradictory status',()=>{
  for(const mutation of [v=>delete v.items[0].signature,v=>v.items[0].signature=42,v=>v.state='unavailable',v=>v.state='empty',v=>v.count=129,v=>v.pending=2,v=>{v.count=2;v.items.push(v.items[0]);},v=>v.items[0].path='/opt/../secret']) {
    const v=quarantineReport();mutation(v);assert.equal(sanitizeQuarantine(v).state,'unavailable');
  }
  assert.equal(sanitizeQuarantine({state:'recorded',items:[],count:0,pending:0}).state,'unavailable');
});
