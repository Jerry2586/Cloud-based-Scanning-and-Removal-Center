import {test} from 'node:test';
import assert from 'node:assert/strict';
import {HOST_SCAN_IDS,hostScanProgress,completeHostScan} from '../src/contracts/host-scan-contract.js';
const check=id=>({id,name:id,detail:'not configured',state:'unavailable',category:'host',severity:'unknown',checked_at:new Date().toISOString(),scope:id,evidence_digest:'a'.repeat(64)});
test('progress accepts only completed fixed checks in order',()=>{
  const checks=HOST_SCAN_IDS.slice(0,3).map(check); const report={state:'running',checks,progress:{completed:3,total:25,current:HOST_SCAN_IDS[3]}};
  assert.equal(hostScanProgress(report).completed,3);
  for(const p of [{completed:24,total:25,current:HOST_SCAN_IDS[3]},{completed:3,total:24,current:HOST_SCAN_IDS[3]},{completed:3,total:25,current:null}]) assert.equal(hostScanProgress({...report,progress:p}),null);
  assert.equal(hostScanProgress({...report,checks:checks.toReversed()}),null);
  assert.equal(completeHostScan(report),false);
});
test('completion counts unavailable without claiming protection',()=>{
  const report={state:'finished',checked_at:new Date().toISOString(),checks:HOST_SCAN_IDS.map(check),progress:{completed:25,total:25,current:null}};
  assert.equal(hostScanProgress(report).completed,25);assert.equal(completeHostScan(report),true);assert.equal(report.checks.filter(c=>c.state==='ok').length,0);
});
