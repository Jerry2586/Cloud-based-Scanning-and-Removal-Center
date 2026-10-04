import test from 'node:test';
import assert from 'node:assert/strict';
import { summarizeHostScan } from '../scripts/security-agent.js';
import { fullHostReport } from './helpers/host-scan-report.js';
import { HOST_SCAN_IDS } from '../packages/core/src/host-scan-contract.js';

test('host report summary discards paths and details and retains findings in a complete report', () => {
  const checked_at = new Date().toISOString();
  const report = fullHostReport({ checked_at, overrides: { 'malware.business': { state:'finding', detail:'/private/path', severity:'high' } } });
  assert.deepEqual(summarizeHostScan(report), { state:'finding', checked_at, counts:{ok:HOST_SCAN_IDS.length - 1, warning:0, finding:1, unavailable:0} });
  for(const invalid of [null, {state:'failed', reason:'private path'}, {state:'finished',checked_at:'bad',checks:[]},
    {...report,checks:[report.checks[0]]}, {...report,checks:Array(HOST_SCAN_IDS.length).fill(report.checks[0])}])
    assert.deepEqual(summarizeHostScan(invalid), {state:'unavailable',checked_at:null});
});
test('summary only reports ok for a complete fresh report with usable history', () => {
  const now=Date.now(), report=fullHostReport({checked_at:new Date(now).toISOString()});
  assert.equal(summarizeHostScan(report,now).state,'ok');
  for(const bad of [
    {...report,checked_at:'2020-01-01T00:00:00Z'},
    {...report,checked_at:new Date(now+121000).toISOString()},
    {...report,checks:[{...report.checks[0],checked_at:'2020-01-01T00:00:00Z'},...report.checks.slice(1)]},
    {...report,checks:[{...report.checks[0],checked_at:new Date(now+121000).toISOString()},...report.checks.slice(1)]},
    {...report,history_state:'unavailable'}, {...report,history:undefined},
  ]) assert.equal(summarizeHostScan(bad,now).state,'unavailable');
  assert.equal(summarizeHostScan({...report,history_state:'truncated'},now).state,'ok');
  const oldFinding=fullHostReport({checked_at:'2020-01-01T00:00:00Z',overrides:{'malware.program':{state:'finding'}}});
  assert.equal(summarizeHostScan(oldFinding,now).state,'finding');
});
