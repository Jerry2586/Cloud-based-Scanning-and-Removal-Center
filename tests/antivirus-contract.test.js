import test from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeAntivirus } from '../src/local/scan-client.js';
const configured = { engine:'ClamAV', installed:true, state:'configured', updater:'scheduled', version:null, update_state:'unavailable', detail:'database metadata', database_at:'2026-10-04T00:00:00.000Z', database_version:100, signatures:400 };
test('antivirus metadata never upgrades missing or malformed state to ready', () => {
  assert.deepEqual(sanitizeAntivirus(configured), configured);
  const legacy={...configured};delete legacy.version;delete legacy.update_state;assert.deepEqual(sanitizeAntivirus(legacy),configured);
  for(const bad of [null, {...configured, installed:false}, {...configured, database_at:'bad'}, {...configured, signatures:-1}, {...configured, state:'ready'}, {...configured, updater:'green'}]) assert.equal(sanitizeAntivirus(bad).state,'unavailable');
  assert.equal('path' in sanitizeAntivirus({...configured,path:'/secret', token:'secret'}),false);
});

test('valid cloud database remains configured with official updater disabled',()=>{
 const value={...configured,updater:'disabled',source:'xuanwu-signed'};assert.deepEqual(sanitizeAntivirus(value),value);assert.equal(sanitizeAntivirus({...value,source:'execute-command'}).state,'unavailable');
});
