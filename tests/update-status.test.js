import test from 'node:test';
import assert from 'node:assert/strict';
import {sanitizeUpdateStatus,updateView,compareVersions} from '../src/contracts/update-status.js';
const now=Date.now();
function sample(){return {schema:'ironcurtain-update-status/v1',installed_version:'0.5.4',check:{state:'verified',installed_version:'0.5.4',latest_version:'0.5.5',installed_integrity:'verified',checked_at:new Date(now).toISOString(),manifest_sha256:'a'.repeat(64),package_sha256:'b'.repeat(64),source:{state:'observed',commit:'c'.repeat(40),release_commit:'d'.repeat(40)}},job:{state:'idle'}};}
test('only fresh verified higher releases enable an update and Git source is independent',()=>{
 const value=sample(),view=updateView(value,'0.5.4',now);assert.equal(view.can_install,true);assert.equal(view.check.source.has_unreleased_changes,true);
 for(const change of [v=>v.check.state='failed',v=>v.check.installed_integrity='mismatch',v=>v.check.package_sha256='bad',v=>v.job.state='running',v=>v.check.latest_version='0.5.4',v=>v.check.latest_version='0.5.3',v=>v.installed_version='0.5.3',v=>v.check.checked_at=new Date(now-900001).toISOString(),v=>v.check.checked_at=new Date(now+30001).toISOString()]){const v=sample();change(v);assert.equal(updateView(v,'0.5.4',now).can_install,false);}
 assert.equal(updateView(value,'0.5.3',now).can_install,false);
 value.check.state='failed';const failed=sanitizeUpdateStatus(value);assert.equal(failed.check.source.commit,'c'.repeat(40));assert.equal(failed.check.update_available,false);
});
test('version and disk metadata sanitization rejects malformed and private input',()=>{
 for(const v of ['00.1.0','1.02.3','1.0.00','v1.0.0',null,{},'1.0'])assert.equal(compareVersions(v,'1.0.0'),null);
 assert.equal(compareVersions('0.10.0','0.9.0'),1);
 const value=sample();value.token='secret';value.check.source.url='https://secret';value.job={state:'finished',result:'updated',command:'bad'};
 assert.doesNotMatch(JSON.stringify(sanitizeUpdateStatus(value)),/secret|command|url/);
 for(const v of [null,{},[],{schema:'ironcurtain-update-status/v1',check:{state:'verified',source:null}}])assert.equal(updateView(v,'0.5.4',now).can_install,false);
});
