import test from 'node:test';
import assert from 'node:assert/strict';
import {sanitizeRelease} from '../src/contracts/release-status.js';
const ready={state:'ready',version:'0.3.0',manifest_sha256:'a'.repeat(64),delivery:'pull-only',activation:'local-admin'};
test('release metadata rejects changed trust boundary and malformed version/digest',()=>{
  assert.deepEqual(sanitizeRelease({...ready,command:'untrusted'}),ready);
  for(const value of [null,[],{...ready,version:'00.3.0'},{...ready,manifest_sha256:'bad'},{...ready,delivery:'push'},{...ready,activation:'cloud'},{...ready,state:'installed'}, {state:'ready'}]) assert.equal(sanitizeRelease(value).state,'unavailable');
  assert.equal(sanitizeRelease({...ready,state:'missing'}).state,'missing');
});
