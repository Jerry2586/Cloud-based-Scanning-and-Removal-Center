import test from 'node:test';
import assert from 'node:assert/strict';
import {sanitizeEngineUpdate} from '../src/contracts/engine-update-status.js';
const make=()=>({schema:'ironcurtain-engine-update/v1',state:'running',task_id:'a'.repeat(32),started_at:'2026-10-09T12:00:00.000Z',updated_at:'2026-10-09T12:00:00.000Z',detail:'病毒库更新中'});
test('engine update identity and terminal timestamps are bounded and copied without private fields',()=>{
 const v=make();assert.deepEqual(sanitizeEngineUpdate({...v,token:'secret'}),v);
 for(const edit of [x=>x.task_id='bad',x=>x.updated_at='bad',x=>x.updated_at='2026-10-08T12:00:00.000Z',x=>x.state='finished',x=>x.finished_at=x.started_at,x=>x.detail='x'.repeat(181)]){const x=make();edit(x);assert.equal(sanitizeEngineUpdate(x).state,'unavailable');}
 for(const state of ['finished','failed','paused']){const x={...v,state,finished_at:v.updated_at};assert.deepEqual(sanitizeEngineUpdate(x),x);}
 const bad={...v,state:'finished',finished_at:'2026-10-08T12:00:00.000Z'};assert.equal(sanitizeEngineUpdate(bad).state,'unavailable');
 assert.deepEqual(sanitizeEngineUpdate(null),{schema:v.schema,state:'unavailable'});
});
