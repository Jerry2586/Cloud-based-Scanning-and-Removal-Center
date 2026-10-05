import test from 'node:test';
import assert from 'node:assert/strict';
import {sanitizeProtection,sanitizeInventory,sanitizeFullScan,describeFullScan} from '../src/contracts/protection-status.js';
const now=Date.parse('2026-10-05T10:00:00.000Z'), stamp=new Date(now).toISOString();
const protection={schema:'ironcurtain-protection/v1',state:'ready',checked_at:stamp,issues:[],program_roots:1,business_roots:0,enrolled_containers:1,discovered_containers:1,unenrolled_containers:0,file_scope:'configured-directories-only',trust:'independent-signatures-required',monitor_interval_seconds:300};
const inventory={schema:'ironcurtain-inventory/v1',observed_at:stamp,container_state:'complete',listener_state:'complete',directory_state:'complete',drift_state:'first-observation',truncated:false,container_count:0,listener_count:0,candidate_count:0,containers:[],listeners:[],candidates:[],issues:[],drift:[]};
const full={schema:'ironcurtain-full-scan/v1',state:'finished',started_at:stamp,updated_at:stamp,finished_at:stamp,indexed:2,processed:2,clean:2,infected:0,skipped:0,errors:0,bytes_scanned:42,index_complete:true,scope:'enrolled-directories-only',reasons:[]};
test('ready protection requires enrolled file scope and consistent container coverage',()=>{
 assert.equal(sanitizeProtection(protection).state,'ready');
 for(const patch of [{program_roots:0},{discovered_containers:10},{unenrolled_containers:1},{issues:['未就绪']},{business_roots:33},{enrolled_containers:-1}]) assert.equal(sanitizeProtection({...protection,...patch}).state,'unavailable');
 assert.equal(sanitizeProtection({...protection,state:'incomplete',program_roots:0,issues:['未配置目录']}).state,'incomplete');
});
test('inventory retains explicit incomplete states and strips unrecognized metadata',()=>{
 const result=sanitizeInventory({...inventory,container_state:'unavailable',listener_state:'partial',Env:['SECRET']});
 assert.equal(result.container_state,'unavailable');assert.equal(result.listener_state,'partial');assert.equal('Env' in result,false);
 for(const patch of [{containers:[null],container_count:1},{listeners:[{protocol:'tcp',address:'*:80',port:80,processes:[{name:'x',pid:0}]}],listener_count:1},{container_state:'healthy'},{candidate_count:-1}]) assert.equal(sanitizeInventory({...inventory,...patch}).state,'unavailable');
});
test('scan counters and completion cannot fabricate full coverage',()=>{
 assert.equal(sanitizeFullScan(full).state,'finished');
 for(const patch of [{indexed:0,processed:0,clean:0},{processed:3},{errors:1},{skipped:1},{index_complete:false},{indexed:200001},{bytes_scanned:NaN}]) assert.equal(sanitizeFullScan({...full,...patch}).state,'unavailable');
 assert.equal(sanitizeFullScan({...full,state:'partial',skipped:3}).state,'partial');
});
test('old terminal results and stalled scans never show current green safety',()=>{
 assert.equal(describeFullScan(full,now).tone,'ok');assert.equal(describeFullScan(full,now).percent,100);
 const old={...full,updated_at:new Date(now-901000).toISOString()};const view=describeFullScan(old,now);
 assert.equal(view.stale,true);assert.equal(view.tone,'warning');assert.equal(view.percent,null);assert.match(view.label,/历史/);
 assert.equal(describeFullScan({...old,infected:1},now).tone,'finding');
 assert.equal(describeFullScan({...full,state:'scanning',updated_at:new Date(now-181000).toISOString()},now).active,false);
 assert.equal(describeFullScan({...full,state:'scanning'},now).active,true);
 assert.equal(describeFullScan({...full,updated_at:new Date(now+31000).toISOString()},now).stale,true);
});
