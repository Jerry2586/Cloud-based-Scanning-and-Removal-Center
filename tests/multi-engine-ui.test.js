import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
import {ENGINE_IDS,ENGINE_META,sanitizeMultiEngine} from '../src/contracts/multi-engine-status.js';
import {engineDisplayText} from '../src/local/public/assets/portal/engine-labels.js';
const job=(id='a',state='finished')=>({schema:'ironcurtain-multi-engine/v1',job_id:id.repeat(64),profile_digest:'b'.repeat(64),state,started_at:'2026-10-06T01:00:00.000Z',updated_at:'2026-10-06T01:00:01.000Z',...(state==='running'?{}:{finished_at:'2026-10-06T01:00:01.000Z'}),completed:4,total:4,coverage:4,engines:ENGINE_IDS.map(id=>({id,state:'complete',detail:'observed',completed:1,total:1,finding_total:0,findings:[]}))});
async function fixture(){
 class Element{constructor(){this.children=[];this.dataset={};this.handlers={};this.textContent='';this.disabled=false;}append(...x){this.children.push(...x);}replaceChildren(...x){this.children=x;}addEventListener(k,f){this.handlers[k]=f;}setAttribute(k,v){this[k]=v;}}
 const ids=['panel','percent','completed','coverage','state','detail','progress','list','findings','start','evidence'];const elements=Object.fromEntries(ids.map(x=>['multi-engine-'+x,new Element()]));let tid=0;const timers=new Map(),pending=[],notices=[],state={csrf:'first'};
 let source=await readFile(new URL('../src/local/public/assets/portal/multi-engine.js',import.meta.url),'utf8');source=source.replace(/^import[^\n]+\n/gm,'').replace('export function','function');
 const context=vm.createContext({ENGINE_IDS,ENGINE_META,sanitizeMultiEngine,engineDisplayText,document:{getElementById:id=>elements[id],createElement:()=>new Element()},setTimeout:fn=>{timers.set(++tid,fn);return tid;},clearTimeout:id=>timers.delete(id),Date});vm.runInContext(source,context);
 const ui=context.createMultiEngine({state,request:(path,options)=>new Promise((resolve,reject)=>pending.push({path,options,resolve,reject})),notify:(...x)=>notices.push(x)});ui.bind();ui.start();
 const flush=async()=>{for(let i=0;i<6;i++)await Promise.resolve();};
 return {elements,pending,timers,notices,state,ui,flush,click:()=>elements['multi-engine-start'].handlers.click(),poll:()=>{const fn=timers.values().next().value;timers.clear();fn();}};
}
test('rejected new multi-engine requests cannot display historical 100 percent',async()=>{
 const f=await fixture();f.pending.shift().resolve(job());await f.flush();assert.equal(f.elements['multi-engine-percent'].textContent,'100%');
 for(const reason of ['已有检测正在运行','请求过于频繁']){
  const click=f.click();assert.equal(f.elements['multi-engine-percent'].textContent,'—');assert.equal(f.elements['multi-engine-start'].disabled,true);
  f.pending.shift().reject(new Error(reason));await click;assert.equal(f.elements['multi-engine-start'].disabled,false);assert.equal(f.elements['multi-engine-percent'].textContent,'—');assert.equal(f.elements['multi-engine-detail'].textContent,reason);
  f.pending.shift().resolve(job());await f.flush();assert.equal(f.elements['multi-engine-percent'].textContent,'—');assert.equal(f.elements['multi-engine-detail'].textContent,reason);
 }
 assert.equal(f.notices.length,2);
});
test('running multi-engine completion waits for terminal report and binds the accepted job',async()=>{
 const f=await fixture();f.pending.shift().resolve(job());await f.flush();const click=f.click();f.pending.shift().resolve(job('c','running'));await click;
 assert.equal(f.elements['multi-engine-percent'].textContent,'99%');assert.equal(f.elements['multi-engine-progress'].value,99);
 f.pending.shift().resolve(job());await f.flush();assert.equal(f.elements['multi-engine-percent'].textContent,'—');assert.match(f.elements['multi-engine-detail'].textContent,/旧报告不代表/);
 f.poll();f.pending.shift().resolve(job('c'));await f.flush();assert.equal(f.elements['multi-engine-percent'].textContent,'100%');assert.equal(f.elements['multi-engine-start'].disabled,false);
 f.poll();f.state.csrf=null;f.ui.start();f.pending.shift().resolve(job('c'));await f.flush();assert.equal(f.elements['multi-engine-percent'].textContent,'—');assert.match(f.elements['multi-engine-detail'].textContent,/登录/);assert.equal(f.timers.size,0);
});
