import test from 'node:test';
import assert from 'node:assert/strict';
import {replaceKeyedItems,nodeDiagnostics,auditPresentation} from '../src/cloud/public/view-state.js';
class Element {
  constructor(tag,doc){this.tagName=tag.toUpperCase();this.ownerDocument=doc;this.dataset={};this.children=[];this.open=false;this.disabled=false;}
  append(...els){for(const el of els){el.parent=this;this.children.push(el);}}
  replaceChildren(...els){for(const el of this.children)el.parent=null;this.children=[];this.append(...els);}
  contains(el){return el===this||this.children.some(child=>child.contains(el));}
  closest(){return this.dataset.itemKey?this:this.parent?.closest();}
  querySelector(selector){return this.querySelectorAll(selector)[0];}
  querySelectorAll(selector){
    const matches=child=>selector==='details[open]'?child.tagName==='DETAILS'&&child.open:selector==='details'?child.tagName==='DETAILS':['SUMMARY','BUTTON'].includes(child.tagName);
    return this.children.flatMap(child=>[...(matches(child)?[child]:[]),...child.querySelectorAll(selector)]);
  }
  focus(options){this.ownerDocument.activeElement=this;this.focusOptions=options;}
}
function fixture(){const doc={activeElement:null,createElement:tag=>new Element(tag,doc)},target=doc.createElement('div');const render=()=>{const card=doc.createElement('article'),details=doc.createElement('details'),summary=doc.createElement('summary'),button=doc.createElement('button');button.dataset.action='check';details.append(summary);card.append(details,button);return card;};return {doc,target,render};}
test('refresh keeps plugin details and keyboard focus bound to stable identities',()=>{
  const {doc,target,render}=fixture();replaceKeyedItems(target,[['a',{}],['b',{}]],render,'empty');target.children[0].querySelector('details').open=true;target.children[0].querySelector('details').children[0].focus();
  replaceKeyedItems(target,[['b',{}],['a',{}]],render,'empty');assert.equal(target.children[0].querySelector('details').open,false);assert.equal(target.children[1].querySelector('details').open,true);assert.equal(doc.activeElement,target.children[1].querySelector('details').children[0]);assert.equal(doc.activeElement.focusOptions.preventScroll,true);
  const button=target.children[1].children[1];button.focus();replaceKeyedItems(target,[['a',{}]],render,'empty');assert.equal(doc.activeElement,target.children[0].children[1]);
});
test('removed cards do not transfer details or focus to unrelated cards',()=>{
  const {doc,target,render}=fixture();replaceKeyedItems(target,[['a',{}]],render,'empty');target.children[0].querySelector('details').open=true;target.children[0].children[1].focus();const oldFocus=doc.activeElement;replaceKeyedItems(target,[['c',{}]],render,'empty');assert.equal(target.children[0].querySelector('details').open,false);assert.equal(doc.activeElement,oldFocus);replaceKeyedItems(target,[],render,'尚无节点');assert.equal(target.children[0].textContent,'尚无节点');
});
test('fresh authenticated reports do not imply full protection',()=>{
  const value=nodeDiagnostics({certificate_state:'healthy',report_fresh:true,baseline_files:0,host_scan:{state:'unavailable',counts:{ok:5,warning:5,finding:0,unavailable:15}}});assert.equal(value.rows.find(row=>row[0]==='认证上报')[1],'ok');assert.equal(value.rows.find(row=>row[0]==='文件完整性')[1],'missing');assert.match(value.rows.find(row=>row[0]==='宿主环境检查')[2],/未完成 15/);assert(value.guidance.some(text=>text.includes('可信发布')));assert(value.guidance.some(text=>text.includes('逐项报告')));
});
test('stale reports and missing identities remain actionable',()=>{const value=nodeDiagnostics({last_report_at:'2026-10-01T00:00:00Z',report_fresh:false});assert.equal(value.rows[1][1],'stale');assert(value.guidance.some(text=>text.includes('恢复认证上报')));assert(value.guidance.some(text=>text.includes('证书')));});

test('audit distinguishes accepted tasks, incomplete evidence and failures',()=>{
  assert.deepEqual(auditPresentation('job.enqueue'),['检测任务已受理','queued']);
  assert.deepEqual(auditPresentation('job.recovered'),['中断任务已重新排队','queued']);
  assert.deepEqual(auditPresentation('job.partial'),['检测任务证据不足','partial']);
  assert.deepEqual(auditPresentation('job.failed'),['检测任务执行失败','failed']);
  assert.equal(auditPresentation('unrecognized.action')[1],'unknown');
});
