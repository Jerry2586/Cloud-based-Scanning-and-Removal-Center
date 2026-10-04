import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { verifyRuleEnvelope, validateRules, parseRuleJson, ruleSummary, ruleSource } from '../src/rules.js';
import { sanitizeRules, sanitizeRuleHits } from '../src/contracts/rule-status.js';
import { renderDashboard } from '../src/dashboard.js';
const now=Math.floor(Date.now()/1000);
const {privateKey,publicKey}=generateKeyPairSync('ed25519');
const key=publicKey.export({format:'pem',type:'spki'});
const payload=(changes={})=>({schema:'ironcurtain-threat-rules/v1',version:'0.2.0',sequence:1,issued_at:now-10,expires_at:now+3600,minimum_agent_version:'0.2.0',indicators:[{id:'fixture',sha256:createHash('sha256').update('fixture').digest('hex'),label:'恶意文件测试 🔐'}],...changes});
const envelope=raw=>{const bytes=Buffer.from(typeof raw==='string'?raw:JSON.stringify(raw));return {schema:'ironcurtain-signed-rules/v1',payload:bytes.toString('base64'),signature:sign(null,bytes,privateKey).toString('base64')};};
test('signed rules verify exact publisher bytes and reject tampering, wrong key and command fields',()=>{
 const pack=envelope(payload()),verified=verifyRuleEnvelope(pack,key,now);
 assert.equal(verified.value.sequence,1);assert.equal(ruleSummary(verified).indicators,1);
 assert.throws(()=>verifyRuleEnvelope({...pack,payload:Buffer.from(JSON.stringify(payload({sequence:2}))).toString('base64')},key,now),/SIGNATURE/);
 const wrong=generateKeyPairSync('ed25519').publicKey.export({format:'pem',type:'spki'});
 assert.throws(()=>verifyRuleEnvelope(pack,wrong,now),/SIGNATURE/);
 for(const value of [payload({command:'id'}),payload({baseline:{}}),payload({paths:['/etc']}),payload({indicators:[{...payload().indicators[0],command:'id'}]})])assert.throws(()=>verifyRuleEnvelope(envelope(value),key,now));
});
test('signed rules enforce freshness, safe integers, compatibility and bounded indicator identity',()=>{
 const bad=[{sequence:0},{sequence:true},{sequence:9007199254740992},{issued_at:now+301},{expires_at:now},{expires_at:now+2678401,issued_at:now},{version:'01.2.0'},{minimum_agent_version:'999999.0.0'},{version:'1000000.0.0'},{indicators:Array(1025).fill(payload().indicators[0])},{indicators:[payload().indicators[0],payload().indicators[0]]},{indicators:[{...payload().indicators[0],label:'\ud800'}]},{indicators:[{...payload().indicators[0],label:'a\n'}]},{indicators:[{...payload().indicators[0],id:['bad']}]}];
 for(const changes of bad)assert.throws(()=>verifyRuleEnvelope(envelope(payload(changes)),key,now));
 assert.equal(validateRules(payload({minimum_agent_version:'0.1.99'}),now).sequence,1);
 assert.equal(validateRules(payload({minimum_agent_version:'0.2.1'}),now,'0.2.1').sequence,1);
 assert.throws(()=>validateRules(payload({minimum_agent_version:'0.2.1'}),now,'0.2.0'),/COMPATIBILITY/);
 for(const agentVersion of ['garbage','9','9.9',null,9])assert.throws(()=>validateRules(payload({minimum_agent_version:'9.9.9'}),now,agentVersion),/COMPATIBILITY/);
});
test('strict JSON rejects duplicates including escaped keys, floats, invalid UTF8 and deep nesting',()=>{
 for(const text of ['{"sequence":1,"sequence":2}','{"a":{"x":1,"\u0078":2}}','{"n":1.0}','{"n":1e0}','['.repeat(34)+'0'+']'.repeat(34)])assert.throws(()=>parseRuleJson(Buffer.from(text)));
 assert.throws(()=>parseRuleJson(Buffer.from([0xff])));
 assert.deepEqual(parseRuleJson(Buffer.from('{"a":[{},true,null,3],"b":"{ hi }"}')),{a:[{},true,null,3],b:'{ hi }'});
 const text=JSON.stringify(payload()).replace('"sequence":1','"sequence":1,"sequence":2');
 assert.throws(()=>verifyRuleEnvelope(envelope(text),key,now),/DUPLICATE/);
 const pack=envelope(payload());assert.throws(()=>verifyRuleEnvelope({...pack,payload:pack.payload+' '},key,now),/ENCODING/);
 assert.throws(()=>verifyRuleEnvelope({...pack,signature:'AA=='},key,now));
});
test('missing rule source and malformed metadata never show ready or zero threats as a success',()=>{
 assert.equal(ruleSource('/definitely-missing-ironcurtain-rules.json',key)().error,'RULE_MISSING');
 const ready=ruleSummary(verifyRuleEnvelope(envelope(payload()),key,now));assert.equal(sanitizeRules(ready).state,'ready');
 assert.equal(sanitizeRules({...ready,expires_at:now}).state,'unavailable');
 assert.equal(sanitizeRuleHits({state:'complete',items:[],total:9}).total,9);
 assert.equal(sanitizeRuleHits({state:'complete',items:[],total:20001}).state,'unavailable');
});
test('cloud rule dashboard shows actual signature metadata and keeps unfinished delivery explicit',()=>{
 const rules=ruleSummary(verifyRuleEnvelope(envelope(payload()),key,now));
 const html=renderDashboard({status:{nodes:{},rules},identities:{nodes:[],readers:[]},policy:{version:1}});
 assert.match(html,/签名已核验/);assert.match(html,new RegExp(rules.payload_sha256));assert.match(html,/云端病毒库分发尚待验收/);
 const escaped=renderDashboard({status:{nodes:{},rules:{...rules,version:'<script>bad</script>'}},identities:{nodes:[],readers:[]},policy:{version:1}});
 assert.doesNotMatch(escaped,/<script>bad/);assert.match(escaped,/&lt;script&gt;bad/);
});
