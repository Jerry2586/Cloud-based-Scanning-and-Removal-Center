import { createPublicKey, verify, createHash } from 'node:crypto';
import { readFileSync, readSync, openSync, closeSync, fstatSync, lstatSync, constants } from 'node:fs';
import { dirname, resolve, parse } from 'node:path';
export const RULE_LIMIT = 196608;
export const RULE_SCHEMA = 'ironcurtain-threat-rules/v1';
const installedVersion=JSON.parse(readFileSync(new URL('../package.json',import.meta.url),'utf8'));
const version = /^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$/;
const exact = (value, keys) => value && !Array.isArray(value) && typeof value === 'object' && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const fields = ['schema','version','sequence','issued_at','expires_at','minimum_agent_version','indicators'];
export function validateRules(value, now = Math.floor(Date.now()/1000), agentVersion = installedVersion.version) {
  if (!exact(value,fields) || value.schema !== RULE_SCHEMA || typeof value.version!=='string' || !version.test(value.version) || typeof value.minimum_agent_version!=='string' || !version.test(value.minimum_agent_version)) throw Error('RULE_SCHEMA');
  if (![value.sequence,value.issued_at,value.expires_at].every(x=>Number.isSafeInteger(x) && x > 0) || value.issued_at > now+300 || value.expires_at <= now || value.expires_at <= value.issued_at || value.expires_at-value.issued_at > 2678400) throw Error('RULE_TIME_OR_SEQUENCE');
  if(typeof agentVersion!=='string' || !version.test(agentVersion))throw Error('RULE_COMPATIBILITY');
  const required=value.minimum_agent_version.split('.').map(Number), current=agentVersion.split('.').map(Number);
  for(let i=0;i<3;i++){if(required[i]>current[i])throw Error('RULE_COMPATIBILITY');if(required[i]<current[i])break;}
  if(!Array.isArray(value.indicators) || value.indicators.length > 1024) throw Error('RULE_INDICATORS');
  const ids=new Set(), hashes=new Set();
  for(const item of value.indicators){
    if(!exact(item,['id','sha256','label']) || typeof item.id!=='string' || typeof item.sha256!=='string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(item.id) || !/^[a-f0-9]{64}$/.test(item.sha256) || typeof item.label!=='string' || !item.label.length || [...item.label].length>128 || /[\x00-\x1f\x7f]/.test(item.label) || [...item.label].some(c=>c.codePointAt(0)>=0xd800 && c.codePointAt(0)<=0xdfff) || ids.has(item.id) || hashes.has(item.sha256)) throw Error('RULE_INDICATOR');
    ids.add(item.id);hashes.add(item.sha256);
  }
  return value;
}
function decode(value, limit){
  if(typeof value!=='string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))throw Error('RULE_ENCODING');
  const bytes=Buffer.from(value,'base64'); if(bytes.length>limit || bytes.toString('base64')!==value)throw Error('RULE_ENCODING');return bytes;
}
export function parseRuleJson(bytes) {
  const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
  // Native parse establishes JSON grammar; the second walk rejects duplicate keys.
  const value=JSON.parse(text), tokens=text.match(/"(?:[^"\\]|\\.)*"|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null|[{}\[\]:,]/g);
  let position=0;
  function walk(depth=0) {
    if(depth>32) throw Error('RULE_JSON_DEPTH');
    const token=tokens[position++];
    if(/^-?[0-9]/.test(token) && /[.eE]/.test(token))throw Error('RULE_JSON_INTEGER');
    if(token==='{') {
      const keys=new Set(); if(tokens[position]==='}') {position++;return;}
      while(true) {const key=JSON.parse(tokens[position++]);if(keys.has(key))throw Error('RULE_JSON_DUPLICATE');keys.add(key);position++;walk(depth+1);if(tokens[position++]==='}')break;}
    } else if(token==='[') {if(tokens[position]===']'){position++;return;}while(true){walk(depth+1);if(tokens[position++]===']')break;}}
  }
  walk();return value;
}
export function trustedRuleBytes(file,limit=RULE_LIMIT,privateKey=false) {
  const absolute=resolve(file);
  if(process.platform!=='win32') for(let parent=dirname(absolute);parent!==parse(parent).root;parent=dirname(parent)) {
    const info=lstatSync(parent);if(!info.isDirectory() || info.isSymbolicLink() || (info.uid!==0 && !(privateKey && info.uid===process.getuid())) || (info.mode&0o022 && !(info.mode&0o1000)))throw Error('RULE_DIRECTORY');
  }
  const fd=openSync(absolute,constants.O_RDONLY|(constants.O_NOFOLLOW??0)|(constants.O_NONBLOCK??0));
  try {
    const before=fstatSync(fd);if(!before.isFile() || before.nlink!==1 || before.size>limit || (process.platform!=='win32' && (before.uid!==(privateKey?process.getuid():0) || (before.mode&(privateKey?0o077:0o022)))))throw Error('RULE_FILE');
    const bytes=Buffer.alloc(limit+1);let size=0;while(size<bytes.length){const n=readSync(fd,bytes,size,bytes.length-size,null);if(!n)break;size+=n;}
    const after=fstatSync(fd);if(size>limit || before.ino!==after.ino || before.size!==after.size || before.mtimeMs!==after.mtimeMs || before.ctimeMs!==after.ctimeMs)throw Error('RULE_CHANGED');return bytes.subarray(0,size);
  } finally {closeSync(fd);}
}
export function verifyRuleEnvelope(envelope, publicKey, now, agentVersion) {
  if(!exact(envelope,['schema','payload','signature']) || envelope.schema!=='ironcurtain-signed-rules/v1' || Buffer.byteLength(JSON.stringify(envelope))>RULE_LIMIT)throw Error('RULE_ENVELOPE');
  const bytes=decode(envelope.payload,131072), signature=decode(envelope.signature,64),key=createPublicKey(publicKey);
  if(signature.length!==64 || key.asymmetricKeyType!=='ed25519' || !verify(null,bytes,key,signature))throw Error('RULE_SIGNATURE');
  // Fatal UTF-8 decoding keeps the Python and Node validators on the same bytes.
  const value=validateRules(parseRuleJson(bytes),now,agentVersion);
  return {value, digest:createHash('sha256').update(bytes).digest('hex'), envelope};
}
export function ruleSummary(verified){const p=verified.value;return {state:'ready',version:p.version,sequence:p.sequence,issued_at:p.issued_at,expires_at:p.expires_at,indicators:p.indicators.length,payload_sha256:verified.digest,delivery:'pull-only'};}
export function ruleSource(file, publicKey, now = ()=>Math.floor(Date.now()/1000)) {
  return ()=>{try {
    return verifyRuleEnvelope(parseRuleJson(trustedRuleBytes(file)),publicKey,now());
  }catch(error){return {error:error.code==='ENOENT'?'RULE_MISSING':'RULE_UNAVAILABLE'};}};
}
