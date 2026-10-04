import { readFileSync, writeFileSync, mkdirSync, renameSync, rmSync, existsSync, lstatSync } from 'node:fs';
import { createCipheriv, createDecipheriv, randomBytes, scryptSync, X509Certificate, createPrivateKey, createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { passwordRecord } from '../src/local/auth.js';
import { validateConfiguration } from '../src/monitor.js';
import { loadCloudClient } from '../src/local/cloud-client.js';
import { join } from 'node:path';
export function seal(value, password) {
  if(typeof password!=='string'||password.length<16||password.length>256) throw Error('配对密码须为 16–256 个字符');
  const salt=randomBytes(32), iv=randomBytes(12), key=scryptSync(password,salt,32);
  const cipher=createCipheriv('aes-256-gcm',key,iv); cipher.setAAD(Buffer.from('ironcurtain-pair/v1'));
  const encrypted=Buffer.concat([cipher.update(JSON.stringify(value)),cipher.final()]);
  return {schema:'ironcurtain-pair/v1',salt:salt.toString('hex'),iv:iv.toString('hex'),tag:cipher.getAuthTag().toString('hex'),payload:encrypted.toString('base64')};
}
export function unseal(envelope, password) {
  if(envelope?.schema!=='ironcurtain-pair/v1'||! /^[a-f0-9]{64}$/.test(envelope.salt)||! /^[a-f0-9]{24}$/.test(envelope.iv)||! /^[a-f0-9]{32}$/.test(envelope.tag)||typeof envelope.payload!=='string'||envelope.payload.length>65536||! /^[A-Za-z0-9+/]*={0,2}$/.test(envelope.payload)||typeof password!=='string'||password.length<16||password.length>256) throw Error('身份包格式或密码无效');
  const cipher=createDecipheriv('aes-256-gcm',scryptSync(password,Buffer.from(envelope.salt,'hex'),32),Buffer.from(envelope.iv,'hex'));
  cipher.setAAD(Buffer.from('ironcurtain-pair/v1')); cipher.setAuthTag(Buffer.from(envelope.tag,'hex'));
  return JSON.parse(Buffer.concat([cipher.update(Buffer.from(envelope.payload,'base64')),cipher.final()]));
}
export function validateBundle(value,fingerprint,now=Date.now()) {
  if(value?.schema!=='ironcurtain-node-bundle/v1'||! /^node-[a-z0-9][a-z0-9-]{0,63}$/.test(value.config?.node_id)||value.config.schema!=='ironcurtain-cloud/v1'||Object.keys(value.config).sort().join(',')!=='endpoint,node_id,schema') throw Error('节点身份格式无效');
  const url=new URL(value.config.endpoint); if(url.protocol!=='https:'||url.username||url.password||url.pathname!=='/'||url.search||url.hash) throw Error('云端地址无效');
  if(!value.files||Object.keys(value.files).sort().join(',')!=='ca.crt,client.crt,client.key,token'||Object.values(value.files).some(v=>typeof v!=='string'||v.length>16384)) throw Error('身份包内容无效');
  const ca=new X509Certificate(value.files['ca.crt']), client=new X509Certificate(value.files['client.crt']);
  const expected=String(fingerprint).replace(/:/g,'').toUpperCase();
  if(! /^[A-F0-9]{64}$/.test(expected)||ca.fingerprint256.replace(/:/g,'')!==expected||!ca.ca||!ca.verify(ca.publicKey)||!client.verify(ca.publicKey)||!client.checkIssued(ca)||client.ca||!client.keyUsage?.includes('1.3.6.1.5.5.7.3.2')||!client.checkPrivateKey(createPrivateKey(value.files['client.key']))||client.subject!=='CN='+value.config.node_id||! /^[a-f0-9]{64}\n?$/.test(value.files.token)) throw Error('CA、证书、私钥或节点身份校验失败');
  for(const cert of [ca,client]) if(!Number.isFinite(Date.parse(cert.validFrom))||now<Date.parse(cert.validFrom)||now>=Date.parse(cert.validTo)) throw Error('配对证书尚未生效或已过期');
  return value;
}
export function addNode(config, bundle) {
  validateConfiguration(config);
  validateBundle(bundle,new X509Certificate(bundle.files['ca.crt']).fingerprint256);
  const name=bundle.config.node_id;
  if(Object.hasOwn(config.nodes,name)) throw Error('节点已登记，须先撤销或使用新名称');
  const candidate=structuredClone(config);
  const cert=new X509Certificate(bundle.files['client.crt']);
  candidate.nodes[name]={role:'ironcurtain-node',identities:[{fingerprint256:cert.fingerprint256,token_sha256:createHash('sha256').update(bundle.files.token.trim()).digest('hex'),status:'active',issued_at:new Date(cert.validFrom).toISOString(),cert_not_after:new Date(cert.validTo).toISOString()}],baseline:{}};
  return validateConfiguration(candidate);
}
export function removeNode(config,name) {
  validateConfiguration(config);
  if(!/^node-[a-z0-9][a-z0-9-]{0,63}$/.test(name) || !Object.hasOwn(config.nodes,name)) throw Error('节点未登记');
  const candidate=structuredClone(config);delete candidate.nodes[name];return validateConfiguration(candidate);
}
export function atomic(file,data){const temp=file+'.'+randomBytes(12).toString('hex')+'.new';try{writeFileSync(temp,data,{mode:0o600,flag:'wx'});renameSync(temp,file);}finally{rmSync(temp,{force:true});}}
export function writeIdentity(directory,value){
  try { lstatSync(directory); throw Error('既有身份目录不得覆盖'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const stage=directory+'.'+randomBytes(12).toString('hex')+'.stage';
  try{mkdirSync(stage,{mode:0o700});for(const [name,data] of Object.entries(value.files))writeFileSync(join(stage,name),data,{mode:0o600,flag:'wx'});writeFileSync(join(stage,'cloud.json'),JSON.stringify(value.config)+'\n',{mode:0o600,flag:'wx'});renameSync(stage,directory);}finally{rmSync(stage,{recursive:true,force:true});}
}
async function main(){
  const operation=process.argv[2]; const work=process.env.IRONCURTAIN_CONTROL_WORK || '/work';
  const load=name=>readFileSync(work+'/'+name,'utf8');
  if(operation==='init-local') {
    const password=randomBytes(24).toString('base64url');
    atomic(work+'/panel-auth.json',JSON.stringify(passwordRecord(password))+'\n');
    atomic(work+'/initial-credentials.txt','admin\n'+password+'\n'); return;
  }
  if(operation==='validate-cloud'){validateConfiguration(JSON.parse(load('config.json')));return;}
  if(operation==='seal'){
    const password=(await readInput()).replace(/[\r\n]+$/,'');
    const config=JSON.parse(load('cloud.json')); const files={};
    for(const name of ['ca.crt','client.crt','client.key','token']) files[name]=load(name);
    const ca=new X509Certificate(files['ca.crt']);const value=validateBundle({schema:'ironcurtain-node-bundle/v1',config,files},ca.fingerprint256);
    atomic(work+'/pairing.icpair',JSON.stringify(seal(value,password))+'\n');return;
  }
  if(operation==='unseal'){
    const input=JSON.parse(await readInput()); const raw=load('pairing.icpair');if(Buffer.byteLength(raw)>100000)throw Error('身份包超出限制');
    const value=validateBundle(unseal(JSON.parse(raw),input.password),input.fingerprint);
    writeIdentity(work+'/identity',value);return;
  }
  if(operation==='identity'){
    const cert=new X509Certificate(load('client.crt'));const token=load('token').trim();if(! /^[a-f0-9]{64}$/.test(token))throw Error('Token format');
    atomic(work+'/identity.json',JSON.stringify({fingerprint256:cert.fingerprint256,token_sha256:createHash('sha256').update(token).digest('hex'),status:'active',issued_at:new Date(cert.validFrom).toISOString(),cert_not_after:new Date(cert.validTo).toISOString()})+'\n');return;
  }
  if(operation==='register-node') {
    const files={};for(const name of ['ca.crt','client.crt','client.key','token']) files[name]=load(name);
    const bundle={schema:'ironcurtain-node-bundle/v1',config:JSON.parse(load('cloud.json')),files};
    atomic(work+'/config.next.json',JSON.stringify(addNode(JSON.parse(load('config.json')),bundle))+'\n');return;
  }
  if(operation==='revoke-node') {
    const input=JSON.parse(await readInput());if(Object.keys(input).join(',')!=='node_id')throw Error('参数错误');
    atomic(work+'/config.next.json',JSON.stringify(removeNode(JSON.parse(load('config.json')),input.node_id))+'\n');return;
  }
  if(operation==='probe'){const client=await loadCloudClient(work+'/identity');await client.status();return;}
  throw Error('未知管理动作');
}
async function readInput(){let text='';for await(const chunk of process.stdin){text+=chunk;if(Buffer.byteLength(text)>2048)throw Error('输入超出限制');}return text;}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) main().catch(()=>{console.error('管理动作失败；未接受无效身份或覆盖既有配置');process.exitCode=1;});
