// Run only in the independent publishing environment. Never copy the private key to Xuanwu.
import { readFileSync, writeFileSync } from 'node:fs';
import { createPrivateKey, sign } from 'node:crypto';
import { validateRules, verifyRuleEnvelope, parseRuleJson, trustedRuleBytes } from '../src/rules.js';
const [source,privateFile,destination]=process.argv.slice(2);
if(!source || !privateFile || !destination || process.argv.length!==5) throw Error('Usage: node scripts/sign-rules.js rules.json offline-private.pem signed-rules.json');
const value=validateRules(parseRuleJson(trustedRuleBytes(source,131072,true))),key=createPrivateKey(trustedRuleBytes(privateFile,8192,true));
if(key.asymmetricKeyType!=='ed25519') throw Error('Ed25519 key required');
const bytes=Buffer.from(JSON.stringify(value));
const envelope={schema:'ironcurtain-signed-rules/v1',payload:bytes.toString('base64'),signature:sign(null,bytes,key).toString('base64')};
verifyRuleEnvelope(envelope,readFileSync(new URL('../release-public.pem',import.meta.url)));
writeFileSync(destination,JSON.stringify(envelope)+'\n',{mode:0o600,flag:'wx'});
console.log('签名规则已生成；玄武和铁幕仅持有发布公钥。');
