// Test-only publisher: runs exclusively in an explicitly disposable root runner.
// The ephemeral private key stays outside the copied source and container images.
import {generateKeyPairSync,createHash} from 'node:crypto';
import {readFileSync,writeFileSync,mkdirSync,existsSync,chmodSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';
const [source,work]=process.argv.slice(2);
assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);
assert.equal(process.env.IRONCURTAIN_ACCEPT_DISPOSABLE_RUNNER,'1');
assert.match(work,/^\/opt\/ironcurtain-deployment-test\.[A-Za-z0-9]+$/);
assert.equal(source,work+'/source');
const fixture='/srv/ironcurtain-rule-ci';
assert.equal(existsSync(fixture),false);mkdirSync(fixture,{mode:0o750});
const bytes=Buffer.from('IronCurtain harmless signed rule acceptance fixture\n');
writeFileSync(fixture+'/sample.bin',bytes,{mode:0o640,flag:'wx'});
const {privateKey,publicKey}=generateKeyPairSync('ed25519');
writeFileSync(work+'/rules-publisher.key',privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600,flag:'wx'});
writeFileSync(source+'/release-public.pem',publicKey.export({type:'spki',format:'pem'}));chmodSync(source+'/release-public.pem',0o644);
const now=Math.floor(Date.now()/1000),minimum=JSON.parse(readFileSync(source+'/package.json')).version;
for(const sequence of [1,2]){
 const rules={schema:'ironcurtain-threat-rules/v1',version:minimum,sequence,issued_at:now,expires_at:now+86400,minimum_agent_version:minimum,indicators:[{id:'CI.HARMLESS',sha256:createHash('sha256').update(bytes).digest('hex'),label:'无害验收样本'}]};
 writeFileSync(work+'/rules-'+sequence+'.json',JSON.stringify(rules),{mode:0o600,flag:'wx'});
 execFileSync(process.execPath,[source+'/scripts/sign-rules.js',work+'/rules-'+sequence+'.json',work+'/rules-publisher.key',work+'/signed-rules-'+sequence+'.json'],{stdio:'pipe'});
}
console.log('Disposable offline-signed hash fixtures prepared; private key excluded from source.');
