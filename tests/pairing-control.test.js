import test from 'node:test';
import { Readable } from 'node:stream';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync, readdirSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { X509Certificate, createHash } from 'node:crypto';
import { seal, unseal, validateBundle, writeIdentity, addNode, removeNode } from '../scripts/control.js';
import { createMonitor } from '../src/monitor.js';

const openssl = process.platform === 'win32' ? 'C:/Program Files/Git/usr/bin/openssl.exe' : 'openssl';
const available = spawnSync(openssl, ['version']).status === 0;
const password = 'test-pairing-password-32-characters';
const digest = input => createHash('sha256').update(input).digest('hex');
function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'ironcurtain-pairing-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const run = (...args) => { const result = spawnSync(openssl, args, { cwd: directory, encoding: 'utf8' }); assert.equal(result.status, 0, result.stderr); };
  const read = name => readFileSync(join(directory, name), 'utf8');
  run('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '1', '-subj', '/CN=Independent Pairing CA', '-addext', 'basicConstraints=critical,CA:TRUE');
  for (const [name, subject, extensions] of [
    ['client', 'node-test', 'basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\n'],
    ['wrong-purpose', 'node-test', 'basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n'],
    ['wrong-name', 'node-other', 'basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\n'],
    ['not-client', 'node-test', 'basicConstraints=critical,CA:TRUE\nextendedKeyUsage=clientAuth\n']
  ]) {
    run('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', name+'.key', '-out', name+'.csr', '-subj', '/CN='+subject);
    writeFileSync(join(directory, name+'.ext'), extensions.replaceAll('\\n','\n'));
    run('x509', '-req', '-in', name+'.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', name+'.crt', '-days', '1', '-extfile', name+'.ext');
  }
  const value = { schema:'ironcurtain-node-bundle/v1', config:{schema:'ironcurtain-cloud/v1', node_id:'node-test', endpoint:'https://security.example:9443/'}, files:{'ca.crt':read('ca.crt'),'client.crt':read('client.crt'),'client.key':read('client.key'),token:'a'.repeat(64)+'\n'} };
  const fingerprint = new X509Certificate(read('ca.crt')).fingerprint256;
  const config = {nodes:{},readers:[{role:'reader',token_sha256:digest('reader'),fingerprint256:'BB:'.repeat(31)+'BB'}],policy:{rules:{require_signed_updates:true,allow_remote_commands:false,allow_cloud_push:false}}};
  return {directory,read,value,fingerprint,config};
}
test('pairing encryption authenticates every field, rejects short password and never embeds private text', () => {
  const value={private_key:'private test only'}; const encrypted=seal(value,password);
  assert.deepEqual(unseal(encrypted,password),value);
  assert.ok(!JSON.stringify(encrypted).includes(value.private_key));
  assert.throws(()=>seal(value,'short'));
  assert.throws(()=>unseal(encrypted,password+'wrong'));
  for(const key of ['salt','iv','tag','payload']) {
    const changed={...encrypted}; changed[key]=(changed[key][0]==='a'?'b':'a')+changed[key].slice(1);
    assert.throws(()=>unseal(changed,password));
  }
});
test('real pairing certificates require pinned CA, clientAuth, matching key, exact node and validity', {skip:!available}, t => {
  const {value,fingerprint,read}=fixture(t);
  assert.equal(validateBundle(value,fingerprint),value);
  assert.throws(()=>validateBundle(value,'CC'.repeat(32)));
  assert.throws(()=>validateBundle(value,fingerprint,Date.parse(new X509Certificate(value.files['client.crt']).validTo)+1));
  for(const name of ['wrong-purpose','wrong-name','not-client']) assert.throws(()=>validateBundle({...value,files:{...value.files,'client.crt':read(name+'.crt'),'client.key':read(name+'.key')}},fingerprint));
  assert.throws(()=>validateBundle({...value,files:{...value.files,'client.key':read('wrong-name.key')}},fingerprint));
  assert.throws(()=>validateBundle({...value,files:{...value.files,token:'weak'}},fingerprint));
  assert.throws(()=>validateBundle({...value,config:{...value.config,command:'shell'}},fingerprint));
  assert.throws(()=>validateBundle({...value,config:{...value.config,endpoint:'http://security.example/'}},fingerprint));
  assert.throws(()=>validateBundle({...value,files:{...value.files,'extra.key':'secret'}},fingerprint));
});
test('identity output is all-or-nothing and existing identity cannot be overwritten', {skip:!available}, t => {
  const {directory,value,fingerprint}=fixture(t);const target=join(directory,'identity');
  writeIdentity(target,validateBundle(value,fingerprint));
  assert.deepEqual(readdirSync(target).sort(),['ca.crt','client.crt','client.key','cloud.json','token']);
  const before=readFileSync(join(target,'client.key'));
  assert.throws(()=>writeIdentity(target,value));
  assert.deepEqual(readFileSync(join(target,'client.key')),before);
  const failure=join(directory,'failed'); assert.throws(()=>writeIdentity(failure,{files:{'client.key':null}}));
  assert.equal(existsSync(failure),false);assert.equal(readdirSync(directory).some(name=>name.endsWith('.stage')),false);
});
test('dangling identity link is not overwritten', {skip:process.platform==='win32'}, t => {
  const directory=mkdtempSync(join(tmpdir(),'ironcurtain-link-'));t.after(()=>rmSync(directory,{recursive:true,force:true}));
  const target=join(directory,'identity');symlinkSync(join(directory,'missing'),target);
  assert.throws(()=>writeIdentity(target,{files:{}}),/覆盖/);
});
test('register and revoke update only node allowlist and invalidate old node authentication', {skip:!available}, async t => {
  const {value,fingerprint,config}=fixture(t); validateBundle(value,fingerprint);
  const registered=addNode(config,value);assert.deepEqual(Object.keys(config.nodes),[]);
  assert.deepEqual(Object.keys(registered.nodes),['node-test']);
  assert.equal(registered.nodes['node-test'].identities[0].token_sha256,digest(value.files.token.trim()));
  assert.ok(!JSON.stringify(registered).includes(value.files.token.trim()));
  assert.throws(()=>addNode(registered,value),/登记/);
  const call = monitor => new Promise((resolve, reject) => {
    const req = Readable.from([]);
    req.method = 'GET'; req.url = '/v1/node/status';
    req.headers = { authorization: 'Bearer '+value.files.token.trim() };
    req.socket = { authorized: true, getPeerCertificate: () => ({ fingerprint256: new X509Certificate(value.files['client.crt']).fingerprint256 }) };
    const res = { writeHead(status) { this.status = status; }, end(text) { resolve({ status: this.status, data: JSON.parse(text) }); } };
    monitor.handler(req, res).catch(reject);
  });
  const response = await call(createMonitor(registered));
  assert.equal(response.status,200); assert.equal(response.data.identity,'node-test');
  const revoked=removeNode(registered,'node-test');assert.deepEqual(Object.keys(revoked.nodes),[]);
  assert.deepEqual(revoked.readers,registered.readers);assert.deepEqual(revoked.policy,registered.policy);
  assert.equal((await call(createMonitor(revoked))).status,403);
  assert.throws(()=>removeNode(revoked,'node-test'),/登记/);
  assert.throws(()=>removeNode(registered,'reader'));
});
