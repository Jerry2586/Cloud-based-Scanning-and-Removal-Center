import test from 'node:test';
import assert from 'node:assert/strict';
import {request} from 'node:http';
import {mkdtemp,rm,writeFile,rename,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createLocalServer} from '../src/local/server.js';
import {loadCredentials,passwordRecord,verifyPassword} from '../src/local/auth.js';
const original='account-regression-old-password';
const replacement='account-regression-new-password';
async function fixture(t,role='local',options={}) {
  const directory=await mkdtemp(join(tmpdir(),'ironcurtain-account-'));
  const credentials=await loadCredentials(directory,original);
  let calls=0;
  const rotate=async password=>{await writeFile(join(directory,'next.json'),JSON.stringify(passwordRecord(password)),{mode:0o600});await rename(join(directory,'next.json'),join(directory,'panel-auth.json'));};
  const server=createLocalServer({credentials,credentialDirectory:directory,role,origin:'http://127.0.0.1:8791',...options,changePassword:async value=>{calls++;if(options.failure)return {response_status:409,error:'管理操作正在运行'};await rotate(value.new_password);return {response_status:200,changed:true};}});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(async()=>{await new Promise(resolve=>server.close(resolve));await rm(directory,{recursive:true,force:true});});
  const call=(route,value,session={},extra={})=>new Promise((resolve,reject)=>{
    const data=value===undefined?undefined:JSON.stringify(value);
    const req=request({host:'127.0.0.1',port:server.address().port,path:route,method:data?'POST':'GET',headers:{Host:'127.0.0.1:8791',...(data?{Origin:'http://127.0.0.1:8791','Content-Type':'application/json'}:{}),...(session.cookie?{Cookie:session.cookie,'X-CSRF-Token':session.csrf}:{}),...extra}},res=>{let body='';res.on('data',chunk=>body+=chunk);res.on('end',()=>resolve({status:res.statusCode,data:JSON.parse(body),cookie:res.headers['set-cookie']?.[0].split(';')[0]}));});
    req.on('error',reject);req.end(data);
  });
  const login=async(password=original)=>{const res=await call('/api/login',{username:'admin',password});assert.equal(res.status,200);return {cookie:res.cookie,csrf:res.data.csrf};};
  return {call,login,rotate,directory,calls:()=>calls};
}
for(const role of ['local','cloud'])test(role+' password rotation revokes every old session and persists new login',async t=>{
  const f=await fixture(t,role),a=await f.login(),b=await f.login();
  const route='/api/account/password',value={current_password:original,new_password:replacement};
  assert.equal((await f.call(route,value)).status,401);
  assert.equal((await f.call(route,value,a,{Origin:'https://other.invalid'})).status,403);
  assert.equal((await f.call(route,value,a,{'X-CSRF-Token':'bad'})).status,403);
  for(const bad of [{...value,command:'anything'},{...value,new_password:'short'},{...value,new_password:'x'.repeat(257)},{...value,new_password:'a'.repeat(12)+'\n'},{new_password:replacement}])assert.equal((await f.call(route,bad,a)).status,400);
  assert.equal(f.calls(),0);
  assert.equal((await f.call(route,{...value,current_password:'incorrect'},a)).status,400);
  assert.equal((await f.call(route,{...value,new_password:original},a)).status,400);
  assert.equal((await f.call('/api/session',undefined,a)).data.authenticated,true);
  const changed=await f.call(route,value,a);assert.equal(changed.status,200);assert.equal(changed.data.changed,true);assert.equal(changed.cookie,'ironcurtain_session=');
  for(const session of [a,b])assert.equal((await f.call('/api/session',undefined,session)).data.authenticated,false);
  assert.equal((await f.call('/api/login',{username:'admin',password:original})).status,401);
  await f.login(replacement);
  const record=JSON.parse(await readFile(join(f.directory,'panel-auth.json'),'utf8'));assert.equal(verifyPassword(record,replacement),true);assert.equal(JSON.stringify(record).includes(replacement),false);
});
test('CLI credential replacement invalidates sessions without panel restart',async t=>{
  const f=await fixture(t),a=await f.login();await f.rotate(replacement);
  assert.equal((await f.call('/api/session',undefined,a)).data.authenticated,false);
  assert.equal((await f.call('/api/login',{username:'admin',password:original})).status,401);await f.login(replacement);
});
test('password attempts are bounded and failed controller preserves login',async t=>{
  let now=0;const f=await fixture(t,'cloud',{now:()=>now,failure:true}),a=await f.login();
  const value={current_password:original,new_password:replacement};
  assert.equal((await f.call('/api/account/password',value,a)).status,409);assert.equal((await f.call('/api/session',undefined,a)).data.authenticated,true);
  for(let i=0;i<4;i++)assert.equal((await f.call('/api/account/password',{...value,current_password:'bad'},a)).status,400);
  assert.equal((await f.call('/api/account/password',value,a)).status,429);now=600001;
  assert.equal((await f.call('/api/account/password',value,a)).status,409);
});
