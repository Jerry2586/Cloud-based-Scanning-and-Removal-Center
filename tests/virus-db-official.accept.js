// Explicit disposable Linux acceptance. Uses real downloaded official CVD bytes.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync,mkdirSync,rmSync,existsSync,readdirSync,openSync,readSync,writeSync,closeSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
import {createMonitor} from '../src/monitor.js';
import {virusDatabaseSource} from '../src/virus-db-store.js';
import {pullVirusDatabase} from '../scripts/virus-db-pull.js';
import {deliveryTLS,tlsServer,pairedIdentity,requestRelease} from './helpers/delivery-tls.js';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
test('real official signed CVD cloud transport, root activation and clean/EICAR scans',async t=>{
 assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);
 assert.equal(process.env.IRONCURTAIN_ACCEPT_DISPOSABLE_RUNNER,'1');assert.equal(process.env.GITHUB_ACTIONS,'true');
 const work=process.env.IRONCURTAIN_OFFICIAL_DB_WORK;assert.ok(work?.startsWith('/tmp/'));
 const root=resolve(import.meta.dirname,'..'),publicKey=readFileSync(join(work,'publisher-public.pem'));
 // The publishing key is already removed before any cloud service runs.
 assert.equal(existsSync(join(work,'publisher-private.pem')),false);
 const dirs={};for(const name of ['tls','identity','download','local-cache']){dirs[name]=join(work,name);mkdirSync(dirs[name],{mode:0o700});}
 const tls=deliveryTLS(dirs.tls),store=virusDatabaseSource(join(work,'cloud-cache'),publicKey);
 assert.equal(store.summary().state,'ready');
 const monitor=createMonitor({nodes:{'node-ci':{fingerprint256:tls['node-ci'].fingerprint256,token_sha256:hash(tls['node-ci'].token)}},virusDatabases:store});
 const {endpoint}=await tlsServer(t,tls.server,monitor.handler);
 pairedIdentity(dirs.identity,tls['node-ci'],endpoint);
 assert.equal((await requestRelease(endpoint,tls['node-ci'],{path:'/v1/virus-db/latest',token:'invalid'})).status,403);
 const result=await pullVirusDatabase({identityDirectory:dirs.identity,directory:dirs.download,publicKey});
 assert.equal(result.state,'downloaded-verified');assert.equal(result.snapshot,store.summary().snapshot);
 const runPython=(code,...args)=>JSON.parse(execFileSync('python3',['-c',code,...args],{encoding:'utf8',timeout:360000}));
 const activate=runPython("import importlib.util,json,sys;from pathlib import Path;s=importlib.util.spec_from_file_location('activation',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);print(json.dumps(m.activate_database(sys.argv[2],sys.argv[3],'/var/lib/ironcurtain-antivirus',sys.argv[4])))",join(root,'scripts/virus-db-activate.py'),dirs.download,dirs['local-cache'],join(work,'publisher-public.pem'));
 assert.equal(activate.state,'activated');assert.equal(activate.snapshot,result.snapshot);
 const db='/var/lib/ironcurtain-antivirus/database';
 for(const name of ['main.cvd','daily.cvd','bytecode.cvd'])assert.match(execFileSync('sigtool',['--info',join(db,name)],{encoding:'utf8',timeout:120000}),/Verification OK/);
 execFileSync('clamscan',['--database='+db,'--official-db-only=yes','--no-summary',join(work,'clean.txt')],{timeout:180000,stdio:'pipe'});
 let found;try{execFileSync('clamscan',['--database='+db,'--official-db-only=yes','--no-summary',join(work,'eicar.txt')],{timeout:180000,stdio:'pipe'});}catch(error){found=error;}
 assert.equal(found?.status,1);assert.match(found.stdout.toString(),/Eicar.*FOUND/i);
 // Both rejected imports leave the previous authenticated cache pointer unchanged.
 const cache=join(work,'cloud-cache'),pointer=readFileSync(join(cache,'active.json'));
 const importCode="import importlib.util,sys;s=importlib.util.spec_from_file_location('cache',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.import_database(sys.argv[2],sys.argv[3],sys.argv[4])";
 const corrupt=join(dirs.download,'daily.cvd'),fd=openSync(corrupt,'r+');const byte=Buffer.alloc(1);readSync(fd,byte,0,1,512);byte[0]^=1;writeSync(fd,byte,0,1,512);closeSync(fd);
 assert.throws(()=>execFileSync('python3',['-c',importCode,join(root,'scripts/virus-db-cache.py'),dirs.download,cache,join(work,'publisher-public.pem')],{stdio:'pipe',timeout:120000}));assert.deepEqual(readFileSync(join(cache,'active.json')),pointer);
 writeFileSync(join(dirs.download,'manifest.json.sig'),Buffer.alloc(64),{mode:0o600});
 assert.throws(()=>execFileSync('python3',['-c',importCode,join(root,'scripts/virus-db-cache.py'),dirs.download,cache,join(work,'publisher-public.pem')],{stdio:'pipe',timeout:120000}));assert.deepEqual(readFileSync(join(cache,'active.json')),pointer);
 assert.equal(JSON.parse(readFileSync('/var/lib/ironcurtain-antivirus/source.json')).source,'xuanwu-signed');
 console.log('Official CVD cloud delivery + independent publisher/vendor signatures + root activation + clean/EICAR: accepted.');
});
