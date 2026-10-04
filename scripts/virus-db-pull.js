import {request} from 'node:https';
import {readdirSync,writeFileSync,chmodSync,rmSync,openSync,closeSync,fsyncSync,createWriteStream} from 'node:fs';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {Transform} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import {readReleaseFile,trustedReleaseDirectory} from '../src/release-store.js';
import {verifyVirusManifest} from '../src/virus-db-store.js';

// Protected root menu only. Streaming data does not authorize cloud execution.
export async function pullVirusDatabase({identityDirectory,directory,publicKey,timeout=600000}) {
  trustedReleaseDirectory(directory);
  if(readdirSync(directory).length)throw Error('DB_OUTPUT_NOT_EMPTY');
  const config=JSON.parse(readReleaseFile(join(identityDirectory,'cloud.json'),32768));
  if(!config||Object.keys(config).sort().join(',')!=='endpoint,node_id,schema'||config.schema!=='ironcurtain-cloud/v1'||!/^node-[a-z0-9][a-z0-9-]{0,63}$/.test(config.node_id))throw Error('DB_IDENTITY_CONFIG');
  const endpoint=new URL(config.endpoint);
  if(endpoint.protocol!=='https:'||endpoint.username||endpoint.password||endpoint.pathname!=='/'||endpoint.search||endpoint.hash)throw Error('DB_ENDPOINT');
  const identity=Object.fromEntries(['ca.crt','client.crt','client.key','token'].map(name=>[name,readReleaseFile(join(identityDirectory,name),32768)]));
  const token=identity.token.toString('utf8').trim();
  if(!/^[A-Za-z0-9_-]{32,256}$/.test(token))throw Error('DB_TOKEN');
  const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),timeout);let peer;
  const created=[];
  function get(path,type,maximum,exactSize) {
    return new Promise((done,fail)=>{
      const req=request(new URL(path,endpoint),{method:'GET',agent:false,ca:identity['ca.crt'],cert:identity['client.crt'],key:identity['client.key'],minVersion:'TLSv1.2',signal:abort.signal,headers:{authorization:'Bearer '+token,accept:type}},res=>{
        const length=res.headers['content-length'];
        if(res.statusCode!==200||res.headers['content-type']?.split(';')[0].trim().toLowerCase()!==type||res.headers['content-encoding']||length!==undefined&&(!/^[0-9]+$/.test(length)||Number(length)>maximum||exactSize!==undefined&&Number(length)!==exactSize)) {
          res.destroy();return fail(Error('DB_CLOUD_REJECTED'));
        }
        done(res);
      });
      req.on('socket',socket=>socket.once('secureConnect',()=>{
        const observed=socket.getPeerCertificate().fingerprint256;
        if(!socket.authorized||!observed||peer&&peer!==observed)req.destroy(Error('DB_CLOUD_PEER_CHANGED'));else peer=observed;
      }));req.on('error',fail);req.end();
    });
  }
  async function small(path,limit) {
    const res=await get(path,'application/json',limit),chunks=[];let length=0;
    for await(const chunk of res){length+=chunk.length;if(length>limit){res.destroy();throw Error('DB_DOWNLOAD_LIMIT');}chunks.push(chunk);}
    if(!res.complete)throw Error('DB_DOWNLOAD_ABORTED');return Buffer.concat(chunks);
  }
  function save(name,bytes) {
    const file=join(directory,name),fd=openSync(file,'wx',0o600);created.push(file);
    try{writeFileSync(fd,bytes);fsyncSync(fd);}finally{closeSync(fd);}chmodSync(file,0o600);
  }
  try {
    const connected=JSON.parse(await small('/v1/connectivity',4096));
    if(connected.identity!==config.node_id)throw Error('DB_NODE_IDENTITY');
    const offer=JSON.parse(await small('/v1/virus-db/latest',32768));
    if(!offer||Object.keys(offer).sort().join(',')!=='manifest,schema,signature,snapshot'||offer.schema!=='ironcurtain-virus-db-offer/v1'||!/^[a-f0-9]{64}$/.test(offer.snapshot))throw Error('DB_OFFER');
    const decode=(value,limit)=>{
      if(typeof value!=='string'||value.length>limit*2||!/^[A-Za-z0-9+/]+={0,2}$/.test(value))throw Error('DB_OFFER');
      const bytes=Buffer.from(value,'base64');if(bytes.length>limit||bytes.toString('base64')!==value)throw Error('DB_OFFER');return bytes;
    };
    const bytes=decode(offer.manifest,16384),signature=decode(offer.signature,64),manifest=verifyVirusManifest(bytes,signature,publicKey);
    if(createHash('sha256').update(bytes).digest('hex')!==offer.snapshot)throw Error('DB_OFFER_DIGEST');
    save('manifest.json',bytes);save('manifest.json.sig',signature);
    for(const name of ['main.cvd','daily.cvd','bytecode.cvd']) {
      const row=manifest.files[name],res=await get('/v1/virus-db/'+offer.snapshot+'/'+name,'application/octet-stream',row.size,row.size);
      const file=join(directory,name);let length=0;const hash=createHash('sha256');
      const fd=openSync(file,'wx',0o600);created.push(file);
      try {
        const limit=new Transform({transform(chunk,_encoding,done){length+=chunk.length;if(length>row.size)return done(Error('DB_DOWNLOAD_LIMIT'));hash.update(chunk);done(null,chunk);}});
        await pipeline(res,limit,createWriteStream('',{fd,autoClose:false}),{signal:abort.signal});
        if(!res.complete||length!==row.size||hash.digest('hex')!==row.sha256)throw Error('DB_SIGNED_DIGEST');fsyncSync(fd);
      } finally {closeSync(fd);res.destroy();}
      chmodSync(file,0o600);
    }
    const dirfd=openSync(directory,'r');try{fsyncSync(dirfd);}finally{closeSync(dirfd);}
    return {state:'downloaded-verified',snapshot:offer.snapshot,files:manifest.files,activation:'pending-vendor-and-engine-validation'};
  }catch(error){for(const file of created)rmSync(file,{force:true});throw error;}
  finally{clearTimeout(timer);abort.abort();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  if(process.platform!=='linux'||process.getuid?.()!==0||process.argv.length!==2)throw Error('DB_ROOT_FIXED_ACTION');
  console.log(JSON.stringify(await pullVirusDatabase({identityDirectory:'/identity',directory:'/output',publicKey:readReleaseFile('/app/release-public.pem',32768)})));
}
