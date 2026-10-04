import {constants,openSync,fstatSync,readSync,closeSync,createReadStream,readdirSync} from 'node:fs';
import {join} from 'node:path';
import {createHash,verify} from 'node:crypto';
import {trustedReleaseDirectory,readReleaseFile} from './release-store.js';
export const VIRUS_DB_LIMIT=512*1024*1024;
const names=['bytecode.cvd','daily.cvd','main.cvd'];
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const sameKeys=(v,keys)=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===keys.sort().join(',');
export function verifyVirusManifest(bytes,signature,publicKey,clock=Date.now()) {
  if(bytes.length>16384||signature.length!==64||!verify(null,bytes,publicKey,signature))throw Error('DB_PUBLISHER_SIGNATURE');
  const value=JSON.parse(bytes);
  if(!sameKeys(value,['schema','files'])||value.schema!=='ironcurtain-virus-db/v1'||!sameKeys(value.files,names))throw Error('DB_MANIFEST');
  let total=0;
  for(const row of Object.values(value.files)) {
    if(!sameKeys(row,['version','signatures','functionality','timestamp','size','sha256'])||!['version','signatures','functionality','timestamp','size'].every(k=>Number.isSafeInteger(row[k])&&row[k]>=0)||Math.min(row.version,row.signatures,row.timestamp)<=0||row.size<512||row.size>VIRUS_DB_LIMIT||!/^[a-f0-9]{64}$/.test(row.sha256))throw Error('DB_MANIFEST');
    if(row.timestamp*1000>clock+300000)throw Error('DB_FUTURE');
    total+=row.size;
  }
  if(total>1024*1024*1024)throw Error('DB_LIMIT');
  if(clock-value.files['daily.cvd'].timestamp*1000>7*86400000)throw Error('DB_STALE');
  return value;
}
function current(directory,publicKey) {
  trustedReleaseDirectory(directory);
  const pointer=JSON.parse(readReleaseFile(join(directory,'active.json'),4096));
  if(!sameKeys(pointer,['schema','snapshot'])||pointer.schema!=='ironcurtain-virus-db-pointer/v1'||!/^[a-f0-9]{64}$/.test(pointer.snapshot))throw Error('DB_POINTER');
  const root=trustedReleaseDirectory(join(directory,pointer.snapshot));
  if(readdirSync(root).sort().join(',')!==[...names,'manifest.json','manifest.json.sig'].sort().join(','))throw Error('DB_FIXED_FILES');
  const bytes=readReleaseFile(join(root,'manifest.json'),16384),signature=readReleaseFile(join(root,'manifest.json.sig'),64);
  if(digest(bytes)!==pointer.snapshot)throw Error('DB_POINTER_DIGEST');
  const manifest=verifyVirusManifest(bytes,signature,publicKey);
  return {root,manifest,bytes,signature,snapshot:pointer.snapshot};
}
export function virusDatabaseSource(directory,publicKey) {
  return {
    latest(){const item=current(directory,publicKey);return {schema:'ironcurtain-virus-db-offer/v1',snapshot:item.snapshot,manifest:item.bytes.toString('base64'),signature:item.signature.toString('base64')};},
    summary(){try {const item=current(directory,publicKey);return {state:'ready',snapshot:item.snapshot,daily_version:item.manifest.files['daily.cvd'].version,signatures:Object.values(item.manifest.files).reduce((n,row)=>n+row.signatures,0),delivery:'pull-only',activation:'local-admin'};}catch(error){let missing=false;try{trustedReleaseDirectory(directory);missing=error.code==='ENOENT'&&!readdirSync(directory).includes('active.json');}catch{}return {state:missing?'missing':'unavailable',delivery:'pull-only',activation:'local-admin'};}},
    asset(snapshot,name){
      const item=current(directory,publicKey);
      if(snapshot!==item.snapshot||!names.includes(name))throw Error('DB_NOT_FOUND');
      const row=item.manifest.files[name],fd=openSync(join(item.root,name),constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
      try {
        const before=fstatSync(fd);
        if(!before.isFile()||before.uid!==0||before.mode&0o022||before.nlink!==1||before.size!==row.size)throw Error('DB_FILE');
        const hash=createHash('sha256'),chunk=Buffer.alloc(1024*1024);let position=0;
        for(;;){const count=readSync(fd,chunk,0,chunk.length,position);if(!count)break;position+=count;if(position>row.size)throw Error('DB_FILE_CHANGED');hash.update(chunk.subarray(0,count));}
        const after=fstatSync(fd);
        if(position!==row.size||hash.digest('hex')!==row.sha256||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs||before.size!==after.size)throw Error('DB_ASSET_DIGEST');
        return {size:row.size,stream:createReadStream('',{fd,autoClose:true,start:0,end:row.size-1})};
      } catch(error){closeSync(fd);throw error;}
    }
  };
}
