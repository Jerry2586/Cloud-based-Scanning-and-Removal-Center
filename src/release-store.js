import { constants, openSync, fstatSync, readSync, closeSync, lstatSync, mkdirSync, writeFileSync, renameSync, rmSync, readdirSync, chmodSync, fsyncSync } from 'node:fs';
import { join, resolve, dirname, parse } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { releaseAssetNames, verifyRelease, verifyReleaseManifest } from './release-verification.js';

export const RELEASE_LIMIT = 64 * 1024 * 1024;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const versionPattern = /^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$/;
export function compareVersions(a, b) {
  if (!versionPattern.test(a) || !versionPattern.test(b)) throw Error('RELEASE_VERSION');
  const x=a.split('.').map(Number), y=b.split('.').map(Number);
  for(let i=0;i<3;i++) if(x[i]!==y[i]) return x[i]>y[i]?1:-1;
  return 0;
}
export function trustedReleaseDirectory(directory) {
  if(process.platform!=='linux') throw Error('RELEASE_PLATFORM_UNSUPPORTED');
  directory=resolve(directory);
  for(let p=directory;;p=dirname(p)) {
    const info=lstatSync(p);
    if(!info.isDirectory() || info.isSymbolicLink() || (process.platform!=='win32' && (info.uid!==0 || ((info.mode&0o022) && !(info.mode&0o1000 && p===parse(p).root+'tmp'))))) throw Error('RELEASE_DIRECTORY');
    if(p===parse(p).root) break;
  }
  return directory;
}
export function readReleaseFile(file, maximum=RELEASE_LIMIT) {
  trustedReleaseDirectory(dirname(file));
  const fd=openSync(file,constants.O_RDONLY|(constants.O_NOFOLLOW??0)|(constants.O_NONBLOCK??0));
  try {
    const before=fstatSync(fd);
    if(!before.isFile() || before.nlink!==1 || before.size<1 || before.size>maximum || (process.platform!=='win32' && (before.uid!==0 || before.mode&0o022))) throw Error('RELEASE_FILE');
    const bytes=Buffer.alloc(before.size+1); let n=0;
    while(n<bytes.length){const got=readSync(fd,bytes,n,bytes.length-n,null);if(!got)break;n+=got;}
    const after=fstatSync(fd);
    if(n!==before.size || before.ino!==after.ino || before.mtimeMs!==after.mtimeMs || before.ctimeMs!==after.ctimeMs || before.size!==after.size) throw Error('RELEASE_CHANGED');
    return bytes.subarray(0,n);
  } finally {closeSync(fd);}
}
function storedManifest(directory, version, publicKey) {
  if(!versionPattern.test(version)) throw Error('RELEASE_VERSION');
  const root=join(directory,version);
  trustedReleaseDirectory(root);
  if(readdirSync(root).sort().join(',')!==releaseAssetNames(version).join(',')) throw Error('RELEASE_ASSET_LIST');
  const manifest=readReleaseFile(join(root,'release-manifest.json'),65536);
  const signature=readReleaseFile(join(root,'release-manifest.json.sig'),64);
  const value=verifyReleaseManifest({manifestBytes:manifest,signature,publicKey,expectedVersion:version});
  return {root,manifest,signature,value,digest:hash(manifest)};
}
function current(directory,publicKey) {
  trustedReleaseDirectory(directory);
  const pointer=JSON.parse(readReleaseFile(join(directory,'active.json'),4096));
  if(Object.keys(pointer).sort().join(',')!=='manifest_sha256,schema,version' || pointer.schema!=='ironcurtain-release-pointer/v1' || !/^[a-f0-9]{64}$/.test(pointer.manifest_sha256)) throw Error('RELEASE_POINTER');
  const result=storedManifest(directory,pointer.version,publicKey);
  if(result.digest!==pointer.manifest_sha256) throw Error('RELEASE_POINTER_DIGEST');
  return result;
}
function atomic(file,bytes) {
  const temporary=file+'.'+randomBytes(12).toString('hex')+'.new';
  try {
    const fd=openSync(temporary,'wx',0o640);
    try {writeFileSync(fd,bytes);fsyncSync(fd);} finally {closeSync(fd);}
    chmodSync(temporary,0o640);
    renameSync(temporary,file);
    if(process.platform!=='win32'){const fd=openSync(dirname(file),constants.O_RDONLY);try{fsyncSync(fd);}finally{closeSync(fd);}}
  } finally {rmSync(temporary,{force:true});}
}
export function importRelease({input,directory,publicKey}) {
  input=trustedReleaseDirectory(input); directory=trustedReleaseDirectory(directory);
  // Input is a protected snapshot populated by the root menu, never a browser path.
  for(const name of readdirSync(input)) readReleaseFile(join(input,name));
  const verified=verifyRelease({directory:input,publicKey});
  const version=verified.version; compareVersions(version,version);
  let old;
  try {old=current(directory,publicKey);} catch(error) {if(error.code!=='ENOENT')throw error; if(readdirSync(directory).includes('active.json'))throw error;}
  const digest=hash(readReleaseFile(join(input,'release-manifest.json'),65536));
  if(old && compareVersions(version,old.value.version)<0) throw Error('RELEASE_DOWNGRADE');
  if(old && version===old.value.version && digest!==old.digest) throw Error('RELEASE_SAME_VERSION_CHANGED');
  const target=join(directory,version); let exists=false;
  try {trustedReleaseDirectory(target);exists=true;} catch(error){if(error.code!=='ENOENT')throw error;}
  if(exists) {
    verifyRelease({directory:target,publicKey,expectedVersion:version});
    if(hash(readReleaseFile(join(target,'release-manifest.json'),65536))!==digest)throw Error('RELEASE_SAME_VERSION_CHANGED');
  } else {
    const stage=join(directory,'.import-'+randomBytes(12).toString('hex'));
    mkdirSync(stage,{mode:0o750});
    try {
      chmodSync(stage,0o750);
      for(const name of releaseAssetNames(version))atomic(join(stage,name),readReleaseFile(join(input,name)));
      verifyRelease({directory:stage,publicKey,expectedVersion:version});
      renameSync(stage,target);
    } finally {rmSync(stage,{recursive:true,force:true});}
  }
  atomic(join(directory,'active.json'),JSON.stringify({schema:'ironcurtain-release-pointer/v1',version,manifest_sha256:digest})+'\n');
  return {state:'ready',version,manifest_sha256:digest,delivery:'pull-only'};
}
function missingPointer(directory,error) {
  if(error.code!=='ENOENT')return false;
  try { trustedReleaseDirectory(directory); return !readdirSync(directory).includes('active.json'); } catch {return false;}
}
export function releaseSource(directory,publicKey) {
  return {
    latest() {const item=current(directory,publicKey);return {schema:'ironcurtain-release-offer/v1',version:item.value.version,manifest:item.manifest.toString('base64'),signature:item.signature.toString('base64')};},
    summary() {try {const item=current(directory,publicKey);return {state:'ready',version:item.value.version,manifest_sha256:item.digest,delivery:'pull-only',activation:'local-admin'};}catch(error){return {state:missingPointer(directory,error)?'missing':'unavailable',delivery:'pull-only',activation:'local-admin'};}},
    asset(version,name) {
      const active=current(directory,publicKey);
      if(version!==active.value.version || !releaseAssetNames(version).includes(name))throw Error('RELEASE_NOT_FOUND');
      const bytes=readReleaseFile(join(active.root,name));
      if(name===active.value.run_name || name===active.value.tar_name) {
        const field=name===active.value.run_name?'run':'tar';
        if(hash(bytes)!==active.value[field+'_sha256'])throw Error('RELEASE_ASSET_DIGEST');
      } else if(name.endsWith('.sha256')) {
        const field=name===active.value.run_name+'.sha256'?'run':'tar';
        if(bytes.toString('utf8')!==active.value[field+'_sha256']+'  '+active.value[field+'_name']+'\n')throw Error('RELEASE_ASSET_DIGEST');
      } else if(!bytes.equals(name.endsWith('.sig')?active.signature:active.manifest)) throw Error('RELEASE_ASSET_DIGEST');
      return bytes;
    }
  };
}
