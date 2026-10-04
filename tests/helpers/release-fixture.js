import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { mkdtempSync, writeFileSync, rmSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { independentContract, legacyContract } from '../../src/release-contract.js';
import { runHeader } from '../../src/release-verification.js';
export const publisher = generateKeyPairSync('ed25519');
export const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export function temporary(t, prefix='ironcurtain-delivery-') {
  const dir = mkdtempSync(join(tmpdir(), prefix)); chmodSync(dir,0o700);
  t.after(()=>rmSync(dir,{recursive:true,force:true})); return dir;
}
export function signedRelease(t, {version='0.3.0',keys=publisher,content='trusted release',directory=temporary(t)}={}) {
  const contract={...legacyContract,independent:independentContract}; const parts=[];
  for(const [name,value] of [['./package.json',JSON.stringify({name:legacyContract.product,version})],['./release-contract.json',JSON.stringify(contract)],['./sample.txt',content]]) {
    const data=Buffer.from(value),header=Buffer.alloc(512);
    header.write(name,0,100);header.write('0000600\0',100);header.write('0000000\0',108);header.write('0000000\0',116);
    header.write(data.length.toString(8).padStart(11,'0')+'\0',124);header.write('00000000000\0',136);
    header.fill(32,148,156);header.write('0',156);header.write('ustar\0',257);header.write('00',263);
    header.write(header.reduce((sum,byte)=>sum+byte,0).toString(8).padStart(6,'0')+'\0 ',148);
    parts.push(header,data,Buffer.alloc((512-data.length%512)%512));
  }
  const archive=gzipSync(Buffer.concat([...parts,Buffer.alloc(1024)])), run=Buffer.concat([Buffer.from(runHeader),archive]);
  const prefix='APPGOG-Cloud-Security-Center-'+version;
  const manifest={schema:1,product:legacyContract.product,version,tar_name:prefix+'.tar.gz',tar_sha256:hash(archive),run_name:prefix+'.run',run_sha256:hash(run),environment:contract};
  for(const [name,bytes] of [[manifest.tar_name,archive],[manifest.run_name,run]]) {
    writeFileSync(join(directory,name),bytes,{mode:0o600});
    writeFileSync(join(directory,name+'.sha256'),hash(bytes)+'  '+name+'\n',{mode:0o600});
  }
  const bytes=Buffer.from(JSON.stringify(manifest));
  writeFileSync(join(directory,'release-manifest.json'),bytes,{mode:0o600});
  writeFileSync(join(directory,'release-manifest.json.sig'),sign(null,bytes,keys.privateKey),{mode:0o600});
  return {directory,manifest,keys};
}
