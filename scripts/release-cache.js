import { readFileSync } from 'node:fs';
import { importRelease, releaseSource } from '../src/release-store.js';
const key=readFileSync(new URL('../release-public.pem',import.meta.url));
const action=process.argv[2];
if(action==='import') console.log(JSON.stringify(importRelease({input:'/input',directory:'/store',publicKey:key})));
else if(action==='status') console.log(JSON.stringify(releaseSource('/store',key).summary()));
else throw Error('Unknown fixed release-cache operation');
