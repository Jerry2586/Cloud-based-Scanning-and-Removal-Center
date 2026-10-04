import https from 'node:https';
import {readFileSync} from 'node:fs';
import {checkServerIdentity} from 'node:tls';
const local=process.env.IRONCURTAIN_ROLE==='local';
const host=process.env.IRONCURTAIN_PUBLIC_HOST;
const root=local?'/etc/ironcurtain':'/etc/xuanwu';
const options={hostname:'127.0.0.1',port:local?8790:9443,path:local?'/healthz':'/health',
  headers:local?{host:host+':8790'}:{},ca:readFileSync(root+(local?'/panel.crt':'/ca.crt')),
  checkServerIdentity:(_name,certificate)=>checkServerIdentity(host,certificate),rejectUnauthorized:true,timeout:3000};
if(!local){options.cert=readFileSync(root+'/health.crt');options.key=readFileSync(root+'/health.key');}
const req=https.request(options,res=>{let value='';res.on('data',chunk=>{value+=chunk;if(value.length>4096)req.destroy();});res.on('end',()=>{try{const data=JSON.parse(value);process.exit(res.statusCode===200&&(local?data.ready===true:data.ok===true)?0:1);}catch{process.exit(1);}});});
req.on('timeout',()=>req.destroy());req.on('error',()=>process.exit(1));req.end();
