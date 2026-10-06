import https from 'node:https';
import {readFileSync} from 'node:fs';
import {checkServerIdentity} from 'node:tls';
const local=process.env.IRONCURTAIN_ROLE==='local';
const host=process.env.IRONCURTAIN_PUBLIC_HOST;
const root=local?'/etc/ironcurtain':'/etc/xuanwu';
function check(panel){return new Promise(resolve=>{
  const port=panel?(local?8790:8791):9443;
  const options={hostname:'127.0.0.1',port,path:panel?'/healthz':'/health',headers:panel?{host:host+':'+port}:{},
    ca:readFileSync(root+(panel?'/panel.crt':'/ca.crt')),checkServerIdentity:(_name,certificate)=>checkServerIdentity(host,certificate),rejectUnauthorized:true,timeout:3000};
  if(!panel){options.cert=readFileSync(root+'/health.crt');options.key=readFileSync(root+'/health.key');}
  const req=https.request(options,res=>{let value='';res.on('data',chunk=>{value+=chunk;if(value.length>4096)req.destroy();});res.on('error',()=>resolve(false));res.on('end',()=>{try{const data=JSON.parse(value);resolve(res.statusCode===200&&(panel?data.ready===true&&data.service===(local?'ironcurtain-local':'xuanwu-admin'):data.ok===true));}catch{resolve(false);}});});
  req.on('timeout',()=>req.destroy());req.on('error',()=>resolve(false));req.end();
});}
process.exit((await Promise.all(local?[check(true)]:[check(false),check(true)])).every(Boolean)?0:1);
