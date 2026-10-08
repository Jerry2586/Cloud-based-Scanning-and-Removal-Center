import { request } from 'node:http';
import { sanitizeUpdateStatus } from '../contracts/update-status.js';
export function localUpdate(action='status',env=process.env){
 if(!['status','check','install'].includes(action))return Promise.resolve({state:'unavailable',response_status:400});
 return new Promise(resolve=>{
  const fail=()=>resolve(action==='status'?sanitizeUpdateStatus(null):{state:'unavailable',response_status:503});
  const req=request({socketPath:env.IRONCURTAIN_ROLE==='cloud'?(env.IRONCURTAIN_UPDATE_SOCKET||'/run/ironcurtain-update-cloud/control.sock'):(env.IRONCURTAIN_SCAN_SOCKET||'/run/ironcurtain/scan.sock'),path:{status:'/update-status',check:'/update-check',install:'/update'}[action],method:action==='status'?'GET':'POST',headers:{'Content-Length':'0'},timeout:5000},res=>{
   let bytes=0;const chunks=[];
   res.on('data',chunk=>{bytes+=chunk.length;if(bytes>16384){fail();res.destroy();req.destroy();}else chunks.push(chunk);});
   res.on('error',fail);res.on('aborted',fail);
   res.on('end',()=>{try{const v=JSON.parse(Buffer.concat(chunks));if(action==='status'){if(res.statusCode!==200)return fail();return resolve(sanitizeUpdateStatus(v));}
    if(res.statusCode===409&&v.state==='unavailable'&&v.conflict==='management-active')return resolve({state:'unavailable',response_status:409,conflict:'management-active'});
    if(([202,409].includes(res.statusCode)&&v.state==='running')||([429,503].includes(res.statusCode)&&v.state==='unavailable'))return resolve({state:v.state,response_status:res.statusCode});fail();
   }catch{fail();}});
  });req.on('error',fail);req.on('timeout',()=>req.destroy());req.end();
 });
}
