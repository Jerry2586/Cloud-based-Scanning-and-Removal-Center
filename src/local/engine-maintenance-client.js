import {request as unixRequest} from 'node:http';
import {sanitizeEngineMaintenance,unavailableMaintenance} from '../contracts/engine-maintenance.js';
export function localEngineMaintenance(action,env=process.env){
 if(!['status','install'].includes(action))throw new TypeError('Unknown maintenance action');
 const fail=()=>({...unavailableMaintenance(),response_status:503});
 return new Promise(resolve=>{
  const req=unixRequest({socketPath:env.IRONCURTAIN_SCAN_SOCKET || '/run/ironcurtain/scan.sock',path:'/engine-maintenance',method:action==='status'?'GET':'POST',timeout:5000,headers:action==='status'?{}:{'Content-Length':'0'}},res=>{
   let size=0;const chunks=[];
   res.on('data',chunk=>{size+=chunk.length;if(size>4096){resolve(fail());res.destroy();req.destroy();}else chunks.push(chunk);});
   res.on('error',()=>resolve(fail()));res.on('aborted',()=>resolve(fail()));
   res.on('end',()=>{try{const raw=JSON.parse(Buffer.concat(chunks).toString('utf8'));const v=sanitizeEngineMaintenance(raw);
    const valid=raw.state===v.state && raw.code===v.code && (action==='status'?res.statusCode===200:res.statusCode===202?v.state==='queued':[409,429,503].includes(res.statusCode) && ['queued','running','unavailable'].includes(v.state));
    resolve(valid?{...v,...(action==='install'?{response_status:res.statusCode}:{})}:fail());
   }catch{resolve(fail());}});
  });req.on('timeout',()=>{resolve(fail());req.destroy();});req.on('error',()=>resolve(fail()));req.end();
 });
}
