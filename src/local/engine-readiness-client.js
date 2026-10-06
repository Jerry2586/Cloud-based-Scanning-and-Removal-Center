import {request as unixRequest} from 'node:http';
import {sanitizeEngineReadiness,unavailableReadiness} from '../contracts/engine-readiness.js';
export function localEngineReadiness(action,env=process.env) {
 if(!['status','check'].includes(action))throw new TypeError('Unknown readiness action');
 const unavailable=reason=>({...unavailableReadiness(reason),response_status:503});
 return new Promise(resolve=>{
  const req=unixRequest({socketPath:env.IRONCURTAIN_SCAN_SOCKET || '/run/ironcurtain/scan.sock',path:'/engines',method:action==='status'?'GET':'POST',timeout:5000,headers:action==='status'?{}:{'Content-Length':'0'}},res=>{
   const chunks=[];let size=0;
   res.on('data',chunk=>{size+=chunk.length;if(size>16384){resolve(unavailable('本机诊断响应超过预算'));res.destroy();req.destroy();}else chunks.push(chunk);});
   res.on('error',()=>resolve(unavailable('本机诊断响应中断')));res.on('aborted',()=>resolve(unavailable('本机诊断响应中断')));
   res.on('end',()=>{try{
    const raw=JSON.parse(Buffer.concat(chunks).toString('utf8'));const result=sanitizeEngineReadiness(raw);
    const valid=raw.state===result.state && (action==='status'?res.statusCode===200:(res.statusCode===202 && result.state==='checking') || (res.statusCode===409 && ['checking','unavailable'].includes(result.state)) || ([429,503].includes(res.statusCode)));
    resolve(valid?{...result,...(action==='check'?{response_status:res.statusCode}:{})}:unavailable('本机诊断响应无法核验'));
   }catch{resolve(unavailable('本机诊断响应无法核验'));}});
  });
  req.on('timeout',()=>{resolve(unavailable('本机诊断响应超时'));req.destroy();});req.on('error',()=>resolve(unavailable('本机检查代理未接入')));req.end();
 });
}
