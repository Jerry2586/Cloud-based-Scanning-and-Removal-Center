import {request as unixRequest} from 'node:http';
import {sanitizeMultiEngine} from '../contracts/multi-engine-status.js';
export function localMultiEngine(action,env=process.env) {
 if (!['status','start'].includes(action)) throw new TypeError('Unknown multi-engine action');
 const unavailable=reason=>({schema:'ironcurtain-multi-engine/v1',state:'unavailable',reason,response_status:503});
 return new Promise(resolve=>{
  const req=unixRequest({socketPath:env.IRONCURTAIN_SCAN_SOCKET || '/run/ironcurtain/scan.sock',path:'/multi-engine',method:action==='status'?'GET':'POST',timeout:5000,headers:action==='status'?{}:{'Content-Length':'0'}},res=>{
   const chunks=[];let size=0;
   res.on('data',chunk=>{size+=chunk.length;if(size>65536){resolve(unavailable('本机任务响应超过预算'));res.destroy();req.destroy();}else chunks.push(chunk);});
   res.on('error',()=>resolve(unavailable('本机任务响应中断')));
   res.on('aborted',()=>resolve(unavailable('本机任务响应中断')));
   res.on('end',()=>{
    try {
     const result=sanitizeMultiEngine(JSON.parse(Buffer.concat(chunks).toString('utf8')));
     const valid=action==='status'?res.statusCode===200:(res.statusCode===202 && result.state==='running') || (res.statusCode===409 && ['running','unavailable'].includes(result.state)) || ([429,503].includes(res.statusCode) && result.state==='unavailable');
     resolve(valid?{...result,...(action==='start'?{response_status:res.statusCode}:{})}:unavailable('本机任务响应无法核验'));
    }catch{resolve(unavailable('本机任务响应无法核验'));}
   });
  });
  req.on('timeout',()=>{resolve(unavailable('本机任务代理响应超时'));req.destroy();});
  req.on('error',()=>resolve(unavailable('本机检测代理未接入')));req.end();
 });
}
