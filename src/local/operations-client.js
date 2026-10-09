import {request as unixRequest} from 'node:http';
import {validateOperation, sanitizeOperations, unavailableOperations} from '../contracts/operations-status.js';

export function localOperations(action, value, env=process.env) {
  if (!['status','apply'].includes(action)) throw TypeError('Unknown operation');
  const input=action==='apply'?validateOperation(value):null;
  const payload=input?JSON.stringify(input):null;
  return new Promise(resolve=>{
    let settled=false,response;
    const fail=reason=>({...unavailableOperations(reason),response_status:503});
    const finish=result=>{
      if(settled)return;
      settled=true;clearTimeout(deadline);resolve(result);response?.destroy();req.destroy();
    };
    const req=unixRequest({
      socketPath:env.IRONCURTAIN_OPERATIONS_SOCKET || '/run/ironcurtain-operations-local/control.sock',
      path:'/operations',method:payload?'POST':'GET',
      headers:payload?{'Content-Type':'application/json','Content-Length':Buffer.byteLength(payload)}:{}
    },res=>{
      response=res;const chunks=[];let size=0;
      res.on('data',chunk=>{
        size+=chunk.length;
        if(size>262144)finish(fail('处置响应超过预算'));
        else chunks.push(chunk);
      });
      res.on('error',()=>finish(fail('处置响应中断')));
      res.on('aborted',()=>finish(fail('处置响应中断')));
      res.on('end',()=>{
        try {
          if((res.headers['content-type'] || '').split(';')[0].trim().toLowerCase()!=='application/json')return finish(fail('处置响应类型无法核验'));
          const raw=JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if([200,202].includes(res.statusCode)) {
            const clean=sanitizeOperations(raw);
            const expected=action==='status'?'ready':'running';
            if(clean.state!==expected || res.statusCode!==(action==='status'?200:202) || (input && clean.job.action!==input.action))return finish(fail('处置响应与请求不一致'));
            return finish({...clean,response_status:res.statusCode});
          }
          if(action==='apply' && [400,409,503].includes(res.statusCode)) {
            const reason=res.statusCode===409?'本机检测、更新或其他管理任务正在运行，或存在待恢复事务':res.statusCode===400?'处置请求无效，请重新检查证据':'本机处置服务不可用';
            return finish({...unavailableOperations(reason),response_status:res.statusCode});
          }
          finish(fail('处置响应无法核验'));
        } catch {finish(fail('处置响应无法核验'));}
      });
    });
    const deadline=setTimeout(()=>finish(fail('处置服务响应超时')),5000);deadline.unref();
    req.on('error',()=>finish(fail('本机处置服务未接入')));req.end(payload);
  });
}
