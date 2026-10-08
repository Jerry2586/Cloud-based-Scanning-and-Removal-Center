import {request} from 'node:http';
export function accountPassword(value, env = process.env) {
  const role = env.IRONCURTAIN_ROLE === 'cloud' ? 'cloud' : 'local';
  const socketPath = '/run/ironcurtain-account-' + role + '/control.sock';
  return new Promise(resolve => {
    let done = false;
    const finish = data => {if (!done) {done = true; resolve(data);}};
    const fail = () => finish({response_status:503, error:'账号服务未接入，请更新程序或在 Linux 菜单检查服务'});
    const payload = JSON.stringify(value);
    const req = request({socketPath, path:'/account/password', method:'POST', timeout:5000,
      headers:{'Content-Type':'application/json', 'Content-Length':Buffer.byteLength(payload)}}, res => {
      let size=0; const chunks=[];
      res.on('data',chunk=>{size+=chunk.length;if(size>4096){fail();res.destroy();}else chunks.push(chunk);});
      res.on('error',fail);res.on('aborted',fail);
      res.on('end',()=>{try {const data=JSON.parse(Buffer.concat(chunks));if(res.statusCode===200&&data.changed===true)finish({response_status:200,changed:true});else finish({response_status:[400,403,409].includes(res.statusCode)?res.statusCode:503,error:typeof data.error==='string'?data.error.slice(0,200):'密码更改未完成'});}catch{fail();}});
    });
    req.on('error',fail);req.on('timeout',()=>{fail();req.destroy();});req.end(payload);
  });
}
