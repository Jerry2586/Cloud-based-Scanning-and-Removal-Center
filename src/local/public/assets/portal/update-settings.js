import { updateView } from '/contracts/update-status.js';
export function createUpdateSettings({state,request,notify},scope=document){
 let generation=0,timer=null,bound=false,busy=false,last=null,active=false,pendingUntil=0;
 const set=(k,v)=>scope.querySelectorAll('[data-update-'+k+']').forEach(n=>{n.textContent=v;});
 const button=(k,disabled)=>scope.querySelectorAll('[data-update-'+k+']').forEach(n=>{n.disabled=disabled;});
 function paint(data){const v=updateView(data,data.running_version);last=v;
  set('running',v.running_version?'v'+v.running_version:'未读取');set('installed',v.installed_version?'v'+v.installed_version:'安装记录不可用');set('latest',v.check.latest_version?'v'+v.check.latest_version:'正式版本未核验');
  set('time',v.check.checked_at?new Date(v.check.checked_at).toLocaleString():'尚未检查');
  set('integrity',!v.installed_version?'安装记录不可用 · 暂无法校准':v.running_version!==v.installed_version?'运行版本与安装记录不一致':({verified:'安装文件摘要一致',mismatch:'文件摘要不一致 · 更新已阻止'})[v.check.installed_integrity]||'等待安装文件核验');
  set('signature',v.check.state==='verified'?'Ed25519 清单签名已验证':v.check.state==='running'?'正在核验正式发布':v.check.state==='failed'?'正式发布核验未完成':'等待正式发布核验');
  set('commit',v.check.source?.commit?.slice(0,12)||'源码提交未读取');
  set('source',v.check.source?.state!=='observed'?'Git 源码状态不可用':v.check.source.has_unreleased_changes===true?'Git 有尚未发布的源码变化':v.check.source.has_unreleased_changes===false?'Git main 与最新正式标签一致':'已读取 main · 正式标签提交待核对');
  active=v.check.state==='running'||v.job.state==='running';
  if(active)pendingUntil=0;
  const pending=pendingUntil>Date.now();
  set('state',pending?'任务已受理 · 等待后台开始':active?'正在执行真实检查 / 更新任务':v.job.state==='failed'?'更新未完成，请查看 Linux 菜单记录':v.check.state==='failed'||v.check.state==='unavailable'?'版本校准未完成':v.can_install?'发现可安装正式更新':v.check.state==='verified'?(v.fresh?'已校准 · 当前无可安装更新':'检查记录已过期，请重新检查'):'等待版本检查');
  set('job',v.job.state==='finished'?v.job.result==='updated'?'更新已完成，请重新登录核对运行版本':'当前已是最新正式版本':v.job.state==='running'?'安装中 · 面板可能短暂断开':v.job.state==='failed'?'安装失败 · 以事务恢复和健康检查结果为准':'尚无面板安装任务');
  button('check',busy||active||pending);button('install',busy||active||pending||!v.can_install);
 }
 function stop(){generation++;clearTimeout(timer);timer=null;busy=false;active=false;last=null;pendingUntil=0;}
 async function refresh(id=generation){const session=state.csrf;if(!session)return;try{const data=await request('/api/updates');if(id!==generation||session!==state.csrf)return;paint(data);}catch{if(id!==generation||session!==state.csrf)return;set('state','面板连接暂不可用 · 重新连接后核对实际状态');button('install',true);}finally{if(id===generation&&session===state.csrf)timer=setTimeout(()=>refresh(id),(active||pendingUntil>Date.now())?2000:60000);}}
 function start(){stop();if(state.csrf)void refresh(generation);}
 async function act(action){if(busy||!state.csrf||(action==='install'&&!last?.can_install))return;
  if(action==='install'&&!globalThis.confirm('安装已签名的最新正式版本？更新会备份并可能短暂重启面板。'))return;
  const id=generation,session=state.csrf;busy=true;button('check',true);button('install',true);set('state',action==='check'?'正在检查 Git 与正式发布':'已提交安装请求，等待实际任务状态');
  try{await request('/api/updates/'+action,{method:'POST',body:{}});if(id===generation&&session===state.csrf)pendingUntil=Date.now()+15000;}catch(error){if(id===generation&&session===state.csrf)notify(error.message,true);}finally{if(id===generation&&session===state.csrf){busy=false;clearTimeout(timer);void refresh(id);}}
 }
 function bind(){if(bound)return;bound=true;scope.querySelectorAll('[data-update-check]').forEach(n=>n.addEventListener('click',()=>act('check')));scope.querySelectorAll('[data-update-install]').forEach(n=>n.addEventListener('click',()=>act('install')));scope.addEventListener('ironcurtain-session-cleared',stop);}
 return {bind,start,stop};
}
