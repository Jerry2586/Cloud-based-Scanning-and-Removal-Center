import {createDomainSettings} from '/assets/portal/domain-settings.js';
const state={csrf:null}; let timer, generation=0;
const $=id=>document.getElementById(id);
function notify(message,error=false){$('message').textContent=message;$('message').dataset.error=String(error);}
async function request(url,options={}){
  const headers={};if(options.body)headers['Content-Type']='application/json';if(options.method==='POST'&&state.csrf)headers['X-CSRF-Token']=state.csrf;
  const response=await fetch(url,{method:options.method||'GET',credentials:'same-origin',headers,...(options.body?{body:JSON.stringify(options.body)}:{})});
  const value=await response.json();if(!response.ok){if(response.status===401)clear();throw Error(value.error||'请求未完成');}return value;
}
const domain=createDomainSettings({state,request,notify});domain.bind();
function clear(){generation++;clearTimeout(timer);state.csrf=null;domain.stop();$('workspace').hidden=true;$('login').hidden=false;}
const labels={ready:'已就绪',ok:'正常',finding:'发现风险',warning:'需要关注',stale:'已过期',missing:'未配置',unavailable:'不可用',connected:'已连接',unpaired:'未对接',idle:'待运行','not-enrolled':'尚未登记',partial:'配置不完整','waiting-first-report':'等待首次上报','attention-required':'需要处理',expiring:'即将到期',unknown:'等待检测',healthy:'正常',expired:'已过期'};
function label(value){return labels[value]||value||'不可用';}
async function refresh(){const id=generation;try{const data=await request('/api/cloud/status');if(id!==generation||!state.csrf)return;const entries=Object.entries(data.nodes||{});$('node-count').textContent=String(entries.length);$('connected-count').textContent=String((data.deployment?.connected_roles||[]).length);$('database-state').textContent=label(data.virus_databases?.state);$('release-state').textContent=label(data.releases?.state);$('nodes').replaceChildren();if(!entries.length)$('nodes').textContent='尚未登记节点，请在 xuanwu 管理菜单登记并导出身份包。';for(const [name,node]of entries){const row=document.createElement('div');row.className='node';const title=document.createElement('strong'),status=document.createElement('span');title.textContent=name;status.textContent=label(node.summary_state)+' · '+label(node.pairing_state);row.append(title,status);$('nodes').append(row);}}catch(error){if(id===generation)notify(error.message,true);}finally{if(id===generation&&state.csrf)timer=setTimeout(refresh,30000);}}
function enter(session){generation++;clearTimeout(timer);state.csrf=session.csrf;$('login').hidden=true;$('workspace').hidden=false;notify('');domain.start();void refresh();}
$('login-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.currentTarget;const button=form.querySelector('button');button.disabled=true;try{const session=await request('/api/login',{method:'POST',body:{username:form.elements.username.value,password:form.elements.password.value}});form.elements.password.value='';enter(session);}catch(error){notify(error.message,true);}finally{button.disabled=false;}});
$('logout').addEventListener('click',async()=>{try{await request('/api/logout',{method:'POST',body:{}});clear();}catch(error){notify(error.message,true);}});
$('refresh').addEventListener('click',()=>{clearTimeout(timer);void refresh();});
try{const session=await request('/api/session');if(session.authenticated)enter(session);}catch(error){notify(error.message,true);}
