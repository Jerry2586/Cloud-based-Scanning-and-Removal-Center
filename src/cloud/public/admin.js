import {replaceKeyedItems, nodeDiagnostics, auditPresentation} from '/assets/view-state.js';
import {createUpdateSettings} from '/assets/portal/update-settings.js';
import {createDomainSettings} from '/assets/portal/domain-settings.js';
const state = { csrf: null }; let timer, generation = 0, busy = false, policyRevision, policyDirty = false, flight, refreshPending = false, taskRequest;
const $ = id => document.getElementById(id);
const views = { overview: ['安全总览','可信来源、节点连接与检测裁决。'], nodes: ['节点中心','每个节点独立身份，状态来自真实上报。'], plugins: ['引擎与特征','统一玄武能力，来源与授权透明可查。'], policies: ['策略中心','控制自动调度与风险裁决边界。'], tasks: ['检测任务','真实队列、执行证据与风险结论。'], audit: ['操作审计','追溯配置变更与任务生命周期。'], account: ['用户中心','管理独立账号与登录密码。'], settings: ['系统设置','可信发布、域名与访问配置。'] };
const labels = { ready:'已就绪',ok:'正常',finding:'发现风险',warning:'需要关注',stale:'已过期',missing:'未配置',unavailable:'不可用',connected:'已连接',unpaired:'未对接',idle:'待运行','not-enrolled':'尚未登记',partial:'部分完成',unknown:'证据不足',healthy:'正常',matched:'基线一致',changed:'文件变更','identity-created':'身份已创建',expired:'已过期',queued:'排队中',running:'检测中',complete:'已完成',failed:'执行失败',malicious:'恶意命中',suspicious:'可疑',known:'已有情报','waiting-first-report':'等待首次上报','attention-required':'需要处理',expiring:'即将到期' };
const label = value => labels[value] || value || '未知';
const time = value => value && Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString('zh-CN', { hour12:false }) : '尚无记录';
function notify(message, error=false) { $('message').textContent = message; $('message').dataset.error = String(error); }
async function request(url, options={}) {
  const headers={}; if(options.body) headers['Content-Type']='application/json'; if(options.method==='POST'&&state.csrf) headers['X-CSRF-Token']=state.csrf;
  const response=await fetch(url,{method:options.method||'GET',credentials:'same-origin',signal:AbortSignal.timeout(12000),headers,...(options.body?{body:JSON.stringify(options.body)}:{})});
  const value=await response.json(); if(!response.ok){if(response.status===401)clear();throw Object.assign(Error(value.error||'请求未完成'),{status:response.status});} return value;
}
const updates=createUpdateSettings({state,request,notify}); updates.bind();
const domain=createDomainSettings({state,request,notify}); domain.bind();
function clear(){generation++;clearTimeout(timer);state.csrf=null;updates.stop();domain.stop();$('workspace').hidden=true;$('login').hidden=false;$('logout').hidden=true;$('account-link').hidden=true;$('password-form').reset();for(const input of $('password-form').querySelectorAll('input[type=text]'))input.type='password';}
function route(){const view=location.hash.slice(1);const name=Object.hasOwn(views,view)?view:'overview';for(const el of document.querySelectorAll('[data-panel]'))el.hidden=el.dataset.panel!==name;for(const el of document.querySelectorAll('[data-view]')){el.classList.toggle('active',el.dataset.view===name);if(el.dataset.view===name)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');}$('page-title').textContent=views[name][0];$('page-description').textContent=views[name][1];}
window.addEventListener('hashchange',route);route();
function element(tag,text,className){const el=document.createElement(tag);if(text!==undefined)el.textContent=String(text);if(className)el.className=className;return el;}
function badge(value){const el=element('span',label(value),'badge');el.dataset.tone=['finding','malicious','failed','expired'].includes(value)?'bad':['unknown','unavailable','missing','warning','partial','suspicious','stale'].includes(value)?'warn':'normal';return el;}
function empty(target,text){target.replaceChildren(element('p',text,'empty'));}
function row(title,subtitle,status){const el=element('div',undefined,'row');const left=element('div');left.append(element('strong',title),element('small',subtitle));el.append(left,badge(status));return el;}
function renderJob(job){const el=element('details',undefined,'task'),head=element('summary');head.append(element('span',job.sha256),badge(job.result?.verdict||job.state));el.append(head,element('small',job.requester+' · '+time(job.created_at)+' · '+label(job.state)));const detail=element('div',undefined,'evidence');detail.append(element('p','任务 '+job.id),element('p','策略修订 '+job.policy.revision+' · 尝试 '+job.attempts+' 次'));if(!job.result)detail.append(element('p','等待真实执行结果。'));else{detail.append(element('p',job.result.reason));for(const item of job.result.evidence){const line=element('p');line.append(element('strong',labelPlugin(item.provider)+'：'),document.createTextNode(label(item.state)+' · '+(item.reason||'恶意 '+(item.malicious??0)+' / 可疑 '+(item.suspicious??0))));detail.append(line);if(item.version)detail.append(element('small','特征版本 '+item.version+' · 摘要 '+item.digest));if(item.indicator)detail.append(element('p',item.indicator+' · '+item.label));if(item.analyzed_at)detail.append(element('small','情报检测时间 '+time(item.analyzed_at)));}}el.append(detail);return el;}
const labelPlugin=id=>({'signed-rules':'文件特征规则','official-database':'文件查杀病毒库','hash-intelligence':'云端哈希情报'})[id]||id;
function paint(cloud,control){
  const nodes=Object.entries(cloud.nodes||{}),plugins=control.plugins||[],jobs=control.jobs||[];
  $('node-count').textContent=String(nodes.length);$('connected-count').textContent=String(cloud.deployment?.connected_roles?.length||0)+' 个已连接';$('plugin-count').textContent=String(plugins.filter(p=>p.enabled&&p.readiness.state==='ready').length);$('pending-count').textContent=String((control.counts.queued||0)+(control.counts.running||0));$('risk-count').textContent=String(jobs.filter(j=>['malicious','suspicious'].includes(j.result?.verdict)).length);$('summary-state').textContent=label(cloud.summary_state);$('overview-reason').textContent=nodes.length?'已登记 '+nodes.length+' 个节点 · '+plugins.filter(p=>p.enabled&&p.readiness.state==='ready').length+' 项检测能力就绪。展开节点查看未完成项。':'尚未登记铁幕节点，先配置可信来源与独立身份。';$('version').textContent='v'+control.running_version;$('data-age').textContent='服务器数据时间：'+time(control.generated_at);
  $('source-status').replaceChildren(row('文件特征',cloud.rules?.version?'版本 '+cloud.rules.version:'签名规则尚未就绪',cloud.rules?.state),row('文件查杀病毒库',cloud.virus_databases?.signatures?cloud.virus_databases.signatures+' 条官方特征':'尚无有效病毒库',cloud.virus_databases?.state),row('程序发布',cloud.releases?.version||'尚未导入正式安装包',cloud.releases?.state));
  replaceKeyedItems($('nodes'),nodes,(node,name)=>{
    const details=element('details',undefined,'node-detail'), head=element('summary');
    head.append(element('strong',name),badge(node.summary_state));details.append(head);
    const diagnostic=nodeDiagnostics(node), evidence=element('div',undefined,'node-evidence');
    evidence.append(element('p',label(node.pairing_state)+' · 最近上报 '+time(node.last_report_at),'muted'));
    for(const [title,status,description] of diagnostic.rows)evidence.append(row(title,description,status));
    const guidance=element('div',undefined,'node-guidance');guidance.append(element('strong','下一步'));
    for(const text of diagnostic.guidance)guidance.append(element('p',text));
    evidence.append(guidance);details.append(evidence);return details;
  },'尚未登记节点。在 xuanwu 管理菜单创建独立节点身份。');
  replaceKeyedItems($('plugins'),plugins.map(plugin=>[plugin.id,plugin]),plugin=>{const el=element('article',undefined,'plugin');el.append(badge(plugin.enabled?plugin.readiness.state:plugin.installed?'idle':'missing'),element('h2',plugin.name),element('p',plugin.readiness.reason||'可信来源校验已通过','description muted'),element('small',plugin.enabled?'已启用 · 按适用能力调用':plugin.installed?'已暂停':'尚未安装'));const info=element('details');info.append(element('summary','来源与校验详情'),element('p',plugin.source),element('p',plugin.license),element('p','能力 '+({'hash-analysis':'哈希分析','file-scan':'本机文件扫描数据源'})[plugin.capability]),element('p','来源版本 '+(plugin.readiness.version||plugin.readiness.daily_version||'未知')));if(plugin.readiness.digest||plugin.readiness.snapshot)info.append(element('p','摘要 '+(plugin.readiness.digest||plugin.readiness.snapshot)));el.append(info);const actions=element('div',undefined,'actions');const names={install:'安装启用',enable:'启用',pause:'暂停',remove:'移除',check:'检查来源'};const available=plugin.installed?[plugin.enabled?'pause':'enable','remove','check']:['install','check'];for(const action of available){const b=element('button',names[action]);b.type='button';b.dataset.plugin=plugin.id;b.dataset.action=action;b.disabled=busy||(['install','enable'].includes(action)&&plugin.readiness.state!=='ready');actions.append(b);}el.append(actions);return el;},'尚无检测能力来源。');
  if(!policyDirty){policyRevision=control.policy.revision;$('policy-threshold').value=control.policy.malicious_threshold;$('policy-external').checked=control.policy.external_hash_lookup;}$('policy-revision').textContent=String(control.policy.revision)+(policyDirty?'（有未保存修改）':'');
  for(const id of ['jobs','recent-jobs']){const target=$(id);const values=id==='recent-jobs'?jobs.slice(0,3):jobs;const open=new Set([...target.querySelectorAll('details[open]')].map(e=>e.dataset.id));target.replaceChildren();if(!values.length)empty(target,'还没有检测任务。');for(const job of values){const el=renderJob(job);el.dataset.id=job.id;el.open=open.has(job.id);target.append(el);}}
  $('audit').replaceChildren();if(!control.audit.length)empty($('audit'),'尚无操作记录。');for(const record of control.audit){const [title,result]=auditPresentation(record.action);$('audit').append(row(title,record.actor+' · '+record.subject+' · '+time(record.at),result));}
  $('release-details').replaceChildren(row('当前运行版本',control.running_version,'ready'),row('已导入节点分发包',cloud.releases?.version||'尚未导入',cloud.releases?.state));
}
async function refresh(){
  if(flight){refreshPending=true;return flight;}const id=generation;clearTimeout(timer);
  flight=(async()=>{try{const[cloud,control]=await Promise.all([request('/api/cloud/status'),request('/api/control')]);if(id!==generation||!state.csrf)return;paint(cloud,control);}catch(error){if(id===generation){$('data-age').textContent='读取失败：以下可能为上次数据，请刷新核实。';notify(error.message,true);}}finally{flight=undefined;if(state.csrf){const immediate=refreshPending||id!==generation;refreshPending=false;timer=setTimeout(refresh,immediate?0:10000);}}})();return flight;
}
function enter(session){generation++;clearTimeout(timer);state.csrf=session.csrf;policyDirty=false;$('login').hidden=true;$('workspace').hidden=false;$('logout').hidden=false;$('account-link').hidden=false;notify('');updates.start();domain.start();void refresh();}
async function action(button,fn){if(busy||!state.csrf)return;busy=true;const session=state.csrf;button.disabled=true;try{await fn();if(session===state.csrf)notify('操作已完成，正在读取实际状态。');}catch(error){if(session===state.csrf)notify(error.message,true);}finally{busy=false;button.disabled=false;if(session===state.csrf)void refresh();}}
$('login-form').addEventListener('submit',async event=>{event.preventDefault();const form=event.currentTarget,b=form.querySelector('button');b.disabled=true;try{const session=await request('/api/login',{method:'POST',body:{username:form.elements.username.value,password:form.elements.password.value}});form.elements.password.value='';enter(session);}catch(error){notify(error.message,true);}finally{b.disabled=false;}});
$('logout').addEventListener('click',()=>action($('logout'),async()=>{await request('/api/logout',{method:'POST',body:{}});clear();}));
$('password-visible').addEventListener('change',event=>{for(const id of ['current-password','new-password','confirm-password'])$(id).type=event.target.checked?'text':'password';});
$('password-form').addEventListener('submit',async event=>{
  event.preventDefault(); const form=event.currentTarget, button=form.querySelector('button[type=submit]'), feedback=$('password-feedback');
  if(button.disabled || !state.csrf)return;
  if($('new-password').value!==$('confirm-password').value){feedback.textContent='两次新密码输入不一致，请重新确认。';$('confirm-password').focus();return;}
  button.disabled=true;feedback.textContent='正在保存新密码…';
  try {
    await request('/api/account/password',{method:'POST',body:{current_password:$('current-password').value,new_password:$('new-password').value}});
    clear();feedback.textContent='';notify('密码已更改，所有旧登录会话已退出。请使用新密码登录。');$('login-form').elements.password.focus();
  } catch(error) {feedback.textContent=error.message;}
  finally {button.disabled=false;}
});
$('refresh').addEventListener('click',()=>void refresh());
$('plugins').addEventListener('click',event=>{const b=event.target.closest('button[data-plugin]');if(b)void action(b,()=>request('/api/plugins',{method:'POST',body:{id:b.dataset.plugin,action:b.dataset.action}}));});
$('policy-form').addEventListener('input',()=>{policyDirty=true;});
$('policy-form').addEventListener('submit',event=>{event.preventDefault();const b=event.currentTarget.querySelector('button');void action(b,async()=>{let next;try{next=await request('/api/policy',{method:'POST',body:{revision:policyRevision,malicious_threshold:Number($('policy-threshold').value),external_hash_lookup:$('policy-external').checked}});}catch(error){if(error.status===409){policyDirty=false;error.message='策略已被其他会话修改，正在载入最新策略，请核对后重新编辑。';}throw error;}policyRevision=next.revision;policyDirty=false;});});
$('task-form').addEventListener('submit',event=>{event.preventDefault();const b=event.currentTarget.querySelector('button');void action(b,async()=>{const hash=$('task-hash').value.trim().toLowerCase();if(!taskRequest||taskRequest.sha256!==hash)taskRequest={sha256:hash,request_key:crypto.randomUUID()};await request('/api/intelligence',{method:'POST',body:taskRequest});taskRequest=undefined;});});
try{const session=await request('/api/session');if(session.authenticated)enter(session);}catch(error){notify(error.message,true);}
