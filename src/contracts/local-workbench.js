import { describeCheckup } from './checkup-status.js';
import { describeFullScan, sanitizeFullScan, sanitizeProtection } from './protection-status.js';
import { hostScanProgress, safeTimestamp, validHostCheck } from './host-scan-contract.js';

const CHECK_NAMES = Object.freeze({
 'integrity.program':'程序文件完整性','host.configuration':'受保护配置','container.contract':'容器运行配置',
 'container.approved-image':'容器镜像基线','response.containment':'封控准备','host.os-release':'操作系统',
 'host.systemd-state':'系统服务','ssh.effective':'SSH 安全配置','permissions.secret-inventory':'敏感文件权限',
 'permissions.installation':'安装目录权限','permissions.cron':'计划任务权限','network.listeners':'TCP 监听与归属',
 'network.udp-listeners':'UDP 监听与归属','network.routes':'网络路由','host.kernel-security':'内核安全参数',
 'network.firewall':'主机防火墙','malware.program':'程序目录病毒特征','malware.business':'业务目录病毒特征',
 'database.sqlite':'数据库结构','host.process-executables':'进程可执行文件','host.failed-units':'失败服务',
 'cloudflare.dns':'DNS 记录','cloudflare.workers':'Workers 配置','cloudflare.rules':'Cloudflare 规则','cloudflare.settings':'Cloudflare 设置'
});
export function checkName(id) { return CHECK_NAMES[id] || '汇总检查报告'; }
export function friendlyActivity(value) {
 let text=String(value || '');
 for(const [id,name] of Object.entries(CHECK_NAMES)) text=text.replaceAll(id,name);
 return text;
}
// A missing history store or incomplete coverage must never hide observed findings.
export function summarizeLocalSecurity(report,{coverageComplete=false,stale=false,historyUnavailable=true,now=Date.now()}={}) {
 const checks=Array.isArray(report?.checks)?report.checks:[];
 const knownById=new Map();
 for(const check of checks){
  if(!validHostCheck(check) || !Object.hasOwn(CHECK_NAMES,check.id))continue;
  const existing=knownById.get(check.id);
  if(!existing || existing.state!=='finding' && check.state==='finding' || existing.state==='ok' && check.state!=='ok')knownById.set(check.id,check);
 }
 const known=[...knownById.values()];
 const findings=known.filter(x=>x.state==='finding').length;
 const attention=known.filter(x=>['warning','unavailable'].includes(x.state)).length;
 const file=sanitizeFullScan(report?.full_scan);
 const infected=Number.isSafeInteger(file.infected)?file.infected:0;
 const historicalFiles=infected>0 && (Date.parse(file.updated_at)<now-900000 || Date.parse(file.updated_at)>now+30000);
 const protection=sanitizeProtection(report?.protection);
 const protectionAt=Date.parse(protection.checked_at);
 const protectionReady=protection.state==='ready' && Number.isFinite(protectionAt) && protectionAt>=now-900000 && protectionAt<=now+30000;
 const notes=[];
 if(report && !protectionReady)notes.push(protection.issues?.length ? '防护范围尚未就绪：'+protection.issues.join('；') : '防护范围尚未完整核验');
 if(stale && report?.checked_at)notes.push('环境报告已过期或时间异常');
 if(report?.state==='finished' && !coverageComplete)notes.push('环境检查覆盖不完整');
 if(historyUnavailable)notes.push('告警历史暂不可用');
 if(historicalFiles)notes.push('文件命中来自历史查杀记录，请复核处置状态');
 const risk=findings>0 || infected>0;
 let title,detail,tone='warning';
 if(risk){title='发现需要处理的风险';tone='finding';detail=[findings?findings+' 项环境风险':'',infected?infected+' 个文件特征命中':''].filter(Boolean).join(' · ');}
 else if(report?.state==='running' || report?.checkup?.state==='running' || ['indexing','scanning'].includes(file.state)){title='正在检查这台服务器';detail='结论将在检查结束后汇总';tone='running';}
 else if(report?.state==='unavailable' || !report){title='本机检测尚未就绪';detail=report?.reason || '尚未取得 Linux 主机代理报告';}
 else if(report?.state==='failed'){title='本次检查未完成';detail=report.reason || '请查看错误原因并重新检查';}
 else if(report?.state==='finished' && coverageComplete && !stale && !historyUnavailable && attention===0 && known.length===Object.keys(CHECK_NAMES).length && protectionReady){title='检查范围内未发现异常';detail='结论仅覆盖本次有效检查范围';tone='ok';}
 else if(report?.state==='finished'){title='检查结果需要复核';detail=[attention?attention+' 项需复核或不可用':'',...notes].filter(Boolean).join('；') || '请核对检查范围';}
 else {title='等待首次安全检查';detail='先检查本机环境，再扫描已纳管文件';}
 return {title,detail,tone,findings,infected,attention,notes,coverage:coverageComplete && !stale?'报告完整且有效':'尚不能确认完整覆盖'};
}
// Exactly one foreground task; each percentage keeps its original denominator.
export function describeWorkbenchTask(report,{busy=false,action=null,trusted=false,requestIssue=null,requestedTaskId=null,now=Date.now()}={}) {
 const checkup=describeCheckup(report,{busy:busy && action==='checkup',now});
 const file=sanitizeFullScan(report?.full_scan), fileView=describeFullScan(file,now);
 const progress=hostScanProgress(report);
 const engine=report?.antivirus;
 const task=(kind,title,detail,percent,active,stage,at)=>({kind,title,detail:friendlyActivity(detail),percent,active,stage,at:at || null});
 if(busy)return task(action || 'scan','正在提交任务','等待本机代理确认请求',null,true,'请求中');
 if(requestIssue)return task(action || 'scan','本次请求未确认启动',requestIssue+'；下方保留上一次报告，请刷新核对正在运行的任务',null,false,'请求需要复核');
 if(requestedTaskId && ![report?.task_id,report?.checkup?.task_id,file.task_id].includes(requestedTaskId))return task(action || 'scan','任务已受理 · 等待本次报告','正在获取任务 '+requestedTaskId.slice(0,8)+' 的进度；旧报告不代表本次结果',null,true,'等待本次报告');
 if(checkup.active)return task('checkup',checkup.status,checkup.detail,checkup.percent,true,report.checkup?.stage==='files'?'2 / 2 · 文件查杀':'1 / 2 · 环境体检',report.checkup?.updated_at);
 if(report?.state==='running'){
  const activity=report.checks?.at(-1)?.checked_at || report.started_at;
  const fresh=safeTimestamp(activity) && Date.parse(activity)>=now-180000 && Date.parse(activity)<=now+30000;
  return task('scan',fresh?'环境与容器检查中':'环境检查进度已过期',fresh && progress?'已完成 '+progress.completed+' / '+progress.total+' 项 · '+checkName(progress.current):fresh?'等待本机代理报告进度':'未收到近期进度，请核对本机代理',fresh && progress?Math.min(99,Math.floor(progress.completed*100/progress.total)):null,true,'25 项固定核验',activity);
 }
 if(fileView.active)return task('full-scan',fileView.label,fileView.files+(fileView.detail?' · '+fileView.detail:''),fileView.percent,true,file.state==='indexing'?'建立文件清单':'逐文件查杀',file.updated_at);
 if(engine?.update_state==='running')return task('engine-update','病毒库更新中','正在获取并验证本机病毒库',null,true,'病毒库维护');
 const entries=[
  report?.checkup?.updated_at && task('checkup',checkup.status,checkup.detail,checkup.percent,false,'全面体检记录',report.checkup.updated_at),
  file.updated_at && task('full-scan',fileView.label,fileView.files,fileView.percent,false,'文件查杀记录',file.updated_at),
  report?.checked_at && task('scan',trusted?'环境与容器检查已完成':'环境检查记录待复核',trusted?'25 项固定核验 · 详情见主机与容器':'请核对报告时间和覆盖范围',trusted?100:null,false,'环境检查记录',report.checked_at)
 ].filter(entry=>entry && safeTimestamp(entry.at)).sort((a,b)=>Date.parse(b.at)-Date.parse(a.at));
 return entries[0] || task('idle','还没有执行扫描','一键体检会先检查主机、容器和端口，再扫描已纳管目录',null,false,'等待开始');
}
