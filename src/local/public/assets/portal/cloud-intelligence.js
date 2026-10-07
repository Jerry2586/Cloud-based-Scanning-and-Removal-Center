import { HASH_PATTERN, TASK_PATTERN, validateHashJob } from '/contracts/hash-intelligence.js';

// Hash-only enhancement. Local scanning never depends on this module or cloud availability.
export function createCloudIntelligence({state,request,notify},scope=document) {
  let generation=0, timer=null, bound=false, busy=false, task=null, pending=null;
  const labels={queued:'已排队',running:'分析中',complete:'分析完成',partial:'部分分析 / 覆盖不足',failed:'任务失败'};
  const verdicts={unknown:'未知 · 不代表安全',suspicious:'可疑 · 需要复核',malicious:'命中恶意特征'};
  const set=(key,value)=>scope.querySelectorAll('[data-intelligence-'+key+']').forEach(n=>{n.textContent=value;});
  const disable=(value)=>scope.querySelectorAll('[data-intelligence-submit]').forEach(n=>{n.disabled=value;});
  const current=(id,session)=>id===generation && session===state.csrf && Boolean(session);
  function paint(value) {
    task=validateHashJob(value);
    set('state',labels[task.state]); set('id',task.id);
    set('hash',task.sha256); set('time',new Date(task.updated_at).toLocaleString('zh-CN'));
    set('verdict',task.result?verdicts[task.result.verdict]:'等待实际检测结果');
    set('detail',task.result?task.result.reason:'玄武按已启用的可信来源处理此摘要；不会上传文件内容。');
    const list=scope.querySelector('[data-intelligence-evidence]'); list?.replaceChildren();
    for(const item of task.result?.evidence||[]) {
      const row=document.createElement('li'),title=document.createElement('strong'),detail=document.createElement('p');
      title.textContent=(item.provider==='signed-rules'?'文件特征规则':'云端哈希情报')+' · '+({malicious:'命中特征',known:'已有分析记录',unknown:'未命中 / 未收录',unavailable:'来源不可用'})[item.state];
      detail.textContent=item.state==='known'?'恶意 '+item.malicious+' · 可疑 '+item.suspicious+' · 分析时间 '+(item.analyzed_at?new Date(item.analyzed_at).toLocaleString('zh-CN'):'未知'):item.reason||'仅基于摘要，不能代替本机文件查杀';
      row.dataset.state=item.state==='malicious'?'finding':item.state==='unavailable'?'unavailable':'warning'; row.append(title,detail);list?.append(row);
    }
    busy=['queued','running'].includes(task.state);disable(busy);
  }
  function schedule(id,session){clearTimeout(timer);if(current(id,session)&&task&&['queued','running'].includes(task.state))timer=setTimeout(()=>poll(id,session),2000);}
  async function poll(id=generation,session=state.csrf){
    if(!current(id,session)||!task)return;
    try{const value=await request('/api/intelligence/'+task.id);if(!current(id,session))return;paint(validateHashJob(value,{id:task.id,sha256:task.sha256}));schedule(id,session);}
    catch(error){if(!current(id,session))return;busy=false;disable(false);set('state','查询暂不可用');set('detail','保留任务编号，可点击“刷新结果”核对；本机检测继续运行。');notify(error.message,true);}
  }
  function stop(){generation++;clearTimeout(timer);timer=null;busy=false;task=null;pending=null;disable(false);set('state','尚未提交');set('id','—');set('hash','—');set('time','—');set('verdict','等待实际检测结果');set('detail','仅发送 SHA-256；玄武未配对时，本机仍可独立查杀。');scope.querySelector('[data-intelligence-evidence]')?.replaceChildren();const input=scope.querySelector('[data-intelligence-input]');if(input)input.value='';}
  async function submit(event){
    event.preventDefault();if(busy||!state.csrf)return;
    const input=scope.querySelector('[data-intelligence-input]'),hash=(input?.value||'').trim().toLowerCase();
    if(!HASH_PATTERN.test(hash)){notify('请输入文件的 64 位 SHA-256 摘要',true);return;}
    if(!pending||pending.sha256!==hash){const key=globalThis.crypto.randomUUID();if(!TASK_PATTERN.test(key))return;pending={sha256:hash,request_key:key};}
    const id=generation,session=state.csrf;busy=true;disable(true);set('state','正在提交');
    try{const value=await request('/api/intelligence',{method:'POST',body:pending});if(!current(id,session))return;paint(validateHashJob(value,{sha256:hash}));pending=null;schedule(id,session);}
    catch(error){if(!current(id,session))return;busy=false;disable(false);set('state','提交未确认');set('detail','请重试核对受理状态；重试同一摘要使用相同请求编号，避免重复排队。');notify(error.message,true);}
  }
  function bind(){if(bound)return;bound=true;scope.querySelector('[data-intelligence-form]')?.addEventListener('submit',submit);scope.querySelector('[data-intelligence-refresh]')?.addEventListener('click',()=>{if(!busy&&task&&state.csrf){busy=true;disable(true);void poll();}});scope.addEventListener('ironcurtain-session-cleared',stop);}
  return {bind,stop};
}
