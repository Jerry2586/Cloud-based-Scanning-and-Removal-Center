import { sanitizeInventory, sanitizeProtection } from '/contracts/protection-status.js';
// Render bounded real observations. Asset presence is not a security verdict.
export function hostWorkspaceModel(report,now=Date.now()) {
  const clean=sanitizeInventory(report?.inventory); const inv=clean.schema?clean:null; const env=inv?.environment;
  const stamp=Date.parse(inv?.observed_at); const fresh=Number.isFinite(stamp) && stamp<=now+30000 && stamp>=now-900000;
  return {inventory:inv?.schema==='ironcurtain-inventory/v1'?inv:null,environment:env?.schema==='ironcurtain-environment/v1'?env:null,
    fresh,label:!inv?.schema?'主机清单不可用':fresh?'本次主机观测':'历史主机观测 · 请重新检查',observed:inv?.observed_at||'尚无观测时间'};
}
export function createHostWorkspace(scope) {
  let latest=null;
  const set=(key,value)=>scope?.querySelectorAll('[data-host-'+key+']').forEach(n=>{n.textContent=value;});
  const table=(key,rows,values,empty)=>{
    const body=scope?.querySelector('[data-host-table="'+key+'"]'); if(!body)return;
    body.replaceChildren();
    for(const row of rows){const tr=document.createElement('tr');for(const v of values(row)){const td=document.createElement('td');td.textContent=String(v);tr.append(td);}body.append(tr);}
    if(!rows.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=5;td.textContent=empty;tr.append(td);body.append(tr);}
  };
  const state=v=>({complete:'读取完整',partial:'覆盖不完整',unavailable:'读取不可用'})[v]||'等待检查';
  function update(report) {
    const protection=sanitizeProtection(report?.protection);const view=hostWorkspaceModel(report);const inv=view.inventory;const env=view.environment;latest={inventory:inv,protection,observation:view.label};
    set('status',view.label);set('time',view.observed);
    set('os',env?.os.PRETTY_NAME||env?.os.ID||'系统版本不可用');set('kernel',env?.kernel||'内核不可用');
    set('packages',env?env.package_count+' 个软件包 · '+state(env.package_state):'软件清单不可用');
    set('services',env?env.running_services+' 运行 / '+env.service_count+' 个服务 · '+state(env.service_state):'服务清单不可用');
    set('failed',env?env.failed_services+' 个失败服务':'—');
    set('containers',inv?inv.container_count+' 个容器 · '+state(inv.container_state):'容器清单不可用');
    set('listeners',inv?inv.listener_count+' 个监听 · '+state(inv.listener_state):'监听清单不可用');
    set('comparison',env?.change_state==='compared'?'与上次完整观测比较':env?.change_state==='partial'?'变化比较不完整':'首次观测 · 未批准为可信基线');
    set('limits','展示最多 32 个软件包、16 个服务、8 个容器和 8 个监听。计数受采集上限约束；软件版本未对接漏洞库。');
    table('packages',env?.packages||[],x=>[x.name,x.version],state(env?.package_state));
    table('services',env?.services||[],x=>[x.name,x.load,x.active,x.sub],state(env?.service_state));
    table('containers',inv?.containers||[],x=>[x.name,x.running?'运行':'已停止',x.readonly?'只读':'可写',x.process_count??'未读取',x.risks.join('；')||'本项元数据未发现风险'],state(inv?.container_state));
    table('listeners',inv?.listeners||[],x=>[x.protocol.toUpperCase(),x.address,x.processes.map(p=>p.name+' ('+p.pid+')').join('、')||'归属未读取'],state(inv?.listener_state));
    const changes=scope?.querySelector('[data-host-changes]');changes?.replaceChildren();
    const messages=[...(inv?.drift||[]),...(env?.changes||[]),...(inv?.issues||[]),...(env?.issues||[]),...(protection.issues||[])];
    for(const text of [...new Set(messages)].slice(0,64)){const li=document.createElement('li');li.textContent=text;changes?.append(li);}
    if(!messages.length){const li=document.createElement('li');li.textContent=inv?'清单未记录变化；完整性仍需独立签名基线核验':'等待真实主机检查';changes?.append(li);}
    scope?.querySelectorAll('[data-host-export]').forEach(n=>{n.disabled=!inv;});
  }
  function bind(){scope?.querySelectorAll('[data-host-export]').forEach(button=>button.addEventListener('click',()=>{
    if(!latest)return;const blob=new Blob([JSON.stringify({schema:'ironcurtain-panel-report/v1',exported_at:new Date().toISOString(),coverage:'bounded-public-report',observation:latest.observation,report:latest},null,2)],{type:'application/json'});
    const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='ironcurtain-report.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  }));}
  return {update,bind};
}
