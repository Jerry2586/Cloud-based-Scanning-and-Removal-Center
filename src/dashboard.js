const escapeHtml = value => String(value ?? '')
  .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;').replaceAll("'", '&#39;');

const labels = {
  ok: '正常', warning: '警告', finding: '发现风险', unavailable: '不可用', stale: '数据过期',
  healthy: '在线', unreachable: '无法连接', unhealthy: '异常', unknown: '未知', unconfigured: '未配置',
  matched: '完整', changed: '已篡改', active: '正常', staged: '轮换中', expiring: '即将过期', expired: '已过期',
};
const label = value => labels[value] ?? String(value ?? '未知');
const tone = value => ['ok', 'healthy', 'matched', 'active'].includes(value) ? 'ok'
  : ['warning', 'staged', 'expiring', 'stale'].includes(value) ? 'warning'
    : ['finding', 'changed', 'expired'].includes(value) ? 'danger' : 'muted';
const badge = value => `<span class="badge ${tone(value)}">${escapeHtml(label(value))}</span>`;
const time = value => value ? escapeHtml(value) : '—';

export function renderDashboard({ status, identities, policy }) {
  const nodes = Object.entries(status.nodes).map(([name, node]) => `
    <article class="card node-card">
      <div class="card-head"><div><p class="eyebrow">受保护节点</p><h2>${escapeHtml(name)}</h2></div>${badge(node.summary_state)}</div>
      <div class="metric-grid">
        <div><span>公网探测</span><strong>${badge(node.probe.state)}</strong></div>
        <div><span>文件完整性</span><strong>${badge(node.integrity.state)}</strong></div>
        <div><span>宿主环境</span><strong>${badge(node.host_scan.state)}</strong></div>
        <div><span>报告新鲜度</span><strong>${badge(node.report_fresh ? 'ok' : 'stale')}</strong></div>
      </div>
      <dl class="details"><div><dt>最后报告</dt><dd>${time(node.last_report_at)}</dd></div>
      <div><dt>可信基线</dt><dd>${escapeHtml(node.baseline_files)} 个文件</dd></div></dl>
    </article>`).join('');
  const roles = Object.entries(identities.roles).map(([name, role]) => `
    <div class="identity-row"><div><strong>${escapeHtml(name)}</strong><small>${escapeHtml(role.identity_count)} 个身份 · ${escapeHtml(role.certificate_not_after ?? '有效期未知')}</small></div>
      <div>${badge(role.rotation_state)} ${badge(role.certificate_state)}</div></div>`).join('');
  const events = status.events.length ? status.events.map(event => `
    <li><span class="event-dot ${tone(event.kind.includes('resumed') ? 'ok' : event.kind.includes('warning') ? 'warning' : 'finding')}"></span>
      <div><strong>${escapeHtml(event.kind)}</strong><p>${escapeHtml(event.node)} · ${escapeHtml(typeof event.details === 'string' ? event.details : JSON.stringify(event.details))}</p></div>
      <time>${time(event.at)}</time></li>`).join('') : '<li class="empty">暂无安全事件</li>';
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="refresh" content="30"><title>APPGOG Cloud Security Center</title><style>
  :root{color-scheme:dark;--bg:#070b14;--panel:#0d1423;--line:#1d2a40;--text:#f4f7fb;--muted:#8fa0b8;--cyan:#38bdf8;--green:#34d399;--amber:#fbbf24;--red:#fb7185}
  *{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% 0,#10233f 0,transparent 34%),var(--bg);color:var(--text);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
  main{width:min(1280px,calc(100% - 32px));margin:auto;padding:36px 0 64px}.top{display:flex;justify-content:space-between;gap:24px;align-items:flex-end;margin-bottom:24px}.brand{display:flex;gap:14px;align-items:center}.logo{width:46px;height:46px;border-radius:14px;display:grid;place-items:center;background:linear-gradient(135deg,#2563eb,#06b6d4);box-shadow:0 16px 40px #0891b233;font-size:22px}.eyebrow{margin:0;color:var(--cyan);font-size:11px;font-weight:800;letter-spacing:.14em;text-transform:uppercase}h1,h2{margin:2px 0 0}h1{font-size:26px}h2{font-size:18px}.stamp{color:var(--muted);text-align:right}.overview{display:grid;grid-template-columns:1.4fr repeat(3,1fr);gap:14px;margin-bottom:14px}.card{background:linear-gradient(180deg,#111a2b,#0b111e);border:1px solid var(--line);border-radius:18px;padding:20px;box-shadow:0 14px 40px #0004}.hero{display:flex;justify-content:space-between;align-items:center}.hero strong{font-size:22px}.stat span,.metric-grid span{display:block;color:var(--muted);font-size:12px}.stat strong{display:block;margin-top:8px;font-size:18px}.node-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}.card-head,.identity-row{display:flex;justify-content:space-between;gap:16px;align-items:center}.badge{display:inline-flex;align-items:center;border:1px solid;padding:4px 9px;border-radius:999px;font-size:11px;font-weight:750;white-space:nowrap}.badge.ok{color:var(--green);border-color:#34d39955;background:#34d39912}.badge.warning{color:var(--amber);border-color:#fbbf2455;background:#fbbf2412}.badge.danger{color:var(--red);border-color:#fb718555;background:#fb718512}.badge.muted{color:var(--muted);background:#64748b12}.metric-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin:20px 0}.metric-grid>div,.details>div{padding:12px;border-radius:12px;background:#070c16;border:1px solid #172239}.metric-grid strong{display:block;margin-top:7px}.details{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:0}.details dt{color:var(--muted);font-size:12px}.details dd{margin:4px 0 0}.lower{display:grid;grid-template-columns:1fr 1.4fr;gap:14px;margin-top:14px}.identity-row{padding:13px 0;border-bottom:1px solid var(--line)}.identity-row:last-child{border:0}.identity-row small{display:block;color:var(--muted);margin-top:3px}.policy{margin-top:16px;padding:13px;border-radius:12px;background:#071321;border:1px solid #164e63;color:#a5f3fc}.events{list-style:none;padding:0;margin:10px 0 0}.events li{display:grid;grid-template-columns:10px 1fr auto;gap:12px;padding:12px 0;border-bottom:1px solid var(--line);align-items:start}.events p{margin:2px 0;color:var(--muted);font-size:12px}.events time{color:var(--muted);font-size:11px}.event-dot{width:8px;height:8px;border-radius:50%;margin-top:6px;background:var(--red)}.event-dot.ok{background:var(--green)}.event-dot.warning{background:var(--amber)}.empty{color:var(--muted)}
  @media(max-width:850px){.overview,.node-grid,.lower{grid-template-columns:1fr}.top{align-items:flex-start;flex-direction:column}.stamp{text-align:left}.overview{grid-template-columns:1fr 1fr}.hero{grid-column:1/-1}}@media(max-width:520px){.overview{grid-template-columns:1fr}.hero{grid-column:auto}.metric-grid,.details{grid-template-columns:1fr}}
  </style></head><body><main><header class="top"><div class="brand"><div class="logo">◈</div><div><p class="eyebrow">Zero Trust Operations</p><h1>APPGOG Cloud Security Center</h1></div></div><div class="stamp">只读监测 · Pull-only 策略<br>${time(status.generated_at)}</div></header>
  <section class="overview"><article class="card hero"><div><p class="eyebrow">总体安全态势</p><strong>${escapeHtml(label(status.summary_state))}</strong></div>${badge(status.summary_state)}</article>
  <article class="card stat"><span>受保护节点</span><strong>${escapeHtml(Object.keys(status.nodes).length)}</strong></article><article class="card stat"><span>待关注事件</span><strong>${escapeHtml(status.events.length)}</strong></article><article class="card stat"><span>策略版本</span><strong>${escapeHtml(policy.version)}</strong></article></section>
  <section class="node-grid">${nodes || '<article class="card empty">尚未注册业务节点</article>'}</section>
  <section class="lower"><article class="card"><div class="card-head"><div><p class="eyebrow">Identity Trust</p><h2>身份与证书</h2></div></div>${roles}<div class="policy">云端无 SSH、Docker Socket 或远程命令能力；处置由业务节点本地执行。</div></article>
  <article class="card"><div class="card-head"><div><p class="eyebrow">Audit Timeline</p><h2>最近安全事件</h2></div></div><ul class="events">${events}</ul></article></section>
  </main></body></html>`;
}
