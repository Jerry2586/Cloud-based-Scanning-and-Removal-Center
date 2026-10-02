const escapeHtml = value => String(value ?? '')
  .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;').replaceAll("'", '&#39;');

const labels = {
  ok: '正常', warning: '警告', finding: '发现风险', unavailable: '不可用', stale: '数据过期',
  healthy: '在线', unreachable: '无法连接', unhealthy: '异常', unknown: '未知', unconfigured: '未配置',
  matched: '完整', changed: '已篡改', active: '正常', staged: '轮换中', expiring: '即将过期', expired: '已过期',
  'not-enrolled': '未注册', partial: '部分注册', ready: '身份已就绪', 'identity-created': '身份已创建',
  'waiting-first-report': '等待首次上报', connected: '已认证连接', 'attention-required': '需要处理',
  'license-center': '授权中心', 'build-center': '打包中心',
};
const label = value => labels[value] ?? String(value ?? '未知');
const tone = value => ['ok', 'healthy', 'matched', 'active', 'connected', 'ready', 'identity-created'].includes(value) ? 'ok'
  : ['warning', 'staged', 'expiring', 'stale', 'partial', 'waiting-first-report'].includes(value) ? 'warning'
    : ['finding', 'changed', 'expired', 'attention-required'].includes(value) ? 'danger' : 'muted';
const badge = value => `<span class="badge ${tone(value)}">${escapeHtml(label(value))}</span>`;
const time = value => value ? escapeHtml(value) : '—';

export function renderDashboard({ status, identities, policy }) {
  const requiredRoles = status.deployment?.required_roles ?? ['license-center', 'build-center'];
  const nodes = requiredRoles.map(name => {
    const node = status.nodes[name];
    if (!node) return `
    <article class="card node-card pending">
      <div class="card-head"><div><p class="eyebrow">受保护节点</p><h2>${escapeHtml(label(name))}</h2></div>${badge('not-enrolled')}</div>
      <div class="empty-state"><strong>等待在 Linux 管理菜单中注册</strong><p>准备可信基线和 HTTPS 健康地址，由 root 创建专属 mTLS 身份。</p></div>
    </article>`;
    return `
    <article class="card node-card">
      <div class="card-head"><div><p class="eyebrow">受保护节点</p><h2>${escapeHtml(label(name))}</h2></div>${badge(node.pairing_state)}</div>
      <div class="metric-grid">
        <div><span>公网探测</span><strong>${badge(node.probe.state)}</strong></div>
        <div><span>文件完整性</span><strong>${badge(node.integrity.state)}</strong></div>
        <div><span>宿主环境</span><strong>${badge(node.host_scan.state)}</strong></div>
        <div><span>报告新鲜度</span><strong>${badge(node.report_fresh ? 'ok' : 'stale')}</strong></div>
      </div>
      <dl class="details"><div><dt>最后报告</dt><dd>${time(node.last_report_at)}</dd></div>
      <div><dt>可信基线</dt><dd>${escapeHtml(node.baseline_files)} 个文件</dd></div>
      <div><dt>客户端证书</dt><dd>${badge(node.certificate_state)}</dd></div>
      <div><dt>证书到期</dt><dd>${time(node.certificate_not_after)}</dd></div></dl>
      <div class="next"><span>建议操作</span><p>${escapeHtml(node.recommended_action)}</p></div>
    </article>`;
  }).join('');
  const roles = Object.entries(identities.roles).map(([name, role]) => `
    <div class="identity-row"><div><strong>${escapeHtml(label(name))}</strong><small>${escapeHtml(role.identity_count)} 个身份 · ${escapeHtml(role.certificate_not_after ?? '有效期未知')}</small></div>
      <div>${badge(role.rotation_state)} ${badge(role.certificate_state)}</div></div>`).join('');
  const events = status.events.length ? status.events.map(event => `
    <li><span class="event-dot ${tone(event.kind.includes('resumed') ? 'ok' : event.kind.includes('warning') ? 'warning' : 'finding')}"></span>
      <div><strong>${escapeHtml(event.kind)}</strong><p>${escapeHtml(event.node)} · ${escapeHtml(typeof event.details === 'string' ? event.details : JSON.stringify(event.details))}</p></div>
      <time>${time(event.at)}</time></li>`).join('') : '<li class="empty">暂无安全事件</li>';
  const configured = new Set(status.deployment?.configured_roles ?? []);
  const connected = new Set(status.deployment?.connected_roles ?? []);
  const licenseConfigured = configured.has('license-center');
  const buildConfigured = configured.has('build-center');
  const identitiesReady = licenseConfigured && buildConfigured;
  const fullyConnected = connected.has('license-center') && connected.has('build-center');
  const guideSteps = [
    { done: true, title: '云端服务已安装', detail: '安全中心正在运行，网页只读监测可用。' },
    { done: licenseConfigured, title: '授权中心已注册', detail: '已创建授权中心专属证书与令牌。' },
    { done: buildConfigured, title: '打包中心已注册', detail: '已创建打包中心专属证书与令牌。' },
    { done: identitiesReady, title: '业务身份已准备', detail: '把 Linux 向导导出的身份包安全部署到对应业务服务器。' },
    { done: fullyConnected, title: '监测连接已完成', detail: '两个业务角色均已通过 mTLS 认证并开始上报。' },
  ];
  const firstPending = guideSteps.findIndex(step => !step.done);
  const guide = guideSteps.map((step, index) => {
    const current = index === firstPending;
    return `<li class="guide-step ${step.done ? 'done' : current ? 'current' : ''}"><span>${step.done ? '✓' : index + 1}</span><div><strong>${escapeHtml(step.title)}</strong><p>${escapeHtml(step.detail)}</p></div><em>${step.done ? '已完成' : current ? '当前步骤' : '待完成'}</em></li>`;
  }).join('');
  const nextAction = !licenseConfigured
    ? '在安全服务器运行 sudo appgog-security，选择 1“首次配置向导”。'
    : !buildConfigured
      ? '继续在 Linux 管理菜单中注册打包中心；不要覆盖已有授权身份。'
      : !fullyConnected
        ? '把向导生成的身份包导入业务服务器，启动本地上报代理后刷新本页。'
        : '首次对接已完成。现在可定期检查告警、备份和签名更新。';
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="refresh" content="30"><title>APPGOG 云端安全监测中心</title><style>
  :root{color-scheme:dark;--bg:#070b14;--panel:#0d1423;--line:#1d2a40;--text:#f4f7fb;--muted:#8fa0b8;--cyan:#38bdf8;--green:#34d399;--amber:#fbbf24;--red:#fb7185}
  *{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% 0,#10233f 0,transparent 34%),var(--bg);color:var(--text);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
  main{width:min(1320px,calc(100% - 32px));margin:auto;padding:36px 0 64px}.top{display:flex;justify-content:space-between;gap:24px;align-items:flex-end;margin-bottom:24px}.brand{display:flex;gap:14px;align-items:center}.logo{width:46px;height:46px;border-radius:14px;display:grid;place-items:center;background:linear-gradient(135deg,#2563eb,#06b6d4);box-shadow:0 16px 40px #0891b233;font-size:22px}.eyebrow{margin:0;color:var(--cyan);font-size:11px;font-weight:800;letter-spacing:.14em;text-transform:uppercase}h1,h2{margin:2px 0 0}h1{font-size:26px}h2{font-size:18px}.stamp{color:var(--muted);text-align:right}.overview{display:grid;grid-template-columns:1.4fr repeat(3,1fr);gap:14px;margin-bottom:14px}.card{background:linear-gradient(180deg,#111a2b,#0b111e);border:1px solid var(--line);border-radius:18px;padding:20px;box-shadow:0 14px 40px #0004}.hero{display:flex;justify-content:space-between;align-items:center}.hero strong{font-size:22px}.stat span,.metric-grid span,.next span{display:block;color:var(--muted);font-size:12px}.stat strong{display:block;margin-top:8px;font-size:18px}.topology{margin-bottom:14px}.topology-head,.card-head,.identity-row{display:flex;justify-content:space-between;gap:16px;align-items:center}.flow{display:grid;grid-template-columns:1fr auto 1fr auto 1fr;gap:12px;align-items:center;margin-top:18px}.flow-card{padding:15px;border-radius:14px;background:#070c16;border:1px solid #1d3555}.flow-card strong{display:block}.flow-card small{display:block;color:var(--muted);margin-top:4px}.arrow{color:var(--cyan);font-size:20px}.mode-note{margin-top:14px;color:#b8c7db}.node-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}.badge{display:inline-flex;align-items:center;border:1px solid;padding:4px 9px;border-radius:999px;font-size:11px;font-weight:750;white-space:nowrap}.badge.ok{color:var(--green);border-color:#34d39955;background:#34d39912}.badge.warning{color:var(--amber);border-color:#fbbf2455;background:#fbbf2412}.badge.danger{color:var(--red);border-color:#fb718555;background:#fb718512}.badge.muted{color:var(--muted);background:#64748b12}.metric-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin:20px 0}.metric-grid>div,.details>div{padding:12px;border-radius:12px;background:#070c16;border:1px solid #172239}.metric-grid strong{display:block;margin-top:7px}.details{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:0}.details dt{color:var(--muted);font-size:12px}.details dd{margin:4px 0 0}.next{margin-top:12px;padding:12px;border-radius:12px;background:#0b1b30;border:1px solid #1e3a5f}.next p{margin:4px 0 0}.empty-state{min-height:275px;display:grid;place-content:center;text-align:center;color:var(--muted);padding:20px}.empty-state strong{color:var(--text)}.empty-state p{max-width:360px}.lower{display:grid;grid-template-columns:1fr 1.4fr;gap:14px;margin-top:14px}.identity-row{padding:13px 0;border-bottom:1px solid var(--line)}.identity-row:last-child{border:0}.identity-row small{display:block;color:var(--muted);margin-top:3px}.policy{margin-top:16px;padding:13px;border-radius:12px;background:#071321;border:1px solid #164e63;color:#a5f3fc}.events{list-style:none;padding:0;margin:10px 0 0}.events li{display:grid;grid-template-columns:10px 1fr auto;gap:12px;padding:12px 0;border-bottom:1px solid var(--line);align-items:start}.events p{margin:2px 0;color:var(--muted);font-size:12px}.events time{color:var(--muted);font-size:11px}.event-dot{width:8px;height:8px;border-radius:50%;margin-top:6px;background:var(--red)}.event-dot.ok{background:var(--green)}.event-dot.warning{background:var(--amber)}.empty{color:var(--muted)}
  @media(max-width:850px){.overview,.node-grid,.lower{grid-template-columns:1fr}.top{align-items:flex-start;flex-direction:column}.stamp{text-align:left}.overview{grid-template-columns:1fr 1fr}.hero{grid-column:1/-1}.flow{grid-template-columns:1fr}.arrow{transform:rotate(90deg);text-align:center}}@media(max-width:520px){.overview{grid-template-columns:1fr}.hero{grid-column:auto}.metric-grid,.details{grid-template-columns:1fr}}
  .quick-start{margin:14px 0}.guide-list{list-style:none;padding:0;margin:16px 0 0;display:grid;gap:9px}.guide-step{display:grid;grid-template-columns:34px 1fr auto;gap:12px;align-items:center;padding:12px;border:1px solid var(--line);border-radius:12px;background:#080e19}.guide-step>span{display:grid;place-items:center;width:30px;height:30px;border-radius:50%;background:#172239;color:var(--muted);font-weight:800}.guide-step p{margin:2px 0 0;color:var(--muted);font-size:12px}.guide-step em{font-style:normal;color:var(--muted);font-size:12px}.guide-step.done{border-color:#14532d}.guide-step.done>span{background:#14532d;color:var(--green)}.guide-step.current{border-color:#0369a1;background:#071b2c}.guide-step.current>span{background:#075985;color:#bae6fd}.guide-step.current em{color:var(--cyan)}.guide-next{margin-top:12px;padding:12px;border-radius:12px;background:#10233f;border:1px solid #1d4ed8}.guide-next strong{display:block;margin-bottom:4px}
  </style></head><body><main><header class="top"><div class="brand"><div class="logo">◈</div><div><p class="eyebrow">Zero Trust Operations</p><h1>APPGOG 云端安全监测中心</h1></div></div><div class="stamp">只读监测 · Pull-only · 30 秒刷新<br>${time(status.generated_at)}</div></header>
  <section class="overview"><article class="card hero"><div><p class="eyebrow">总体安全态势</p><strong>${escapeHtml(label(status.summary_state))}</strong></div>${badge(status.summary_state)}</article>
  <article class="card stat"><span>已注册节点</span><strong>${escapeHtml(status.deployment?.configured_roles?.length ?? Object.keys(status.nodes).length)} / 2</strong></article><article class="card stat"><span>已认证连接</span><strong>${escapeHtml(status.deployment?.connected_roles?.length ?? 0)} / 2</strong></article><article class="card stat"><span>策略版本</span><strong>${escapeHtml(policy.version)}</strong></article></section>
  <section class="card topology"><div class="topology-head"><div><p class="eyebrow">Deployment Topology</p><h2>业务节点安全对接</h2></div>${badge(status.deployment?.state ?? 'not-enrolled')}</div>
  <div class="flow"><div class="flow-card"><strong>授权中心</strong><small>专属证书与令牌 · 本地上报</small></div><div class="arrow">⇄</div><div class="flow-card"><strong>云端安全中心</strong><small>公网探测 · 完整性比对 · 审计</small></div><div class="arrow">⇄</div><div class="flow-card"><strong>打包中心</strong><small>专属证书与令牌 · 本地上报</small></div></div>
  <div class="mode-note">支持两种拓扑：授权与打包同机部署（双机总架构），或授权、打包分别部署（三机总架构）。两种方式都使用独立身份，云端不能主动登录业务服务器。</div></section>
  <section class="card quick-start"><div class="card-head"><div><p class="eyebrow">Quick Start</p><h2>首次对接进度</h2></div>${badge(fullyConnected ? 'ready' : 'partial')}</div><ol class="guide-list">${guide}</ol><div class="guide-next"><strong>现在只做这一件事</strong>${escapeHtml(nextAction)}</div></section>
  <section class="node-grid">${nodes}</section>
  <section class="lower"><article class="card"><div class="card-head"><div><p class="eyebrow">Identity Trust</p><h2>身份与证书</h2></div></div>${roles}<div class="policy">云端无 SSH、Docker Socket 或远程命令能力；处置由业务节点本地执行。</div></article>
  <article class="card"><div class="card-head"><div><p class="eyebrow">Audit Timeline</p><h2>最近安全事件</h2></div></div><ul class="events">${events}</ul></article></section>
  </main></body></html>`;
}
