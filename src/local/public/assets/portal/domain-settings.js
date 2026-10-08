export function createDomainSettings({ state, request, notify }, scope = document) {
  let generation = 0, timer, busy = false, bound = false, running = false, unknown = true;
  const nodes = key => scope.querySelectorAll('[data-domain-' + key + ']');
  const set = (key, value) => nodes(key).forEach(n => { n.textContent = value; });
  function paint(data) {
    running = data.state === 'running';
    unknown = data.state === 'unavailable';
    set('origin', data.origin || (unknown ? '当前域名配置无法读取 · 现有访问入口保留' : '尚未设置 · 当前 IP 入口继续可用'));
    set('status', ({ idle: '请输入已解析到本服务器的域名', running: '正在验证域名并申请证书，请稍候', ready: '域名已启用 · 证书自动续期', failed: '设置未完成 · 原访问入口保留', unavailable: '域名服务未接入' })[data.state] || '状态不可用');
    set('reason', data.reason || '');
    set('certificate', unknown ? '证书状态暂时无法确认' : data.certificate === 'public-ca' ? '已申请公共 CA 证书' : '尚未申请公共 CA 证书');
    nodes('save').forEach(n => { n.disabled = busy || running || unknown || data.state === 'unavailable'; });
    nodes('input').forEach(n => { if (document.activeElement !== n && !n.value) n.value = data.requested_domain || data.domain || ''; });
  }
  function stop() { generation++; clearTimeout(timer); busy = false; running = false; unknown = true; }
  async function refresh(id = generation) {
    const session = state.csrf; if (!session) return;
    try { const data = await request('/api/domain'); if (id !== generation || session !== state.csrf) return; paint(data); }
    catch (e) { if (id !== generation || session !== state.csrf) return; unknown = true; set('origin', '当前域名配置无法读取 · 现有访问入口保留'); set('certificate', '证书状态暂时无法确认'); set('status', '无法确认域名任务状态 · 正在重试'); set('reason', e.message); nodes('save').forEach(n => { n.disabled = true; }); }
    finally { if (id === generation && session === state.csrf) timer = setTimeout(() => refresh(id), (running || unknown) ? 2000 : 60000); }
  }
  function start() { stop(); if (state.csrf) void refresh(generation); }
  async function save(event) {
    event.preventDefault(); if (busy || running || unknown || !state.csrf) return;
    const domain = event.currentTarget.querySelector('[data-domain-input]').value.trim().toLowerCase();
    const id = generation, session = state.csrf; busy = true; nodes('save').forEach(n => { n.disabled = true; });
    try { await request('/api/domain', { method: 'POST', body: { domain } }); if (id === generation && session === state.csrf) notify('域名任务已受理，完成后显示实际访问地址。'); }
    catch (error) { if (id === generation && session === state.csrf) notify(error.message, true); }
    finally { if (id === generation && session === state.csrf) { busy = false; clearTimeout(timer); void refresh(id); } }
  }
  function bind() { if (bound) return; bound = true; nodes('form').forEach(n => n.addEventListener('submit', save)); scope.addEventListener('ironcurtain-session-cleared', stop); }
  return { bind, start, stop };
}
