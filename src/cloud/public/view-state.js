/** Preserve reading and keyboard context while replacing server-backed cards. */
export function replaceKeyedItems(target, items, render, emptyText) {
  const opened = new Set([...target.querySelectorAll('details[open]')].map(el => el.dataset.itemKey));
  const active = target.ownerDocument.activeElement;
  const focusedItem = target.contains(active) ? active.closest('[data-item-key]') : null;
  const focus = focusedItem && { key: focusedItem.dataset.itemKey, tag: active.tagName, action: active.dataset.action };
  const cards = items.map(([key, value]) => {
    const card = render(value, key);
    card.dataset.itemKey = key;
    const details = card.tagName === 'DETAILS' ? card : card.querySelector('details');
    if (details) { details.dataset.itemKey = key; details.open = opened.has(key); }
    return card;
  });
  if (!cards.length) {
    const message = target.ownerDocument.createElement('p');
    message.className = 'empty'; message.textContent = emptyText;
    cards.push(message);
  }
  target.replaceChildren(...cards);
  if (focus) {
    const card = cards.find(el => el.dataset.itemKey === focus.key);
    const control = card && [...card.querySelectorAll('summary, button')].find(el => el.tagName === focus.tag && el.dataset.action === focus.action && !el.disabled);
    control?.focus({ preventScroll: true });
  }
}

/** Connection, freshness and scan coverage are separate facts. */
export function nodeDiagnostics(node) {
  const counts = node.host_scan?.counts;
  const rows = [
    ['节点身份', node.certificate_state || 'unknown', '证书有效期：' + (node.certificate_not_after || '尚无记录')],
    ['认证上报', node.report_fresh ? 'ok' : node.last_report_at ? 'stale' : 'unavailable', node.last_report_at || '等待本机代理首次上报'],
    ['公网健康探测', node.probe?.state || 'unknown', node.probe?.checked_at || node.probe?.at || '尚无探测记录'],
    ['文件完整性', node.baseline_files > 0 ? node.integrity?.state || 'unknown' : 'missing', node.baseline_files > 0 ? '可信基线 ' + node.baseline_files + ' 个文件' : '尚无可信文件基线，当前无法判断文件是否被修改'],
    ['宿主环境检查', node.host_scan?.state || 'unavailable', counts ? '正常 ' + counts.ok + ' · 提醒 ' + counts.warning + ' · 风险 ' + counts.finding + ' · 未完成 ' + counts.unavailable : '尚无可用检查报告'],
  ];
  const guidance = [];
  if (!node.report_fresh) guidance.push('在铁幕检查代理、网络与节点身份，恢复认证上报。');
  if (!node.baseline_files) guidance.push('在铁幕纳管保护目录，并通过可信发布建立文件基线。');
  if (!counts || counts.unavailable) guidance.push('在铁幕查看环境检查逐项报告，补齐缺失的检测能力和保护范围。');
  if (node.certificate_state !== 'healthy') guidance.push('检查节点证书有效期，按管理菜单提示修复或轮换身份。');
  if (!guidance.length) guidance.push(node.recommended_action || '保持本机代理运行并定期核实检测报告。');
  return { rows, guidance };
}

/** Audit operation success does not imply that detection coverage is complete. */
export function auditPresentation(action) {
  const known = {
    'job.enqueue': ['检测任务已受理', 'queued'],
    'job.start': ['检测任务开始执行', 'running'],
    'job.recovered': ['中断任务已重新排队', 'queued'],
    'job.complete': ['检测任务完成', 'complete'],
    'job.partial': ['检测任务证据不足', 'partial'],
    'job.failed': ['检测任务执行失败', 'failed'],
    'policy.update': ['裁决策略已保存', 'complete'],
    'plugin.install': ['检测能力已安装', 'complete'],
    'plugin.enable': ['检测能力已启用', 'complete'],
    'plugin.pause': ['检测能力已暂停', 'idle'],
    'plugin.remove': ['检测能力已移除', 'complete'],
  };
  return known[action] || [action || '未知操作', 'unknown'];
}
