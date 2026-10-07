import {SCHEDULE_IDS, sanitizeSchedule, unavailableSchedule, validateScheduleConfig} from '/contracts/schedule.js';
const labels = {idle:'尚未执行',dispatching:'正在启动',running:'检测进行中',complete:'本轮检查已完成',partial:'覆盖不完整',failed:'检测失败',unavailable:'无法核验',deferred:'等待其他任务结束',interrupted:'上次检测已中断'};
export function createScheduleSettings({state, request, notify}) {
  const panel = document.querySelector('[data-schedule-panel]');
  let last = unavailableSchedule(), epoch = 0, pending = null, saving = null, dirty = false, timer = null, bound = false, activeSession = null;
  const field = (id, type) => panel?.querySelector('[data-schedule-' + type + '="' + id + '"]');
  function render(value) {
    last = sanitizeSchedule(value);
    if (!panel) return;
    const ready = last.state === 'ready', busy = ready && SCHEDULE_IDS.some(id => ['running','dispatching'].includes(last.records[id].state));
    panel.querySelector('[data-schedule-state]').textContent = ready ? '本机自动执行 · 配置版本 ' + last.config.revision + (dirty ? ' · 有未保存修改' : '') : '本机周期检测不可用，请检查主机代理';
    for (const id of SCHEDULE_IDS) {
      const enabled = field(id, 'enabled'), interval = field(id, 'interval'), detail = field(id, 'record');
      enabled.disabled = interval.disabled = !ready || busy || Boolean(saving) || Boolean(pending);
      if (ready && !dirty) { enabled.checked = last.config.jobs[id].enabled; interval.value = String(last.config.jobs[id].interval_seconds / 60); }
      const record = ready ? last.records[id] : null;
      detail.textContent = record ? labels[record.state] + ' · ' + (record.next_at ? '下次 ' + new Date(record.next_at).toLocaleString() : last.config.jobs[id].enabled ? '等待本轮结束' : '未启用') + (record.last_finished_at ? ' · 上次结束 ' + new Date(record.last_finished_at).toLocaleString() : '') : '尚未取得可信的检测记录';
    }
    panel.querySelector('[data-schedule-save]').disabled = !ready || busy || Boolean(saving) || Boolean(pending) || !state.csrf;
    panel.querySelector('[data-schedule-refresh]').disabled = saving || pending || !state.csrf;
  }
  const current = operation => operation.session === state.csrf && operation.version === epoch;
  function poll(operation) {
    if (!current(operation)) return;
    clearTimeout(timer);
    timer = setTimeout(() => { if (current(operation)) void refresh(); }, last.state === 'ready' && SCHEDULE_IDS.some(id => ['running','dispatching'].includes(last.records[id].state)) ? 3000 : 15000);
  }
  async function refresh() {
    if (!state.csrf || pending || saving) return;
    clearTimeout(timer); const operation = {session:state.csrf, version:epoch}; pending = operation; render(last);
    try { const value = await request('/api/schedule'); if (current(operation)) render(value); }
    catch { if (current(operation)) render(unavailableSchedule()); }
    finally { if (pending === operation) { pending = null; if (current(operation)) { render(last); poll(operation); } } }
  }
  function reset() {
    epoch++; activeSession = state.csrf; clearTimeout(timer); timer = null;
    pending = saving = null; dirty = false; render(unavailableSchedule());
    if (state.csrf) void refresh();
  }
  function bind() {
    if (bound || !panel) return; bound = true;
    panel.querySelector('form').addEventListener('input', () => { dirty = true; render(last); });
    panel.querySelector('[data-schedule-refresh]').addEventListener('click', () => { dirty = false; void refresh(); });
    panel.querySelector('form').addEventListener('submit', async event => {
      event.preventDefault(); if (saving || pending || !state.csrf || last.state !== 'ready' || SCHEDULE_IDS.some(id => ['running','dispatching'].includes(last.records[id].state))) return;
      let config; try { config = validateScheduleConfig({revision: last.config.revision, jobs: Object.fromEntries(SCHEDULE_IDS.map(id => [id, {enabled:field(id,'enabled').checked, interval_seconds: Number(field(id,'interval').value) * 60}]))}); } catch (error) { notify(error.message, true); return; }
      const operation = {session:state.csrf, version:++epoch}; saving = operation; clearTimeout(timer); render(last);
      try { const value = await request('/api/schedule', {method:'POST',body:config}); if (current(operation)) { const clean = sanitizeSchedule(value); if (clean.state !== 'ready') throw Error('保存结果无法核验'); dirty = false; render(clean); notify('周期检测配置已保存到本机'); } }
      catch (error) { if (current(operation)) notify(error.message, true); }
      finally { if (saving === operation) { saving = null; if (current(operation)) { render(last); void refresh(); } } }
    });
    document.addEventListener('ironcurtain-session-cleared', reset);
  }
  return Object.freeze({bind, start() { if (activeSession !== state.csrf) reset(); }});
}
