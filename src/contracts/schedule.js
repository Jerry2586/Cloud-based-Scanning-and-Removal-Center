export const SCHEDULE_IDS = Object.freeze(['quick', 'files', 'engines']);
export const SCHEDULE_LIMITS = Object.freeze({quick: [300, 86400], files: [3600, 604800], engines: [1800, 604800]});
const states = new Set(['idle', 'dispatching', 'running', 'complete', 'partial', 'failed', 'unavailable', 'deferred', 'interrupted']);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, keys) => object(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const timestamp = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0, 19) + 'Z' === value;
export function validateScheduleConfig(value) {
  if (!exact(value, ['revision', 'jobs']) || !Number.isInteger(value.revision) || value.revision < 1 || value.revision > 1000000000 || !exact(value.jobs, SCHEDULE_IDS)) throw new TypeError('周期配置无效');
  const jobs = {};
  for (const id of SCHEDULE_IDS) {
    const job = value.jobs[id], [low, high] = SCHEDULE_LIMITS[id];
    if (!exact(job, ['enabled', 'interval_seconds']) || typeof job.enabled !== 'boolean' || !Number.isInteger(job.interval_seconds) || job.interval_seconds < low || job.interval_seconds > high) throw new TypeError('检测周期超出支持范围');
    jobs[id] = {enabled: job.enabled, interval_seconds: job.interval_seconds};
  }
  return {revision: value.revision, jobs};
}
export function unavailableSchedule(reason = '本机周期检测无法核验') {
  return {schema: 'ironcurtain-schedule/v1', state: 'unavailable', reason};
}
export function sanitizeSchedule(value) {
  const fail = () => unavailableSchedule();
  if (!exact(value, ['schema', 'state', 'config', 'records']) || value.schema !== 'ironcurtain-schedule/v1' || value.state !== 'ready' || !exact(value.records, SCHEDULE_IDS)) return fail();
  let config;
  try { config = validateScheduleConfig(value.config); } catch { return fail(); }
  const records = {};
  for (const id of SCHEDULE_IDS) {
    const record = value.records[id], fields = ['next_at', 'last_attempt_at', 'last_started_at', 'last_finished_at'];
    if (!exact(record, ['state', 'task_id', 'attempts', ...fields]) || !states.has(record.state) || !Number.isInteger(record.attempts) || record.attempts < 0 || record.attempts > 1000000000) return fail();
    if (record.task_id !== null && !(typeof record.task_id === 'string' && new RegExp('^[a-f0-9]{' + (id === 'engines' ? 64 : 32) + '}$').test(record.task_id))) return fail();
    if (fields.some(field => record[field] !== null && !timestamp(record[field]))) return fail();
    const {state, task_id: task, attempts, next_at: next, last_attempt_at: attempt, last_started_at: started, last_finished_at: finished} = record;
    if (state === 'idle') {
      if (task !== null || attempts !== 0 || attempt !== null || started !== null || finished !== null) return fail();
    } else {
      if (attempts < 1 || attempt === null || (task === null) !== (started === null) || (started !== null && started !== attempt)) return fail();
      if (['dispatching','running'].includes(state)) {
        if (finished !== null || next !== null || (state === 'running') !== (task !== null)) return fail();
      } else if (finished === null || finished < attempt) return fail();
      if (['complete','partial','failed'].includes(state) && task === null) return fail();
      if (state === 'deferred' && task !== null) return fail();
    }
    if (!config.jobs[id].enabled && record.next_at !== null) return fail();
    records[id] = {state: record.state, task_id: record.task_id, attempts: record.attempts, ...Object.fromEntries(fields.map(field => [field, record[field]]))};
  }
  return {schema: value.schema, state: 'ready', config, records};
}
