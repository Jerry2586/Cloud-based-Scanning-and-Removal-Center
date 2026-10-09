import { safeTimestamp } from './host-scan-contract.js';
export function sanitizeEngineUpdate(value) {
  const schema='ironcurtain-engine-update/v1', unavailable={schema,state:'unavailable'};
  if (!value || value.schema!==schema || !['running','finished','failed','paused'].includes(value.state) ||
      typeof value.task_id!=='string' || !/^[a-f0-9]{32}$/.test(value.task_id) ||
      !safeTimestamp(value.started_at) || !safeTimestamp(value.updated_at) || Date.parse(value.updated_at)<Date.parse(value.started_at) ||
      typeof value.detail!=='string' || value.detail.length<1 || value.detail.length>180 || /[\x00-\x1f\x7f]/.test(value.detail)) return unavailable;
  if (value.state==='running' ? value.finished_at!=null : !safeTimestamp(value.finished_at) || Date.parse(value.finished_at)<Date.parse(value.started_at) || Date.parse(value.finished_at)>Date.parse(value.updated_at)) return unavailable;
  return {schema,state:value.state,task_id:value.task_id,started_at:value.started_at,updated_at:value.updated_at,detail:value.detail,
    ...(value.state!=='running'?{finished_at:value.finished_at}:{})};
}
