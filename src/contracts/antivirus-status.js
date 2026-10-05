import { safeTimestamp } from './host-scan-contract.js';
export function sanitizeAntivirus(value) {
  const unavailable = { engine: 'ClamAV', installed: null, state: 'unavailable', updater: 'unknown', detail: '病毒引擎状态不可用' };
  if (!value || value.engine !== 'ClamAV' || typeof value.installed !== 'boolean' ||
      !['unavailable','configured','stale'].includes(value.state) || !['scheduled','disabled','failed','unknown'].includes(value.updater) ||
      typeof value.detail !== 'string' || value.detail.length > 180 ||
      value.version !== undefined && value.version !== null && (typeof value.version !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9.-]{1,32})?$/.test(value.version)) ||
      value.update_state !== undefined && !['idle','running','failed','unavailable'].includes(value.update_state) ||
      value.source !== undefined && !['official-direct','xuanwu-signed','unknown'].includes(value.source)) return unavailable;
  if (value.state !== 'unavailable' && (!value.installed || !safeTimestamp(value.database_at) ||
      !Number.isSafeInteger(value.database_version) || value.database_version <= 0 ||
      !Number.isSafeInteger(value.signatures) || value.signatures <= 0)) return unavailable;
  return {engine:'ClamAV', installed:value.installed, state:value.state, updater:value.updater, detail:value.detail, version:value.version ?? null, update_state:value.update_state ?? 'unavailable',
    ...(value.source !== undefined ? {source:value.source} : {}),
    ...(value.state !== 'unavailable' ? {database_at:value.database_at, database_version:value.database_version, signatures:value.signatures} : {})};
}


export function describeAntivirus(value) {
  const engine=sanitizeAntivirus(value);
  const official=engine.source==='official-direct';
  return {...engine, title:engine.installed===null?'本机病毒引擎尚不可核验':!engine.installed?'本机病毒引擎未安装':engine.state==='configured'?'本机引擎与病毒库已配置':engine.state==='stale'?'病毒库已过期':'本机病毒库尚未就绪',
    source_label:official?'官方直接更新 · 无需玄武':engine.source==='xuanwu-signed'?'玄武签名病毒库':'更新来源尚不可核验',
    updater_label:{scheduled:'官方定时更新已启用',disabled:'官方定时更新未启用',failed:'上次官方更新失败',unknown:'定时更新状态不可用'}[engine.updater],
    update_label:official?{running:'官方病毒库更新中',failed:'官方更新失败 · 保留已有病毒库',idle:'官方更新器待命',unavailable:'官方更新器尚未配置'}[engine.update_state]:engine.source==='xuanwu-signed'?'当前来源不使用官方直接更新器':'官方更新器状态尚不可核验',
    can_update:official && engine.installed && ['idle','failed'].includes(engine.update_state)};
}
