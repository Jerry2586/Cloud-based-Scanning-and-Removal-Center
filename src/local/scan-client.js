import { sanitizeEngineUpdate } from '../contracts/engine-update-status.js';
import { sanitizeAntivirus } from '../contracts/antivirus-status.js';
export { sanitizeAntivirus } from '../contracts/antivirus-status.js';
import { sanitizeCheckup } from '../contracts/checkup-status.js';
import { request as unixRequest } from 'node:http';
import { sanitizeProtection, sanitizeInventory, sanitizeFullScan } from '../contracts/protection-status.js';
import { sanitizeRules, sanitizeRuleHits } from '../contracts/rule-status.js';

import { HOST_SCAN_IDS, CHECK_CATEGORIES, CHECK_SEVERITIES, CHECK_STATES, safeTimestamp, completeHostScan, hostScanCoverage, hostScanProgress } from '../contracts/host-scan-contract.js';

function sanitizeCheck(item) {
  if (!item || typeof item.name !== 'string' || typeof item.detail !== 'string' || !CHECK_STATES.has(item.state)) return null;
  const result = {
    name: item.name.slice(0, 60),
    state: item.state,
    detail: item.detail.slice(0, 180),
  };
  if (typeof item.id === 'string' && /^[a-z0-9][a-z0-9._-]{0,79}$/.test(item.id)) result.id = item.id;
  if (typeof item.category === 'string' && item.category.length <= 32 && CHECK_CATEGORIES.has(item.category)) result.category = item.category;
  if (typeof item.severity === 'string' && CHECK_SEVERITIES.has(item.severity)) result.severity = item.severity;
  const checkedAt = safeTimestamp(item.checked_at);
  if (checkedAt !== null) result.checked_at = checkedAt;
  if (typeof item.scope === 'string' && item.scope.length <= 120) result.scope = item.scope;
  if (typeof item.evidence_digest === 'string' && /^[a-f0-9]{64}$/.test(item.evidence_digest)) result.evidence_digest = item.evidence_digest;
  return result;
}



export function sanitizeFindings(value) {
  const unavailable = {findings: [], findings_state: 'unavailable', findings_total: 0};
  if (!value || !Array.isArray(value.findings) || value.findings.length > 8 ||
      !['complete','partial','unavailable'].includes(value.findings_state) ||
      !Number.isSafeInteger(value.findings_total) || value.findings_total < value.findings.length || value.findings_total > 200000) return unavailable;
  const items = [];
  for (const item of value.findings) {
    if (!item || !/^[a-f0-9]{64}$/.test(item.id) || !/^[a-f0-9]{64}$/.test(item.sha256) ||
        typeof item.path !== 'string' || item.path.length > 1024 || !item.path.startsWith('/') || /[\x00-\x1f\x7f]/.test(item.path) ||
        item.path.split('/').includes('..') || typeof item.signature !== 'string' || !/^[A-Za-z0-9_.:/()!+\-]{1,160}$/.test(item.signature) ||
        !safeTimestamp(item.observed_at) || !Number.isSafeInteger(item.size) || item.size < 0 || item.size > 67108864) return unavailable;
    items.push({id:item.id, path:item.path, signature:item.signature, sha256:item.sha256, size:item.size, observed_at:item.observed_at});
  }
  if (new Set(items.map(item=>item.id)).size !== items.length) return unavailable;
  return {findings:items, findings_state:value.findings_state, findings_total:value.findings_total};
}


export function sanitizeQuarantine(value) {
  const unavailable={state:'unavailable',items:[],count:0,pending:0};
  if(!value || value.state==='unavailable' || !['empty','recorded'].includes(value.state) || !Array.isArray(value.items) || value.items.length>8 || !Number.isInteger(value.count) || value.count<value.items.length || value.count>128 || !Number.isInteger(value.pending) || value.pending<0 || value.pending>value.count) return unavailable;
  const items=[];
  for(const item of value.items) {
    if(!item || !/^[a-f0-9]{64}$/.test(item.id) || typeof item.path!=='string' || !item.path.startsWith('/') || item.path.length>1024 || /[\x00-\x1f\x7f]/.test(item.path) || item.path.split('/').includes('..') || typeof item.signature!=='string' || !/^[A-Za-z0-9_.:/()!+\-]{1,160}$/.test(item.signature) || !['preparing','captured','quarantined','restoring','restored'].includes(item.state) || !Number.isInteger(item.size) || item.size<0 || item.size>67108864) return unavailable;
    items.push({id:item.id,path:item.path,signature:item.signature,state:item.state,size:item.size});
  }
  if(new Set(items.map(x=>x.id)).size!==items.length) return unavailable;
  if(value.state==='recorded' && value.count===0) return unavailable;
  if(value.state==='empty' && (value.count || value.pending || items.length)) return unavailable;
  return {state:value.state,items,count:value.count,pending:value.pending};
}

// One fixed local action. The browser never chooses a command or path.
export function localSecurityScan(action, env = process.env) {
  if (!['status', 'scan', 'full-scan', 'checkup', 'engine-update'].includes(action)) throw new TypeError('Unknown security action');
  const socketPath = env.IRONCURTAIN_SCAN_SOCKET || env.APPGOG_HOST_SCAN_SOCKET || '/run/ironcurtain/scan.sock';
  return new Promise((resolve) => {
    const req = unixRequest({ socketPath, path: action === 'status' ? '/status' : '/' + action,
      method: action === 'status' ? 'GET' : 'POST', timeout: 5000,
      headers: action === 'status' ? {} : { 'Content-Length': '0' } }, res => {
      let body = '';
      let byteCount = 0;
      res.setEncoding('utf8');
      res.on('data', chunk => {
        byteCount += Buffer.byteLength(chunk, 'utf8');
        body += chunk;
        if (byteCount > 65536) {
          resolve({ state: 'unavailable', reason: '本机检查代理响应超出限制' });
          res.destroy();
          req.destroy();
        }
      });
      res.on('error', () => resolve({ state: 'unavailable', reason: '本机检查代理响应中断' }));
      res.on('aborted', () => resolve({ state: 'unavailable', reason: '本机检查代理响应中断' }));
      res.on('end', () => {
        try {
          const result = JSON.parse(body);
          const validStatus = action === 'status' ? res.statusCode === 200
            : ([202, 409].includes(res.statusCode) && result?.state === 'running')
              || ([409, 429, 503].includes(res.statusCode) && result?.state === 'unavailable');
          if (!validStatus || !['idle', 'running', 'finished', 'failed', 'unavailable'].includes(result?.state)) {
            resolve({ state: 'unavailable', reason: '本机检查代理返回异常' }); return;
          }
          if (action==='engine-update' && res.statusCode===202 && !/^[a-f0-9]{32}$/.test(result.task_id || '')) {
            resolve({state:'unavailable', reason:'未取得有效更新任务确认'}); return;
          }
          const checks = Array.isArray(result.checks) ? result.checks.slice(0, HOST_SCAN_IDS.length + 1).map(sanitizeCheck).filter(Boolean) : [];
          const history = Array.isArray(result.history) ? result.history.slice(-8).map(item => {
            const clean = sanitizeCheck(item);
            if (!clean || !clean.id || !clean.evidence_digest || !clean.checked_at) return null;
            return { ...clean, previous_state: CHECK_STATES.has(item.previous_state) ? item.previous_state : null };
          }).filter(Boolean) : [];
          if (result.state === 'finished' && (!completeHostScan(result) || checks.length !== result.checks.length)) {
            resolve({ state: 'unavailable', reason: '本机检查报告缺失或不完整' }); return;
          }
          const invalidHistory = !Array.isArray(result.history) || history.length !== Math.min(8, result.history.length);
          const historyState = invalidHistory || result.history_state === 'unavailable' ? 'unavailable' : result.history.length > 8 ? 'truncated'
            : ['ok', 'unavailable', 'truncated'].includes(result.history_state) ? result.history_state : 'unavailable';
          resolve({ state: result.state, task_id:typeof result.task_id==='string' && /^[a-f0-9]{32}$/.test(result.task_id)?result.task_id:undefined, started_at:safeTimestamp(result.started_at), profile_digest:/^[a-f0-9]{64}$/.test(result.profile_digest || '')?result.profile_digest:undefined, response_status: res.statusCode, checkup: sanitizeCheckup(result.checkup), inventory: sanitizeInventory(result.inventory), protection: sanitizeProtection(result.protection), full_scan: sanitizeFullScan(result.full_scan), findings_source: ['quick','full','multi'].includes(result.findings_source) ? result.findings_source : 'unknown', ...sanitizeFindings(result), antivirus: sanitizeAntivirus(result.antivirus), engine_update: sanitizeEngineUpdate(result.engine_update), rules: sanitizeRules(result.rules), rule_hits: sanitizeRuleHits(result.rule_hits), quarantine: sanitizeQuarantine(result.quarantine), history, progress: hostScanProgress(result),
            coverage: result.state === 'finished' ? hostScanCoverage(result) : undefined,
            history_state: historyState, checked_at: safeTimestamp(result.checked_at),
            reason: result.state === 'unavailable' ? ({409:['management operation active','maintenance active'].includes(result.reason)?'本机维护正在进行，请稍后重试':'已有扫描正在进行，请等待当前任务',429:'扫描请求过于频繁，请稍后重试',503:action==='engine-update'?'官方更新器不可用；请核对本机引擎安装和病毒库来源':'本机任务无法启动；请核对保护范围、引擎与代理日志'}[res.statusCode] || '本机检查代理异常') : undefined, checks });
        } catch {
          resolve({ state: 'unavailable', reason: '本机检查代理响应无效' });
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', () => resolve({ state: 'unavailable', reason: '本机检查代理未接入或超时' }));
    req.end();
  });
}

// A fixed digest-only outbound snapshot, never a browser-controlled path.
export function localCloudSnapshot(env = process.env) {
  return new Promise(resolve => {
    const req=unixRequest({socketPath:env.IRONCURTAIN_SCAN_SOCKET || '/run/ironcurtain/scan.sock',path:'/report',method:'GET',timeout:5000},res=>{
      const chunks=[];let length=0;
      res.on('data',chunk=>{length+=chunk.length;if(length>262144){res.destroy();req.destroy();resolve(null);}else chunks.push(chunk);});
      res.on('error',()=>resolve(null));res.on('aborted',()=>resolve(null));
      res.on('end',()=>{try{const data=JSON.parse(Buffer.concat(chunks));resolve(res.statusCode===200 && completeHostScan(data.scan) ? data : null);}catch{resolve(null);}});
    }); req.on('timeout',()=>req.destroy());req.on('error',()=>resolve(null));req.end();
  });
}
