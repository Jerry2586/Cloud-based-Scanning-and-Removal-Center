import { request as unixRequest } from 'node:http';

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

// One fixed local action. The browser never chooses a command or path.
export function localSecurityScan(action, env = process.env) {
  if (!['status', 'scan'].includes(action)) throw new TypeError('Unknown security action');
  const socketPath = env.IRONCURTAIN_SCAN_SOCKET || env.APPGOG_HOST_SCAN_SOCKET || '/run/ironcurtain/scan.sock';
  return new Promise((resolve) => {
    const req = unixRequest({ socketPath, path: action === 'scan' ? '/scan' : '/status',
      method: action === 'scan' ? 'POST' : 'GET', timeout: 5000,
      headers: action === 'scan' ? { 'Content-Length': '0' } : {} }, res => {
      let body = '';
      let byteCount = 0;
      res.setEncoding('utf8');
      res.on('data', chunk => {
        byteCount += Buffer.byteLength(chunk, 'utf8');
        body += chunk;
        if (byteCount > 32768) {
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
              || (res.statusCode === 429 && result?.state === 'unavailable');
          if (!validStatus || !['idle', 'running', 'finished', 'failed', 'unavailable'].includes(result?.state)) {
            resolve({ state: 'unavailable', reason: '本机检查代理返回异常' }); return;
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
          resolve({ state: result.state, history, progress: hostScanProgress(result),
            coverage: result.state === 'finished' ? hostScanCoverage(result) : undefined,
            history_state: historyState, checked_at: safeTimestamp(result.checked_at),
            reason: result.state === 'unavailable' ? '本机检查频率限制或代理异常' : undefined, checks });
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
