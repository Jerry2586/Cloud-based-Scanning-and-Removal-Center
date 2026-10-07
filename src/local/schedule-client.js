import {request as unixRequest} from 'node:http';
import {validateScheduleConfig, sanitizeSchedule, unavailableSchedule} from '../contracts/schedule.js';
const DEADLINE_MS = 5000, MAX_RESPONSE = 16384;
export function localSchedule(action, value, env = process.env) {
  if (!['status', 'save'].includes(action)) throw new TypeError('Unknown schedule action');
  const payload = action === 'save' ? JSON.stringify(validateScheduleConfig(value)) : null;
  const fail = reason => ({...unavailableSchedule(reason), response_status: 503});
  return new Promise(resolve => {
    let settled = false, response;
    const finish = result => {
      if (settled) return;
      settled = true; clearTimeout(deadline); resolve(result);
      response?.destroy(); req.destroy();
    };
    const req = unixRequest({socketPath: env.IRONCURTAIN_SCAN_SOCKET || '/run/ironcurtain/scan.sock', path: '/schedule', method: payload ? 'POST' : 'GET', timeout: DEADLINE_MS, headers: payload ? {'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload)} : {}}, res => {
      response = res; const chunks = []; let size = 0;
      res.on('data', chunk => { size += chunk.length; if (size > MAX_RESPONSE) finish(fail('周期检测响应超过预算')); else chunks.push(chunk); });
      res.on('aborted', () => finish(fail('周期检测响应中断'))); res.on('error', () => finish(fail('周期检测响应中断')));
      res.on('end', () => {
        try {
          const raw = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (res.statusCode === 200) {
            const result = sanitizeSchedule(raw); return finish({...result, response_status: result.state === 'ready' ? 200 : 503});
          }
          if (action === 'save' && [400, 409, 503].includes(res.statusCode) && raw?.state === 'unavailable') return finish({...unavailableSchedule(res.statusCode === 409 ? '配置已变化或检测正在运行，请刷新后再保存' : '本机周期配置无法保存'), response_status: res.statusCode});
          finish(fail('周期检测响应无法核验'));
        } catch { finish(fail('周期检测响应无法核验')); }
      });
    });
    const deadline = setTimeout(() => finish(fail('周期检测响应超时')), DEADLINE_MS);
    deadline.unref();
    req.on('timeout', () => finish(fail('周期检测响应超时'))); req.on('error', () => finish(fail('本机检查代理未接入'))); req.end(payload);
  });
}
