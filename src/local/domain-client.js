import { request } from 'node:http';
import { readFileSync } from 'node:fs';
import { createSecureContext } from 'node:tls';
import { join } from 'node:path';
export function validDomain(value) {
  return typeof value === 'string' && value.length <= 253 && !/^[0-9.]+$/.test(value) && value.includes('.') && value.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) && /^[a-z]{2,63}$/.test(value.split('.').at(-1));
}
export function domainConfiguration(directory) {
  try {
    const data = JSON.parse(readFileSync(join(directory, 'domain.json'), 'utf8'));
    return data.schema === 1 && validDomain(data.domain) && data.origin === 'https://' + data.domain && typeof data.gateway === 'boolean' && /^[a-f0-9]{64}$/.test(data.generation) ? data : null;
  } catch { return null; }
}
export function domainTls(directory, fallback, originalHost) {
  return { ...fallback, SNICallback(name, callback) {
    try {
      const config = domainConfiguration(directory);
      name = name.toLowerCase();
      if (name === originalHost?.toLowerCase()) return callback(null, createSecureContext(fallback));
      if (!config || name !== config.domain) return callback(Error('未知 TLS 服务器名称')); 
      callback(null, createSecureContext({ cert: readFileSync(join(directory, 'domain-certificates', config.generation, 'cert.pem')), key: readFileSync(join(directory, 'domain-certificates', config.generation, 'key.pem')) }));
    } catch (error) { callback(error); }
  }};
}
export function publicDomainStatus(value) {
  const state = ['idle','running','ready','failed','unavailable'].includes(value?.state) ? value.state : 'unavailable';
  return { state, domain: validDomain(value?.domain) ? value.domain : '', origin: value?.certificate === 'public-ca' && validDomain(value?.domain) ? 'https://' + value.domain : '',
    requested_domain: validDomain(value?.requested_domain) ? value.requested_domain : '',
    reason: typeof value?.reason === 'string' ? value.reason.slice(0, 500) : '域名配置服务未接入',
    updated_at: typeof value?.updated_at === 'string' ? value.updated_at.slice(0, 40) : null,
    certificate: value?.certificate === 'public-ca' ? 'public-ca' : 'not-issued' };
}
export function domainRequest(action = 'status', value = {}, env = process.env) {
  if (!['status', 'save'].includes(action) || (action === 'save' && (!validDomain(value.domain) || Object.keys(value).join(',') !== 'domain'))) return Promise.resolve({ response_status: 400, error: '请输入有效域名，不包含协议、端口或路径' });
  const role = env.IRONCURTAIN_ROLE === 'cloud' ? 'cloud' : 'local';
  const socketPath = '/run/ironcurtain-domain-' + role + '/control.sock';
  if (env.IRONCURTAIN_DOMAIN_SOCKET && env.IRONCURTAIN_DOMAIN_SOCKET !== socketPath) return Promise.resolve({response_status:503,...publicDomainStatus(null)});
  return new Promise(resolve => {
    let done = false; const finish = data => { if (!done) { done = true; resolve(data); } };
    const fail = () => finish({ response_status: 503, ...publicDomainStatus(null) });
    const payload = action === 'save' ? JSON.stringify(value) : '';
    const req = request({ socketPath, path: '/domain', method: action === 'save' ? 'POST' : 'GET', timeout: 5000, headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, res => {
      let bytes = 0; const chunks = [];
      res.on('data', chunk => { bytes += chunk.length; if (bytes > 4096) { fail(); res.destroy(); } else chunks.push(chunk); });
      res.on('error', fail); res.on('aborted', fail);
      res.on('end', () => { try { const data = JSON.parse(Buffer.concat(chunks)); finish({ response_status: res.statusCode, ...publicDomainStatus(data), ...(res.statusCode >= 400 ? { error: data.error || '域名配置任务未受理' } : {}) }); } catch { fail(); } });
    }); req.on('error', fail); req.on('timeout', () => { fail(); req.destroy(); }); req.end(payload);
  });
}

// Only the fixed ACME token directory is public before a domain is activated.
export function domainChallenge(directory, host, url, originalHost) {
  const match = /^\/\.well-known\/acme-challenge\/([A-Za-z0-9_-]{16,128})$/.exec(url);
  if (!match) return null;
  try {
    const active = domainConfiguration(directory);
    const pending = JSON.parse(readFileSync(join(directory, 'domain-pending.json'), 'utf8'));
    const permitted = new Set([originalHost, active?.domain, validDomain(pending.domain) ? pending.domain : null].filter(value => typeof value === 'string').map(value => value.toLowerCase()));
    if (typeof host !== 'string' || !permitted.has(host.toLowerCase())) return null;
    const value = readFileSync(join(directory, 'acme-challenge', '.well-known', 'acme-challenge', match[1]));
    return value.length > 0 && value.length <= 4096 ? value : null;
  } catch { return null; }
}
