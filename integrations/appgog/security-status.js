import { request as httpsRequest } from 'node:https';
import { readFileSync } from 'node:fs';

// The admin server is the sole browser-facing client. Never send certificates or tokens to the browser.
export async function cloudSecurityStatus(env = process.env) {
  const url = env.SECURITY_CLOUD_URL;
  if (!url) return { connected: false, reason: '云端安全中心未配置' };
  try {
    const target = new URL('/v1/status', url);
    if (target.protocol !== 'https:' || !env.SECURITY_CLOUD_CLIENT_KEY || !env.SECURITY_CLOUD_CLIENT_CERT
      || !env.SECURITY_CLOUD_CA || !env.SECURITY_CLOUD_TOKEN || env.SECURITY_CLOUD_TOKEN.length < 32) {
      return { connected: false, reason: '云端安全连接配置不完整' };
    }
    const data = await new Promise((resolve, reject) => {
      const req = httpsRequest(target, {
        method: 'GET', timeout: 5000, rejectUnauthorized: true,
        key: readFileSync(env.SECURITY_CLOUD_CLIENT_KEY), cert: readFileSync(env.SECURITY_CLOUD_CLIENT_CERT),
        ca: readFileSync(env.SECURITY_CLOUD_CA),
        headers: { authorization: `Bearer ${env.SECURITY_CLOUD_TOKEN}`, accept: 'application/json' },
      }, res => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', chunk => { text += chunk; if (text.length > 65536) req.destroy(new Error('响应过大')); });
        res.on('end', () => {
          if (res.statusCode !== 200) return reject(new Error('云端拒绝身份或服务不可用'));
          try { resolve(JSON.parse(text)); } catch { reject(new Error('云端响应无效')); }
        });
      });
      req.on('timeout', () => req.destroy(new Error('连接超时')));
      req.on('error', reject);
      req.end();
    });
    if (!data || typeof data.nodes !== 'object' || !Array.isArray(data.events)) throw new Error('云端响应无效');
    return { connected: true, generated_at: data.generated_at, nodes: data.nodes, events: data.events };
  } catch {
    return { connected: false, reason: '云端连接或身份验证失败；请检查证书、凭据与网络' };
  }
}
