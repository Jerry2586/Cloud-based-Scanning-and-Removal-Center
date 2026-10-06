import {readFile} from 'node:fs/promises';
import {createLocalServer} from '../local/server.js';
import {loadCredentials} from '../local/auth.js';
import {domainRequest} from '../local/domain-client.js';
const publicDirectory = new URL('./public/', import.meta.url);
const assets = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/assets/admin.js', ['admin.js', 'text/javascript; charset=utf-8']],
  ['/assets/admin.css', ['admin.css', 'text/css; charset=utf-8']],
  ['/assets/theme.js', [new URL('../local/public/assets/theme.js', import.meta.url), 'text/javascript; charset=utf-8']],
  ['/assets/portal/domain-settings.js', [new URL('../local/public/assets/portal/domain-settings.js', import.meta.url), 'text/javascript; charset=utf-8']],
]);
export async function startCloudAdmin(monitor, env = process.env) {
  const directory = env.IRONCURTAIN_CONFIG_DIR || '/etc/xuanwu';
  const tls = {cert: await readFile(env.IRONCURTAIN_TLS_CERT || directory + '/panel.crt'), key: await readFile(env.IRONCURTAIN_TLS_KEY || directory + '/panel.key')};
  const origin = env.IRONCURTAIN_PUBLIC_ORIGIN;
  if (!origin) throw Error('玄武管理面板缺少公开访问地址');
  const server = createLocalServer({ role: 'cloud', origin, tls, assets, publicDirectory, panelPort: Number(env.IRONCURTAIN_PORT || 8791),
    credentials: await loadCredentials(directory), domainDirectory: directory,
    domains: (action, value) => domainRequest(action, value, {...env, IRONCURTAIN_ROLE: 'cloud'}),
    cloudStatus: () => monitor.status(),
    updates: async () => ({response_status: 503, state: 'unavailable', reason: '玄武程序更新请使用 xuanwu update'}),
  });
  await new Promise((resolve, reject) => {server.once('error', reject); server.listen(Number(env.IRONCURTAIN_PORT || 8791), env.IRONCURTAIN_LISTEN_HOST || '0.0.0.0', () => {server.off('error',reject);resolve();});});
  console.log('玄武引擎管理面板已启动：' + origin);
  return server;
}
