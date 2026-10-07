import {startFromEnvironment} from './monitor.js';
import {startCloudAdmin} from './cloud/admin.js';
const {server, monitor, control} = startFromEnvironment();
let admin, stopping;
function shutdown() {
  if (!stopping) stopping = (async () => {
    const listeners = [server, admin].filter(Boolean);
    const deadline = setTimeout(() => { for (const listener of listeners) listener.closeAllConnections(); }, 10000);
    deadline.unref();
    try {
      await Promise.all([
        control.close(),
        ...listeners.map(listener => new Promise(resolve => { listener.close(() => resolve()); listener.closeIdleConnections(); })),
      ]);
    } finally { clearTimeout(deadline); }
  })();
  return stopping;
}
try {
  await new Promise((resolve, reject) => {
    if (server.listening) return resolve();
    const ready = () => {server.off('error', failed);resolve();};
    const failed = error => {server.off('listening', ready);reject(error);};
    server.once('listening', ready);server.once('error', failed);
  });
  admin = await startCloudAdmin(monitor, process.env, control);
  const fail = error => {
    console.error('玄武服务停止：', error.code || 'listener failure'); process.exitCode = 1;
    void shutdown().catch(() => { console.error('玄武关闭失败'); process.exitCode = 1; });
  };
  server.on('error', fail); admin.on('error', fail);
  for (const signal of ['SIGINT','SIGTERM']) process.once(signal, () => {
    void shutdown().catch(() => { console.error('玄武关闭失败'); process.exitCode = 1; });
  });
} catch (error) { await shutdown(); throw error; }
