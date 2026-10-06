import {startFromEnvironment} from './monitor.js';
import {startCloudAdmin} from './cloud/admin.js';
const {server, monitor} = startFromEnvironment();
try {
  await new Promise((resolve, reject) => {
    if (server.listening) return resolve();
    const ready = () => {server.off('error', failed);resolve();};
    const failed = error => {server.off('listening', ready);reject(error);};
    server.once('listening', ready);server.once('error', failed);
  });
  const admin = await startCloudAdmin(monitor);
  const fail = error => {console.error('玄武服务停止：', error.code || error.message); process.exitCode = 1; admin.close(); server.close();};
  server.on('error', fail); admin.on('error', fail);
  for (const signal of ['SIGINT','SIGTERM']) process.once(signal, () => {admin.close(); server.close();});
} catch (error) {server.close(); throw error;}
