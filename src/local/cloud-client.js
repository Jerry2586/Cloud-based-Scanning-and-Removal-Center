import { request } from 'node:https';
import { randomUUID } from 'node:crypto';
import { open, lstat } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, join, resolve, parse } from 'node:path';
import { HOST_SCAN_IDS, freshHostScan } from '../contracts/host-scan-contract.js';

const genericId = /^node-[a-z0-9][a-z0-9-]{0,63}$/;
const legacyIds = new Set(['license-center', 'build-center']);
async function trustedFile(file, limit = 32768) {
  const absolute = resolve(file);
  if (process.platform !== 'win32') {
    for (let parent = dirname(absolute); parent !== parse(parent).root; parent = dirname(parent)) {
      const info = await lstat(parent);
      if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== 0 || (info.mode & 0o022)) throw Error('UNTRUSTED_CONFIG');
    }
  }
  const handle = await open(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size > limit || (process.platform !== 'win32' && (before.uid !== 0 || (before.mode & 0o022)))) throw Error('UNTRUSTED_CONFIG');
    const bytes = Buffer.alloc(limit + 1); let length = 0;
    while (length < bytes.length) { const result = await handle.read(bytes, length, bytes.length - length); if (!result.bytesRead) break; length += result.bytesRead; }
    const after = await handle.stat();
    if (length > limit || before.ino !== after.ino || before.mtimeMs !== after.mtimeMs || before.size !== after.size) throw Error('UNTRUSTED_CONFIG');
    return bytes.subarray(0, length);
  } finally { await handle.close(); }
}
export async function loadCloudClient(directory) {
  const config = JSON.parse(await trustedFile(join(directory, 'cloud.json')));
  if (!config || Array.isArray(config) || config.schema !== 'ironcurtain-cloud/v1' ||
      Object.keys(config).sort().join(',') !== 'endpoint,node_id,schema' ||
      (!genericId.test(config.node_id) && !legacyIds.has(config.node_id))) throw Error('INVALID_CLOUD_CONFIG');
  const endpoint = new URL(config.endpoint);
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.pathname !== '/' || endpoint.search || endpoint.hash) throw Error('INVALID_CLOUD_ENDPOINT');
  const [ca, cert, key, tokenBytes] = await Promise.all(['ca.crt','client.crt','client.key','token'].map(name => trustedFile(join(directory, name))));
  const token = tokenBytes.toString('utf8').trim();
  if (!/^[A-Za-z0-9_-]{32,256}$/.test(token)) throw Error('INVALID_NODE_TOKEN');
  return new CloudClient({ endpoint: endpoint.origin, nodeId: config.node_id, ca, cert, key, token });
}
export class CloudClient {
  constructor({ endpoint, nodeId, ca, cert, key, token, timeout = 5000 }) {
    this.endpoint = new URL(endpoint);
    if (this.endpoint.protocol !== 'https:' || this.endpoint.username || this.endpoint.password || this.endpoint.pathname !== '/' || this.endpoint.search || this.endpoint.hash || (!genericId.test(nodeId) && !legacyIds.has(nodeId))) throw Error('INVALID_CLOUD_CONFIG');
    this.nodeId=nodeId; this.identity={ca,cert,key}; this.token=token; this.timeout=timeout;
  }
  call(pathname, body) {
    if (!['/v1/connectivity','/v1/node/status','/v1/policy','/v1/report'].includes(pathname) || (pathname === '/v1/report') !== (body !== undefined)) throw Error('INVALID_CLOUD_OPERATION');
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    if (payload?.length > 262144) return Promise.reject(Error('REPORT_TOO_LARGE'));
    return new Promise((resolveCall,reject) => {
      const req = request(new URL(pathname,this.endpoint), { ...this.identity, rejectUnauthorized:true, minVersion:'TLSv1.2',
        method:payload ? 'POST' : 'GET', timeout:this.timeout, agent:false,
        headers:{authorization:'Bearer '+this.token, ...(payload ? {'content-type':'application/json','content-length':payload.length} : {})}}, res => {
        let length=0; const chunks=[];
        res.on('data',chunk=>{length+=chunk.length; if(length>262144){res.destroy(Error('CLOUD_RESPONSE_LIMIT')); return;} chunks.push(chunk);});
        res.on('error',reject); res.on('aborted',()=>reject(Error('CLOUD_RESPONSE_ABORTED')));
        res.on('end',()=>{try {
          if(res.statusCode!==200) throw Error(res.statusCode===403 ? 'CLOUD_AUTH_REJECTED' : 'CLOUD_REQUEST_REJECTED');
          if(!/^application\/json(?:;|$)/i.test(res.headers['content-type'] ?? '')) throw Error('INVALID_CLOUD_RESPONSE');
          const value=JSON.parse(Buffer.concat(chunks)); if(!value || Array.isArray(value) || typeof value!=='object') throw Error('INVALID_CLOUD_RESPONSE'); resolveCall(value);
        } catch(error){reject(error);}});
      });
      req.setTimeout(this.timeout,()=>req.destroy(Error('CLOUD_TIMEOUT')));
      const deadline=setTimeout(()=>req.destroy(Error('CLOUD_TIMEOUT')),this.timeout); deadline.unref(); req.once('close',()=>clearTimeout(deadline));
      req.on('error',reject); req.end(payload);
    });
  }
  async status() {
    const data=await this.call('/v1/node/status');
    if(data.identity!==this.nodeId || !data.node || !data.policy || data.policy.delivery!=='pull-only' || data.policy.remote_execution!==false) throw Error('CLOUD_IDENTITY_MISMATCH');
    return {state:'connected', connected:true, generated_at:data.generated_at, node_id:this.nodeId, node:data.node, nodes:{[this.nodeId]:data.node}, policy:data.policy};
  }
  async report(snapshot) {
    if(!snapshot || !freshHostScan(snapshot.scan) || !['complete','unavailable'].includes(snapshot.files_state) || !snapshot.files || typeof snapshot.files!=='object' || Array.isArray(snapshot.files) || Object.entries(snapshot.files).some(([name,digest])=>name.length>500 || !name.startsWith('/') || name.split('/').includes('..') || !/^[a-f0-9]{64}$/.test(digest))) throw Error('INCOMPLETE_LOCAL_REPORT');
    const counts={ok:0,warning:0,finding:0,unavailable:0}; for(const check of snapshot.scan.checks) if(HOST_SCAN_IDS.includes(check.id) && Object.hasOwn(counts,check.state)) counts[check.state]++;
    const state=counts.finding ? 'finding' : counts.unavailable ? 'unavailable' : counts.warning ? 'warning' : 'ok';
    const payload={files:snapshot.files, files_state:snapshot.files_state, observed_at:new Date().toISOString(),report_id:randomUUID(),host_scan:{state,checked_at:snapshot.scan.checked_at,counts}};
    return this.call('/v1/report',payload);
  }
}
export function createCloudLink({directory, snapshot, interval=30000}) {
  let client, busy=false, stopped=false, checked=0;
  let status={state:'unpaired',reason:'尚未导入玄武节点身份包'};
  async function refresh() {
    if(busy || stopped) return status; busy=true;
    try {
      client=await loadCloudClient(directory);
      if(snapshot) { const report=await snapshot(); if(report?.scan && freshHostScan(report.scan)) await client.report(report); }
      status=await client.status();
    } catch(error) {
      status={state:error.code==='ENOENT' ? 'unpaired' : 'unavailable',reason:error.code==='ENOENT' ? '尚未导入玄武节点身份包' : '云端证书、身份或连接验证失败；本机扫描继续运行'};
    } finally {busy=false;checked=Date.now();} return status;
  }
  const timer=setInterval(()=>void refresh(),interval); timer.unref();
  return {async status(){if(!checked || Date.now()-checked>=interval) await refresh(); return structuredClone(status);}, refresh, close(){stopped=true;clearInterval(timer);}};
}
