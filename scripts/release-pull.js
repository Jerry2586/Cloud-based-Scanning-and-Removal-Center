import { request } from 'node:https';
import { readdirSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { readReleaseFile, trustedReleaseDirectory, compareVersions, RELEASE_LIMIT } from '../src/release-store.js';
import { verifyReleaseManifest, verifyRelease, releaseAssetNames } from '../src/release-verification.js';

// Called only by the root menu with protected identity and empty staging mounts.
// The cloud supplies signed data, never an executable command or a target path.
export async function pullRelease({ identityDirectory, directory, publicKey, installedVersion, timeout = 120000 }) {
  trustedReleaseDirectory(directory);
  if (readdirSync(directory).length) throw Error('RELEASE_OUTPUT_NOT_EMPTY');
  compareVersions(installedVersion, installedVersion);
  const config = JSON.parse(readReleaseFile(join(identityDirectory, 'cloud.json'), 32768));
  if (!config || Object.keys(config).sort().join(',') !== 'endpoint,node_id,schema'
      || config.schema !== 'ironcurtain-cloud/v1' || !/^node-[a-z0-9][a-z0-9-]{0,63}$/.test(config.node_id)) throw Error('RELEASE_IDENTITY_CONFIG');
  const endpoint = new URL(config.endpoint);
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.pathname !== '/' || endpoint.search || endpoint.hash) throw Error('RELEASE_ENDPOINT');
  const identity = Object.fromEntries(['ca.crt', 'client.crt', 'client.key', 'token'].map(name => [name, readReleaseFile(join(identityDirectory, name), 32768)]));
  const token = identity.token.toString('utf8').trim();
  if (!/^[A-Za-z0-9_-]{32,256}$/.test(token)) throw Error('RELEASE_TOKEN');
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), timeout);
  let peer;
  function get(pathname, maximum, type) {
    return new Promise((done, fail) => {
      const req = request(new URL(pathname, endpoint), { method: 'GET', agent: false, ca: identity['ca.crt'],
        cert: identity['client.crt'], key: identity['client.key'], minVersion: 'TLSv1.2', signal: abort.signal,
        headers: { authorization: 'Bearer ' + token, accept: type } }, res => {
        if (res.statusCode !== 200 || res.headers['content-type']?.split(';')[0].trim().toLowerCase() !== type) {
          res.destroy(); return fail(Error('RELEASE_CLOUD_REJECTED'));
        }
        const announced = res.headers['content-length'];
        if (announced !== undefined && (!/^[0-9]+$/.test(announced) || Number(announced) > maximum)) {
          res.destroy(); return fail(Error('RELEASE_DOWNLOAD_LIMIT'));
        }
        const chunks = []; let length = 0;
        res.on('data', chunk => { length += chunk.length; if (length > maximum) res.destroy(Error('RELEASE_DOWNLOAD_LIMIT')); else chunks.push(chunk); });
        res.on('error', fail);
        res.on('aborted', () => fail(Error('RELEASE_DOWNLOAD_ABORTED')));
        res.on('end', () => done(Buffer.concat(chunks)));
      });
      req.on('socket', socket => socket.once('secureConnect', () => {
        const observed = socket.getPeerCertificate().fingerprint256;
        if (!socket.authorized || !observed || (peer && peer !== observed)) req.destroy(Error('RELEASE_CLOUD_PEER_CHANGED'));
        else peer = observed;
      }));
      req.on('error', fail); req.end();
    });
  }
  const created = [];
  try {
    const connected = JSON.parse(await get('/v1/connectivity', 4096, 'application/json'));
    if (connected.identity !== config.node_id) throw Error('RELEASE_NODE_IDENTITY');
    const offer = JSON.parse(await get('/v1/releases/latest', 100000, 'application/json'));
    if (!offer || Object.keys(offer).sort().join(',') !== 'manifest,schema,signature,version' || offer.schema !== 'ironcurtain-release-offer/v1') throw Error('RELEASE_OFFER');
    const decode = (value, limit) => {
      if (typeof value !== 'string' || value.length > limit * 2 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw Error('RELEASE_OFFER');
      const bytes = Buffer.from(value, 'base64');
      if (bytes.length > limit || bytes.toString('base64') !== value) throw Error('RELEASE_OFFER');
      return bytes;
    };
    const manifestBytes = decode(offer.manifest, 65536), signature = decode(offer.signature, 64);
    const manifest = verifyReleaseManifest({ manifestBytes, signature, publicKey, expectedVersion: offer.version });
    if (compareVersions(manifest.version, installedVersion) < 0) throw Error('RELEASE_DOWNGRADE');
    const save = (name, bytes) => {
      const file = join(directory, name); writeFileSync(file, bytes, { flag: 'wx', mode: 0o600 }); chmodSync(file, 0o600); created.push(file);
    };
    save('release-manifest.json', manifestBytes); save('release-manifest.json.sig', signature);
    for (const name of releaseAssetNames(manifest.version)) {
      if (name === 'release-manifest.json' || name === 'release-manifest.json.sig') continue;
      save(name, await get('/v1/releases/' + manifest.version + '/' + name, name.endsWith('.sha256') ? 256 : RELEASE_LIMIT, 'application/octet-stream'));
    }
    verifyRelease({ directory, publicKey, expectedVersion: manifest.version });
    return { state: 'verified', version: manifest.version, run_name: manifest.run_name, activation: 'local-admin' };
  } catch (error) {
    for (const file of created) rmSync(file, { force: true });
    throw error;
  } finally { clearTimeout(timer); abort.abort(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length !== 3 || process.platform === 'win32' || process.getuid() !== 0) throw Error('Root fixed release pull required');
  const result = await pullRelease({ identityDirectory: '/identity', directory: '/output',
    publicKey: readReleaseFile('/app/release-public.pem', 32768), installedVersion: process.argv[2] });
  console.log(JSON.stringify(result));
}
