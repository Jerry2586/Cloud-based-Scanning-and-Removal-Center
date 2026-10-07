import { readFileSync, lstatSync } from 'node:fs';
import { join } from 'node:path';

// Only a fixed, read-only hash endpoint; no samples, supplied URLs or redirects.
export function createHashIntelligence({ key, fetcher = fetch, now = Date.now } = {}) {
  if (!key || !/^[A-Za-z0-9_-]{20,256}$/.test(key)) return undefined;
  let requests = [];
  return async (sha256, signal) => {
    if (typeof sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(sha256)) throw Error('HASH_INVALID');
    const time = now();
    requests = requests.filter(at => time >= at && time - at < 60000);
    if (requests.length >= 4) throw Error('PROVIDER_RATE_LIMIT');
    requests.push(time);
    const response = await fetcher('https://www.virustotal.com/api/v3/files/' + sha256, {
      method: 'GET', redirect: 'error', signal, headers: { 'x-apikey': key, Accept: 'application/json' }
    });
    if (response.status === 404) { await response.body?.cancel(); return { state: 'unknown', source: 'hash-intelligence' }; }
    if (!response.ok) { await response.body?.cancel(); throw Error('PROVIDER_UNAVAILABLE'); }
    let size = 0; const chunks = [];
    for await (const chunk of response.body) { size += chunk.length; if (size > 262144) { throw Error('PROVIDER_SIZE'); } chunks.push(Buffer.from(chunk)); }
    const data = JSON.parse(Buffer.concat(chunks).toString('utf8')).data;
    if (data?.id !== sha256 || data?.type !== 'file') throw Error('PROVIDER_IDENTITY');
    const stats = data.attributes?.last_analysis_stats;
    const result = { state: 'known', source: 'hash-intelligence' };
    for (const field of ['malicious','suspicious','undetected','harmless']) {
      if (!Number.isSafeInteger(stats?.[field]) || stats[field] < 0 || stats[field] > 1000) throw Error('PROVIDER_STATS');
      result[field] = stats[field];
    }
    const at = data.attributes?.last_analysis_date;
    if (!Number.isSafeInteger(at) || at <= 0 || at * 1000 > time + 300000 || time - at * 1000 > 30 * 86400000) throw Error('PROVIDER_STALE');
    result.analyzed_at = new Date(at * 1000).toISOString();
    return result;
  };
}

export function loadHashIntelligence(directory) {
  const file = join(directory, 'hash-intelligence.key');
  try {
    const info = lstatSync(file);
    // Runtime is a root-owned read-only mount, readable by the service group.
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > 512 || (process.platform !== 'win32' && (info.uid !== 0 || info.mode & 0o027))) throw Error('PROVIDER_KEY_FILE');
    const key = readFileSync(file, 'utf8').trim();
    const provider = createHashIntelligence({ key });
    if (!provider) throw Error('PROVIDER_KEY_FORMAT');
    return provider;
  } catch (error) { if (error.code === 'ENOENT') return undefined; throw Error('PROVIDER_CONFIGURATION'); }
}
