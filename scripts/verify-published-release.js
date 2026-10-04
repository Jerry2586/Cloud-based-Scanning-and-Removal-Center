import { execFileSync } from 'node:child_process';
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { releaseAssetNames, verifyRelease } from '../src/release-verification.js';

const repository = 'Jerry2586/Cloud-based-Scanning-and-Removal-Center';
const here = dirname(fileURLToPath(import.meta.url));
const command = args => execFileSync(process.env.GH_BINARY || 'gh', args, {
  encoding: 'utf8', timeout: args[0] === 'release' ? 300000 : 30000, maxBuffer: 4 * 1024 * 1024,
});
function requireValue(ok, message) { if (!ok) throw Error('Published release verification: ' + message); }

export function verifyPublishedRelease({ tag, expectedCommit, outputDirectory, allowNotLatest = false,
  publicKey = readFileSync(join(here, '../release-public.pem')), run = command } = {}) {
  requireValue(/^v\d+\.\d+\.\d+$/.test(tag || ''), 'expected vX.Y.Z tag required');
  requireValue(/^[a-f0-9]{40}$/.test(expectedCommit || ''), 'expected 40-character commit required');
  const api = endpoint => JSON.parse(run(['api', 'repos/' + repository + '/' + endpoint]));
  let object = api('git/ref/tags/' + tag).object;
  for (let depth = 0; object?.type === 'tag' && depth < 3; depth++) {
    requireValue(/^[a-f0-9]{40}$/.test(object.sha), 'invalid annotated tag object');
    object = api('git/tags/' + object.sha).object;
  }
  requireValue(object?.type === 'commit' && object.sha === expectedCommit, 'tag does not resolve to accepted commit');
  const release = api('releases/tags/' + tag);
  requireValue(release.tag_name === tag && release.draft === false && release.prerelease === false, 'not a published stable release');
  requireValue(Number.isSafeInteger(release.id) && release.id > 0, 'invalid release id');
  if (!allowNotLatest) {
    const latest = api('releases/latest');
    requireValue(latest.id === release.id && latest.tag_name === tag, 'release is not Latest');
  }
  const names = releaseAssetNames(tag.slice(1));
  requireValue(Array.isArray(release.assets) && release.assets.length === names.length, 'exactly six assets required');
  requireValue(new Set(release.assets.map(asset => asset.name)).size === names.length
    && names.every(name => release.assets.some(asset => asset.name === name)), 'unexpected or duplicate assets');
  for (const asset of release.assets) {
    requireValue(asset.state === 'uploaded' && Number.isSafeInteger(asset.size) && asset.size > 0 && asset.size <= 64 * 1024 * 1024,
      'asset state or size invalid: ' + asset.name);
  }
  const directory = outputDirectory ? resolve(outputDirectory) : mkdtempSync(join(tmpdir(), 'ironcurtain-release-'));
  if (outputDirectory) mkdirSync(directory, { recursive: false, mode: 0o700 });
  try {
    run(['release', 'download', tag, '--repo', repository, '--dir', directory,
      ...names.flatMap(name => ['--pattern', name])]);
    for (const asset of release.assets) {
      requireValue(lstatSync(join(directory, asset.name)).size === asset.size, 'downloaded size mismatch: ' + asset.name);
    }
    const verified = verifyRelease({ directory, publicKey, expectedVersion: tag.slice(1) });
    const result = { schema: 'ironcurtain-published-release-verification/v1', repository, tag,
      commit: expectedCommit, release_id: release.id, version: verified.version, assets: verified.assets,
      verified_at: new Date().toISOString(), latest_required: !allowNotLatest };
    if (outputDirectory) writeFileSync(join(dirname(directory), tag + '-verification.json'), JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    return result;
  } finally {
    if (!outputDirectory) rmSync(directory, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const value = name => { const index = args.indexOf(name); if (index < 0 || !args[index + 1]) throw Error('Missing ' + name); return args[index + 1]; };
  const result = verifyPublishedRelease({ tag: value('--tag'), expectedCommit: value('--expected-commit'),
    outputDirectory: args.includes('--output-dir') ? value('--output-dir') : undefined,
    allowNotLatest: args.includes('--allow-not-latest') });
  console.log(JSON.stringify(result, null, 2));
}
