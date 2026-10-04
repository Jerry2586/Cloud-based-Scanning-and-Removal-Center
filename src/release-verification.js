import { validateReleaseContract } from './release-contract.js';
import { isDeepStrictEqual } from 'node:util';
import { execFileSync } from 'node:child_process';
import { createHash, verify } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

const MAX_ASSET_BYTES = 64 * 1024 * 1024;
export const runHeader = `#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $(id -u) -eq 0 ]] || { echo 'Run this signed installer as root.' >&2; exit 1; }
archive_line=$(awk '/^__ARCHIVE_BELOW__$/{print NR + 1; exit}' "$0")
[[ -n $archive_line ]] || { echo 'Embedded archive marker is missing.' >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tail -n +"$archive_line" "$0" | tar -xzf - -C "$work"
bash "$work/scripts/install-linux.sh" "$@"
exit $?
__ARCHIVE_BELOW__
`;

export function releaseAssetNames(version) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw Error('Release version is invalid');
  const prefix = 'APPGOG-Cloud-Security-Center-' + version;
  return [prefix + '.run', prefix + '.run.sha256', prefix + '.tar.gz', prefix + '.tar.gz.sha256',
    'release-manifest.json', 'release-manifest.json.sig'].sort();
}

function boundedFile(directory, name, maximum = MAX_ASSET_BYTES) {
  const file = join(directory, name);
  const stat = lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maximum) throw Error('Invalid release asset: ' + name);
  return readFileSync(file);
}

export function verifyRelease({ directory, publicKey, expectedVersion } = {}) {
  directory = resolve(directory);
  const manifestBytes = boundedFile(directory, 'release-manifest.json', 64 * 1024);
  const signature = boundedFile(directory, 'release-manifest.json.sig', 64);
  if (signature.length !== 64 || !verify(null, manifestBytes, publicKey, signature)) {
    throw Error('Release manifest signature verification failed');
  }
  const manifest = JSON.parse(manifestBytes);
  const fields = ['schema', 'product', 'version', 'tar_name', 'tar_sha256', 'run_name', 'run_sha256', 'environment'].sort();
  if (!manifest || !isDeepStrictEqual(Object.keys(manifest).sort(), fields)
    || manifest.schema !== 1 || manifest.product !== 'appgog-cloud-security-center'
    || !/^\d+\.\d+\.\d+$/.test(manifest.version)) throw Error('Release manifest identity is invalid');
  if (expectedVersion !== undefined && manifest.version !== expectedVersion) throw Error('Unexpected release version');
  if (!isDeepStrictEqual(readdirSync(directory).sort(), releaseAssetNames(manifest.version))) {
    throw Error('Release must contain exactly six expected assets');
  }
  validateReleaseContract(manifest.environment, manifest.version);
  const prefix = 'APPGOG-Cloud-Security-Center-' + manifest.version;
  let archive, run;
  for (const [field, extension] of [['tar', '.tar.gz'], ['run', '.run']]) {
    const name = prefix + extension;
    if (manifest[field + '_name'] !== name || !/^[a-f0-9]{64}$/.test(manifest[field + '_sha256'])) {
      throw Error('Invalid artifact name or digest');
    }
    const bytes = boundedFile(directory, name);
    const digest = createHash('sha256').update(bytes).digest('hex');
    if (digest !== manifest[field + '_sha256']) throw Error(name + ' SHA-256 mismatch');
    const checksum = boundedFile(directory, name + '.sha256', 256).toString('utf8');
    if (checksum !== digest + '  ' + name + '\n') throw Error(name + ' checksum attachment mismatch');
    if (field === 'tar') archive = bytes; else run = bytes;
  }
  const header = Buffer.from(runHeader);
  if (!run.subarray(0, header.length).equals(header) || !run.subarray(header.length).equals(archive)) {
    throw Error('RUN installer header or embedded TAR differs from verified release');
  }
  const tarPath = prefix + '.tar.gz';
  const invoke = args => execFileSync('tar', args, { cwd: directory, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024, timeout: 30000 });
  const names = invoke(['-tzf', tarPath]).trimEnd().split('\n');
  if (new Set(names).size !== names.length || names.some(name => name !== './' && (!name.startsWith('./')
    || /[\\\r\0]/.test(name) || name.slice(2).replace(/\/$/, '').split('/').some(part => !part || part === '.' || part === '..')))) {
    throw Error('Archive paths are unsafe or duplicated');
  }
  if (invoke(['-tvzf', tarPath]).trimEnd().split('\n').some(line => !/^[-d]/.test(line))) {
    throw Error('Archive contains links or special files');
  }
  const readArchiveJson = name => JSON.parse(invoke(['-xOzf', tarPath, './' + name]));
  const contract = readArchiveJson('release-contract.json');
  const application = readArchiveJson('package.json');
  if (!isDeepStrictEqual(manifest.environment, contract)) throw Error('Packaged release contract mismatch');
  if (application.name !== manifest.product || application.version !== manifest.version) throw Error('Packaged application identity mismatch');
  return { version: manifest.version, assets: releaseAssetNames(manifest.version) };
}
