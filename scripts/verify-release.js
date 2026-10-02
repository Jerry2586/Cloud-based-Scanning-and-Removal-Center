import { isDeepStrictEqual } from 'node:util';
import { execFileSync } from 'node:child_process';
import { createHash, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';

const args = process.argv.slice(2);
const value = name => {
  const index = args.indexOf(name);
  if (index < 0 || !args[index + 1]) throw Error(`Missing ${name}`);
  return args[index + 1];
};
const directory = resolve(value('--dir'));
const publicKey = resolve(value('--public-key'));
const manifestPath = join(directory, 'release-manifest.json');
const signaturePath = join(directory, 'release-manifest.json.sig');
const manifestBytes = readFileSync(manifestPath);
if (!verify(null, manifestBytes, readFileSync(publicKey), readFileSync(signaturePath))) {
  throw Error('Release manifest signature verification failed');
}
const manifest = JSON.parse(manifestBytes);
if (manifest.schema !== 1 || manifest.product !== 'appgog-cloud-security-center'
  || !/^\d+\.\d+\.\d+$/.test(manifest.version)) throw Error('Release manifest identity is invalid');
const prefix = 'APPGOG-Cloud-Security-Center';
const expected = {
  tar_name: `${prefix}-${manifest.version}.tar.gz`,
  run_name: `${prefix}-${manifest.version}.run`,
};
for (const [field, name] of Object.entries(expected)) {
  if (manifest[field] !== name || basename(manifest[field]) !== manifest[field]) throw Error(`${field} is invalid`);
  const digest = createHash('sha256').update(readFileSync(join(directory, name))).digest('hex');
  if (digest !== manifest[field.replace('_name', '_sha256')]) throw Error(`${name} SHA-256 mismatch`);
}
const tarPath = join(directory, expected.tar_name);
const readArchiveJson = path => JSON.parse(execFileSync('tar', ['-xOzf', tarPath, `./${path}`], {
  encoding: 'utf8',
  maxBuffer: 1024 * 1024,
}));
const packagedContract = readArchiveJson('release-contract.json');
const packagedPackage = readArchiveJson('package.json');
if (!isDeepStrictEqual(manifest.environment, packagedContract)) {
  throw Error('Release manifest contract does not match packaged release-contract.json');
}
const requiredContract = {
  schema: 1,
  product: manifest.product,
  artifact_prefix: prefix,
  node_version: '24.19.0',
  node_major: 24,
  architectures: ['amd64', 'arm64'],
  service: 'appgog-security.service',
  install_root: '/opt/appgog-security',
  config_root: '/etc/appgog-security',
  data_root: '/var/lib/appgog-security',
};
if (!isDeepStrictEqual(packagedContract, requiredContract)) throw Error('Release contract is invalid');
if (packagedPackage.name !== manifest.product || packagedPackage.version !== manifest.version) {
  throw Error('Packaged application identity does not match release manifest');
}
console.log(`Verified signed release v${manifest.version}`);
