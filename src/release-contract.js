import { isDeepStrictEqual } from 'node:util';

export const legacyContract = {
  schema: 1,
  product: 'appgog-cloud-security-center',
  artifact_prefix: 'APPGOG-Cloud-Security-Center',
  node_version: '24.19.0',
  node_major: 24,
  architectures: ['amd64', 'arm64'],
  service: 'appgog-security.service',
  install_root: '/opt/appgog-security',
  config_root: '/etc/appgog-security',
  data_root: '/var/lib/appgog-security',
};

export const independentContract = {
  "roles": [
    "local",
    "cloud"
  ],
  "installer": "scripts/install-independent.sh",
  "menu": {
    "local": "ironcurtain",
    "cloud": "xuanwu"
  },
  "container": {
    "local": "ironcurtain-local",
    "cloud": "ironcurtain-cloud"
  },
  "install_root": "/opt/ironcurtain/<role>",
  "config_root": "/etc/ironcurtain/<role>",
  "data_root": "/var/lib/ironcurtain/<role>",
  "compose_min_version": "2.24.0",
  "host_agent": "ironcurtain-agent.service",
  "ports": {
    "local": 8790,
    "cloud": 9443
  }
};

export function validateReleaseContract(contract, version) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw Error('Release version is invalid');
  const [major, minor] = version.split('.').map(Number);
  const requiresIndependent = major > 0 || minor >= 2;
  const expected = Object.hasOwn(contract, 'independent')
    ? { ...legacyContract, independent: independentContract } : legacyContract;
  if ((requiresIndependent && !Object.hasOwn(contract, 'independent'))
    || !isDeepStrictEqual(contract, expected)) throw Error('Release contract is invalid');
}
