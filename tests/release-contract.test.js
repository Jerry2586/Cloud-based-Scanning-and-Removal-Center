import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { legacyContract, independentContract, validateReleaseContract } from '../src/release-contract.js';

test('signed release contracts preserve legacy and require independent roles on modern releases', () => {
  assert.doesNotThrow(() => validateReleaseContract(legacyContract, '0.1.6'));
  assert.throws(() => validateReleaseContract(legacyContract, '0.2.0'), /contract/);
  const current = JSON.parse(readFileSync(new URL('../release-contract.json', import.meta.url)));
  assert.doesNotThrow(() => validateReleaseContract(current, '0.2.0'));
  assert.doesNotThrow(() => validateReleaseContract(current, '0.1.4'));
  for (const mutate of [
    c => { c.independent.ports.local = 22; },
    c => { c.independent.install_root = '/'; },
    c => { c.independent.roles.push('root-shell'); },
    c => { c.independent.container.cloud = 'appgog'; },
    c => { c.node_major = 99; },
    c => { c.independent.exec = 'arbitrary'; },
    c => { delete c.independent.host_agent; },
  ]) {
    const changed = structuredClone(current); mutate(changed);
    assert.throws(() => validateReleaseContract(changed, '0.2.0'), /contract/);
  }
  assert.deepEqual(current, { ...legacyContract, independent: independentContract });
});
