import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inventory } from '../scripts/security-agent.js';

test('inventory detects edits, additions and symlinks without crossing root', () => {
  const root = mkdtempSync(join(tmpdir(), 'appgog-inventory-'));
  try {
    mkdirSync(join(root, 'apps'));
    writeFileSync(join(root, 'apps', 'one.js'), 'safe');
    const first = inventory(root, ['apps']);
    writeFileSync(join(root, 'apps', 'one.js'), 'changed');
    writeFileSync(join(root, 'apps', 'two.js'), 'added');
    const second = inventory(root, ['apps']);
    assert.notEqual(first['apps/one.js'], second['apps/one.js']);
    assert.ok(second['apps/two.js']);
    assert.throws(() => inventory(root, ['../outside']), /越界/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
const root = join(import.meta.dirname, '..');
test('monitored source roots are copied into the runtime image', () => {
  const dockerfile = readFileSync(join(root, 'Dockerfile'), 'utf8');
  for (const source of ['apps', 'packages', 'scripts', 'Dockerfile', 'compose.yaml', 'compose.license.yaml', 'compose.build.yaml']) {
    assert.match(dockerfile, new RegExp(`\\b${source.replace('.', '\\.') }\\b`));
  }
  assert.match(dockerfile, /^COPY apps \.\/apps$/m);
  assert.match(dockerfile, /^COPY packages \.\/packages$/m);
  assert.match(dockerfile, /^COPY scripts \.\/scripts$/m);
  assert.match(dockerfile, /^COPY .*\bDockerfile compose\.yaml compose\.license\.yaml compose\.build\.yaml \.\/$/m);
});
