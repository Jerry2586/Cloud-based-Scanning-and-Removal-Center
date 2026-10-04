import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
const python = process.env.APPGOG_TEST_PYTHON || 'python3';
test('bounded local response, recovery and offline source-repair boundaries', { skip: spawnSync(python, ['--version']).status !== 0 }, () => {
  const result = spawnSync(python, ['tests/fixtures/host-security-response.py', '-v'], { encoding: 'utf8', timeout: 30000, env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
});
