import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
const python=process.env.APPGOG_TEST_PYTHON || 'python3';
test('bounded local SSH login inventory detects persistence changes and rejects unsafe approval', {skip:spawnSync(python,['--version']).status!==0}, () => {
 const result=spawnSync(python,['-I','tests/fixtures/host-security-login.py'],{encoding:'utf8',timeout:20000,env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'}});
 assert.equal(result.status,0,result.stderr || result.error?.message);
});
