import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
const python=process.env.APPGOG_TEST_PYTHON||'python3';
test('fixed firewall snapshots, exact approval, private reports and fault boundaries', {skip:spawnSync(python,['--version']).status!==0},()=>{
 const result=spawnSync(python,['tests/fixtures/host-security-firewall.py'],{encoding:'utf8',timeout:20000,env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'}});
 assert.equal(result.status,0,result.stderr||result.error?.message);
});
