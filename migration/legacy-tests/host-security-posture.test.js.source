import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const python = process.env.APPGOG_TEST_PYTHON || 'python3';
const pythonAvailable = spawnSync(python, ['--version']).status === 0;
const pythonOnly = { skip: !pythonAvailable };
const agentPath = JSON.stringify(resolve('scripts/host-security-agent.py'));

function runPython(script) {
  const bootstrap = `import importlib.util, socketserver\n` +
    `if not hasattr(socketserver, 'UnixStreamServer'): socketserver.UnixStreamServer=socketserver.TCPServer\n` +
    `s=importlib.util.spec_from_file_location('agent', ${agentPath})\n` +
    `a=importlib.util.module_from_spec(s); s.loader.exec_module(a)\n`;
  const result = spawnSync(python, ['-c', bootstrap + script], {
    encoding: 'utf8', timeout: 10000,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
}

test('host agent exposes fixed read-only posture checks and no destructive response path', () => {
  const source = readFileSync('scripts/host-security-agent.py', 'utf8');
  for (const symbol of ['container_contract_check', 'evaluate_permission', 'secret_permissions_check',
    'sshd_effective_check', 'listener_posture_from_text', 'listener_posture_check']) {
    assert.match(source, new RegExp(`def ${symbol}\\(`), `missing ${symbol}`);
  }
  assert.doesNotMatch(source, /docker\s+(?:stop|kill|rm|network\s+disconnect)|subprocess\.(?:run|Popen)\([^\n]*(?:rm|unlink|shred)/i);
  assert.doesNotMatch(source, /os\.remove|shutil\.rmtree/);
  const scan = source.slice(source.indexOf('def malware_scan()'), source.indexOf('def expected_platform_image()'));
  assert.doesNotMatch(scan, /unlink|remove|atomic_json/);
});

test('evidence fields are bounded, deterministic and preserve compatibility fields', pythonOnly, () => {
  runPython(`one=a.check('容器合同','warning','detail',check_id='container.contract',category='container',severity='high',scope='appgog service',evidence={'b':2,'a':1})\n` +
    `two=a.check('容器合同','warning','detail',check_id='container.contract',category='container',severity='high',scope='appgog service',evidence={'a':1,'b':2})\n` +
    `assert one['name']=='容器合同' and one['state']=='warning' and one['detail']=='detail'\n` +
    `assert one['id']=='container.contract' and one['category']=='container' and one['severity']=='high'\n` +
    `assert one['scope']=='appgog service' and one['evidence_digest']==two['evidence_digest']\n` +
    `assert len(one['evidence_digest'])==64 and one['checked_at'].endswith('+00:00')\n`);
});

test('container contract accepts the fixed hardened APPGOG container and detects dangerous drift', pythonOnly, () => {
  runPython(`import copy, json, subprocess, types, unittest.mock\n` +
    `healthy={'Name':'/appgog-appgog-1','Config':{'Image':'appgog-platform:1.2.68','User':'node'},'State':{'Status':'running','Health':{'Status':'healthy'}},'HostConfig':{'Privileged':False,'ReadonlyRootfs':True,'CapAdd':None},'Mounts':[{'Type':'bind','Source':'/run/appgog-security','Destination':'/app/runtime/host-security','RW':False},{'Type':'volume','Source':'appgog-db','Destination':'/app/var/data','RW':True}]}\n` +
    `def inspect(payload):\n` +
    ` calls=[]\n` +
    ` def fake(args, **kwargs):\n` +
    `  calls.append(args)\n` +
    `  if args[:2]==['docker','ps']: return types.SimpleNamespace(returncode=0,stdout='abc123\\n',stderr='')\n` +
    `  if args[:2]==['docker','inspect']: return types.SimpleNamespace(returncode=0,stdout=json.dumps([payload]),stderr='')\n` +
    `  raise AssertionError(args)\n` +
    ` with unittest.mock.patch.object(a.subprocess,'run',side_effect=fake): result=a.container_contract_check()\n` +
    ` assert calls[0]==['docker','ps','--filter','label=com.docker.compose.project=appgog','--filter','label=com.docker.compose.service=appgog','--format','{{.ID}}']\n` +
    ` assert calls[1]==['docker','inspect','abc123']\n` +
    ` return result\n` +
    `assert inspect(healthy)['state']=='ok'\n` +
    `variants=[]\n` +
    `x=copy.deepcopy(healthy); x['HostConfig']['Privileged']=True; variants.append(x)\n` +
    `x=copy.deepcopy(healthy); x['HostConfig']['ReadonlyRootfs']=False; variants.append(x)\n` +
    `x=copy.deepcopy(healthy); x['HostConfig']['CapAdd']=['SYS_ADMIN']; variants.append(x)\n` +
    `x=copy.deepcopy(healthy); x['Config']['User']='root'; variants.append(x)\n` +
    `x=copy.deepcopy(healthy); x['State']['Health']['Status']='unhealthy'; variants.append(x)\n` +
    `x=copy.deepcopy(healthy); x['Config']['Image']='foreign/image:latest'; variants.append(x)\n` +
    `x=copy.deepcopy(healthy); x['Mounts'].append({'Type':'bind','Source':'/var/run/docker.sock','Destination':'/var/run/docker.sock','RW':True}); variants.append(x)\n` +
    `x=copy.deepcopy(healthy); x['Mounts'].append({'Type':'bind','Source':'/etc','Destination':'/host/etc','RW':False}); variants.append(x)\n` +
    `x=copy.deepcopy(healthy); x['Mounts']=[{'Type':'volume'} for _ in range(64)]+[{'Type':'bind','Source':'/var/run/docker.sock','Destination':'/var/run/docker.sock','RW':True}]; assert inspect(x)['state']=='finding'\n` +
    `assert all(inspect(item)['state']=='finding' for item in variants)\n` +
    `with unittest.mock.patch.object(a.subprocess,'run',side_effect=subprocess.TimeoutExpired('docker',5)): assert a.container_contract_check()['state']=='unavailable'\n`);
});

test('secret permission evaluation checks owner and mode without reading secret contents', pythonOnly, () => {
  runPython(`import stat, types\n` +
    `safe=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600)\n` +
    `wide=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o644)\n` +
    `foreign=types.SimpleNamespace(st_uid=1000,st_mode=stat.S_IFREG|0o600)\n` +
    `assert a.evaluate_permission('/secret',name='密钥',check_id='secret.key',metadata=safe)['state']=='ok'\n` +
    `assert a.evaluate_permission('/secret',name='密钥',check_id='secret.key',metadata=wide)['state']=='finding'\n` +
    `assert a.evaluate_permission('/secret',name='密钥',check_id='secret.key',metadata=foreign)['state']=='finding'\n`);
});

test('effective sshd posture uses the fixed expansion context and fails closed on errors', pythonOnly, () => {
  runPython(`import subprocess, types, unittest.mock\n` +
    `safe='port 57777\\npermitrootlogin prohibit-password\\npasswordauthentication no\\npermitemptypasswords no\\n'\n` +
    `risky='port 22\\npermitrootlogin yes\\npasswordauthentication yes\\npermitemptypasswords yes\\n'\n` +
    `calls=[]\n` +
    `def result(text):\n` +
    ` def fake(args, **kwargs): calls.append(args); return types.SimpleNamespace(returncode=0,stdout=text,stderr='')\n` +
    ` with unittest.mock.patch.object(a.subprocess,'run',side_effect=fake): return a.sshd_effective_check()\n` +
    `assert result(safe)['state']=='ok'\n` +
    `assert calls[-1]==['sshd','-T','-C','user=root,host=localhost,addr=127.0.0.1']\n` +
    `assert result(risky)['state']=='finding'\n` +
    `with unittest.mock.patch.object(a.subprocess,'run',side_effect=subprocess.TimeoutExpired('sshd',5)): assert a.sshd_effective_check()['state']=='unavailable'\n`);
});

test('listener posture distinguishes loopback from public dangerous ports', pythonOnly, () => {
  runPython(`header='sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\\n'\n` +
    `loop=header+'0: 0100007F:0947 00000000:0000 0A 0 0 0 0 0 0\\n'\n` +
    `public=header+'0: 00000000:0947 00000000:0000 0A 0 0 0 0 0 0\\n'\n` +
    `benign=header+'0: 00000000:2328 00000000:0000 0A 0 0 0 0 0 0\\n'\n` +
    `assert a.listener_posture_from_text(loop,'')['state']=='ok'\n` +
    `assert a.listener_posture_from_text(public,'')['state']=='finding'\n` +
    `assert a.listener_posture_from_text(benign,'')['state']!='finding'\n` +
    `many=header+''.join(str(i)+': 0100007F:2328 00000000:0000 0A 0 0 0 0 0 0\\n' for i in range(64))+public.split('\\n')[1]+'\\n'\n` +
    `assert a.listener_posture_from_text(many,'')['state']=='finding'\n` +
    `malformed=loop+'1: invalid:0947 00000000:0000 0A 0 0 0 0 0 0\\n'; assert a.listener_posture_from_text(malformed,'')['state']=='unavailable'\n`);
});

test('Node boundary explicitly whitelists extended evidence fields', () => {
  const source = readFileSync('apps/license-api/src/modules/operations/local-security-scan.js', 'utf8');
  for (const field of ['id', 'category', 'severity', 'checked_at', 'scope', 'evidence_digest']) {
    assert.match(source, new RegExp(`\\b${field}\\b`), `missing ${field}`);
  }
});
