import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { HOST_SCAN_IDS, completeHostScan, freshHostScan, safeTimestamp } from '../packages/core/src/host-scan-contract.js';
import { fullHostReport } from './helpers/host-scan-report.js';
const python = process.env.APPGOG_TEST_PYTHON || 'python3';
const enabled = { skip: spawnSync(python, ['--version']).status !== 0 };
const agent = JSON.stringify(fileURLToPath(new URL('../scripts/host-security-agent.py', import.meta.url)));
function run(script) {
  const result = spawnSync(python, ['-c', `import importlib.util, socketserver, json
if not hasattr(socketserver, 'UnixStreamServer'): socketserver.UnixStreamServer = socketserver.TCPServer
s = importlib.util.spec_from_file_location('agent', ${agent})
a = importlib.util.module_from_spec(s); s.loader.exec_module(a)
${script}`], { encoding: 'utf8', timeout: 10000, env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  return result.stdout;
}
test('API, browser and Python retain the same fixed coverage contract', enabled, () => {
  const source = readFileSync(new URL('../apps/web/public/assets/portal/security-ui.js', import.meta.url), 'utf8');
  const match = source.match(/const HOST_SCAN_IDS = Object.freeze\(\[([\s\S]*?)\]\);/);
  assert.ok(match);
  const browserIds = [...match[1].matchAll(/'([^']+)'/g)].map(item => item[1]);
  assert.deepEqual(browserIds, HOST_SCAN_IDS);
  assert.deepEqual(JSON.parse(run('print(json.dumps(sorted(a.HOST_SCAN_IDS)))')), [...HOST_SCAN_IDS].sort());
});
test('real Python scan assembly emits exactly the fixed checks when dependencies fail', enabled, () => {
  const ids = JSON.parse(run(`
import types
class InaccessiblePath:
 def __init__(self, *args): pass
 def read_text(self, **kwargs): raise OSError('fixture inaccessible')
 def stat(self): raise OSError('fixture inaccessible')
a.Path = InaccessiblePath; a.ROOT = InaccessiblePath()
def blocked(*args, **kwargs): raise OSError('fixture unavailable')
a.subprocess.run = blocked
mapping = {
 'integrity_check':'integrity.program', 'host_configuration_check':'host.configuration',
 'container_contract_check':'container.contract', 'approved_image_check':'container.approved-image',
 'containment_check':'response.containment', 'sshd_effective_check':'ssh.effective',
 'secret_permissions_check':'permissions.secret-inventory', 'listener_posture_check':'network.listeners',
 'udp_posture_check':'network.udp-listeners', 'route_configuration_check':'network.routes',
 'kernel_security_check':'host.kernel-security', 'firewall_check':'network.firewall',
 'malware_scan':'malware.program', 'business_malware_scan':'malware.business',
 'sqlite_health_check':'database.sqlite',
 'process_posture_check':'host.process-executables', 'failed_services_check':'host.failed-units'}
for name, identifier in mapping.items():
 setattr(a, name, lambda *args, identifier=identifier: a.check(identifier, 'unavailable', 'bounded fixture', check_id=identifier))
a.cloudflare_checks = lambda: [a.check(identifier, 'unavailable', 'fixture', check_id=identifier) for identifier in sorted(a.HOST_SCAN_IDS) if identifier.startswith('cloudflare.')]
checks = a.scan()
assert a.complete_scan_checks(checks, a.datetime.now(a.timezone.utc).isoformat())
assert len(checks) == len(a.HOST_SCAN_IDS)
print(json.dumps(sorted(row['id'] for row in checks)))`));
  assert.deepEqual(ids, [...HOST_SCAN_IDS].sort());
});
test('Python refuses incomplete reports before saving history and preserves complete findings', enabled, () => {
  run(`
import copy
now = a.datetime.now(a.timezone.utc).isoformat()
checks = [a.check(identifier, 'ok', 'fixture', check_id=identifier, checked_at=now) for identifier in sorted(a.HOST_SCAN_IDS)]
invalid = [checks[1:], checks + [checks[0]], [dict(checks[0], id='foreign.id')] + checks[1:]]
for field, value in [('scope',''),('category','foreign'),('severity','panic'),('checked_at','2026-02-30T00:00:00Z'),('checked_at',now[:19]),('checked_at',(a.datetime.now(a.timezone.utc)+a.timedelta(minutes=3)).isoformat()),('evidence_digest','bad')]:
 invalid.append([dict(checks[0], **{field:value})] + checks[1:])
for value in [None, {}, [], now[:19], '2026-02-30T00:00:00Z', now.replace('+00:00','+08:00')]:
 assert not a.complete_scan_checks(checks, value)
original_save = a.save_history
for rows in invalid:
 saved=[]; a.save_history=lambda rows: saved.append(rows)
 a.scan=lambda rows=rows: copy.deepcopy(rows)
 a.run_scan()
 assert a.STATE['state']=='failed' and not saved
finding=[dict(checks[0],state='finding',severity='high')]+checks[1:]
saved=[]; a.save_history=lambda rows: saved.append(rows) or []
a.scan=lambda: copy.deepcopy(finding); a.run_scan()
assert a.STATE['state']=='finished' and saved and a.STATE['checks'][0]['state']=='finding'
def unavailable_history(rows): raise OSError('fixture unreadable')
a.save_history=unavailable_history; a.scan=lambda: copy.deepcopy(checks); a.run_scan()
assert a.STATE['state']=='finished' and a.STATE['history_state']=='unavailable'
assert a.STATE['checks'][-1]['id']=='host.history'
assert a.complete_scan_checks(a.STATE['checks'], a.STATE['checked_at'])
`);
});
test('UTC timestamps and freshness cannot be normalized into healthy evidence', () => {
  for (const stamp of ['2026-02-30T00:00:00Z','2026-10-03T00:00:00','2026-10-03T00:00:00+08:00']) assert.equal(safeTimestamp(stamp), null);
  const report = fullHostReport(); assert.equal(completeHostScan(report), true);
  const stale = fullHostReport({ overrides: { 'ssh.effective': { checked_at: '2020-01-01T00:00:00Z' } } });
  assert.equal(completeHostScan(stale), true); assert.equal(freshHostScan(stale), false);
});
