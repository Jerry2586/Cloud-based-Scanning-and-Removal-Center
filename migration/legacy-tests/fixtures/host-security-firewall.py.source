import importlib.util
import copy
import json
import os
from pathlib import Path
import socketserver
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from datetime import datetime, timezone, timedelta
if not hasattr(socketserver, 'UnixStreamServer'):
    socketserver.UnixStreamServer = socketserver.TCPServer
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('firewall', ROOT / 'scripts/host-security-firewall.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
a = f.agent
META = {'metainfo': {'json_schema_version': 1}}
NFT = {'nftables': [META, {'table': {'family': 'inet', 'name': 'filter'}},
    {'chain': {'family': 'inet', 'table': 'filter', 'name': 'input', 'policy': 'drop'}},
    {'rule': {'family': 'inet', 'table': 'filter', 'chain': 'input', 'expr': [{'accept': None}]}},
    {'set': {'family': 'inet', 'table': 'filter', 'name': 'allowed', 'elem': ['203.0.113.10']}}]}
IPT = b'*filter\n:INPUT DROP [12:340]\n-A INPUT -p tcp --dport 443 -j ACCEPT\nCOMMIT\n'
def raw(item=NFT): return json.dumps(item).encode()
def snapshot(rules=1):
    sources = {name: {'digest': 'a' * 64, 'rules': rules} for name in ('nftables', 'iptables', 'ip6tables')}
    return {'digest': f.digest(sources), 'sources': sources, 'rules': 3 * rules}

class Firewall(unittest.TestCase):
    def test_nft_policy_order_and_set_changes_are_hashed(self):
        original = f.nft_snapshot(raw())
        for index, field, value in [(2, 'policy', 'accept'), (4, 'elem', ['203.0.113.11'])]:
            changed = copy.deepcopy(NFT)
            next(iter(changed['nftables'][index].values()))[field] = value
            self.assertNotEqual(original, f.nft_snapshot(raw(changed)))
        changed = copy.deepcopy(NFT)
        changed['nftables'][1:3] = reversed(changed['nftables'][1:3])
        self.assertNotEqual(original, f.nft_snapshot(raw(changed)))
        self.assertEqual(original['rules'], 1)
        self.assertEqual(f.nft_snapshot(raw({'nftables': [META]}))['rules'], 0)

    def test_nft_invalid_schema_and_resource_budgets(self):
        invalid = [b'{"nftables":[],"nftables":[]}', b'x' * 262145,
            raw({'nftables': []}), raw({'nftables': [META, META]}),
            raw({'nftables': [{'metainfo': {'json_schema_version': True}}]}),
            raw({'nftables': [META, {'unexpected': {}}]}), raw({'nftables': [META, {'rule': None}]}),
            raw({'nftables': [META] * 4097}), raw({'nftables': [META, {'rule': {'value': 1.2}}]})]
        nested = 'leaf'
        for _ in range(34): nested = [nested]
        invalid.append(raw({'nftables': [META, {'rule': {'nested': nested}}]}))
        for item in invalid:
            with self.subTest(size=len(item)), self.assertRaises((ValueError, RecursionError)):
                f.nft_snapshot(item)
        with self.assertRaises(ValueError): f.validate_json_budget([0] * 32768)

    def test_iptables_counters_comments_ignored_configuration_retained(self):
        expected = f.iptables_snapshot(IPT)
        self.assertEqual(expected, f.iptables_snapshot(b'# new timestamp\n' + IPT.replace(b'[12:340]', b'[90:450]') + b'# completed\n'))
        self.assertNotEqual(expected, f.iptables_snapshot(IPT.replace(b'DROP', b'ACCEPT')))
        self.assertNotEqual(expected, f.iptables_snapshot(IPT.replace(b'443', b'8443')))
        self.assertEqual(expected['rules'], 1)
        for item in [b'COMMIT\n', b'*filter\n', b'*filter\n*nat\nCOMMIT\n', b'-A INPUT -j ACCEPT\n', b'*filter\n:INPUT ACCEPT [x:0]\nCOMMIT\n', b'*filter\n-X INPUT\nCOMMIT\n', b'x' * 262145, b'*filter\n' + b'-A INPUT -j ACCEPT\n' * 8193 + b'COMMIT\n']:
            with self.assertRaises(ValueError): f.iptables_snapshot(item)

    def test_summary_strict_binding(self):
        item = snapshot()
        self.assertTrue(f.valid_snapshot(item)); self.assertTrue(a.valid_firewall_snapshot(item))
        invalid = [dict(item, rules=True), dict(item, rules=1), dict(item, digest='0'*64), dict(item, extra=True), dict(item, digest=123)]
        missing = copy.deepcopy(item); del missing['sources']['ip6tables']; invalid.append(missing)
        bad = copy.deepcopy(item); bad['sources']['nftables']['rules'] = True; invalid.append(bad)
        bad_hash = copy.deepcopy(item); bad_hash['sources']['nftables']['digest'] = 123; invalid.append(bad_hash)
        for value in invalid:
            self.assertFalse(f.valid_snapshot(value)); self.assertFalse(a.valid_firewall_snapshot(value))

    def test_installation_contract_rejects_boolean_schema(self):
        with patch.object(a, 'read_state', return_value=json.dumps({'schema': True, 'root': '/opt/appgog'}).encode()):
            with self.assertRaises(ValueError): f.installation_root()

    def test_fixed_commands_optional_absence_and_namespace_guard(self):
        def available(path):
            if 'legacy' in path: raise FileNotFoundError
            return path
        def output(command): return raw() if command[0].endswith('/nft') else IPT
        with patch.object(f, 'host_namespace', return_value=True), patch.object(f, 'trusted_executable', side_effect=available), patch.object(f.Path, 'is_symlink', return_value=False), patch.object(a, 'bounded_command_output', side_effect=output) as run:
            current = f.snapshot()
            self.assertEqual(len(current['sources']), 3)
            self.assertEqual(run.call_count, 6)
            self.assertIn(['/usr/sbin/iptables-save', '-M', '/bin/false'], [x.args[0] for x in run.call_args_list])
        # Absence fixture must not depend on installed distro alternatives. A
        # genuinely dangling optional alias remains a production failure.
        with patch.object(f, 'host_namespace', return_value=True), patch.object(f, 'COMMANDS', (('iptables-legacy', '/fixed/dangling', (), False),)), patch.object(f, 'trusted_executable', side_effect=FileNotFoundError()), patch.object(f.Path, 'is_symlink', return_value=True):
            with self.assertRaises(ValueError): f.snapshot_once()
        with patch.object(f, 'host_namespace', return_value=False), patch.object(a, 'bounded_command_output') as run:
            with self.assertRaises(ValueError): f.snapshot_once()
            run.assert_not_called()
        for failure in [FileNotFoundError(), ValueError('unsafe')]:
            with patch.object(f, 'host_namespace', return_value=True), patch.object(f, 'trusted_executable', side_effect=failure):
                with self.assertRaises(ValueError): f.snapshot_once()

    def test_container_detector_failure_never_claims_host(self):
        metadata = SimpleNamespace(st_dev=7, st_ino=9, st_uid=0, st_mode=0o100444)
        with patch.object(f.os, 'stat', return_value=metadata), patch.object(f, 'trusted_executable', return_value='/usr/bin/systemd-detect-virt'):
            for code, expected in [(0, False), (1, True)]:
                with patch.object(f.subprocess, 'run', return_value=SimpleNamespace(returncode=code)) as run:
                    self.assertEqual(f.host_namespace(), expected)
                    self.assertEqual(run.call_args.args[0], ['/usr/bin/systemd-detect-virt', '--container', '--quiet'])
            with patch.object(f.subprocess, 'run', return_value=SimpleNamespace(returncode=2)):
                with self.assertRaises(ValueError): f.host_namespace()
            with patch.object(f.subprocess, 'run', side_effect=subprocess.TimeoutExpired('fixed', 2)):
                with self.assertRaises(subprocess.TimeoutExpired): f.host_namespace()

    def test_private_namespace_proof_is_fresh_for_exact_activation_and_boot(self):
        own = SimpleNamespace(st_dev=7, st_ino=9)
        proof = {'schema': 1, 'invocation': 'a' * 32, 'boot': 'b' * 36, 'created': 990, 'dev': 7, 'ino': 9}
        with patch.object(f, 'SERVICE_COLLECTION', True), patch.object(f.os, 'stat', return_value=own) as probe, patch.object(a, 'read_state', return_value=json.dumps(proof).encode()), patch.object(f, 'invocation_id', return_value='a'*32), patch.object(f, 'boot_id', return_value='b'*36), patch.object(f.time, 'monotonic', return_value=1000), patch.object(f, 'trusted_executable', return_value='/usr/bin/systemd-detect-virt'), patch.object(f.subprocess, 'run', return_value=SimpleNamespace(returncode=1)):
            self.assertTrue(f.host_namespace())
            self.assertNotIn('/proc/1/ns/net', [call.args[0] for call in probe.call_args_list])
            for change in ({'schema': True}, {'invocation':'c'*32}, {'boot':'c'*36}, {'created':879}, {'created':1001}, {'created':True}, {'created':float('nan')}, {'created':float('inf')}, {'created':10**500}, {'dev':True}, {'dev':-1}, {'ino':2**64}, {'extra':'bad'}):
                with self.subTest(change=change), patch.object(a, 'read_state', return_value=json.dumps(proof | change).encode()):
                    with self.assertRaises(ValueError): f.host_namespace()
            for change in ({'dev':8}, {'ino':10}):
                with patch.object(a, 'read_state', return_value=json.dumps(proof | change).encode()):
                    self.assertFalse(f.host_namespace())
            for error in (FileNotFoundError(), PermissionError(13, 'permission denied')):
                with patch.object(a, 'read_state', side_effect=error):
                    with self.assertRaises(OSError): f.host_namespace()
            with patch.object(a, 'read_state', return_value=b'{}'):
                with self.assertRaises(ValueError): f.host_namespace()

    def test_root_cli_ignores_proof_and_denied_init_access_never_falls_back(self):
        own = SimpleNamespace(st_dev=7, st_ino=9)
        with patch.object(f.os, 'stat', side_effect=[own, PermissionError(13, 'denied')]), patch.object(a, 'read_state') as state:
            with self.assertRaises(PermissionError): f.host_namespace()
            state.assert_not_called()
        with patch.object(f.os.environ, 'get', return_value='invalid'):
            with self.assertRaises(ValueError): f.invocation_id()

    def test_privileged_preflight_records_only_identity_and_rejects_other_namespace(self):
        own = SimpleNamespace(st_dev=7, st_ino=9)
        with patch.object(f, 'invocation_id', return_value='a'*32), patch.object(f, 'boot_id', return_value='b'*36), patch.object(f.time, 'monotonic', return_value=1000), patch.object(f.os, 'stat', return_value=own), patch.object(a, 'atomic_json') as write:
            f.prepare_namespace()
            self.assertEqual(write.call_args.args, (f.NAMESPACE_PROOF, {'schema':1, 'invocation':'a'*32, 'boot':'b'*36, 'created':1000, 'dev':7, 'ino':9}))
            with patch.object(f.os, 'stat', side_effect=[own, SimpleNamespace(st_dev=8, st_ino=9)]):
                with self.assertRaises(ValueError): f.prepare_namespace()
            self.assertEqual(write.call_count, 1)

    def test_capture_races_and_deadlines_are_rejected(self):
        with patch.object(f, 'snapshot_once', side_effect=[snapshot(), snapshot(0)]):
            with self.assertRaises(ValueError): f.snapshot()
        with patch.object(f, 'host_namespace', return_value=True), patch.object(f.time, 'monotonic', return_value=2), patch.object(a, 'bounded_command_output') as run:
            with self.assertRaises(ValueError): f.snapshot_once(1)
            run.assert_not_called()
        with patch.object(f, 'host_namespace', return_value=True), patch.object(f, 'trusted_executable', side_effect=lambda p:p), patch.object(f.time, 'monotonic', side_effect=[0, 2]), patch.object(a, 'bounded_command_output', return_value=raw()):
            with self.assertRaises(ValueError): f.snapshot_once(1)

    def test_approval_exact_digest_and_collection_failures_preserve_baseline(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(f, 'BASELINE', Path(tmp)/'base.json'), patch.object(f, 'REPORT', Path(tmp)/'report.json'), patch.object(f, 'installation_root', return_value=str(a.ROOT)):
            current = snapshot()
            with patch.object(f, 'snapshot', return_value=current):
                for value in ['0'*64, 'short', current['digest'].upper()]:
                    with self.assertRaises(ValueError): f.approve(value)
                    self.assertFalse(f.BASELINE.exists())
                f.approve(current['digest'])
                old = f.BASELINE.read_bytes()
                self.assertEqual(json.loads(f.REPORT.read_bytes())['state'], 'finished')
            with patch.object(f, 'snapshot', side_effect=ValueError('partial')):
                self.assertEqual(f.collect()['state'], 'unavailable')
                with self.assertRaises(ValueError): f.approve(current['digest'])
            self.assertEqual(f.BASELINE.read_bytes(), old)

    def test_approval_followup_must_finish_before_baseline_changes(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(f, 'BASELINE', Path(tmp)/'base.json'), patch.object(f, 'REPORT', Path(tmp)/'report.json'), patch.object(f, 'installation_root', return_value=str(a.ROOT)):
            previous, current = snapshot(0), snapshot()
            with patch.object(f, 'snapshot', return_value=previous):
                f.approve(previous['digest'])
            old = f.BASELINE.read_bytes()
            for following in [ValueError('partial'), snapshot(0)]:
                with patch.object(f, 'snapshot', side_effect=[current, following]):
                    with self.assertRaises(ValueError): f.approve(current['digest'])
                self.assertEqual(f.BASELINE.read_bytes(), old)
            write = a.atomic_json
            def failed_report(path, value):
                if path == f.REPORT:
                    raise OSError('report write failed')
                return write(path, value)
            with patch.object(f, 'snapshot', return_value=current), patch.object(a, 'atomic_json', side_effect=failed_report):
                with self.assertRaises(OSError): f.approve(current['digest'])
            self.assertEqual(f.BASELINE.read_bytes(), old)
            with patch.object(f, 'snapshot', return_value=current):
                f.approve(current['digest'])
            self.assertEqual(json.loads(f.BASELINE.read_bytes())['snapshot'], current)
            self.assertEqual(json.loads(f.REPORT.read_bytes())['snapshot'], current)

    def test_report_real_private_bytes_states_and_baseline_preservation(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(a, 'STATE_DIR', Path(tmp)):
            target, baseline = Path(tmp)/'firewall-report.json', Path(tmp)/'firewall-baseline.json'
            current = snapshot()
            report = {'schema': 1, 'root': str(a.ROOT), 'state': 'finished', 'checked_at': datetime.now(timezone.utc).isoformat(), 'snapshot': current}
            self.assertEqual(a.firewall_check()['state'], 'unavailable')
            a.atomic_json(target, report)
            self.assertIsInstance(a.read_state(target), bytes)
            self.assertEqual(a.firewall_check()['state'], 'warning')
            approved = {'schema': 1, 'root': str(a.ROOT), 'approved_at': datetime.now(timezone.utc).isoformat(), 'snapshot': current}
            a.atomic_json(baseline, approved)
            self.assertEqual(a.firewall_check()['state'], 'ok')
            original = baseline.read_bytes()
            a.atomic_json(target, dict(report, snapshot=snapshot(0)))
            self.assertEqual(a.firewall_check()['state'], 'finding')
            self.assertEqual(baseline.read_bytes(), original)
            a.atomic_json(baseline, dict(approved, snapshot=snapshot(0)))
            self.assertEqual(a.firewall_check()['state'], 'warning')
            for item in [dict(report, root='/foreign'), dict(report, state='unavailable'), dict(report, schema=True), dict(report, snapshot=dict(current, digest='0'*64)), dict(report, checked_at='bad')]:
                a.atomic_json(target, item)
                self.assertEqual(a.firewall_check()['state'], 'unavailable')
            for delta in [-901, 121]:
                a.atomic_json(target, dict(report, checked_at=(datetime.now(timezone.utc)+timedelta(seconds=delta)).isoformat()))
                self.assertEqual(a.firewall_check()['state'], 'unavailable')
            a.atomic_json(target, report)
            for item in [dict(approved, root='/foreign'), dict(approved, approved_at='bad'), dict(approved, approved_at=(datetime.now(timezone.utc)+timedelta(seconds=121)).isoformat())]:
                a.atomic_json(baseline, item)
                self.assertEqual(a.firewall_check()['state'], 'unavailable')
            if os.name == 'posix':
                a.atomic_json(baseline, approved)
                target.chmod(0o644)
                self.assertEqual(a.firewall_check()['state'], 'unavailable')

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'root POSIX executable trust')
    def test_executable_alias_preserves_multicall_name_rejects_mutable_path(self):
        with tempfile.TemporaryDirectory(dir='/root') as tmp:
            base = Path(tmp); executable = base/'multi'; executable.write_bytes(b'fixed'); executable.chmod(0o700)
            alias = base/'iptables-save'; alias.symlink_to(executable)
            self.assertEqual(f.trusted_executable(str(alias)), str(alias))
            executable.chmod(0o777)
            with self.assertRaises(ValueError): f.trusted_executable(str(alias))
            executable.chmod(0o700); base.chmod(0o777)
            with self.assertRaises(ValueError): f.trusted_executable(str(alias))
            base.chmod(0o700); alias.unlink(); alias.symlink_to(base/'missing')
            with self.assertRaises(OSError): f.trusted_executable(str(alias))

if __name__ == '__main__': unittest.main()
