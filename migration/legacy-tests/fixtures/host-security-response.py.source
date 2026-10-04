"""Deterministic response boundary tests; mocks do not substitute Linux acceptance."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socketserver
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

if not hasattr(socketserver, 'UnixStreamServer'):
    socketserver.UnixStreamServer = socketserver.TCPServer
try:
    import fcntl
except ImportError:
    sys.modules['fcntl'] = types.SimpleNamespace()

ROOT = Path(__file__).resolve().parents[2]
def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

a = load('response_test_agent', 'host-security-agent.py')
c = load('response_test_control', 'host-security-response.py')
r = load('response_test_repair', 'host-security-repair.py')
CID = 'a' * 64
IMAGE = 'sha256:' + 'b' * 64
VERSION = json.loads((ROOT / 'package.json').read_text())['version']

class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        p = Path(self.tmp.name).resolve()
        c.ROOT = p
        c.VERSION = VERSION
        c.AGENT = a
        c.STATE = p / 'state'
        c.STATE.mkdir(mode=0o700)
        c.INCIDENT = c.STATE / 'incident.json'
        c.POLICY = c.STATE / 'response-policy.json'
        c.IMAGE = c.STATE / 'approved-image.json'
        c.DIRECTORY = p / 'independent'
        c.DIRECTORY.mkdir()
        a.ROOT = p
        a.STATE_DIR = c.STATE
        a.BASELINE = c.STATE / 'baseline.json'
        a.HOST_BASELINE = c.STATE / 'host-baseline.json'
        a.atomic_json(a.BASELINE, {'schema': 2, 'version': VERSION, 'files': {'package.json': 'a' * 64}})
        a.atomic_json(a.HOST_BASELINE, {'schema': 1, 'files': {'appgog.environment': {'missing': True}}})
        # Windows unit fixtures only: production root/path checking is exercised on Linux.
        self.addCleanup(patch.stopall)
        patch.object(c, 'trusted', lambda path, directory=False: Path(path)).start()
        self.original = {
            'Id': CID, 'Image': IMAGE,
            'Config': {'Labels': {'com.docker.compose.project': 'appgog',
                'com.docker.compose.service': 'appgog',
                'com.docker.compose.project.working_dir': str(p),
                'com.docker.compose.project.config_files': str(p / 'compose.yaml')},
                'Env': ['SECRET=must-not-be-persisted']},
            'HostConfig': {'RestartPolicy': {'Name': 'unless-stopped', 'MaximumRetryCount': 0}},
            'State': {'Running': True, 'Health': {'Status': 'healthy'}}}
        self.container = copy.deepcopy(self.original)
        self.calls = []
        self.ids = [CID]
        self.fail_stop = False
        patch.object(c, 'docker', self.docker).start()
        patch.object(a, 'scan', lambda: [a.check('program', 'ok', 'clean', check_id='integrity.program')]).start()
        for name in ('integrity_check', 'host_configuration_check', 'secret_permissions_check',
                     'malware_scan', 'business_malware_scan', 'sqlite_health_check', 'container_contract_check'):
            patch.object(a, name, lambda: {'state': 'ok'}).start()

    def docker(self, *args):
        self.calls.append(args)
        if args[0] == 'ps':
            return '\n'.join(self.ids)
        if args[0] == 'inspect':
            return json.dumps([self.container])
        if args[0] in {'update', 'stop', 'start'}:
            # Evidence must be durable before any external containment/recovery mutation.
            self.assertTrue(c.INCIDENT.exists())
        if args[0] == 'update':
            self.container['HostConfig']['RestartPolicy']['Name'] = args[1].split('=', 1)[1]
        if args[0] == 'stop':
            if self.fail_stop:
                raise RuntimeError('test stop failed')
            self.container['State']['Running'] = False
        if args[0] == 'start':
            self.container['State']['Running'] = True
        return ''

    def test_database_unknown_or_corrupt_blocks_recovery(self):
        for state in ('finding', 'unavailable'):
            with patch.object(a, 'sqlite_health_check', lambda: {'state': state}):
                with self.assertRaises(ValueError):
                    c.recovery_checks()

    def test_image_approval_rejects_host_findings_unknown_and_preserves_pin(self):
        c.approve_image(IMAGE)
        original = c.IMAGE.read_bytes()
        for state in ('finding', 'warning', 'unavailable'):
            with patch.object(a, 'host_configuration_check', lambda: {'state': state}):
                with self.assertRaises(ValueError):
                    c.approve_image(IMAGE)
                self.assertEqual(c.IMAGE.read_bytes(), original)
        self.assertEqual(c.approve_image(IMAGE)['state'], 'approved')

    def test_resume_rejects_fresh_host_login_findings_before_start(self):
        self.pinned()
        for state in ('finding', 'warning', 'unavailable'):
            with patch.object(a, 'host_configuration_check', lambda: {'state': state}):
                with self.assertRaises(ValueError):
                    c.resume('APPROVE-DATA-AND-RESUME')
                self.assertContained()
                self.assertFalse(any(call[0] == 'start' for call in self.calls))

    def pinned(self):
        c.approve_image(IMAGE)
        c.isolate()

    def assertContained(self):
        self.assertNotEqual(c.incident()['state'], 'released')
        with self.assertRaises(ValueError):
            c.dispatch(['guard'])

    def test_redacted_evidence_precedes_stop_and_is_idempotent(self):
        first = c.isolate()
        self.assertEqual(first['state'], 'contained')
        self.assertNotIn('SECRET', c.INCIDENT.read_text())
        self.assertNotIn('must-not-be-persisted', c.INCIDENT.read_text())
        self.assertEqual(self.container['HostConfig']['RestartPolicy']['Name'], 'no')
        self.assertFalse(self.container['State']['Running'])
        self.assertEqual(c.isolate()['created_at'], first['created_at'])
        self.assertTrue(all(x[-1] == CID for x in self.calls if x[0] in {'update', 'stop'}))
        self.assertFalse(any(x[0] in {'rm', 'rmi', 'volume', 'exec'} for x in self.calls))
        self.assertContained()

    def test_foreign_labels_paths_and_multiple_targets_refused(self):
        labels = self.container['Config']['Labels']
        for key, value in [('com.docker.compose.project', 'foreign'),
                           ('com.docker.compose.service', 'foreign'),
                           ('com.docker.compose.project.working_dir', '/foreign'),
                           ('com.docker.compose.project.config_files', '/foreign/compose.yaml')]:
            with self.subTest(key=key):
                old = labels[key]
                labels[key] = value
                with self.assertRaises(ValueError):
                    c.isolate()
                labels[key] = old
        self.ids.append('c' * 64)
        with self.assertRaises(ValueError):
            c.isolate()
        self.assertFalse(c.INCIDENT.exists())
        self.assertFalse(any(x[0] in {'stop', 'update'} for x in self.calls))

    def test_stop_failure_remains_fenced_and_retryable(self):
        self.fail_stop = True
        with self.assertRaises(RuntimeError):
            c.isolate()
        self.assertEqual(c.incident()['state'], 'containment_failed')
        self.assertContained()
        self.fail_stop = False
        self.assertEqual(c.evaluate()['state'], 'contained')

    def test_auto_policy_requires_two_positive_findings(self):
        self.assertEqual(c.evaluate(), {'mode': 'alert-only', 'action': 'none'})
        c.set_policy('auto-contain')
        for malware, integrity in [('ok', 'finding'), ('unavailable', 'finding'), ('finding', 'ok')]:
            patch.object(a, 'scan', lambda m=malware, i=integrity: [
                a.check('malware', m, 'test', check_id='malware.program'),
                a.check('integrity', i, 'test', check_id='integrity.program')]).start()
            self.assertEqual(c.evaluate()['action'], 'none')
        patch.object(a, 'scan', lambda: [a.check('malware', 'finding', 'test', check_id='malware.program'),
            a.check('integrity', 'finding', 'test', check_id='integrity.program')]).start()
        self.assertEqual(c.evaluate()['state'], 'contained')

    def test_image_pin_baseline_and_data_review_required(self):
        self.pinned()
        with self.assertRaises(ValueError):
            c.resume('yes')
        with self.assertRaises(ValueError):
            c.approve_image(IMAGE)
        a.atomic_json(a.BASELINE, {'schema': 2, 'version': VERSION, 'files': {'package.json': 'c' * 64}})
        with self.assertRaisesRegex(ValueError, 'baseline differs'):
            c.resume('APPROVE-DATA-AND-RESUME')
        self.assertContained()
        self.assertFalse(self.container['State']['Running'])

    def test_unknown_antivirus_and_changed_image_block_resume(self):
        self.pinned()
        with patch.object(a, 'malware_scan', lambda: {'state': 'unavailable'}):
            with self.assertRaises(ValueError):
                c.resume('APPROVE-DATA-AND-RESUME')
        self.container['Image'] = 'sha256:' + 'c' * 64
        with self.assertRaises(ValueError):
            c.resume('APPROVE-DATA-AND-RESUME')
        self.assertContained()
        self.assertFalse(self.container['State']['Running'])

    def test_business_unknown_or_finding_never_starts_or_releases(self):
        self.pinned()
        for state in ('unavailable', 'finding', 'warning'):
            before = len(self.calls)
            with patch.object(a, 'business_malware_scan', lambda: {'state': state}):
                with self.assertRaisesRegex(ValueError, 'business antivirus'):
                    c.resume('APPROVE-DATA-AND-RESUME')
            self.assertFalse(any(call[0] == 'start' for call in self.calls[before:]))
            self.assertFalse(self.container['State']['Running'])
            self.assertContained()

    def test_contract_failure_stops_recovery_and_records_failed_recontainment(self):
        self.pinned()
        with patch.object(a, 'container_contract_check', lambda: {'state': 'finding'}):
            with self.assertRaises(ValueError):
                c.resume('APPROVE-DATA-AND-RESUME')
        self.assertFalse(self.container['State']['Running'])
        self.assertContained()
        self.fail_stop = True
        with patch.object(a, 'container_contract_check', lambda: {'state': 'finding'}):
            with self.assertRaises(RuntimeError):
                c.resume('APPROVE-DATA-AND-RESUME')
        self.assertEqual(c.incident()['state'], 'containment_failed')
        self.assertContained()

    def test_reviewed_false_positive_restores_policy_and_keeps_audit(self):
        self.pinned()
        created = c.incident()['created_at']
        self.assertEqual(c.resume('APPROVE-DATA-AND-RESUME')['state'], 'released')
        self.assertTrue(self.container['State']['Running'])
        self.assertEqual(self.container['HostConfig']['RestartPolicy']['Name'], 'unless-stopped')
        self.assertEqual(c.incident()['created_at'], created)
        self.assertEqual(c.dispatch(['guard']), {'state': 'clear'})

    def archive(self, extra=(), version=VERSION):
        buffer = io.BytesIO()
        prefix = 'APPGOG-Packaging-Licensing-System-' + version + '/'
        with zipfile.ZipFile(buffer, 'w') as z:
            z.writestr(prefix + 'package.json', json.dumps({'version': version}))
            for name in ('compose.yaml', 'compose.license.yaml', 'compose.build.yaml', 'scripts/host-security-agent.py'):
                z.writestr(prefix + name, 'trusted')
            for name, value in extra:
                entry = zipfile.ZipInfo()
                entry.filename = prefix + name  # Preserve malicious separators even on Windows.
                z.writestr(entry, value)
        return buffer.getvalue()

    def test_zip_paths_duplicates_special_files_and_root_entries_rejected(self):
        self.assertEqual(len(r.validated_entries(self.archive(), VERSION)), 5)
        symbolic = zipfile.ZipInfo('scripts/link')
        # archive() prepends the release prefix; create the link fixture directly.
        symbolic.filename = 'APPGOG-Packaging-Licensing-System-' + VERSION + '/scripts/link'
        symbolic.create_system = 3
        symbolic.external_attr = (stat.S_IFLNK | 0o777) << 16
        for extra in [('../escape', 'bad'), ('package.json', '{}'), ('evil.txt', 'bad'),
                      ('scripts\\escape', 'bad')]:
            with self.subTest(extra=extra[0]), self.assertRaises(ValueError):
                r.validated_entries(self.archive([extra]), VERSION)
        buffer = io.BytesIO(self.archive())
        with zipfile.ZipFile(buffer, 'a') as z:
            z.writestr(symbolic, '/etc/shadow')
        with self.assertRaises(ValueError):
            r.validated_entries(buffer.getvalue(), VERSION)

    def test_bad_signature_and_implicit_version_switch_refused(self):
        bundle = c.ROOT / 'bundle'
        bundle.mkdir()
        (bundle / 'release-manifest.json').write_text('{}')
        (bundle / 'release-manifest.json.sig').write_bytes(b'x' * 64)
        with patch.object(r.subprocess, 'run', lambda *args, **kw: types.SimpleNamespace(returncode=1)):
            with self.assertRaisesRegex(ValueError, 'signature rejected'):
                r.cache(c, bundle)
        with self.assertRaisesRegex(ValueError, 'no implicit upgrade/downgrade'):
            r.repair(c, '0.0.1')
        self.assertFalse((c.STATE / 'trusted-releases').exists())

if __name__ == '__main__':
    unittest.main()
