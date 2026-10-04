import importlib.util
import json
import os
from pathlib import Path
import socketserver
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
if not hasattr(socketserver, 'UnixStreamServer'):
    socketserver.UnixStreamServer = socketserver.TCPServer

def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

c = module('cloudflare', 'host-security-cloudflare.py')
a = module('agent', 'host-security-agent.py')
ZONE = 'a' * 32
ID = 'b' * 32
SECRET = 'DO_NOT_EXPOSE_TOKEN_VALUE_12345'
CONFIG = {'schema': 1, 'zone_id': ZONE}

class FakeClient:
    def __init__(self):
        self.calls = []
        self.changed = False
    def get(self, path):
        self.calls.append(path)
        if '/dns_records?' in path:
            return {'result': [{'id': ID, 'name': 'auth.example.test', 'type': 'A', 'content': '203.0.113.20' if self.changed else '203.0.113.10', 'ttl': 1, 'proxied': True}], 'result_info': {'page': 1, 'count': 1, 'total_count': 1, 'total_pages': 1}}
        if path.endswith('/workers/routes'):
            return {'result': [{'id': ID, 'pattern': 'example.test/*', 'script': 'release-worker'}]}
        if '/rulesets?per_page=50' in path:
            return {'result': [{'id': ID}]}
        if '/rulesets/' in path:
            return {'result': {'id': ID, 'rules': [{'id': 'rule', 'expression': 'true', 'action': 'block'}]}}
        if path.endswith('/pagerules'):
            return {'result': [{'id': ID, 'targets': [], 'actions': [], 'status': 'active'}]}
        if '/settings/' in path:
            key = path.rsplit('/', 1)[1]
            return {'result': {'id': key, 'value': 'strict'}}
        return {'result': {'id': ZONE, 'paused': False, 'name_servers': ['ns.example.test'], 'status': 'active'}}

class CloudflareTests(unittest.TestCase):
    def snapshots(self):
        return c.capture(CONFIG, FakeClient())
    def baseline(self, snapshots):
        return {'schema': 1, 'zone_id': ZONE, 'approved_at': c.now(), 'snapshots': snapshots}

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'root private-file integration')
    def test_real_private_files_reject_links_modes_and_oversize(self):
        parent = Path('/appgog-host-security-ci')
        if not parent.is_dir():
            parent = Path('/root')
        with tempfile.TemporaryDirectory(dir=parent) as temporary:
            directory = Path(temporary)
            target = directory / 'identity'
            c.write_private(target, SECRET.encode())
            self.assertEqual(c.read_private(target), SECRET.encode())
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError): c.read_private(target, 8)
            target.chmod(0o644)
            with self.assertRaises(ValueError): c.read_private(target)
            target.chmod(0o600)
            alias = directory / 'alias'
            alias.symlink_to(target)
            with self.assertRaises(OSError): c.read_private(alias)
            os.link(target, directory / 'hardlink')
            with self.assertRaises(ValueError): c.read_private(target)
            nested = directory / 'private' / 'report.json'
            c.write_json(nested, {'schema': 1})
            self.assertEqual(json.loads(c.read_private(nested)), {'schema': 1})

    def test_complete_snapshots_are_semantic_and_secret_free(self):
        fake = FakeClient()
        snapshots = c.capture(CONFIG, fake)
        self.assertTrue(all(row is not None for row in snapshots.values()))
        baseline = self.baseline(snapshots)
        self.assertTrue(c.valid_baseline(baseline, CONFIG))
        self.assertTrue(all(row['state'] == 'ok' for row in c.result_rows(snapshots, baseline)))
        serialized = json.dumps(snapshots)
        self.assertNotIn('203.0.113.10', serialized)
        self.assertNotIn('expression', serialized)
        fake.changed = True
        changed = c.capture(CONFIG, fake)
        self.assertEqual(c.result_rows(changed, baseline)[0]['state'], 'finding')
        self.assertEqual(baseline['snapshots'], snapshots)
        self.assertTrue(all(path.startswith('/zones/' + ZONE) for path in fake.calls))

    def test_cursor_pagination_cannot_be_reported_complete(self):
        for info in ({'cursors': {'after': 'another-page'}}, {'cursor': 'another-page'}, {'cursors': []}):
            with self.subTest(info=info), self.assertRaises(ValueError):
                c.list_result({'result': [], 'result_info': info})

    def test_ruleset_cursor_pages_are_complete_unique_and_bounded(self):
        first = {'result': [{'id': ID}], 'result_info': {'cursors': {'after': 'next+/='}}}
        last = {'result': [{'id': 'c' * 32}]}
        fake = SimpleNamespace(get=Mock(side_effect=[first, last]))
        self.assertEqual(len(c.ruleset_listing(fake, '/zones/' + ZONE)), 2)
        self.assertEqual(fake.get.call_args.args[0], '/zones/' + ZONE + '/rulesets?per_page=50&cursor=next%2B%2F%3D')
        for pages in [[first, first], [dict(first, result=[])] , [dict(first, result=[{}] * 17)]]:
            client = SimpleNamespace(get=__import__('unittest.mock', fromlist=['Mock']).Mock(side_effect=pages))
            with self.assertRaises(ValueError):
                c.ruleset_listing(client, '/zones/' + ZONE)

    def test_read_failure_and_missing_baseline_cannot_be_clean(self):
        snapshots = self.snapshots()
        self.assertTrue(all(row['state'] == 'unavailable' for row in c.result_rows(snapshots, None)))
        with patch.object(FakeClient, 'get', side_effect=PermissionError(SECRET)):
            partial = c.capture(CONFIG, FakeClient())
        rows = c.result_rows(partial, self.baseline(snapshots))
        self.assertTrue(all(row['state'] == 'unavailable' for row in rows))
        self.assertNotIn(SECRET, json.dumps(rows))
        with patch.object(c, 'load_config', side_effect=ValueError(SECRET)), patch.object(c, 'write_json') as write:
            report = c.collect_safe()
            self.assertEqual(write.call_count, 1)
            self.assertNotIn(SECRET, json.dumps(report))

    def test_incomplete_pagination_duplicates_and_shape_rejected(self):
        examples = [
            {'result': [], 'result_info': {'page': 1, 'total_count': 2, 'total_pages': 1}},
            {'result': [], 'result_info': {'page': 1, 'total_count': 5000, 'total_pages': 5}},
            {'result': [{'id': ID}, {'id': ID}], 'result_info': {'page': 1, 'total_count': 2, 'total_pages': 1}},
            {'result': [{'id': ID, 'name': 'x', 'type': 'A', 'content': 'x'}], 'result_info': {'page': 1, 'total_count': 1, 'total_pages': 1}},
            {'result': [], 'result_info': {'page': 1, 'total_count': True, 'total_pages': 1}},
        ]
        for value in examples:
            with self.subTest(value=value):
                client = SimpleNamespace(get=lambda path: value)
                with self.assertRaises(ValueError):
                    c.dns_snapshot(client, '/zones/' + ZONE)
        with self.assertRaises(ValueError):
            c.list_result({'result': [], 'result_info': {'total_count': 100, 'total_pages': 2}})

    def test_request_transport_is_get_only_tls_verified_no_proxy_or_redirect(self):
        response = SimpleNamespace(status=200, geturl=lambda: c.API + '/zones/' + ZONE)
        parts = iter([b'{"success":true,"errors":[],"result":{}}', b''])
        response.read = lambda size: next(parts)
        class Context:
            def __enter__(self): return response
            def __exit__(self, *args): pass
        calls = []
        client = c.Client(SECRET)
        client.opener = SimpleNamespace(open=lambda request, timeout: (calls.append((request, timeout)) or Context()))
        self.assertEqual(client.get('/zones/' + ZONE)['result'], {})
        request, timeout = calls[0]
        self.assertEqual(request.get_method(), 'GET')
        self.assertEqual(request.get_header('Authorization'), 'Bearer ' + SECRET)
        self.assertIsNone(request.data)
        for invalid in ['/accounts/' + ZONE, '/zones/' + ZONE + '/settings/ssl?write=true', 'https://evil.test/', '/zones/' + ZONE + '/dns_records/../tokens']:
            with self.assertRaises(ValueError): client.get(invalid)
        self.assertEqual(len(calls), 1)
        with self.assertRaises(ValueError): c.NoRedirect().redirect_request(None, None, 302, '', None, 'https://evil.test')
        self.assertEqual(ssl.create_default_context().verify_mode, ssl.CERT_REQUIRED)
        client.requests = c.MAX_REQUESTS
        with self.assertRaises(ValueError): client.get('/zones/' + ZONE)

    def test_api_failures_oversize_and_wrong_final_url_rejected(self):
        class Response:
            status = 200
            def __init__(self, content, url): self.content, self.url = content, url
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def geturl(self): return self.url
            def read(self, size):
                value, self.content = self.content[:size], self.content[size:]
                return value
        for content, url in [(b'x' * (c.MAX_BYTES + 1), c.API + '/zones/' + ZONE), (b'{"success":false,"result":[]}', c.API + '/zones/' + ZONE), (b'{}', 'https://evil.test')]:
            client = c.Client(SECRET)
            client.opener = SimpleNamespace(open=lambda request, timeout: Response(content, url))
            with self.assertRaises(ValueError): client.get('/zones/' + ZONE)

    def test_approval_requires_exact_complete_candidate_and_never_auto_learns(self):
        snapshots = self.snapshots()
        fingerprint = c.digest({'zone_id': ZONE, 'snapshots': snapshots})
        with patch.object(c, 'collect', return_value=(CONFIG, snapshots, {})), patch.object(c, 'collect_safe'), patch.object(c, 'write_json') as write:
            with self.assertRaises(ValueError): c.approve('0' * 64)
            write.assert_not_called()
            c.approve(fingerprint)
            self.assertEqual(write.call_args.args[0], c.BASELINE)
            self.assertTrue(c.valid_baseline(write.call_args.args[1], CONFIG))
        partial = dict(snapshots, dns=None)
        with patch.object(c, 'collect', return_value=(CONFIG, partial, {})), patch.object(c, 'write_json') as write:
            with self.assertRaises(ValueError): c.approve(c.digest({'zone_id': ZONE, 'snapshots': partial}))
            write.assert_not_called()

    def test_stale_future_partial_reports_and_missing_evidence_are_unknown(self):
        snapshots = self.snapshots()
        rows = c.result_rows(snapshots, self.baseline(snapshots))
        report = {'schema': 1, 'checked_at': c.now(), 'checks': rows}
        with patch.object(a, 'read_state', return_value=json.dumps(report).encode()):
            results = a.cloudflare_checks()
            self.assertEqual(len(results), 4)
            self.assertTrue(all(row['state'] == 'ok' for row in results))
            self.assertTrue(all(a.history_item(row)['category'] == 'network' for row in results))
        for delta in [-901, 121]:
            bad = dict(report, checked_at=(datetime.now(timezone.utc) + timedelta(seconds=delta)).isoformat())
            with patch.object(a, 'read_state', return_value=json.dumps(bad).encode()):
                self.assertTrue(all(row['state'] == 'unavailable' for row in a.cloudflare_checks()))
        for bad in [dict(report, checks=rows[:3]), dict(report, checks=[dict(rows[0], evidence=None), *rows[1:]]), dict(report, checks=[rows[1], rows[0], *rows[2:]])]:
            with patch.object(a, 'read_state', return_value=json.dumps(bad).encode()):
                self.assertTrue(all(row['state'] == 'unavailable' for row in a.cloudflare_checks()))

    def test_actual_private_report_bytes_and_malformed_json(self):
        rows = c.result_rows(self.snapshots(), self.baseline(self.snapshots()))
        with tempfile.TemporaryDirectory() as tmp, patch.object(a, 'STATE_DIR', Path(tmp)):
            target = Path(tmp) / 'cloudflare-report.json'
            a.atomic_json(target, {'schema': 1, 'checked_at': c.now(), 'checks': rows})
            self.assertIsInstance(a.read_state(target), bytes)
            self.assertTrue(all(row['state'] == 'ok' for row in a.cloudflare_checks()))
            target.write_bytes(b'{incomplete')
            self.assertTrue(all(row['state'] == 'unavailable' for row in a.cloudflare_checks()))
            if os.name == 'posix':
                a.atomic_json(target, {'schema': 1, 'checked_at': c.now(), 'checks': rows})
                target.chmod(0o644)
                self.assertTrue(all(row['state'] == 'unavailable' for row in a.cloudflare_checks()))

    def test_failed_service_state_not_description_is_used(self):
        with patch.object(a, 'bounded_command_output', return_value=b'bad.service loaded failed failed Description with spaces\n'):
            self.assertEqual(a.failed_services_check()['state'], 'warning')
        with patch.object(a, 'bounded_command_output', return_value=b''):
            self.assertEqual(a.failed_services_check()['state'], 'ok')
        for raw in [b'bad.service loaded active running forged\n', b'bad data\n', b'x' * 2049]:
            with patch.object(a, 'bounded_command_output', return_value=raw):
                self.assertEqual(a.failed_services_check()['state'], 'unavailable')

    def test_process_inventory_is_bounded_and_does_not_read_cmdline(self):
        class Entries:
            def __enter__(self): return iter([SimpleNamespace(name='1'), SimpleNamespace(name='2')])
            def __exit__(self, *args): pass
        with patch.object(a.os, 'scandir', return_value=Entries()), patch.object(a.os, 'readlink', side_effect=['/usr/bin/python3', '/tmp/malware (deleted)']):
            row = a.process_posture_check()
            self.assertEqual(row['state'], 'warning')
            self.assertNotIn('/tmp/malware', json.dumps(row))
        with patch.object(a.os, 'scandir', return_value=Entries()), patch.object(a.os, 'readlink', side_effect=PermissionError):
            self.assertEqual(a.process_posture_check()['state'], 'unavailable')

    @unittest.skipUnless(sys.platform == 'linux', 'POSIX bounded pipe selector')
    def test_real_bounded_command_output(self):
        self.assertEqual(a.bounded_command_output([sys.executable, '-c', 'print("good")']), b'good\n')
        with self.assertRaises(ValueError):
            a.bounded_command_output([sys.executable, '-c', 'import sys; sys.stdout.write("x"*300000)'])
        with self.assertRaises(ValueError):
            a.bounded_command_output([sys.executable, '-c', 'raise SystemExit(2)'])

if __name__ == '__main__':
    unittest.main()
