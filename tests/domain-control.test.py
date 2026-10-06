#!/usr/bin/env python3
"""Linux root regression: real HTTP parser, bounded DNS and simulated service transactions."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import domain_control as dc
import shared_ingress as si

class ProbeTests(unittest.TestCase):
    def serve(self, handler):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        listener.settimeout(2)
        port = listener.getsockname()[1]
        def run():
            try:
                client, _ = listener.accept()
                with client:
                    client.settimeout(2)
                    client.recv(4096)
                    handler(client)
            except (OSError, TimeoutError):
                pass
            finally:
                listener.close()
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.addCleanup(lambda: thread.join(3))
        original = socket.create_connection
        def connect(address, timeout):
            self.assertEqual(address, ('93.184.215.14', 80))
            return original(('127.0.0.1', port), timeout)
        return patch.object(dc.socket, 'create_connection', side_effect=connect)

    def probe(self, handler, value=b'expected', timeout=1):
        with self.serve(handler), patch.object(dc, 'public_addresses', return_value=['93.184.215.14']), patch.object(dc, 'PROBE_TIMEOUT', timeout):
            return dc.probe('guard.example.com', '/.well-known/acme-challenge/fixed', value)

    def test_actual_http_exact_body(self):
        self.probe(lambda c: c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nexpected'))

    def test_wrong_role_and_oversized_body_fail_closed(self):
        for value in [b'other-app', b'x' * 4097]:
            with self.subTest(size=len(value)), self.assertRaises(dc.DomainError):
                self.probe(lambda c: c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(value)).encode() + b'\r\n\r\n' + value))

    def test_chunked_response_requires_exact_bounded_content(self):
        self.probe(lambda c: c.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nexpe\r\n4\r\ncted\r\n0\r\n\r\n'))

    def test_slow_body_and_headers_have_total_deadline(self):
        for header in [b'HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n', b'HTTP/1.1 200 OK\r\nX-Slow: ']:
            def drip(c):
                c.sendall(header)
                for _ in range(40):
                    c.sendall(b'x')
                    time.sleep(0.03)
            began = time.monotonic()
            with self.assertRaises(dc.DomainError):
                self.probe(drip, timeout=0.2)
            self.assertLess(time.monotonic() - began, 1)

    def test_cross_domain_and_plaintext_redirects_rejected(self):
        for target in [b'https://other.example.com/', b'http://guard.example.com/']:
            with self.subTest(target=target), self.assertRaises(dc.DomainError):
                self.probe(lambda c: c.sendall(b'HTTP/1.1 302 Found\r\nLocation: ' + target + b'\r\nContent-Length: 0\r\n\r\n'))

    def test_dns_child_has_deadline_and_rejects_mixed_private_answers(self):
        completed = subprocess.CompletedProcess([], 0, b'["93.184.215.14","127.0.0.1"]')
        with patch.object(dc.subprocess, 'run', return_value=completed) as resolve, self.assertRaises(dc.DomainError):
            dc.public_addresses('guard.example.com', 443, time.monotonic() + 2)
        self.assertLessEqual(resolve.call_args.kwargs['timeout'], 2)
        self.assertIn('-I', resolve.call_args.args[0])
        with patch.object(dc.subprocess, 'run', side_effect=subprocess.TimeoutExpired('dns', 1)), self.assertRaises(dc.DomainError):
            dc.public_addresses('guard.example.com', 443, time.monotonic() + 1)

@unittest.skipUnless(os.geteuid() == 0, 'requires isolated Linux root runner')
class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='ironcurtain-domain-test.', dir='/var/lib'))
        os.chmod(self.root, 0o700)
        self.addCleanup(lambda: shutil.rmtree(self.root))
        self.controller = dc.Controller('local')
        c = self.controller
        c.conf = self.root
        c.runtime = self.root / 'runtime'
        c.control = self.root / 'domain-control'
        c.runtime.mkdir(mode=0o750)
        c.control.mkdir(mode=0o700)
        self.old = {'schema':1,'domain':'old.example.com','origin':'https://old.example.com','generation':'a'*64,'gateway':True}
        dc.atomic_json(c.runtime / 'domain.json', self.old, public=True)
        dc.atomic_json(c.control / 'request.json', {'domain':'next.example.com'})

    def simulated(self, probe=None):
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(dc, 'ingress_lock', contextlib.nullcontext))
        stack.enter_context(patch.object(dc, 'port_free', return_value=True))
        stack.enter_context(patch.object(dc.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)))
        stack.enter_context(patch.object(dc, 'run', return_value=b''))
        stack.enter_context(patch.object(self.controller, 'challenge_probe'))
        stack.enter_context(patch.object(self.controller, 'issue', return_value='b'*64))
        stack.enter_context(patch.object(dc, 'probe', side_effect=probe))
        stack.enter_context(patch.object(dc.time, 'sleep'))
        return stack

    def test_https_failure_restores_old_origin_and_removes_finished_journal(self):
        with self.simulated(dc.DomainError('wrong HTTPS role')), self.assertRaises(dc.DomainError):
            self.controller.apply()
        self.assertEqual(dc.read_json(self.controller.runtime / 'domain.json'), self.old)
        self.assertFalse((self.controller.control / 'transaction.json').exists())
        self.assertEqual(self.controller.status()['state'], 'failed')
        self.assertEqual(self.controller.status()['domain'], self.old['domain'])

    def test_success_commits_exact_identity_and_root_owned_public_config(self):
        with self.simulated() as _:
            self.controller.apply()
        active = dc.read_json(self.controller.runtime / 'domain.json')
        self.assertEqual(active['domain'], 'next.example.com')
        self.assertEqual(self.controller.status()['state'], 'ready')
        self.assertFalse((self.controller.control / 'transaction.json').exists())
        info = (self.controller.runtime / 'domain.json').stat()
        self.assertEqual(info.st_uid, 0)
        self.assertEqual(info.st_gid, 10001)
        self.assertEqual(info.st_mode & 0o777, 0o640)
        self.assertEqual(json.loads((self.controller.control / 'audit.jsonl').read_text())['domain'], active['domain'])

    def test_failed_recovery_retains_journal_for_next_attempt(self):
        with self.simulated(dc.DomainError('health')), patch.object(self.controller, 'restore', side_effect=[None, dc.DomainError('recovery')]), self.assertRaises(dc.DomainError):
            self.controller.apply()
        self.assertTrue((self.controller.control / 'transaction.json').exists())
        self.assertIn('恢复尚未完成', self.controller.status()['reason'])

    def test_incomplete_journal_is_restored_before_new_request(self):
        dc.atomic_json(self.controller.control / 'transaction.json', {'previous':self.old,'gateway':{'enabled':False,'active':False},'domain':'next.example.com','shared':None})
        dc.atomic_json(self.controller.runtime / 'domain.json', {**self.old,'domain':'partial.example.com'})
        with patch.object(dc, 'run', return_value=b''):
            self.controller.restore()
        self.assertEqual(dc.read_json(self.controller.runtime / 'domain.json'), self.old)
        self.assertFalse((self.controller.control / 'transaction.json').exists())

    def test_unmanaged_occupied_entry_never_issues_certificate(self):
        with self.simulated(), patch.object(dc, 'port_free', return_value=False), patch.object(dc.SharedIngress, 'discover', side_effect=RuntimeError('unmanaged ingress')), patch.object(self.controller, 'issue') as issue, self.assertRaises(RuntimeError):
            self.controller.apply()
        issue.assert_not_called()
        self.assertEqual(dc.read_json(self.controller.runtime / 'domain.json'), self.old)

    def test_queue_keeps_installation_excluded_through_dispatch(self):
        import fcntl
        role_lock = Path('/run/lock/ironcurtain-local.lock')
        existed = role_lock.exists()
        if not existed:
            role_lock.touch(mode=0o600)
            self.addCleanup(lambda: role_lock.unlink(missing_ok=True))
        def dispatch(*args, **kwargs):
            fd = os.open(role_lock, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertEqual(dc.read_json(self.controller.control / 'request.json'), {'domain':'next.example.com'})
            finally:
                os.close(fd)
            return b''
        with patch.object(dc, 'run', side_effect=dispatch):
            self.assertEqual(self.controller.queue({'domain':'next.example.com'})[0], 202)
        with role_lock.open('r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_queue_validates_only_domain_and_rejects_parallel_or_cooldown(self):
        role_lock = Path('/run/lock/ironcurtain-local.lock')
        existed = role_lock.exists()
        if not existed:
            role_lock.touch(mode=0o600)
            self.addCleanup(lambda: role_lock.unlink(missing_ok=True))
        for value in [{'domain':'https://next.example.com'}, {'domain':'next.example.com','command':'sh'}, {}]:
            self.assertEqual(self.controller.queue(value)[0], 400)
        with patch.object(dc, 'run', return_value=b''):
            self.assertEqual(self.controller.queue({'domain':'next.example.com'})[0], 202)
            self.assertEqual(self.controller.queue({'domain':'next.example.com'})[0], 409)
        self.controller.status_write('failed', 'next.example.com', 'retry')
        self.assertEqual(self.controller.queue({'domain':'next.example.com'})[0], 429)

@unittest.skipUnless(shutil.which('bash') and shutil.which('jq'), 'requires Bash and jq')
class MenuTests(unittest.TestCase):
    def invoke(self, response, status=0):
        source = (Path(__file__).resolve().parents[1] / 'scripts/ironcurtain.sh').read_text()
        function = 'configure_domain() {' + source.split('configure_domain() {', 1)[1].split('\ndispatch() {', 1)[0]
        # Only replace terminal input in the fixture; run the actual production function.
        function = function.replace('</dev/tty', '')
        env = dict(os.environ, IC_TEST_RESPONSE=json.dumps(response), IC_TEST_HTTP_STATUS=str(status))
        script = 'curl() { printf "%s" "$IC_TEST_RESPONSE"; return "$IC_TEST_HTTP_STATUS"; }; ROLE=local\n'
        # Menu dispatch handles failures explicitly, so errexit must not hide this regression.
        return subprocess.run(['bash', '-c', script + function + '\nconfigure_domain'], input='guard.example.com\n',
                              text=True, capture_output=True, env=env, timeout=5)

    def test_rejected_request_never_reports_background_certificate_application(self):
        for body, status in [({'error':'invalid domain'},22), ({'state':'failed','reason':'worker unavailable'},0), ({},0)]:
            with self.subTest(body=body):
                result = self.invoke(body, status)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('后台正在验证域名并申请证书', result.stdout)
                self.assertIn('域名', result.stderr)

    def test_accepted_request_reports_running_task_and_status_menu(self):
        result = self.invoke({'state':'running','requested_domain':'guard.example.com'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('后台正在验证域名并申请证书', result.stdout)
        self.assertIn('选 36', result.stdout)

class SharedIngressTests(unittest.TestCase):
    def test_role_and_container_are_fixed(self):
        for role, identity in [('bad','a'*12), ('local','../../etc'), ('cloud','a'*64)]:
            with self.assertRaises(RuntimeError):
                si.SharedIngress(role, identity)

if __name__ == '__main__':
    unittest.main()
