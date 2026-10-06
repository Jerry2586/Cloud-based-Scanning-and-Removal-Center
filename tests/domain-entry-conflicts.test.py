#!/usr/bin/env python3
"""Real systemd workers preserve external listeners; disposable runner only."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import time

if os.geteuid() != 0 or os.environ.get('IRONCURTAIN_ACCEPT_DISPOSABLE_RUNNER') != '1':
    raise SystemExit('Requires an explicitly disposable Linux root runner')

def command(*args):
    return subprocess.check_output(args, timeout=15).strip()

def request(role, method, payload=None):
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(10)
    client.connect('/run/ironcurtain-domain-' + role + '/control.sock')
    connection = http.client.HTTPConnection('localhost', timeout=10)
    connection.sock = client
    body = json.dumps(payload) if payload is not None else None
    connection.request(method, '/domain', body, {'Content-Type': 'application/json'})
    response = connection.getresponse()
    result = response.status, json.loads(response.read())
    connection.close()
    return result

for role in ('local', 'cloud'):
    conf = Path('/etc/ironcurtain') / role
    control = conf / 'domain-control'
    runtime = conf / 'runtime'
    container = 'ironcurtain-' + role
    identity = command('docker', 'inspect', '-f', '{{.Id}} {{.State.Running}}', container)
    certificate = hashlib.sha256((runtime / 'panel.crt').read_bytes()).digest()
    origin_file = runtime / 'domain.json'
    original = origin_file.read_bytes() if origin_file.exists() else None
    for port in (80, 443):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('0.0.0.0', port))
            listener.listen(4)
            listener.settimeout(5)
            code, queued = request(role, 'POST', {'domain': 'guard.example.com'})
            assert code == 202, (code, queued)
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                code, status = request(role, 'GET')
                if status.get('state') == 'failed':
                    break
                time.sleep(0.2)
            else:
                raise AssertionError('Real domain worker did not report conflict')
            # Status is durable before the systemd oneshot exits; await its release.
            while time.monotonic() < deadline:
                worker = command('systemctl', 'show', '-p', 'ActiveState', '--value',
                                 'ironcurtain-domain-' + role + '-apply.service')
                if worker in (b'inactive', b'failed'):
                    break
                time.sleep(0.1)
            else:
                raise AssertionError('Domain worker did not release its installation lock')
            assert code == 200 and str(port) in status['reason'], status
            assert '占用' in status['reason'], status
            assert not (control / 'transaction.json').exists()
            assert (origin_file.read_bytes() if origin_file.exists() else None) == original
            assert hashlib.sha256((runtime / 'panel.crt').read_bytes()).digest() == certificate
            assert command('docker', 'inspect', '-f', '{{.Id}} {{.State.Running}}', container) == identity
            assert command('systemctl', 'is-active', 'ironcurtain-domain-' + role + '-control.service') == b'active'
            assert subprocess.run(['systemctl', 'is-active', '--quiet', 'ironcurtain-domain-' + role + '-gateway.socket']).returncode != 0
            # The unrelated listener stays bound and continues accepting connections.
            with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
                peer, _ = listener.accept()
                with peer:
                    peer.sendall(b'external-listener-unchanged')
                    assert client.recv(64) == b'external-listener-unchanged'
        # Reset this test's queue records, never any production configuration.
        (control / 'status.json').unlink()
        (control / 'request.json').unlink()
    print(role + ': real 80/443 conflicts preserved listener, certificate, origin and container')
