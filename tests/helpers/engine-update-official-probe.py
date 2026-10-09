"""Disposable Linux: installed agent, real root peer and trusted systemd updater."""
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time

if (os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true'
        or os.environ.get('IRONCURTAIN_ACCEPT_DISPOSABLE_RUNNER') != '1'):
    raise SystemExit('Requires explicit disposable root Linux CI')

class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect('/run/ironcurtain/scan.sock')

def call(path, post=False):
    client = UnixConnection('localhost', timeout=10)
    try:
        client.request('POST' if post else 'GET', path, headers={'Content-Length':'0'} if post else {})
        reply = client.getresponse()
        payload = reply.read(262145)
        assert len(payload) <= 262144, 'Acceptance response exceeds bound'
        return reply.status, json.loads(payload)
    finally:
        client.close()

started = None
deadline = time.monotonic() + 120
while time.monotonic() < deadline:
    code, receipt = call('/engine-update', True)
    if code == 202:
        assert receipt['state'] == 'running' and re.fullmatch(r'[a-f0-9]{32}', receipt['task_id']), receipt
        started = receipt
        break
    assert code in (409, 429), (code, receipt)
    time.sleep(1)
assert started, 'Official update not accepted within bounded wait'
finished = None
deadline = time.monotonic() + 290
while time.monotonic() < deadline:
    code, status = call('/status')
    assert code == 200, code
    task = status['engine_update']
    assert task['task_id'] == started['task_id'], task
    assert task['state'] in ('running', 'finished'), task
    if task['state'] == 'finished':
        finished = task
        break
    time.sleep(.25)
assert finished and finished['finished_at'] >= finished['started_at'], 'No confirmed updater completion'
assert subprocess.check_output(['systemctl','show','-p','Result','--value','ironcurtain-antivirus-update.service'], text=True).strip() == 'success'
assert subprocess.run(['systemctl','is-active','--quiet','ironcurtain-antivirus-update.service']).returncode != 0
saved = json.loads(Path('/var/lib/ironcurtain/local/agent/engine-update-report.json').read_text())
assert saved == finished, 'Completion not durably stored with the accepted identity'
assert call('/engine-update', True)[0] == 429, 'Confirmed update must retain cooldown'
print('Real installed agent/root Unix peer -> trusted official systemd updater: receipt identity, confirmed terminal, persistence and cooldown passed.')
