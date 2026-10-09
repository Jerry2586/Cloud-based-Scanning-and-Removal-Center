"""Real authenticated HTTPS -> installed root worker -> trusted package repair."""
import http.client
import json
import os
from pathlib import Path
import ssl
import subprocess
import time

import ci_credentials
from file_response_recheck import file_response_recheck

if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('IRONCURTAIN_ACCEPT_DISPOSABLE_RUNNER') != '1':
    raise SystemExit('Requires explicit disposable root Linux CI')
conf = Path('/etc/ironcurtain/local')
origin = 'https://127.0.0.1:8790'
context = ssl.create_default_context(cafile=str(conf / 'runtime/panel.crt'))
credentials = ci_credentials.consume()
cookie = csrf = ''

def call(path, body=None, *, bad_csrf=False):
    headers = {}
    if body is not None:
        body = json.dumps(body).encode()
        headers.update({'Origin': origin, 'Content-Type': 'application/json'})
    if cookie:
        headers.update({'Cookie': cookie, 'X-CSRF-Token': 'invalid' if bad_csrf else csrf})
    client = http.client.HTTPSConnection('127.0.0.1', 8790, context=context, timeout=10)
    try:
        client.request('POST' if body is not None else 'GET', path, body, headers)
        reply = client.getresponse()
        payload = reply.read(262145)
        assert len(payload) <= 262144, 'Acceptance response exceeds bound'
        return reply.status, dict(reply.getheaders()), json.loads(payload)
    finally:
        client.close()

assert call('/api/engines/maintenance')[0] == 401
assert call('/api/engines/install', {})[0] == 401
code, headers, result = call('/api/login', credentials)
assert code == 200, 'Disposable panel credentials rejected'
cookie = headers['Set-Cookie'].split(';')[0]
csrf = result['csrf']
del credentials
assert call('/api/engines/install', {}, bad_csrf=True)[0] == 403
assert call('/api/engines/install', {'command': 'custom'})[0] == 400
code, _, status = call('/api/engines/maintenance')
assert code == 200 and status['state'] in ('idle', 'finished', 'failed'), status
# Signed-install/recovery timers can legitimately hold the management lease.
# Bound the wait and follow only the identity of this newly accepted request.
started = None
deadline = time.monotonic() + 120
while time.monotonic() < deadline:
    code, _, result = call('/api/engines/install', {})
    if code == 202:
        assert result['state'] == 'queued', result
        started = result
        break
    assert code in (409, 429) and result['code'] in ('busy', 'cooldown'), (code, result)
    time.sleep(1)
assert started is not None, 'Maintenance not accepted within bounded wait'
deadline = time.monotonic() + 700
finished = None
unavailable_since = None
while time.monotonic() < deadline:
    code, _, result = call('/api/engines/maintenance')
    assert code == 200, (code, result)
    # The worker writes its terminal record immediately before systemd reaps it.
    # During that narrow transition the bridge deliberately fails closed.
    if result['state'] == 'unavailable':
        if unavailable_since is None:
            unavailable_since = time.monotonic()
        assert time.monotonic() - unavailable_since < 5, result
        time.sleep(.1)
        continue
    unavailable_since = None
    assert result.get('id') == started['id'], result
    assert result['state'] in ('queued', 'running', 'finished'), result
    if result['state'] == 'finished':
        finished = result
        break
    time.sleep(1)
assert finished and finished['code'] == 'finished', 'Maintenance did not finish'
assert finished['started_at'] and finished['finished_at']
unit = 'ironcurtain-engine-install.service'
assert subprocess.check_output(['systemctl', 'show', '-p', 'Result', '--value', unit], text=True).strip() == 'success'
assert subprocess.check_output(['systemctl', 'show', '-p', 'UnitFileState', '--value', unit], text=True).strip() == 'static'
assert subprocess.run(['systemctl', 'is-active', '--quiet', unit]).returncode != 0
job = json.loads(Path('/var/lib/ironcurtain/local/engine-maintenance/job.json').read_text())
assert job['id'] == started['id'] and job['state'] == 'finished'
def response_api(path, body=None):
    code, _, result = call(path, body)
    return code, result

file_response_recheck(response_api)
assert call('/api/logout', {})[0] == 200
print('Real trusted HTTPS maintenance: auth/CSRF/strict input, fresh task, installed root worker and actual package repair passed.')
