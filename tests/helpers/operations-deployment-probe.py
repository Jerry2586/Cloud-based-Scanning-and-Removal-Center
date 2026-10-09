#!/usr/bin/env python3
"""Probe the installed systemd controller, real profile writes and container mount."""
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import shutil
import tempfile
import fcntl
import stat
import subprocess
import sys
import time

from response_recheck import recheck, require_disposable

ADDRESS = '/run/ironcurtain-operations-local/control.sock'
PROFILE = Path('/etc/ironcurtain/local/profile.json')
SERVICE = 'ironcurtain-operations-local-control.service'
# Match the installed agent's defaults: fresh profiles contain only the schema.
_spec = importlib.util.spec_from_file_location('operations_probe_agent', Path(__file__).resolve().parents[2] / 'src/host/agent.py')
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)


def request(method, value=None, uid=10001):
    child = subprocess.run([sys.executable, '-B', __file__, 'request', method, str(uid), json.dumps(value)],
                           check=True, capture_output=True, text=True, timeout=12)
    return json.loads(child.stdout)


def ready():
    # systemctl restart returns before the Python listener has rebound its socket.
    deadline = time.monotonic() + 15
    while True:
        active = subprocess.run(['systemctl', 'is-active', '--quiet', SERVICE]).returncode == 0
        result = {'transport': 'service-starting'}
        code = 0
        if active:
            directory = Path(ADDRESS).parent.stat()
            assert (directory.st_uid, directory.st_gid, stat.S_IMODE(directory.st_mode)) == (0, 10001, 0o750)
            try:
                meta = Path(ADDRESS).stat()
            except FileNotFoundError:
                result = {'transport': 'socket-starting'}
            else:
                assert stat.S_ISSOCK(meta.st_mode) and (meta.st_uid, meta.st_gid, stat.S_IMODE(meta.st_mode)) == (0, 10001, 0o660)
                code, result = request('GET')
        if code == 200 and result.get('state') == 'ready':
            assert result['schema'] == 'ironcurtain-operations/v1'
            return result
        assert code in (0, 503) and time.monotonic() < deadline, (code, result)
        time.sleep(0.25)


def apply(tcp, udp):
    deadline = time.monotonic() + 45
    while True:
        state = ready()
        code, result = request('POST', {'action': 'ports', 'revision': state['policy']['revision'], 'tcp': tcp, 'udp': udp})
        if code == 202:
            job_id = result['job']['id']
            break
        assert code == 409 and time.monotonic() < deadline, (code, result)
        time.sleep(0.5)
    deadline = time.monotonic() + 45
    while True:
        state = ready()
        assert state['job']['id'] == job_id, state['job']
        if state['job']['state'] != 'running':
            assert state['job']['state'] == 'complete', state['job']
            assert state['policy']['tcp'] == sorted(tcp) and state['policy']['udp'] == sorted(udp)
            assert any(item['id'] == job_id and item['state'] == 'complete' for item in state['audit'])
            return state
        assert time.monotonic() < deadline, state['job']
        time.sleep(0.25)


def container_ready():
    code = 'import {localOperations} from "./src/local/operations-client.js";const r=await localOperations("status");if(r.state!=="ready")throw Error(JSON.stringify(r));console.log("operations mount ready");'
    subprocess.run(['docker', 'exec', 'ironcurtain-local', 'node', '--input-type=module', '-e', code], check=True, timeout=15)


def scope_web(mode='scope'):
    require_disposable()
    # This probe runs only on the disposable deployment runner. Credentials stay in memory.
    origin = 'https://127.0.0.1:8790'
    context = ssl.create_default_context(cafile='/etc/ironcurtain/local/runtime/panel.crt')
    cookie = csrf = ''
    def web(route, value=None, authenticated=True):
        connection = http.client.HTTPSConnection('127.0.0.1', 8790, context=context, timeout=12)
        headers = {'Origin': origin}
        if authenticated and cookie: headers['Cookie'] = cookie
        if authenticated and csrf: headers['X-CSRF-Token'] = csrf
        payload = None if value is None else json.dumps(value).encode()
        if payload is not None: headers['Content-Type'] = 'application/json'
        try:
            connection.request('GET' if payload is None else 'POST', route, payload, headers)
            response = connection.getresponse(); body = response.read(262145)
            assert len(body) <= 262144
            return response.status, response.getheader('Set-Cookie'), body
        finally: connection.close()
    def api(route, value=None):
        code, _, raw = web(route, value)
        return code, json.loads(raw)
    def operation(value):
        deadline = time.monotonic() + 45
        while True:
            code, result = api('/api/operations', value)
            if code == 202: break
            assert code == 409 and time.monotonic() < deadline, (code, result)
            time.sleep(0.5)
        ident = result['job']['id']
        while True:
            code, result = api('/api/operations')
            assert code == 200 and result['job']['id'] == ident, (code, result)
            if result['job']['state'] != 'running':
                assert result['job']['state'] == 'complete', result['job']
                assert any(item['id'] == ident and item['state'] == 'complete' for item in result['audit'])
                return result
            assert time.monotonic() < deadline, result['job']
            time.sleep(0.25)
    assert web('/api/operations', authenticated=False)[0] == 401
    credentials = Path('/etc/ironcurtain/local/credentials/initial-credentials.txt').read_text().strip().splitlines()
    code, session_cookie, raw = web('/api/login', {'username': credentials[0], 'password': credentials[1]}, authenticated=False)
    assert code == 200
    cookie = session_cookie.split(';')[0]; csrf = json.loads(raw)['csrf']
    del credentials, raw, session_cookie
    if mode == 'policy':
        try:
            expected = agent.profile_validate(json.loads(PROFILE.read_text()))
            state = ready()
            assert state['job']['action'] == 'ports' and state['job']['state'] == 'complete'
            recheck(api, 'scan', agent.fullscan.profile_digest(expected), state['job'])
            print('Real completed port policy -> authenticated scan -> fresh environment report passed.')
            return
        finally:
            web('/api/logout', {})
    code, _, body = web('/assets/portal/scope-workspace.js')
    assert code == 200 and b'createScopeWorkspace' in body
    assert api('/api/operations', {'action':'discover','path':'/etc'})[0] == 400
    original = agent.profile_validate(json.loads(PROFILE.read_text()))
    fixture = Path(tempfile.mkdtemp(prefix='ironcurtain-web-enrollment-', dir='/srv'))
    sample = fixture / 'health.txt'; sample.write_text('Plain deployment acceptance fixture.\n')
    name = fixture.name
    expected = None
    try:
        image = subprocess.check_output(['docker','inspect','ironcurtain-local','--format','{{.Image}}'], text=True).strip()
        subprocess.run(['docker','create','--name',name,'--network','none','--read-only',image], check=True, capture_output=True, timeout=15)
        found = operation({'action':'discover'})
        discovery = found['scope']['discovery']
        assert discovery['state'] == 'ready'
        choices = [item for item in discovery['candidates'] if (item['kind'], item['value']) in (('program_roots',str(fixture)),('containers',name))]
        assert len(choices) == 2, discovery
        started = subprocess.check_output(['systemctl','show','ironcurtain-agent.service','-p','ExecMainStartTimestampMonotonic','--value'])
        value = {'action':'enroll','revision':found['policy']['revision'],'inventory':discovery['revision'],'ids':[item['id'] for item in choices]}
        expected = dict(original, program_roots=original['program_roots']+[str(fixture)], containers=original['containers']+[{'name':name}])
        enrolled = operation(value)
        assert json.loads(PROFILE.read_text()) == expected
        assert enrolled['scope']['containers'] == [item['name'] for item in expected['containers']]
        assert enrolled['scope']['discovery']['state'] == 'stale'
        assert subprocess.check_output(['systemctl','show','ironcurtain-agent.service','-p','ExecMainStartTimestampMonotonic','--value']) != started
        assert not Path('/var/lib/ironcurtain/local/agent/operations/port-transaction.json').exists()
        container_ready()
        # This installation deliberately skips the antivirus engine. Confirm the
        # real agent loaded the new profile and refuses to fake file coverage.
        result = recheck(api, 'scan', agent.fullscan.profile_digest(expected), enrolled['job'])
        assert result['protection']['program_roots'] == len(expected['program_roots'])
        assert result['protection']['enrolled_containers'] == len(expected['containers'])
        assert result['protection']['state'] != 'ready'
        assert result['antivirus']['state'] != 'configured'
        code, result = api('/api/full-scan', {})
        assert code == 503 and result.get('state') != 'running', (code, result)
        assert 'image_id' not in expected['containers'][-1]
        print('Real HTTPS discovery, enrollment, agent reload and missing-engine refusal passed.')
    finally:
        # Only this probe's additive profile is restored; unrelated changes stop cleanup.
        current = agent.profile_validate(json.loads(PROFILE.read_text()))
        if current != original:
            assert expected is not None and current == expected, 'Profile changed outside the disposable probe'
            with open('/run/lock/ironcurtain-local.lock','rb') as guard:
                fcntl.flock(guard, fcntl.LOCK_EX)
                agent.atomic_json(PROFILE, original)
                subprocess.run(['systemctl','restart','ironcurtain-agent.service'], check=True)
        subprocess.run(['docker','rm','-f',name], capture_output=True, timeout=15)
        shutil.rmtree(fixture)
        web('/api/logout', {})


if sys.argv[1:2] == ['request']:
    method, uid, raw = sys.argv[2:]
    os.setgroups([]); os.setgid(10001); os.setuid(int(uid))
    connection = None
    sock = socket.socket(socket.AF_UNIX); sock.settimeout(5)
    try:
        sock.connect(ADDRESS)
        connection = http.client.HTTPConnection('localhost', timeout=5); connection.sock = sock
        payload = None if method == 'GET' else json.dumps(json.loads(raw)).encode()
        connection.request(method, '/operations', body=payload, headers={} if payload is None else {'Content-Type': 'application/json'})
        response = connection.getresponse(); body = response.read(262145)
        assert len(body) <= 262144
        print(json.dumps([response.status, json.loads(body)]))
    except (FileNotFoundError, ConnectionRefusedError, ConnectionResetError, BrokenPipeError, TimeoutError, http.client.RemoteDisconnected) as error:
        print(json.dumps([0, {'transport': type(error).__name__}]))
    finally:
        if connection is not None: connection.close()
        sock.close()
else:
    assert os.geteuid() == 0 and sys.argv[1:] in (['ready'], ['policy'], ['scope'])
    ready(); container_ready()
    assert request('GET', uid=10002)[0] == 403
    assert request('POST', {'action': 'shell', 'command': 'id'})[0] == 400
    if sys.argv[1] == 'policy':
        original = agent.profile_validate(json.loads(PROFILE.read_text()))
        tcp = original['approved_tcp_ports']; udp = original['approved_udp_ports']
        extra = next(port for port in range(54000, 54129) if port not in tcp)
        assert len(tcp) < 128
        started = subprocess.check_output(['systemctl', 'show', 'ironcurtain-agent.service', '-p', 'ExecMainStartTimestampMonotonic', '--value'])
        apply(sorted(tcp + [extra]), udp)
        changed = json.loads(PROFILE.read_text())
        assert changed == dict(original, approved_tcp_ports=sorted(tcp + [extra]), approved_udp_ports=sorted(udp))
        assert subprocess.check_output(['systemctl', 'show', 'ironcurtain-agent.service', '-p', 'ExecMainStartTimestampMonotonic', '--value']) != started
        scope_web('policy')
        apply(tcp, udp)
        assert json.loads(PROFILE.read_text()) == dict(original, approved_tcp_ports=sorted(tcp), approved_udp_ports=sorted(udp))
        directory = Path(ADDRESS).parent.stat()
        subprocess.run(['systemctl', 'restart', SERVICE], check=True)
        after = Path(ADDRESS).parent.stat()
        assert (directory.st_dev, directory.st_ino) == (after.st_dev, after.st_ino)
        ready(); container_ready()
    if sys.argv[1] == 'scope': scope_web()
    print('Real operations controller, exact panel identity and container mount passed.')
