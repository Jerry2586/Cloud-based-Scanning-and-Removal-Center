#!/usr/bin/env python3
"""Probe the installed systemd controller, real profile writes and container mount."""
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import time

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
            return
        assert time.monotonic() < deadline, state['job']
        time.sleep(0.25)


def container_ready():
    code = 'import {localOperations} from "./src/local/operations-client.js";const r=await localOperations("status");if(r.state!=="ready")throw Error(JSON.stringify(r));console.log("operations mount ready");'
    subprocess.run(['docker', 'exec', 'ironcurtain-local', 'node', '--input-type=module', '-e', code], check=True, timeout=15)


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
    assert os.geteuid() == 0 and sys.argv[1:] in (['ready'], ['policy'])
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
        apply(tcp, udp)
        assert json.loads(PROFILE.read_text()) == dict(original, approved_tcp_ports=sorted(tcp), approved_udp_ports=sorted(udp))
        directory = Path(ADDRESS).parent.stat()
        subprocess.run(['systemctl', 'restart', SERVICE], check=True)
        after = Path(ADDRESS).parent.stat()
        assert (directory.st_dev, directory.st_ino) == (after.st_dev, after.st_ino)
        ready(); container_ready()
    print('Real operations controller, exact panel identity and container mount passed.')
