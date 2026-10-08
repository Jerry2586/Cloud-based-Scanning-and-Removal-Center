"""Real TLS, PTY and password persistence acceptance on disposable installed Linux."""
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import time

if os.geteuid() != 0 or os.environ.get('IRONCURTAIN_ACCEPT_DISPOSABLE_RUNNER') != '1':
    raise SystemExit('Requires disposable root CI')
spec = importlib.util.spec_from_file_location('menu_input', Path(__file__).with_name('menu-result-input.py'))
menu_input = importlib.util.module_from_spec(spec)
spec.loader.exec_module(menu_input)

def acceptance(role, host):
    conf = Path('/etc/ironcurtain') / role
    entry = 'tiemu' if role == 'local' else 'xuanwu'
    port = 8790 if role == 'local' else 8791
    origin = 'https://' + host + ':' + str(port)
    ctx = ssl.create_default_context(cafile=str(conf / 'runtime/panel.crt'))
    original = (conf / 'credentials/initial-credentials.txt').read_text().splitlines()[1]
    new_password = secrets.token_urlsafe(24)
    next_password = secrets.token_urlsafe(24)
    def call(path, body=None, session=None, bad_csrf=False):
        headers = {}
        if body is not None:
            body = json.dumps(body).encode()
            headers.update({'Origin': origin, 'Content-Type': 'application/json'})
        if session:
            headers.update({'Cookie': session[0], 'X-CSRF-Token': 'invalid' if bad_csrf else session[1]})
        client = http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
        client.request('POST' if body is not None else 'GET', path, body, headers)
        reply = client.getresponse()
        result = (reply.status, dict(reply.getheaders()), json.loads(reply.read()))
        client.close()
        return result
    def login(password):
        code, headers, data = call('/api/login', {'username': 'admin', 'password': password})
        assert code == 200, 'Expected password rejected'
        return headers['Set-Cookie'].split(';')[0], data['csrf']
    def cli_password(password):
        payload = json.dumps({'new_password': password}).encode()
        subprocess.run(['python3', '/opt/ironcurtain/' + role + '/current/scripts/account_control.py', '--role', role, '--action', 'change'], input=payload, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def menu_change(password, confirmation):
        menu = menu_input.Menu(entry)
        try:
            menu.until(menu_input.PROMPT)
            menu.send(b'14\n')
            menu.until('请选择密码操作：'.encode())
            menu.send(b'1\n')
            menu.until('请输入新面板密码（12–256 字符）：'.encode())
            menu.send(password.encode() + b'\n')
            menu.until('再次输入新面板密码：'.encode())
            menu.send(confirmation.encode() + b'\n')
            menu.until(menu_input.PAUSE)
            assert password.encode() not in menu.output, 'Hidden password echoed'
            assert confirmation.encode() not in menu.output, 'Hidden confirmation echoed'
            if password == confirmation:
                assert '面板密码已更改'.encode() in menu.output
            else:
                assert '两次输入不一致'.encode() in menu.output
            menu.stays(1, 1)
            menu.send(b'\n')
            menu.until(menu_input.PROMPT, 2)
            menu.send(b'0\n')
            menu.finish()
        finally:
            menu.close()
    try:
        first, second = login(original), login(original)
        menu_change(new_password, next_password)
        assert call('/api/session', session=first)[2]['authenticated'] is True, 'Mismatch invalidated credentials'
        menu_change(new_password, new_password)
        assert call('/api/session', session=first)[2]['authenticated'] is False
        assert call('/api/session', session=second)[2]['authenticated'] is False
        assert call('/api/login', {'username': 'admin', 'password': original})[0] == 401
        session = login(new_password)
        assert call('/api/account/password', {'current_password': new_password, 'new_password': next_password}, session, True)[0] == 403
        assert call('/api/account/password', {'current_password': 'wrong-password', 'new_password': next_password}, session)[0] == 400
        code, _, result = call('/api/account/password', {'current_password': new_password, 'new_password': next_password}, session)
        assert code == 200 and result['changed'] is True
        assert call('/api/session', session=session)[2]['authenticated'] is False
        assert call('/api/login', {'username': 'admin', 'password': new_password})[0] == 401
        current = login(next_password)
        assert next_password not in (conf / 'credentials/initial-credentials.txt').read_text()
        assert (conf / 'runtime/panel-auth.json').read_bytes() == (conf / 'credentials/panel-auth.json').read_bytes()
        assert subprocess.check_output(['stat', '-c', '%u:%g:%a', str(conf / 'runtime/panel-auth.json')]).strip() == b'10001:10001:600'
        subprocess.run(['systemctl', 'restart', 'ironcurtain-account-' + role + '-control.service'], check=True)
        subprocess.run(['docker', 'restart', 'ironcurtain-' + role], check=True, stdout=subprocess.DEVNULL)
        ready = False
        for _ in range(60):
            try:
                if call('/healthz')[0] == 200:
                    ready = True
                    break
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(1)
        assert ready, 'Panel restart failed'
        login(next_password)
        assert call('/api/session', session=current)[2]['authenticated'] is False
        print(role + ': hidden menu confirmation/mismatch, strict TLS password API, CSRF, old sessions, private mirrors and real restart passed.')
    finally:
        cli_password(original)
    login(original)
    print(role + ': original fixture password restored; no secret emitted.')

acceptance('local', '127.0.0.1')
acceptance('cloud', sys.argv[1])
