"""Real automatic node secrets and local import on disposable root Linux only.

PTY output contains ephemeral secrets; hold it in memory and never print it.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

if os.geteuid() != 0 or os.environ.get('IRONCURTAIN_ACCEPT_DISPOSABLE_RUNNER') != '1':
    raise SystemExit('Requires disposable root CI')

spec = importlib.util.spec_from_file_location('menu_result_input', Path(__file__).with_name('menu-result-input.py'))
menus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(menus)
Menu, PROMPT, PAUSE = menus.Menu, menus.PROMPT, menus.PAUSE
cloud = Path('/etc/ironcurtain/cloud')
exports = cloud / 'exports'
# Node resolves module URLs through current's symlink; use the real path so
# control.js's CLI entry guard actually runs, including wrong-password rejection.
source = Path('/opt/ironcurtain/cloud/current').resolve(strict=True)


def finish_action(menu):
    menu.until(PAUSE)
    menu.stays(1, 1)
    menu.send(b'\n')
    menu.until(PROMPT, 2)
    menu.send(b'0\n')
    menu.finish()


def register(node):
    menu = Menu('xuanwu')
    try:
        menu.until(PROMPT)
        menu.send(b'8\n')
        menu.until('节点名称（如 node-server1）：'.encode())
        menu.send((node + '\n').encode())
        finish_action(menu)
        assert '请输入身份包解锁密码'.encode() not in menu.output, 'Cloud still asks for chosen password'
        assert '节点已登记'.encode() in menu.output, 'Registration did not complete'
        packs = list(exports.glob(node + '-*.icpair'))
        assert len(packs) == 1, 'Expected exactly one published pack'
        pack = packs[0]
        unlock = Path(str(pack) + '.unlock')
        for path in (pack, unlock):
            info = path.lstat()
            assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
            assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
        assert stat.S_IMODE(exports.stat().st_mode) == 0o700
        password = unlock.read_text().strip()
        assert re.fullmatch(r'[a-f0-9]{64}', password), 'Generated secret format invalid'
        assert ('系统生成的身份包解锁密码：' + password).encode() in menu.output, 'Secret not shown on trusted tty'
        assert password not in pack.read_text(), 'Plain secret embedded in encrypted pack'
        for path in (cloud / 'runtime/config.json', cloud / 'management-audit.jsonl'):
            assert password not in path.read_text(), 'Secret leaked to live configuration or audit'
        assert not (cloud / 'runtime' / unlock.name).exists(), 'Secret entered runtime mount'
        return pack, password
    finally:
        menu.close()


pack, password = register('node-ci')
second_pack, second_password = register('node-ci-second')
assert password != second_password, 'Node secrets must be independent'
fingerprint = subprocess.run(['openssl', 'x509', '-in', str(cloud / 'ca.crt'), '-noout', '-fingerprint', '-sha256'],
                             capture_output=True, check=True, text=True).stdout.strip().split('=', 1)[1]
# Exercise both independently registered identities and reject crossed secrets.
for current_pack, current_password, other_password, node_id in (
        (pack, password, second_password, 'node-ci'),
        (second_pack, second_password, password, 'node-ci-second')):
    with tempfile.TemporaryDirectory(prefix='ironcurtain-generated-password-') as work:
        staged = Path(work)
        staged.chmod(0o700)
        (staged / 'pairing.icpair').write_bytes(current_pack.read_bytes())
        env = dict(os.environ, IRONCURTAIN_CONTROL_WORK=work)
        for attempt, expected in ((current_password + 'wrong', False), (other_password, False),
                                  (current_password, True)):
            result = subprocess.run(['node', str(source / 'scripts/control.js'), 'unseal'],
                                    input=json.dumps({'password': attempt, 'fingerprint': fingerprint}),
                                    env=env, capture_output=True, text=True, timeout=30)
            assert (result.returncode == 0) == expected, 'Decryption result incorrect'
            assert (staged / 'identity').exists() == expected
        identity = json.loads((staged / 'identity/cloud.json').read_text())
        assert identity['node_id'] == node_id, 'Bundle contains another node identity'
        certificate = subprocess.run(['openssl', 'x509', '-in', str(staged / 'identity/client.crt'),
                                      '-noout', '-subject', '-nameopt', 'RFC2253'],
                                     capture_output=True, check=True, text=True).stdout.strip()
        assert certificate.endswith('CN=' + node_id), 'Certificate belongs to another node'
        result = subprocess.run(['node', str(source / 'scripts/control.js'), 'probe'],
                                env=env, capture_output=True, timeout=60)
        assert result.returncode == 0, 'Generated node identity fails actual mTLS'

# Actual imports pin CA and perform mTLS for both nodes; leave node-ci active
# for the existing deployment/API acceptance probe.
for current_pack, current_password, node_id in ((second_pack, second_password, 'node-ci-second'),
                                                (pack, password, 'node-ci')):
    menu = Menu('tiemu')
    try:
        menu.until(PROMPT)
        menu.send(b'10\n')
        menu.until('加密身份包在本机的绝对路径：'.encode())
        menu.send((str(current_pack) + '\n').encode())
        menu.until('请核对并输入玄武 CA 的 SHA-256 指纹：'.encode())
        menu.send((fingerprint + '\n').encode())
        menu.until('请输入身份包解锁密码（至少 16 字符）：'.encode())
        menu.send((current_password + '\n').encode())
        finish_action(menu)
        assert '加密身份、CA 指纹及在线握手均通过'.encode() in menu.output, 'Local import failed'
    finally:
        menu.close()
    active = json.loads(Path('/etc/ironcurtain/local/runtime/cloud/cloud.json').read_text())
    assert active['node_id'] == node_id, 'Imported wrong node'
    result = subprocess.run(['/usr/local/bin/tiemu', 'cloud-status'], capture_output=True, timeout=60)
    assert result.returncode == 0 and '玄武 mTLS、节点证书和令牌握手通过'.encode() in result.stdout

# Duplicate registration must preserve the original identity and exported secret.
before_config = (cloud / 'runtime/config.json').read_bytes()
before_exports = {p.name: hashlib.sha256(p.read_bytes()).digest() for p in exports.iterdir()}
menu = Menu('xuanwu')
try:
    menu.until(PROMPT)
    menu.send(b'8\n')
    menu.until('节点名称（如 node-server1）：'.encode())
    menu.send(b'node-ci\n')
    finish_action(menu)
    assert '节点名称已登记'.encode() in menu.output
finally:
    menu.close()
assert (cloud / 'runtime/config.json').read_bytes() == before_config
assert {p.name: hashlib.sha256(p.read_bytes()).digest() for p in exports.iterdir()} == before_exports
assert not list(cloud.glob('.admin.*')), 'Cloud staging secrets were not cleaned'
assert not list(Path('/etc/ironcurtain/local').glob('.admin.*')), 'Local staging identities were not cleaned'
assert not list(exports.glob('*.pending')), 'Successful registration left pending exports'

print('Automatic node secrets: independent generation, protected files, authenticated pack, real local import/mTLS and duplicate refusal passed.')
