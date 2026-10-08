#!/usr/bin/env python3
"""Fixed panel credential rotation; no commands or caller-selected paths."""
import argparse
import fcntl
import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import socket
import socketserver
import stat
import struct
import sys

HINT = 'admin\n密码已更改；请使用您设置的密码。忘记密码可在 root 菜单重置。\n'

class AccountError(Exception):
    def __init__(self, message, status=503):
        super().__init__(message)
        self.status = status

def trusted_dir(path):
    path = Path(path)
    for item in [path, *path.parents]:
        meta = item.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
            raise AccountError('账号目录权限不安全')

def trusted_lock_dir(path):
    # Linux /run/lock is commonly root-owned 1777. Sticky protection plus the
    # O_NOFOLLOW/root-owned/single-link lock-file checks prevent replacement.
    path = Path(path)
    trusted_dir(path.parent)
    meta = path.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or (meta.st_mode & 0o022 and not meta.st_mode & stat.S_ISVTX):
        raise AccountError('管理锁目录权限不安全')

def private_read(path, uid=0):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_uid != uid or meta.st_mode & 0o077 or meta.st_size > 16384:
            raise AccountError('账号文件权限不安全')
        return stream.read(16385)

def atomic(path, value, uid=0):
    path = Path(path)
    if path.exists() or path.is_symlink():
        private_read(path, uid)
    temp = path.parent / ('.account-' + secrets.token_hex(16))
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            os.fchown(stream.fileno(), uid, uid)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        sync_dir(path.parent)
    finally:
        temp.unlink(missing_ok=True)

def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def encode(value):
    return (json.dumps(value, ensure_ascii=False) + '\n').encode('utf-8')

def valid_record(value):
    return isinstance(value, dict) and isinstance(value.get('salt'), str) and isinstance(value.get('hash'), str) and value.get('schema') == 1 and value.get('username') == 'admin' and bool(re.fullmatch('[a-f0-9]{64}', value.get('salt', '') or '')) and bool(re.fullmatch('[a-f0-9]{128}', value.get('hash', '') or ''))

def valid_password(value):
    if not isinstance(value, str) or any(c in value for c in '\r\n\x00'):
        return False
    try:
        return 12 <= len(value.encode('utf-16-le')) // 2 <= 256
    except UnicodeError:
        return False

def digest(password, salt):
    return hashlib.scrypt(password.encode('utf-8'), salt=salt.encode('utf-8'), n=16384, r=8, p=1, dklen=64, maxmem=64*1024*1024).hex()

class AccountControl:
    def __init__(self, role):
        self.role = role
        self.conf = Path('/etc/ironcurtain') / role
        self.base = Path('/opt/ironcurtain') / role
        self.control = self.conf / 'account-control'
        self.runtime = self.conf / 'runtime' / 'panel-auth.json'
        self.recovery = self.conf / 'credentials' / 'panel-auth.json'
        self.initial = self.conf / 'credentials' / 'initial-credentials.txt'
        self.journal = self.control / 'transaction.json'
        self.socket_dir = Path('/run/ironcurtain-account-' + role)
        self.lock_path = Path('/run/lock/ironcurtain-' + role + '.lock')

    def record(self):
        value = json.loads(private_read(self.runtime, 10001))
        if not valid_record(value):
            raise AccountError('面板凭据无效')
        return value

    def recover(self):
        if not self.journal.exists() and not self.journal.is_symlink():
            return
        value = json.loads(private_read(self.journal))
        if not isinstance(value, dict) or set(value) != {'old_runtime', 'old_recovery', 'old_initial', 'next'} or not all(valid_record(value[k]) for k in ['old_runtime', 'old_recovery', 'next']) or not isinstance(value['old_initial'], str):
            raise AccountError('账号恢复记录无效')
        # The runtime rename is the commit point; mirror files are repaired before accepting requests.
        if self.record() == value['next']:
            atomic(self.recovery, encode(value['next']))
            atomic(self.initial, HINT.encode())
        else:
            atomic(self.recovery, encode(value['old_recovery']))
            atomic(self.initial, value['old_initial'].encode())
            atomic(self.runtime, encode(value['old_runtime']), 10001)
        self.journal.unlink()
        sync_dir(self.control)

    def change(self, value, root=False):
        keys = {'new_password'} if root else {'current_password', 'new_password'}
        if not isinstance(value, dict) or set(value) != keys or not valid_password(value.get('new_password')):
            raise AccountError('新密码须为 12–256 个字符，且不能包含换行或空字符', 400)
        if not root and (not isinstance(value.get('current_password'), str) or len(value['current_password']) > 256):
            raise AccountError('当前密码错误', 400)
        for directory in [self.conf, self.control, self.runtime.parent, self.recovery.parent]:
            trusted_dir(directory)
        trusted_lock_dir(self.lock_path.parent)
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            meta = os.fstat(fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_nlink != 1 or meta.st_mode & 0o022:
                raise AccountError('管理锁权限不安全')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise AccountError('另一安装或管理操作正在运行，请稍后重试', 409)
            if (self.base / 'transaction.json').exists() or (self.base / 'admin-transaction.json').exists():
                raise AccountError('请先在 Linux 菜单恢复未完成的管理操作', 409)
            self.recover()
            previous = self.record()
            if not root and not hmac.compare_digest(digest(value['current_password'], previous['salt']), previous['hash']):
                raise AccountError('当前密码错误', 400)
            if hmac.compare_digest(digest(value['new_password'], previous['salt']), previous['hash']):
                raise AccountError('新密码不能与当前密码相同', 400)
            salt = secrets.token_hex(32)
            next_record = {'schema': 1, 'username': 'admin', 'salt': salt, 'hash': digest(value['new_password'], salt)}
            old_recovery = json.loads(private_read(self.recovery))
            if not valid_record(old_recovery):
                raise AccountError('恢复凭据无效')
            old_initial = private_read(self.initial).decode('utf-8')
            atomic(self.journal, encode({'old_runtime': previous, 'old_recovery': old_recovery, 'old_initial': old_initial, 'next': next_record}))
            try:
                atomic(self.recovery, encode(next_record))
                atomic(self.initial, HINT.encode())
                atomic(self.runtime, encode(next_record), 10001)
                self.journal.unlink()
                sync_dir(self.control)
            except Exception:
                committed = self.record() == next_record
                self.recover()
                if not committed:
                    raise AccountError('密码保存未完成，旧密码仍有效')
                return {'changed': True, 'username': 'admin'}
            return {'changed': True, 'username': 'admin'}
        finally:
            os.close(fd)

    def ready(self):
        # Installer readiness must not reacquire the lock it already holds. A pending
        # credential journal is recovered only with the same management lease.
        if self.journal.exists() or self.journal.is_symlink():
            trusted_lock_dir(self.lock_path.parent)
            fd = os.open(self.lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                meta = os.fstat(fd)
                if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_nlink != 1 or meta.st_mode & 0o022:
                    raise AccountError('管理锁权限不安全')
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise AccountError('账号恢复正在等待管理操作结束', 409)
                self.recover()
            finally:
                os.close(fd)
        self.record()
        return {'ready': True}

    def serve(self):
        trusted_dir(self.control)
        trusted_dir(self.socket_dir)
        sock = self.socket_dir / 'control.sock'
        if sock.exists() or sock.is_symlink():
            meta = sock.lstat()
            if not stat.S_ISSOCK(meta.st_mode) or meta.st_uid != 0:
                raise AccountError('账号接口类型异常')
            sock.unlink()
        controller = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(5)
            def send(self, code, value):
                payload = json.dumps(value, ensure_ascii=False).encode()
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            def allowed(self):
                _, uid, gid = struct.unpack('3i', self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                return uid == 0 or (uid == 10001 and gid == 10001)
            def do_GET(self):
                if not self.allowed():
                    return self.send(403, {'error': '身份验证失败'})
                if self.path != '/account':
                    return self.send(404, {'error': '接口不存在'})
                try:
                    self.send(200, controller.ready())
                except AccountError as error:
                    self.send(error.status, {'error': str(error)})
                except Exception:
                    self.send(503, {'error': '账号服务暂不可用'})
            def do_POST(self):
                if not self.allowed():
                    return self.send(403, {'error': '身份验证失败'})
                if self.path != '/account/password':
                    return self.send(404, {'error': '接口不存在'})
                try:
                    if self.headers.get('Transfer-Encoding') or self.headers.get_content_type() != 'application/json':
                        raise AccountError('请求格式无效', 400)
                    sizes = self.headers.get_all('Content-Length') or []
                    if len(sizes) != 1 or not sizes[0].isdigit() or not 1 <= int(sizes[0]) <= 4096:
                        raise AccountError('请求过大或长度无效', 400)
                    raw = self.rfile.read(int(sizes[0]))
                    if len(raw) != int(sizes[0]):
                        raise AccountError('请求不完整', 400)
                    self.send(200, controller.change(json.loads(raw)))
                except AccountError as error:
                    self.send(error.status, {'error': str(error)})
                except (ValueError, UnicodeError):
                    self.send(400, {'error': '请求格式无效'})
                except Exception:
                    self.send(503, {'error': '账号服务暂不可用'})
            def log_message(self, *args):
                pass
        with socketserver.UnixStreamServer(str(sock), Handler) as server:
            os.chown(sock, 0, 10001)
            os.chmod(sock, 0o660)
            server.serve_forever()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', choices=['local', 'cloud'], required=True)
    parser.add_argument('--action', choices=['serve', 'change'], required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise AccountError('请用 sudo 运行')
    controller = AccountControl(args.role)
    if args.action == 'serve':
        controller.serve()
    else:
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            raise AccountError('输入过大', 400)
        controller.change(json.loads(raw), root=True)
        print('面板密码已更改。旧登录会话已失效，请使用新密码重新登录。')

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('错误：' + (str(error) if isinstance(error, AccountError) else '账号操作未完成，请检查服务状态'), file=sys.stderr)
        sys.exit(1)
