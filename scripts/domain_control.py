#!/usr/bin/env python3
"""Fixed-role domain controller; no arbitrary paths, shell strings or commands."""
import argparse
import fcntl
import hashlib
import http.server
import http.client
import ssl
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import socketserver
import struct
import stat
import subprocess
import sys
import threading
import time
import urllib.request
from urllib.parse import urlsplit
from contextlib import contextmanager


def valid_domain(value):
    return (isinstance(value, str) and len(value) <= 253 and '.' in value
            and re.fullmatch(r'[a-z]{2,63}', value.split('.')[-1]) is not None
            and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.')))


def atomic_json(target, value, public=False):
    target = Path(target)
    temporary = target.with_name(target.name + '.' + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640 if public else 0o600)
    try:
        if public:
            os.fchown(fd, 0, 10001)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        parent = os.open(target.parent, os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temporary.unlink(missing_ok=True)


def durable_unlink(target):
    target = Path(target)
    target.unlink(missing_ok=True)
    fd = os.open(target.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_json(target, default=None):
    try:
        if Path(target).is_symlink() or Path(target).stat().st_size > 16384:
            raise ValueError('unsafe configuration')
        return json.loads(Path(target).read_text())
    except FileNotFoundError:
        return default


def trusted_directory(target):
    target = Path(target)
    for part in [target, *target.parents]:
        info = part.lstat()
        if part.is_symlink() or not part.is_dir() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('配置目录必须由 root 控制且不可共享写入')
    return target


class DomainError(Exception):
    pass


def run(args, timeout=60, umask=-1):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False, umask=umask)
    if result.returncode:
        raise DomainError('域名配置步骤未完成，请在 Linux 菜单查看服务日志')
    return result.stdout


def port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Match ThreadingHTTPServer: closed connections in TIME_WAIT are reusable,
        # while a live listener still prevents binding (never use SO_REUSEPORT).
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(('0.0.0.0', port))
            return True
        except OSError:
            return False


@contextmanager
def entry_lock():
    """Serialize security roles without touching business services."""
    fd = os.open('/run/lock/ironcurtain-domain-entry.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
            raise DomainError('安全域名锁异常，请在 Linux 菜单检查服务')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise DomainError('另一个安全域名任务正在执行，请稍后重试') from error
        yield
    finally:
        os.close(fd)


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, domain):
        self.domain = domain

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        address = urlsplit(newurl)
        if address.scheme != 'https' or address.hostname != self.domain or address.port not in (None, 443):
            raise DomainError('域名验证只能跳转至同域名 HTTPS 入口')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


PROBE_TIMEOUT = 20
DNS_TIMEOUT = 5


def public_addresses(domain, port, deadline):
    # libc DNS may block indefinitely; a short-lived child gives it a hard deadline.
    script = ('import json,socket,sys;'
              'print(json.dumps(sorted(set(v[4][0] for v in '
              'socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM)))))')
    try:
        result = subprocess.run([sys.executable, '-I', '-c', script, domain, str(port)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=min(DNS_TIMEOUT, max(0.01, deadline - time.monotonic())), check=True)
        if len(result.stdout) > 16384:
            raise ValueError('too many records')
        addresses = json.loads(result.stdout)
        if not isinstance(addresses, list) or not addresses or any(not isinstance(v, str) or not ipaddress.ip_address(v).is_global for v in addresses):
            raise ValueError('non-public address')
        if len(addresses) > 8:
            raise ValueError('too many records')
        return sorted(set(addresses), key=lambda value: ':' in value)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise DomainError('域名解析未完成或包含非公网地址，请检查 DNS A/AAAA 记录') from error


def probe(domain, path, expected, https=False):
    deadline = time.monotonic() + PROBE_TIMEOUT
    addresses = public_addresses(domain, 443 if https else 80, deadline)
    for address in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        timers = []

        def remaining_timeout():
            value = deadline - time.monotonic()
            if value <= 0:
                raise TimeoutError()
            return min(8, value)

        def bound_socket(sock):
            # Socket timeouts alone do not bound drip-fed response headers or bodies.
            def expire():
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()
            timer = threading.Timer(max(0.001, deadline - time.monotonic()), expire)
            timer.daemon = True
            timers.append(timer)
            timer.start()
            return sock

        class Connection(http.client.HTTPConnection):
            def connect(self):
                self.sock = bound_socket(socket.create_connection((address, self.port), remaining_timeout()))

        class SecureConnection(http.client.HTTPSConnection):
            def connect(self):
                raw = socket.create_connection((address, self.port), remaining_timeout())
                try:
                    raw.settimeout(remaining_timeout())
                    self.sock = bound_socket(self._context.wrap_socket(raw, server_hostname=domain))
                except Exception:
                    raw.close()
                    raise

        class HTTP(urllib.request.HTTPHandler):
            def http_open(self, request):
                return self.do_open(Connection, request)

        class HTTPS(urllib.request.HTTPSHandler):
            def https_open(self, request):
                return self.do_open(SecureConnection, request, context=ssl.create_default_context())

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), HTTP(), HTTPS(), SafeRedirect(domain))
        try:
            with opener.open(('https://' if https else 'http://') + domain + path, timeout=remaining_timeout()) as response:
                chunks, size = [], 0
                while size <= 4096:
                    if time.monotonic() >= deadline:
                        raise TimeoutError()
                    chunk = response.read1(4097 - size)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if response.isclosed():
                        break
                value = b''.join(chunks)
                if len(value) > 4096 or value != expected:
                    raise DomainError('域名未到达本安全面板，请检查 DNS 与入口转发')
                return
        except DomainError:
            raise
        except Exception:
            continue
        finally:
            for timer in timers:
                timer.cancel()
    raise DomainError('公网域名验证不可达，请检查 DNS、80/443 安全组及入口转发')


class Controller:
    def __init__(self, role):
        if role not in ('local', 'cloud'):
            raise ValueError('invalid role')
        self.role = role
        self.conf = Path('/etc/ironcurtain') / role
        self.runtime = self.conf / 'runtime'
        self.control = self.conf / 'domain-control'
        self.socket_dir = Path('/run/ironcurtain-domain-' + role)
        self.gateway = 'ironcurtain-domain-' + role + '-gateway.socket'
        self.worker = 'ironcurtain-domain-' + role + '-apply.service'

    def status(self):
        active = read_json(self.runtime / 'domain.json', {})
        state = read_json(self.control / 'status.json', {'state': 'idle', 'reason': '填写域名并保存后自动申请证书'})
        state.update(domain=active.get('domain', ''), certificate='public-ca' if active else 'not-issued')
        return state

    def status_write(self, state, domain, reason):
        atomic_json(self.control / 'status.json', {'state': state, 'requested_domain': domain,
                    'reason': reason, 'updated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())})

    def queue(self, value):
        if not isinstance(value, dict) or set(value) != {'domain'} or not valid_domain(value['domain']):
            return 400, {'error': '请输入有效域名，不包含协议、端口或路径'}
        role_lock = Path('/run/lock/ironcurtain-' + self.role + '.lock')
        try:
            fd = os.open(role_lock, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return 409, {'error': '安装或管理任务正在执行，请稍后重试'}
        try:
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode):
                return 409, {'error': '安装锁异常，请在 Linux 菜单检查服务'}
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return 409, {'error': '安装或管理任务正在执行，请稍后重试'}
            # Keep the installation excluded until both durable queue publication and
            # systemd dispatch complete. The worker waits briefly for this reader.
            return self.queue_locked(value)
        finally:
            os.close(fd)

    def queue_locked(self, value):
        with (self.control / 'queue.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = self.status()
            if state.get('state') == 'running':
                return 409, {'error': '域名任务正在执行，请等待完成', **state}
            record = self.control / 'status.json'
            if record.exists() and time.time() - record.stat().st_mtime < 30:
                return 429, {'error': '请稍后再提交域名设置', **state}
            atomic_json(self.control / 'request.json', value)
            self.status_write('running', value['domain'], '正在检查入口并申请证书，原访问地址保持可用')
            try:
                run(['systemctl', 'start', '--no-block', self.worker], 10)
            except Exception:
                self.status_write('failed', value['domain'], '域名服务无法启动，请在 Linux 菜单检查服务')
                return 503, self.status()
            return 202, self.status()

    def restore(self):
        transaction = read_json(self.control / 'transaction.json')
        if transaction is None:
            return
        if transaction.get('shared') is not None:
            raise DomainError('发现旧版外部入口恢复记录；保留证据，请管理员检查，程序不会改动其他项目')
        previous = transaction['previous']
        if previous:
            atomic_json(self.runtime / 'domain.json', previous, public=True)
        else:
            durable_unlink(self.runtime / 'domain.json')
        gateway = transaction['gateway']
        if isinstance(gateway, bool):  # tolerate a transaction left by a development build
            gateway = {'active': gateway, 'enabled': gateway}
        run(['systemctl', 'enable' if gateway['enabled'] else 'disable', self.gateway])
        run(['systemctl', 'start' if gateway['active'] else 'stop', self.gateway])
        if not gateway['active']:
            run(['systemctl', 'stop', self.gateway.replace('.socket', '.service')])
        durable_unlink(self.control / 'transaction.json')

    def challenge_probe(self, domain, standalone, webroot):
        token = secrets.token_urlsafe(32)
        value = secrets.token_urlsafe(40).encode()
        route = '/.well-known/acme-challenge/' + token
        challenge_dir = webroot / '.well-known' / 'acme-challenge'
        challenge_dir.mkdir(parents=True, exist_ok=True)
        for directory in [challenge_dir, challenge_dir.parent, webroot]:
            trusted_directory(directory)
            os.chmod(directory, 0o755)
        challenge = challenge_dir / token
        challenge.write_bytes(value)
        os.chmod(challenge, 0o644)
        atomic_json(self.runtime / 'domain-pending.json', {'domain': domain}, public=True)
        server = None
        if standalone:
            class Challenge(http.server.BaseHTTPRequestHandler):
                def setup(self):
                    super().setup()
                    self.connection.settimeout(5)

                def do_GET(self):
                    if self.path == route and (self.headers.get('Host') or '').lower() == domain:
                        self.send_response(200)
                        self.send_header('Content-Length', str(len(value)))
                        self.end_headers()
                        self.wfile.write(value)
                    else:
                        self.send_error(404)

                def log_message(self, *args):
                    pass

            class Server(http.server.ThreadingHTTPServer):
                daemon_threads = True
                slots = threading.BoundedSemaphore(8)

                def process_request(self, request, address):
                    if not self.slots.acquire(blocking=False):
                        self.shutdown_request(request)
                        return
                    try:
                        super().process_request(request, address)
                    except Exception:
                        self.slots.release()
                        raise

                def process_request_thread(self, request, address):
                    try:
                        super().process_request_thread(request, address)
                    finally:
                        self.slots.release()
            server = Server(('0.0.0.0', 80), Challenge)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            probe(domain, route, value)
        finally:
            if server:
                server.shutdown()
                server.server_close()
            challenge.unlink(missing_ok=True)

    def issue(self, domain, standalone, webroot):
        acme = self.control / 'acme'
        acme.mkdir(mode=0o700, exist_ok=True)
        arguments = ['certbot', 'certonly', '--non-interactive', '--agree-tos',
                     '--register-unsafely-without-email', '--keep-until-expiring', '--preferred-challenges', 'http',
                     '--config-dir', str(acme), '--work-dir', str(self.control / 'work'),
                     '--logs-dir', str(self.control / 'logs'), '--cert-name', domain, '-d', domain]
        arguments += ['--standalone'] if standalone else ['--webroot', '-w', str(webroot)]
        try:
            run(arguments, 240, umask=0o022)
        except Exception as error:
            raise DomainError('证书申请未完成；原入口保留。请检查挑战可达性及证书服务限制，稍后重试') from error
        lineage = acme / 'live' / domain
        contents = {}
        for name in ('cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'):
            resolved = (lineage / name).resolve(strict=True)
            if not resolved.is_relative_to(acme.resolve()) or resolved.stat().st_size > 131072:
                raise DomainError('证书输出目录异常')
            contents[name] = resolved.read_bytes()
        run(['openssl', 'verify', '-verify_hostname', domain, '-untrusted', str(lineage / 'chain.pem'), str(lineage / 'cert.pem')])
        run(['openssl', 'x509', '-in', str(lineage / 'cert.pem'), '-checkend', '86400', '-noout'])
        if run(['openssl', 'x509', '-in', str(lineage / 'cert.pem'), '-pubkey', '-noout']) != run(['openssl', 'pkey', '-in', str(lineage / 'privkey.pem'), '-pubout']):
            raise DomainError('证书与私钥不匹配')
        generation = hashlib.sha256(contents['fullchain.pem'] + contents['privkey.pem']).hexdigest()
        directory = self.runtime / 'domain-certificates' / generation
        directory.mkdir(parents=True, exist_ok=True)
        trusted_directory(directory)
        for parent in [directory.parent, directory]:
            os.chmod(parent, 0o750)
            os.chown(parent, 0, 10001)
        for name, content in [('cert.pem', contents['fullchain.pem']), ('key.pem', contents['privkey.pem'])]:
            target = directory / name
            if target.exists():
                if target.is_symlink() or target.read_bytes() != content:
                    raise DomainError('证书代次内容不一致')
            else:
                with target.open('xb') as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(target, 0o640)
                os.chown(target, 0, 10001)
        for parent in [directory, directory.parent]:
            fd = os.open(parent, os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        return generation

    def apply(self, renew=False):
        trusted_directory(self.conf)
        trusted_directory(self.control)
        domain = ''
        try:
            # Security-only lock spans recovery, challenge publication and activation.
            with entry_lock():
                self.restore()
                request = read_json(self.runtime / 'domain.json' if renew else self.control / 'request.json')
                if renew and not request:
                    return
                domain = request.get('domain') if isinstance(request, dict) else None
                if not valid_domain(domain):
                    raise DomainError('域名请求格式错误')
                if renew:
                    with (self.control / 'queue.lock').open('a') as lock:
                        fcntl.flock(lock, fcntl.LOCK_EX)
                        if self.status().get('state') == 'running':
                            return
                        self.status_write('running', domain, '正在检查入口并续期证书')
                else:
                    self.status_write('running', domain, '正在检查入口并申请证书')
                try:
                    if not port_free(80):
                        raise DomainError('80 端口已被其他服务占用，无法自动验证域名；原入口保留，程序不会修改或停止其他服务')
                    previous = read_json(self.runtime / 'domain.json', {})
                    owned = subprocess.run(['systemctl', 'is-active', '--quiet', self.gateway], check=False).returncode == 0
                    enabled = subprocess.run(['systemctl', 'is-enabled', '--quiet', self.gateway], check=False).returncode == 0
                    if not owned and not port_free(443):
                        raise DomainError('443 端口已被其他服务占用，无法启用独立 HTTPS 入口；原入口保留，程序不会修改或停止其他服务')
                    atomic_json(self.control / 'transaction.json', {'previous': previous,
                        'gateway': {'active': owned, 'enabled': enabled}, 'domain': domain})
                    webroot = self.runtime / 'acme-challenge'
                    self.challenge_probe(domain, True, webroot)
                    generation = self.issue(domain, True, webroot)
                    atomic_json(self.runtime / 'domain.json', {'schema': 1, 'domain': domain, 'origin': 'https://' + domain,
                        'gateway': True, 'generation': generation}, public=True)
                    run(['systemctl', 'enable', '--now', self.gateway])
                    service = 'ironcurtain-local' if self.role == 'local' else 'xuanwu-admin'
                    expected = json.dumps({'service': service, 'ready': True}, separators=(',', ':')).encode()
                    for attempt in range(4):
                        try:
                            probe(domain, '/healthz', expected, https=True)
                            break
                        except DomainError:
                            if attempt == 3:
                                raise
                            time.sleep(2)
                    # Commit only after trusted HTTPS routing returns the exact role identity.
                    self.status_write('ready', domain, '域名已启用，公共证书已核验，系统将自动续期')
                    with (self.control / 'audit.jsonl').open('a') as audit:
                        audit.write(json.dumps({'action': 'renew' if renew else 'apply', 'domain': domain,
                            'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}) + '\n')
                        audit.flush()
                        os.fsync(audit.fileno())
                    durable_unlink(self.control / 'transaction.json')
                except Exception:
                    self.restore()
                    raise
        except Exception as error:
            if (self.control / 'transaction.json').exists():
                self.status_write('failed', domain, '恢复尚未完成，保留恢复记录；请在 Linux 菜单检查域名服务')
            else:
                self.status_write('failed', domain, str(error) if isinstance(error, (DomainError, RuntimeError)) else '域名设置未完成，原配置已恢复；请查看 Linux 服务日志')
            raise
        finally:
            (self.runtime / 'domain-pending.json').unlink(missing_ok=True)

    def serve(self):
        controller = self
        trusted_directory(self.control)
        self.socket_dir.mkdir(mode=0o750, exist_ok=True)
        os.chown(self.socket_dir, 0, 10001)
        os.chmod(self.socket_dir, 0o750)
        sock = self.socket_dir / 'control.sock'
        sock.unlink(missing_ok=True)

        class Handler(http.server.BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(5)

            def authorized(self):
                _pid, uid, gid = struct.unpack('3i', self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                return uid == 0 or (uid == 10001 and gid == 10001)

            def send(self, code, value):
                payload = json.dumps(value, ensure_ascii=False).encode()
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):
                if not self.authorized():
                    return self.send(403, {'error': '身份无权访问'})
                if self.path != '/domain':
                    return self.send(404, {'error': '接口不存在'})
                self.send(200, controller.status())

            def do_POST(self):
                if not self.authorized():
                    return self.send(403, {'error': '身份无权访问'})
                if self.path != '/domain' or self.headers.get('Transfer-Encoding') or self.headers.get_content_type() != 'application/json':
                    return self.send(400, {'error': '请求格式无效'})
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                    if not 0 < length <= 1024:
                        raise ValueError()
                    value = json.loads(self.rfile.read(length))
                except (ValueError, TimeoutError):
                    return self.send(400, {'error': '请求格式无效'})
                code, result = controller.queue(value)
                self.send(code, result)

            def log_message(self, *args):
                pass

        class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True
            slots = threading.BoundedSemaphore(8)

            def process_request(self, request, address):
                if not self.slots.acquire(blocking=False):
                    self.shutdown_request(request)
                    return
                try:
                    super().process_request(request, address)
                except Exception:
                    self.slots.release()
                    raise

            def process_request_thread(self, request, address):
                try:
                    super().process_request_thread(request, address)
                finally:
                    self.slots.release()

        with Server(str(sock), Handler) as server:
            os.chown(sock, 0, 10001)
            os.chmod(sock, 0o660)
            if read_json(self.control / 'status.json', {}).get('state') == 'running':
                run(['systemctl', 'start', '--no-block', self.worker], 10)
            server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', required=True, choices=['local', 'cloud'])
    parser.add_argument('--action', required=True, choices=['serve', 'apply', 'renew', 'status'])
    arguments = parser.parse_args()
    controller = Controller(arguments.role)
    if os.geteuid() != 0:
        parser.error('root required')
    if arguments.action == 'serve':
        controller.serve()
    elif arguments.action == 'status':
        print(json.dumps(controller.status(), ensure_ascii=False))
    else:
        controller.apply(renew=arguments.action == 'renew')
