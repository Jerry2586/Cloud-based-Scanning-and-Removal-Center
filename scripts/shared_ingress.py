"""Optional v1 shared ingress contract; only fixed root-managed role sites are writable."""
import fcntl
import ipaddress
import re
import secrets
import stat
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path('/opt/appgog/shared/ingress')


def execute(args, timeout=30):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError('共享入口验证或重启失败；原站点配置将恢复')
    return result.stdout


def controlled(path, directory=False):
    info = path.lstat()
    if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022 or (directory and not path.is_dir()) or (not directory and (not path.is_file() or info.st_nlink != 1)):
        raise RuntimeError('共享入口配置必须由 root 控制')
    return path


def publish(path, content, private=False):
    if path.exists() or path.is_symlink():
        controlled(path)
        if not path.is_file() or path.stat().st_nlink != 1:
            raise RuntimeError('共享入口文件格式异常')
    temporary = path.with_name(path.name + '.' + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640 if private else 0o644)
    try:
        os.fchown(fd, 0, 1000)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


class SharedIngress:
    def __init__(self, role, container, root=ROOT, domain=None):
        if role not in ('local', 'cloud') or not re.fullmatch(r'[a-f0-9]{12}', container):
            raise RuntimeError('共享入口身份无效')
        self.role, self.container, self.root = role, container, root
        self.domain = domain
        self.site = root / ('ironcurtain-' + role + '.caddy')
        self.directory = root / ('ironcurtain-' + role)
        self.webroot = self.directory / 'acme'
        self.base = '/app/runtime/ingress/ironcurtain-' + role

    @classmethod
    def discover(cls, role, domain):
        ids = execute(['docker', 'ps', '--filter', 'label=com.appgog.shared-ingress=v1', '--format', '{{.ID}}']).decode().split()
        matches = []
        for identity in ids:
            if not identity.isalnum() or len(identity) != 12:
                raise RuntimeError('共享入口容器身份异常')
            item = json.loads(execute(['docker', 'inspect', identity]))[0]
            if item.get('Config', {}).get('Labels', {}).get('com.appgog.shared-ingress') != 'v1' or not item.get('State', {}).get('Running'):
                continue
            ports = item.get('NetworkSettings', {}).get('Ports', {})
            owns = lambda key, port: any(binding.get('HostPort') == port for binding in ports.get(key, []) or [])
            if not (owns('8080/tcp', '80') and owns('8443/tcp', '443')):
                continue
            mounts = [m for m in item.get('Mounts', []) if m.get('Destination') == '/app/runtime/ingress']
            if len(mounts) != 1 or mounts[0].get('Source') != str(ROOT) or mounts[0].get('RW'):
                raise RuntimeError('共享入口未使用受控只读目录，请先更新 APPGOG')
            if 'host.docker.internal:host-gateway' not in item['HostConfig'].get('ExtraHosts', []):
                raise RuntimeError('共享入口缺少宿主机转发地址，请先更新 APPGOG')
            env = dict(v.split('=', 1) for v in item['Config'].get('Env', []) if '=' in v)
            if domain in [env.get('AUTH_DOMAIN'), env.get('BUILD_DOMAIN')]:
                raise RuntimeError('安全域名不能覆盖授权或打包域名')
            matches.append(cls(role, identity, domain=domain))
        if len(matches) != 1:
            raise RuntimeError('80/443 已被占用；当前入口未提供共享站点接口，请先更新 APPGOG')
        for directory in [ROOT, *ROOT.parents]:
            controlled(directory, directory=True)
        return matches[0]

    def revalidate(self):
        current = self.discover(self.role, self.domain)
        if current.container != self.container or current.root != self.root:
            raise RuntimeError("共享入口已变化，请稍后重试")

    def snapshot(self):
        self.revalidate()
        if self.site.exists() or self.site.is_symlink():
            controlled(self.site)
            if self.site.stat().st_size > 65536:
                raise RuntimeError('共享入口配置过大')
            content = self.site.read_text()
        else:
            content = None
        return {'content': content}

    def initialize(self):
        self.revalidate()
        for directory in [self.directory, self.webroot, self.webroot / '.well-known', self.webroot / '.well-known/acme-challenge']:
            directory.mkdir(mode=0o755, exist_ok=True)
            controlled(directory, directory=True)
            os.chmod(directory, 0o755)

    def http_site(self, domain, ready=False):
        return ('http://' + domain + ' {\n'
                '  handle /.well-known/acme-challenge/* {\n'
                '    root * ' + self.base + '/acme\n    file_server\n  }\n' +
                ('  handle {\n    redir https://' + domain + '{uri} 308\n  }\n}\n' if ready else '  handle {\n    respond "Domain setup in progress" 503\n  }\n}\n'))

    def prepare(self, domain, previous):
        self.revalidate()
        self.initialize()
        content = previous.get('content') or ''
        if 'http://' + domain + ' {' not in content:
            publish(self.site, (content + '\n' + self.http_site(domain)).encode())
            self.reload()

    def activate(self, domain, generation, runtime, host):
        self.initialize()
        from domain_control import valid_domain
        if not valid_domain(domain) or not re.fullmatch(r'[a-f0-9]{64}', generation):
            raise RuntimeError('共享入口域名或证书代次异常')
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            if not valid_domain(host):
                raise RuntimeError('共享入口上游地址异常')
        certdir = self.directory / generation
        certdir.mkdir(mode=0o750, exist_ok=True)
        controlled(certdir, directory=True)
        os.chown(certdir, 0, 1000)
        os.chmod(certdir, 0o750)
        for source, target, private in [(runtime / 'domain-certificates' / generation / 'cert.pem', 'cert.pem', False),
                                        (runtime / 'domain-certificates' / generation / 'key.pem', 'key.pem', True),
                                        (runtime / 'panel.crt', 'upstream.pem', False)]:
            publish(certdir / target, source.read_bytes(), private)
        port = '8790' if self.role == 'local' else '8791'
        content = self.http_site(domain, ready=True) + ('https://' + domain + ' {\n'
            '  tls ' + self.base + '/' + generation + '/cert.pem ' + self.base + '/' + generation + '/key.pem\n'
            '  reverse_proxy https://host.docker.internal:' + port + ' {\n'
            '    header_up Host {http.request.host}\n'
            '    transport http {\n      tls_server_name ' + host + '\n'
            '      tls_trust_pool file ' + self.base + '/' + generation + '/upstream.pem\n    }\n  }\n}\n')
        if self.snapshot().get('content') != content:
            publish(self.site, content.encode())
            self.reload()

    def reload(self):
        self.revalidate()
        item = json.loads(execute(['docker', 'inspect', self.container]))[0]
        role = next((v.split('=', 1)[1] for v in item['Config'].get('Env', []) if v.startswith('APPGOG_DEPLOYMENT_ROLE=')), 'all')
        if role not in ('all', 'license', 'build'):
            raise RuntimeError('APPGOG 角色配置异常')
        config = '/app/Caddyfile' + ('.' + role if role != 'all' else '')
        execute(['docker', 'exec', self.container, 'caddy', 'validate', '--config', config, '--adapter', 'caddyfile'])
        execute(['docker', 'restart', '--time', '30', self.container], 60)
        for _ in range(30):
            state = json.loads(execute(['docker', 'inspect', self.container]))[0]['State']
            if state.get('Health', {}).get('Status') == 'healthy':
                return
            if not state.get('Running') or state.get('Health', {}).get('Status') == 'unhealthy':
                break
            time.sleep(2)
        raise RuntimeError('共享入口健康检查未通过')

    def restore(self, snapshot):
        self.initialize()
        if self.snapshot().get('content') == snapshot.get('content'):
            return
        if snapshot.get('content') is None:
            self.site.unlink(missing_ok=True)
            fd = os.open(self.site.parent, os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        else:
            publish(self.site, snapshot['content'].encode())
        self.reload()


@contextmanager
def ingress_lock():
    lockpath = Path('/run/lock/appgog-ingress.lock')
    if lockpath.is_symlink():
        raise RuntimeError('共享入口锁不安全')
    fd = os.open(lockpath, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode):
            raise RuntimeError('共享入口锁不受 root 控制')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('APPGOG 更新或另一个域名任务正在运行，请稍后重试') from error
        yield
    finally:
        os.close(fd)
