"""Bounded signed-release checks and fixed systemd jobs for the local panel."""
import argparse
import base64
import datetime
import hashlib
import importlib.util
import ipaddress
import json
import os
import pathlib
import re
import ssl
import stat
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request

try:
    import fcntl
except ImportError:
    fcntl = None

BASE = pathlib.Path('/opt/ironcurtain/local')
DATA = pathlib.Path('/var/lib/ironcurtain/local')
PROJECT = 'Jerry2586/Cloud-based-Scanning-and-Removal-Center'
API = 'https://api.github.com/repos/' + PROJECT
VERSION = re.compile(r'^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$')
HASH = re.compile(r'^[a-f0-9]{64}$')
FAILURE = '版本检查或更新失败；请在 Linux 菜单核对网络、凭据、完整性及安装事务。'


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def version(value):
    if not isinstance(value, str) or len(value) > 32 or not VERSION.fullmatch(value):
        raise ValueError('version invalid')
    return tuple(int(x) for x in value.split('.'))


def receipt(read, base=BASE):
    saved = json.loads(read(base / 'install.json', 8192))
    version(saved.get('version'))
    if saved.get('schema') != 1 or saved.get('role') != 'local':
        raise ValueError('receipt invalid')
    if not re.fullmatch('ironcurtain-security:' + re.escape(saved['version']) + '-local-[a-f0-9]{64}', saved.get('image', '')):
        raise ValueError('image invalid')
    host = saved.get('host', '')
    if not isinstance(host, str) or len(host) > 253:
        raise ValueError('host invalid')
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', host):
            raise ValueError('host invalid')
    ipaddress.IPv4Address(saved.get('bind', ''))
    current = (base / 'current').resolve(strict=True)
    if current.parent != base / 'releases' or json.loads(read(current / 'package.json', 8192)).get('version') != saved['version']:
        raise ValueError('current invalid')
    return saved, current


def payload_digest(current, read):
    names = []
    for directory in ('src', 'docker', 'scripts'):
        if (current / directory).is_symlink():
            raise ValueError('payload link')
        for path in (current / directory).rglob('*'):
            if '__pycache__' in path.parts:
                continue
            if path.is_symlink():
                raise ValueError('payload link')
            if path.is_file():
                names.append(path.relative_to(current).as_posix())
                if len(names) > 10000:
                    raise ValueError('payload limit')
    names += ['package.json', 'release-contract.json', 'release-public.pem', '.dockerignore', 'install.sh']
    total = hashlib.sha256()
    for name in sorted(names):
        total.update((hashlib.sha256(read(current / name, 64 * 1024 * 1024)).hexdigest() + '  ' + name + '\n').encode())
    return total.hexdigest()


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != 'https' or target.port not in (None, 443) or target.hostname not in ('api.github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com') or target.username or target.password:
            raise ValueError('redirect denied')
        if target.hostname == 'api.github.com' and not target.path.startswith('/repos/' + PROJECT + '/'):
            raise ValueError('redirect repo denied')
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected and target.hostname != 'api.github.com':
            redirected.remove_header('Authorization')
        return redirected


def downloader(token=None):
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()), Redirects())
    def get(url, maximum, accept='application/vnd.github+json'):
        target = urllib.parse.urlsplit(url)
        if target.scheme != 'https' or target.hostname != 'api.github.com' or target.port not in (None, 443) or target.username or target.password or not target.path.startswith('/repos/' + PROJECT + '/'):
            raise ValueError('source denied')
        headers = {'Accept': accept, 'User-Agent': 'IronCurtain-release-check', 'X-GitHub-Api-Version': '2022-11-28'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        with opener.open(urllib.request.Request(url, headers=headers), timeout=12) as response:
            if response.status != 200:
                raise ValueError('download failed')
            data = response.read(maximum + 1)
            if len(data) > maximum:
                raise ValueError('download limit')
            return data
    return get


def signed_manifest(data, signature, key, expected, contract):
    if len(data) > 65536 or len(signature) != 64:
        raise ValueError('signature size')
    lines = key.strip().splitlines()
    if len(lines) != 3 or lines[0] != b'-----BEGIN PUBLIC KEY-----' or lines[-1] != b'-----END PUBLIC KEY-----':
        raise ValueError('key invalid')
    der = base64.b64decode(lines[1], validate=True)
    if len(der) != 44 or der[:12] != bytes.fromhex('302a300506032b6570032100'):
        raise ValueError('Ed25519 required')
    with tempfile.TemporaryDirectory(prefix='ironcurtain-version-') as directory:
        root = pathlib.Path(directory)
        for name, content in [('key', key), ('manifest', data), ('signature', signature)]:
            (root / name).write_bytes(content)
        result = subprocess.run(['/usr/bin/openssl', 'pkeyutl', '-verify', '-pubin', '-rawin', '-inkey', str(root / 'key'), '-in', str(root / 'manifest'), '-sigfile', str(root / 'signature')], capture_output=True, timeout=5)
        if result.returncode:
            raise ValueError('signature invalid')
    m = json.loads(data)
    if set(m) != {'schema', 'product', 'version', 'tar_name', 'tar_sha256', 'run_name', 'run_sha256', 'environment'} or m['schema'] != 1 or m['product'] != 'appgog-cloud-security-center' or m['version'] != expected:
        raise ValueError('manifest invalid')
    version(m['version'])
    # Package environment compatibility is enforced again by the signed installer.
    env = m['environment']
    if not isinstance(env, dict) or env.get('schema') != 1 or env.get('product') != m['product'] or env.get('artifact_prefix') != contract.get('artifact_prefix'):
        raise ValueError('contract invalid')
    for field, suffix in [('run', '.run'), ('tar', '.tar.gz')]:
        if m[field + '_name'] != contract['artifact_prefix'] + '-' + expected + suffix or not isinstance(m[field + '_sha256'], str) or not HASH.fullmatch(m[field + '_sha256']):
            raise ValueError('artifact invalid')
    return m


def git_commit(get, reference):
    """Read compact Git objects; large code diffs never hide source changes."""
    obj = json.loads(get(API + '/git/ref/' + reference, 16384)).get('object')
    for _ in range(4):
        if not isinstance(obj, dict) or not isinstance(obj.get('sha'), str) or not re.fullmatch('[a-f0-9]{40}', obj['sha']):
            raise ValueError('Git object invalid')
        if obj.get('type') == 'commit':
            return obj['sha']
        if obj.get('type') != 'tag':
            raise ValueError('Git object type invalid')
        obj = json.loads(get(API + '/git/tags/' + obj['sha'], 16384)).get('object')
    raise ValueError('Git tag depth invalid')


def check_release(read, base=BASE, get=None, verify=signed_manifest):
    saved, current = receipt(read, base)
    expected = saved['image'].rsplit('-', 1)[1]
    result = {'schema': 'ironcurtain-update/v1', 'state': 'failed', 'checked_at': stamp(), 'installed_version': saved['version'], 'installed_integrity': 'unavailable', 'update_available': False, 'source': {'state': 'unavailable'}}
    if read(current / '.payload-sha256', 80).decode().strip() != expected or payload_digest(current, read) != expected:
        result.update(installed_integrity='mismatch', reason='安装文件摘要与安装记录不一致；已阻止面板更新，请在 Linux 菜单排查。')
        return result
    result['installed_integrity'] = 'verified'
    try:
        if get is None:
            token_path = pathlib.Path('/etc/ironcurtain/github-release.token')
            token = None
            if token_path.exists() or token_path.is_symlink():
                token = read(token_path, 1024).decode().strip()
                if stat.S_IMODE(token_path.stat().st_mode) not in (0o600, 0o400) or not re.fullmatch('[A-Za-z0-9_]{1,256}', token):
                    raise ValueError('token invalid')
            get = downloader(token)
        try:
            sha = git_commit(get, 'heads/main')
            if isinstance(sha, str) and re.fullmatch('[a-f0-9]{40}', sha):
                result['source'] = {'state': 'observed', 'commit': sha}
        except Exception:
            pass
        release = json.loads(get(API + '/releases/latest', 262144))
        if release.get('draft') is not False or release.get('prerelease') is not False or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', release.get('tag_name', '')):
            raise ValueError('release invalid')
        latest = release['tag_name'][1:]
        version(latest)
        names = ['APPGOG-Cloud-Security-Center-' + latest + x for x in ('.run', '.run.sha256', '.tar.gz', '.tar.gz.sha256')] + ['release-manifest.json', 'release-manifest.json.sig']
        assets = release.get('assets', [])
        if not isinstance(assets, list) or len(assets) != 6 or any(not isinstance(x, dict) for x in assets) or sorted(x.get('name', '') for x in assets) != sorted(names):
            raise ValueError('assets invalid')
        files = {}
        for asset in assets:
            if type(asset.get('id')) is not int or asset['id'] <= 0 or asset.get('state') != 'uploaded':
                raise ValueError('asset invalid')
            if asset['name'] in ('release-manifest.json', 'release-manifest.json.sig'):
                files[asset['name']] = get(API + '/releases/assets/' + str(asset['id']), 65536 if asset['name'].endswith('.json') else 64, 'application/octet-stream')
        m = verify(files['release-manifest.json'], files['release-manifest.json.sig'], read(current / 'release-public.pem', 8192), latest, json.loads(read(current / 'release-contract.json', 32768)))
        if version(latest) < version(saved['version']):
            raise ValueError('downgrade denied')
        result.update(state='verified', latest_version=latest, manifest_sha256=hashlib.sha256(files['release-manifest.json']).hexdigest(), package_sha256=m['run_sha256'], update_available=version(latest) > version(saved['version']))
        try:
            tagged = git_commit(get, 'tags/v' + latest)
            if result['source']['state'] == 'observed' and isinstance(tagged, str) and re.fullmatch('[a-f0-9]{40}', tagged):
                result['source'].update(release_commit=tagged, has_unreleased_changes=tagged != result['source']['commit'])
        except Exception:
            pass
    except Exception:
        result.update(state='failed', update_available=False, reason=FAILURE)
    return result


def public_record(value, kind):
    """Whitelist disk metadata before returning it to the panel."""
    if not isinstance(value, dict) or value.get('state') not in ('idle', 'running', 'verified', 'failed', 'finished', 'unavailable'):
        raise ValueError('record invalid')
    clean = {'state': value['state']}
    for name in ('checked_at', 'started_at', 'finished_at'):
        date = value.get(name)
        if isinstance(date, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T[0-9:.]+Z', date) and len(date) <= 32:
            clean[name] = date
    for name in ('version', 'installed_version', 'latest_version'):
        if value.get(name) is not None:
            version(value[name]); clean[name] = value[name]
    if value.get('result') in ('updated', 'already-current'):
        clean['result'] = value['result']
    if clean['state'] in ('failed', 'unavailable'):
        clean['reason'] = '安装文件摘要不一致，面板更新已阻止。' if value.get('installed_integrity') == 'mismatch' else FAILURE
    if kind == 'check':
        clean['schema'] = 'ironcurtain-update/v1'
        clean['installed_integrity'] = value.get('installed_integrity') if value.get('installed_integrity') in ('verified', 'mismatch') else 'unavailable'
        source = value.get('source', {})
        if not isinstance(source, dict): source = {}
        clean['source'] = {'state': 'unavailable'}
        if source.get('state') == 'observed' and isinstance(source.get('commit'), str) and re.fullmatch('[a-f0-9]{40}', source['commit']):
            clean['source'] = {'state': 'observed', 'commit': source['commit']}
            if isinstance(source.get('release_commit'), str) and re.fullmatch('[a-f0-9]{40}', source['release_commit']):
                clean['source'].update(release_commit=source['release_commit'], has_unreleased_changes=source['release_commit'] != source['commit'])
        clean['update_available'] = False
        if clean['state'] == 'verified':
            if clean['installed_integrity'] != 'verified' or 'checked_at' not in clean or not all(isinstance(value.get(k), str) and HASH.fullmatch(value[k]) for k in ('manifest_sha256', 'package_sha256')):
                raise ValueError('verified record invalid')
            relation = version(clean['latest_version']) > version(clean['installed_version'])
            if version(clean['latest_version']) < version(clean['installed_version']):
                raise ValueError('downgrade denied')
            clean.update(update_available=relation, manifest_sha256=value['manifest_sha256'], package_sha256=value['package_sha256'])
    return clean


class Bridge:
    def __init__(self, read, atomic, run=subprocess.run, base=BASE, data=DATA):
        self.read, self.atomic, self.run, self.base, self.data = read, atomic, run, base, data
        self.lock = threading.Lock()
        self.last = -10

    def status(self):
        result = {'schema': 'ironcurtain-update-status/v1', 'check': {'state': 'idle'}, 'job': {'state': 'idle'}, 'installed_version': None}
        try:
            result['installed_version'] = receipt(self.read, self.base)[0]['version']
        except Exception:
            pass
        for key in ('check', 'job'):
            try:
                value = json.loads(self.read(self.data / 'panel-update' / (key + '.json'), 8192))
                result[key] = public_record(value, key)
                if result[key]['state'] == 'running':
                    unit = 'check' if key == 'check' else 'update'
                    observed = self.run(['/usr/bin/systemctl', 'show', '--property=ActiveState', '--value', 'ironcurtain-panel-' + unit + '.service'], timeout=1, capture_output=True, text=True)
                    if observed.returncode or observed.stdout.strip() not in ('active', 'activating', 'reloading', 'deactivating'):
                        result[key] = {'state': 'failed', 'reason': FAILURE}
            except FileNotFoundError:
                pass
            except Exception:
                result[key] = {'state': 'unavailable'}
        return result

    def trigger(self, action):
        if action not in ('check', 'update'):
            return 400, {'state': 'unavailable'}
        with self.lock:
            try:
                if time.monotonic() - self.last < 10:
                    return 429, {'state': 'unavailable', 'reason': '请稍后再试'}
                for unit in ('check', 'update'):
                    result = self.run(['/usr/bin/systemctl', 'show', '--property=ActiveState', '--value', 'ironcurtain-panel-' + unit + '.service'], timeout=1, capture_output=True, text=True)
                    if result.returncode or result.stdout.strip() not in ('inactive', 'failed'):
                        return 409 if result.stdout.strip() in ('active', 'activating', 'reloading', 'deactivating') else 503, {'state': 'running' if result.stdout.strip() in ('active', 'activating', 'reloading', 'deactivating') else 'unavailable'}
                result = self.run(['/usr/bin/systemctl', 'start', '--no-block', 'ironcurtain-panel-' + action + '.service'], timeout=1, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result.returncode:
                    return 503, {'state': 'unavailable'}
                self.last = time.monotonic()
                return 202, {'state': 'running'}

            except (OSError, subprocess.SubprocessError):
                return 503, {'state': 'unavailable'}

def work(action):
    spec = importlib.util.spec_from_file_location('update_host', pathlib.Path(__file__).with_name('agent.py'))
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    folder = DATA / 'panel-update'
    folder.mkdir(mode=0o700, exist_ok=True)
    for directory in (folder, *folder.parents):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('update directory invalid')
    if stat.S_IMODE(folder.stat().st_mode) != 0o700:
        raise ValueError('update directory permissions invalid')
    host.private_bytes(BASE / 'install.json', 8192)
    lock = os.open('/run/lock/ironcurtain-panel-update.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock, 'a') as handle:
        info = os.fstat(handle.fileno())
        if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
            raise ValueError('lock invalid')
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        target = folder / ('check.json' if action == 'check' else 'job.json')
        host.atomic_json(target, {'state': 'running', 'started_at': stamp()})
        try:
            checked = check_release(host.private_bytes)
            host.atomic_json(folder / 'check.json', checked)
            if checked['state'] != 'verified':
                raise ValueError('check failed')
            if action == 'check':
                return
            saved, current = receipt(host.private_bytes)
            if not checked['update_available']:
                host.atomic_json(target, {'state': 'finished', 'finished_at': stamp(), 'version': saved['version'], 'result': 'already-current'})
                return
            host.atomic_json(target, {'state': 'running', 'started_at': stamp(), 'version': checked['latest_version']})
            env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8', 'TERM': 'dumb'}
            for proxy in ('HTTPS_PROXY', 'https_proxy', 'NO_PROXY', 'no_proxy'):
                if proxy in os.environ:
                    env[proxy] = os.environ[proxy]
            # The systemd control group bounds descendants, including on timeout.
            logfd = os.open(folder / 'update.log', os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(logfd, 'wb') as log:
                info = os.fstat(log.fileno())
                if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
                    raise ValueError('log invalid')
                result = subprocess.run(['/bin/sh', str(current / 'install.sh'), '--role', 'local', '--host', saved['host'], '--bind', saved['bind'], '--version', checked['latest_version']], env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            actual = receipt(host.private_bytes)[0]['version']
            if result.returncode or actual != checked['latest_version']:
                raise ValueError('update unsuccessful')
            host.atomic_json(target, {'state': 'finished', 'finished_at': stamp(), 'version': actual, 'result': 'updated'})
        except Exception:
            if action == 'update':
                host.atomic_json(target, {'state': 'failed', 'finished_at': stamp(), 'reason': FAILURE})
            else:
                # Preserve independently observed Git metadata if formal verification failed.
                existing = json.loads(host.private_bytes(target, 8192))
                if existing.get('state') == 'running':
                    host.atomic_json(target, {'state': 'failed', 'finished_at': stamp(), 'reason': FAILURE})
            raise SystemExit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['check', 'update'])
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('root required')
    work(args.action)
