#!/usr/bin/env python3
"""Fixed-scope, read-only Linux posture checks exposed on a local Unix socket."""
import hashlib
import ipaddress
import json
import math
import os
import posixpath
import re
import selectors
import tempfile
import socketserver
import stat
import subprocess
import sys
import threading
import time
import zipfile
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler
from pathlib import Path

SOCKET = os.environ.get('APPGOG_HOST_SCAN_SOCKET', '/run/appgog-security/scan.sock')
ROOT = Path(os.environ.get('APPGOG_INSTALL_ROOT', '/opt/appgog')).resolve()
STATE_DIR = Path('/var/lib/appgog-security')
BASELINE = STATE_DIR / 'baseline.json'
HOST_BASELINE = STATE_DIR / 'host-baseline.json'
HISTORY_FILE = STATE_DIR / 'events.json'
PROGRAM_DIRS = ('apps', 'packages', 'scripts')
PROGRAM_ROOT_FILES = ('package.json', 'pnpm-lock.yaml', 'release-contract.json', 'Dockerfile',
                      'compose.yaml', 'compose.license.yaml', 'compose.build.yaml',
                      'Caddyfile', 'Caddyfile.license', 'Caddyfile.build',
                      '.env.example', '.env.docker.example', '.dockerignore', 'install-docker.sh')
IGNORED_DIRS = {'node_modules', '.git', '__pycache__'}
MAX_INVENTORY_FILES = 4096
MAX_INVENTORY_BYTES = 128 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
HOST_FILES = ('/etc/passwd', '/etc/group', '/etc/ssh/sshd_config', '/etc/sudoers',
              '/etc/sysctl.conf', '/etc/ufw/ufw.conf',
              '/etc/crontab', '/etc/docker/daemon.json', '/etc/login.defs', '/etc/ssh/sshrc')
HOST_DIRS = ('/etc/ssh/sshd_config.d', '/etc/sudoers.d', '/etc/cron.d',
             '/etc/sysctl.d', '/etc/ufw', '/etc/firewalld', '/etc/iptables',
             '/etc/systemd/system', '/var/spool/cron')

# Fixed local login scope; neither NSS nor private key files are queried.
LOCAL_PASSWD = Path('/etc/passwd')
NON_LOGIN_SHELLS = frozenset(('/bin/false', '/usr/bin/false', '/sbin/nologin', '/usr/sbin/nologin',
                             '/bin/sync', '/usr/bin/sync', '/sbin/shutdown', '/usr/sbin/shutdown',
                             '/sbin/halt', '/usr/sbin/halt'))
SSH_LOGIN_FILES = ('authorized_keys', 'authorized_keys2', 'authorized_principals', 'rc', 'environment')
MAX_LOCAL_ACCOUNTS = 256
MAX_LOGIN_HOMES = 64
MAX_LOGIN_FILE_BYTES = 64 * 1024
MAX_LOGIN_BYTES = 1024 * 1024

MAX_HISTORY = 64
MAX_RESPONSE_BYTES = 32768
MAX_CHECKS = 26
MAX_RESPONSE_HISTORY = 8
EVENTS = []
PREVIOUS = {}
HISTORY_VALID = True
SCANNER = Path('/usr/bin/clamscan')
CLAM_DATABASE = Path('/var/lib/clamav')
FILES = ('compose.yaml', 'compose.license.yaml', 'compose.build.yaml', 'Dockerfile', 'scripts/install-linux.sh',
         'scripts/host-security-agent.py', 'apps/license-api/src/modules/operations/http-routes.js',
         'apps/web/public/admin.html')
LOCK = threading.Lock()
STATE = {'state': 'idle', 'checked_at': None, 'checks': []}
LAST_START = None
SCAN_INTERVAL_SECONDS = 300
CHECK_STATES = {'ok', 'warning', 'finding', 'unavailable'}
SEVERITIES = {'info', 'low', 'medium', 'high', 'critical', 'unknown'}
DANGEROUS_PUBLIC_PORTS = {21, 23, 2375}
MAX_LISTENERS = 64


def bounded_text(value, limit):
    return str(value if value is not None else '')[:limit]


def bounded_evidence(value, depth=0):
    """Create a deterministic, size-limited evidence shape without reading secrets."""
    if depth >= 4:
        return '<truncated>'
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda item: str(item[0]))[:32]
        return {bounded_text(key, 48): bounded_evidence(item, depth + 1) for key, item in items}
    if isinstance(value, (list, tuple, set)):
        ordered = sorted(value, key=str) if isinstance(value, set) else list(value)
        return [bounded_evidence(item, depth + 1) for item in ordered[:32]]
    if isinstance(value, str):
        return value[:160]
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return bounded_text(value, 160)


HOST_SCAN_IDS = frozenset((
    'integrity.program',
    'host.configuration',
    'container.contract',
    'container.approved-image',
    'response.containment',
    'host.os-release',
    'host.systemd-state',
    'ssh.effective',
    'permissions.secret-inventory',
    'permissions.installation',
    'permissions.cron',
    'network.listeners',
    'network.udp-listeners',
    'network.routes',
    'host.kernel-security',
    'network.firewall',
    'malware.program',
    'malware.business',
    'database.sqlite',
    'host.process-executables',
    'host.failed-units',
    'cloudflare.dns',
    'cloudflare.workers',
    'cloudflare.rules',
    'cloudflare.settings'
))


def complete_scan_checks(checks, checked_at):
    if not isinstance(checks, list) or not len(HOST_SCAN_IDS) <= len(checks) <= len(HOST_SCAN_IDS) + 1:
        return False
    seen = set()
    try:
        if not isinstance(checked_at, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)', checked_at):
            return False
        report_time = datetime.fromisoformat(checked_at.replace('Z', '+00:00'))
        for item in checks:
            if not isinstance(item, dict):
                return False
            identifier = item.get('id')
            if not isinstance(identifier, str) or identifier in seen or identifier not in HOST_SCAN_IDS | {'host.history'}:
                return False
            if (item.get('state') not in CHECK_STATES or item.get('severity') not in SEVERITIES or
                    item.get('category') not in {'host', 'container', 'permissions', 'ssh', 'network', 'malware'} or
                    not isinstance(item.get('name'), str) or not item['name'] or
                    not isinstance(item.get('detail'), str) or not isinstance(item.get('scope'), str) or
                    not 1 <= len(item['scope']) <= 120 or not isinstance(item.get('evidence_digest'), str) or
                    not re.fullmatch(r'[a-f0-9]{64}', item['evidence_digest'])):
                return False
            stamp = item.get('checked_at')
            if not isinstance(stamp, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)', stamp):
                return False
            timestamp = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
            if timestamp > report_time + timedelta(seconds=120):
                return False
            if identifier == 'host.history' and item['state'] != 'unavailable':
                return False
            seen.add(identifier)
    except (ValueError, TypeError, OverflowError):
        return False
    return HOST_SCAN_IDS.issubset(seen)


def check(name, state, detail, *, check_id=None, category='host', severity=None,
          scope='fixed', evidence=None, checked_at=None):
    safe_state = state if state in CHECK_STATES else 'unavailable'
    safe_detail = bounded_text(detail, 180)
    safe_scope = bounded_text(scope, 120)
    safe_severity = severity if severity in SEVERITIES else {
        'ok': 'info', 'warning': 'medium', 'finding': 'high', 'unavailable': 'unknown',
    }[safe_state]
    safe_id = bounded_text(check_id or 'host.' + hashlib.sha256(
        bounded_text(name, 60).encode('utf-8')).hexdigest()[:16], 80)
    evidence_shape = bounded_evidence(evidence if evidence is not None else {
        'state': safe_state, 'detail': safe_detail, 'scope': safe_scope,
    })
    canonical = json.dumps(evidence_shape, ensure_ascii=True, sort_keys=True,
                           separators=(',', ':'), allow_nan=False).encode('utf-8')
    return {
        'name': bounded_text(name, 60),
        'state': safe_state,
        'detail': safe_detail,
        'id': safe_id,
        'category': bounded_text(category, 32),
        'severity': safe_severity,
        'checked_at': bounded_text(checked_at or datetime.now(timezone.utc).isoformat(), 40),
        'scope': safe_scope,
        'evidence_digest': hashlib.sha256(canonical).hexdigest(),
    }


def read_regular(path, limit=MAX_FILE_BYTES, *, proc_lookup=False):
    """No-follow descriptor reads, including ancestors, with size/race limits."""
    target = Path(path).absolute()
    parent_fd = None
    fd = None
    try:
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        if os.name == 'posix':
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            parent_fd = os.open(target.anchor, directory_flags)
            for part in target.parts[1:-1]:
                next_fd = os.open(part, directory_flags, dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = next_fd
            fd = os.open(target.name, flags, dir_fd=parent_fd)
        else:
            # Windows is used only for deterministic development tests.
            if target.is_symlink():
                raise OSError('symlink')
            fd = os.open(str(target), flags)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise OSError('not a bounded regular file')
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > limit:
                raise OSError('file limit exceeded')
        after = os.fstat(fd)
        named = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False) if parent_fd is not None else target.lstat()
        if proc_lookup:
            # Fixed proc entries can instantiate a new inode on path lookup,
            # with fresh timestamps (proc_net_d_revalidate/proc_get_inode).
            # The open descriptor must remain unchanged; the named entry must
            # still have the same device, inode, type, ownership and size.
            named_identity = lambda item: (item.st_dev, item.st_ino, item.st_mode,
                                            item.st_uid, item.st_gid, item.st_size)
            same_named_entry = named_identity(after) == named_identity(named)
        else:
            same_named_entry = file_identity(after) == file_identity(named)
        if file_identity(before) != file_identity(after) or not same_named_entry:
            raise OSError('file changed during read')
        return b''.join(chunks)
    finally:
        if fd is not None:
            os.close(fd)
        if parent_fd is not None:
            os.close(parent_fd)


def read_state(path, limit=1024 * 1024):
    metadata = Path(path).lstat()
    if os.name == 'posix' and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise OSError('untrusted state file permissions')
    return read_regular(path, limit)


def file_digest(path):
    return hashlib.sha256(read_regular(path)).hexdigest()


def private_directory(folder):
    folder = Path(folder).absolute()
    # Reject symlink ancestors before creating or writing root-owned evidence.
    for item in reversed((folder, *folder.parents)):
        if item.exists() or item.is_symlink():
            metadata = item.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise OSError('unsafe state directory')
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = folder.lstat()
    if os.name == 'posix' and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise OSError('state directory must be private and owned by the agent')


def atomic_json(target, value):
    target = Path(target)
    private_directory(target.parent)
    if target.is_symlink():
        raise OSError('state symlink')
    fd, name = tempfile.mkstemp(prefix='.' + target.name + '-', dir=str(target.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o600)
        os.replace(name, target)
        if os.name == 'posix':
            directory = os.open(str(target.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def release_root():
    candidate = ROOT / 'current'
    if not candidate.exists() and not candidate.is_symlink():
        return ROOT  # Supported direct Docker source layout.
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(ROOT)
        if candidate.is_symlink():
            resolved.relative_to(ROOT / 'releases')
    except ValueError as error:
        raise OSError('release escapes installation') from error
    if not resolved.is_dir() or resolved == ROOT:
        raise OSError('invalid release directory')
    return resolved


def bounded_tree(folder, *, allow_links=False):
    """Bounded enumeration; do not follow any directory or file symlink."""
    pending, seen = [Path(folder)], 0
    started = time.monotonic()
    while pending:
        current = pending.pop()
        before = current.lstat()
        if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise OSError('unsafe inventory directory')
        with os.scandir(current) as entries:
            for entry in entries:
                seen += 1
                if seen > MAX_INVENTORY_FILES or time.monotonic() - started > 15:
                    raise OSError('inventory count or time limit')
                item = Path(entry.path)
                # Windows DirEntry.stat may omit file identity; production uses
                # descriptor-independent POSIX metadata including inode/ctime.
                metadata = entry.stat(follow_symlinks=False) if os.name == 'posix' else item.lstat()
                if stat.S_ISDIR(metadata.st_mode):
                    if entry.name not in IGNORED_DIRS:
                        pending.append(item)
                elif stat.S_ISREG(metadata.st_mode) or (allow_links and stat.S_ISLNK(metadata.st_mode)):
                    yield item, metadata
                else:
                    raise OSError('unsupported inventory entry')
        if file_identity(before) != file_identity(current.lstat()):
            raise OSError('directory changed during inventory')


def program_snapshot():
    root = release_root()
    result, total = {}, 0
    for name in PROGRAM_ROOT_FILES:
        payload = read_regular(root / name)
        result[name] = hashlib.sha256(payload).hexdigest()
        total += len(payload)
    for name in PROGRAM_DIRS:
        for target, metadata in bounded_tree(root / name):
            key = target.relative_to(root).as_posix()
            payload = read_regular(target)
            total += len(payload)
            if len(result) >= MAX_INVENTORY_FILES or total > MAX_INVENTORY_BYTES:
                raise OSError('program inventory limit')
            result[key] = hashlib.sha256(payload).hexdigest()
    if total > MAX_INVENTORY_BYTES:
        raise OSError('program byte limit')
    if release_root() != root:
        raise OSError('active release changed during inventory')
    return result


def write_baseline():
    files = program_snapshot()
    version = installed_version()
    if file_digest(release_root() / 'package.json') != files['package.json']:
        raise OSError('version changed during approval')
    atomic_json(BASELINE, {'schema': 2, 'version': version, 'files': files,
                           'approved_at': datetime.now(timezone.utc).isoformat()})


def installed_version():
    package = json.loads(read_regular(release_root() / 'package.json', 65536))
    version = package.get('version')
    if not isinstance(version, str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?', version):
        raise ValueError('invalid package version')
    return version


def integrity_check():
    try:
        baseline = json.loads(read_state(BASELINE))
        if not isinstance(baseline, dict):
            raise ValueError('invalid baseline')
        if baseline.get('schema') != 2:
            # Preserve old evidence; never silently approve expanded coverage.
            if set(baseline) != set(FILES):
                raise ValueError('invalid legacy baseline')
            changed = [name for name in FILES if file_digest(release_root() / name) != baseline[name]]
            return check('程序文件完整性', 'finding' if changed else 'warning',
                         '旧基线文件变化：' + ', '.join(changed[:5]) if changed else '旧版仅覆盖少量文件；请在可信版本核验后由 root 批准扩展基线',
                         check_id='integrity.program', scope='legacy fixed inventory', evidence={'changed': changed})
        expected = baseline.get('files')
        if not isinstance(expected, dict) or not expected or len(expected) > MAX_INVENTORY_FILES:
            raise ValueError('invalid inventory')
        if any(not isinstance(key, str) or not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{64}', value) for key, value in expected.items()):
            raise ValueError('invalid file digest')
        current = program_snapshot()
        changed = sorted(key for key in set(expected) | set(current) if expected.get(key) != current.get(key))
        version_drift = baseline.get('version') != installed_version()
        return check('程序文件完整性', 'finding' if changed or version_drift else 'ok',
                     f'程序清单 {len(current)} 个；新增/删除/修改 {len(changed)} 个；' + ('版本与批准基线不符；' if version_drift else '') +
                     (', '.join(changed[:4]) if changed else '与本机批准基线一致；仍需独立可信核验'),
                     check_id='integrity.program', scope='apps/packages/scripts and release contracts; excludes data/node_modules',
                     evidence={'count': len(current), 'changed': changed, 'version_drift': version_drift})
    except (OSError, ValueError, TypeError):
        return check('程序文件完整性', 'unavailable', '基线缺失、清单超限、符号链接、文件不可读或扫描期间变化',
                     check_id='integrity.program', scope='bounded program inventory')



def login_directory_metadata(folder):
    """Descriptor-checked ancestors; a missing path never follows a symlink."""
    target = Path(folder).absolute()
    if os.name != 'posix':
        for item in reversed((target, *target.parents)):
            try:
                metadata = item.lstat()
            except FileNotFoundError:
                return None
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise OSError('unsafe login directory')
        return metadata
    descriptors, opened = [], []
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
        descriptor = os.open(target.anchor, flags)
        descriptors.append(descriptor)
        current = Path(target.anchor)
        opened.append((current, os.fstat(descriptor)))
        missing = False
        for part in target.parts[1:]:
            current = current / part
            try:
                descriptor = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                missing = True
                break
            descriptors.append(descriptor)
            opened.append((current, os.fstat(descriptor)))
        # Check each named ancestor against the pinned descriptor. Directory
        # timestamps are intentionally not compared for unrelated sibling IO.
        identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid)
        for (name, before), descriptor in zip(opened, descriptors):
            if identity(before) != identity(os.fstat(descriptor)) or identity(before) != identity(name.lstat()):
                raise OSError('login directory changed during lookup')
        return None if missing else opened[-1][1]
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def local_login_inventory(expected_passwd_digest=None):
    """Only fixed SSH entry files for bounded local root/login-shell accounts."""
    passwd = read_regular(LOCAL_PASSWD, 256 * 1024)
    if expected_passwd_digest is not None and hashlib.sha256(passwd).hexdigest() != expected_passwd_digest:
        raise OSError('local account inventory changed after host read')
    homes, users = {}, set()
    rows = passwd.decode('utf-8', errors='strict').splitlines()
    if not rows or len(rows) > MAX_LOCAL_ACCOUNTS:
        raise OSError('local account inventory limit')
    for row in rows:
        fields = row.split(':')
        if len(fields) != 7:
            raise OSError('invalid local account inventory')
        user, _, uid_text, gid_text, _, home, shell = fields
        if (not user or len(user) > 64 or any(ord(char) < 33 or ord(char) == 127 for char in user)
                or user in users or not re.fullmatch(r'[0-9]{1,10}', uid_text)
                or not re.fullmatch(r'[0-9]{1,10}', gid_text)):
            raise OSError('invalid local account identity')
        users.add(user)
        uid, gid = int(uid_text), int(gid_text)
        if uid > 4294967294 or gid > 4294967294:
            raise OSError('invalid local account numeric identity')
        if uid != 0 and shell in NON_LOGIN_SHELLS:
            continue
        if (not home.startswith('/') or home == '/' or len(home) > 512
                or posixpath.normpath(home) != home or home.startswith('//')
                or any(ord(char) < 32 or ord(char) == 127 for char in home)
                or len(Path(home).parts) > 32):
            raise OSError('unsupported local login home')
        homes.setdefault(home, set()).add(uid)
        if len(homes) > MAX_LOGIN_HOMES:
            raise OSError('local login home limit')
    result, total = {}, 0
    def directory(name, owners):
        metadata = login_directory_metadata(name)
        if metadata is None:
            result[str(name) + '/'] = {'missing': True}
            return None
        if os.name == 'posix' and (metadata.st_uid not in owners | {0} or stat.S_IMODE(metadata.st_mode) & 0o022):
            raise OSError('unsafe login directory ownership or permissions')
        result[str(name) + '/'] = {'mode': stat.S_IMODE(metadata.st_mode), 'uid': metadata.st_uid, 'gid': metadata.st_gid}
        return metadata
    for name, owners in sorted(homes.items()):
        home, ssh = Path(name), Path(name) / '.ssh'
        home_before = directory(home, owners)
        ssh_before = directory(ssh, owners) if home_before is not None else None
        if home_before is None:
            result[str(ssh) + '/'] = {'missing': True}
        for entry in SSH_LOGIN_FILES:
            target = ssh / entry
            if ssh_before is None:
                result[str(target)] = {'missing': True}
                continue
            try:
                metadata = target.lstat()
            except FileNotFoundError:
                result[str(target)] = {'missing': True}
                continue
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or (os.name == 'posix' and (metadata.st_uid not in owners | {0} or stat.S_IMODE(metadata.st_mode) & 0o022))):
                raise OSError('unsafe login entry ownership, type or permissions')
            payload = read_regular(target, MAX_LOGIN_FILE_BYTES)
            total += len(payload)
            if total > MAX_LOGIN_BYTES:
                raise OSError('login entry byte limit')
            if file_identity(metadata) != file_identity(target.lstat()):
                raise OSError('login entry changed during read')
            result[str(target)] = {'digest': hashlib.sha256(payload).hexdigest(),
                                  'mode': stat.S_IMODE(metadata.st_mode), 'uid': metadata.st_uid,
                                  'gid': metadata.st_gid, 'link': False}
        for target, before in ((home, home_before), (ssh, ssh_before)):
            after = login_directory_metadata(target)
            if (before is None) != (after is None) or (before is not None and file_identity(before) != file_identity(after)):
                raise OSError('login directory changed during inventory')
    if read_regular(LOCAL_PASSWD, 256 * 1024) != passwd:
        raise OSError('local account inventory changed during scan')
    return result


def host_snapshot():
    result, total = {}, 0
    def record(target, metadata):
        nonlocal total
        if stat.S_ISLNK(metadata.st_mode):
            # systemd enablement links are evidence, not executable scan targets.
            data = os.readlink(target).encode('utf-8')
        else:
            data = read_regular(target, 1024 * 1024)
        total += len(data)
        if total > 16 * 1024 * 1024 or len(result) >= 2048:
            raise OSError('host inventory limit')
        if file_identity(metadata) != file_identity(target.lstat()):
            raise OSError('host configuration changed during read')
        result[str(target)] = {'digest': hashlib.sha256(data).hexdigest(),
                              'mode': stat.S_IMODE(metadata.st_mode), 'uid': getattr(metadata, 'st_uid', 0),
                              'gid': getattr(metadata, 'st_gid', 0), 'link': stat.S_ISLNK(metadata.st_mode)}
    for name in HOST_FILES:
        target = Path(name)
        try:
            metadata = target.lstat()
        except FileNotFoundError:
            result[name] = {'missing': True}
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError('unsafe host file')
        record(target, metadata)
    for name in HOST_DIRS:
        target = Path(name)
        if not target.exists() and not target.is_symlink():
            result[name + '/'] = {'missing': True}
            continue
        metadata = target.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise OSError('unsafe host configuration directory')
        result[name + '/'] = {'mode': stat.S_IMODE(metadata.st_mode), 'uid': getattr(metadata, 'st_uid', 0), 'gid': getattr(metadata, 'st_gid', 0)}
        for item, item_meta in bounded_tree(target, allow_links=True):
            record(item, item_meta)
    passwd_record = result.get(str(LOCAL_PASSWD), {})
    login = local_login_inventory(passwd_record.get('digest'))
    if len(result) + len(login) > 2048:
        raise OSError('host inventory limit')
    result.update(login)
    # Hash application settings locally; never return their contents or individual hashes.
    shared = ROOT / 'shared'
    settings = shared / '.env' if shared.is_dir() else ROOT / '.env'
    try:
        metadata = settings.lstat()
    except FileNotFoundError:
        result['appgog.environment'] = {'missing': True}
    else:
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError('unsafe application settings')
        record(settings, metadata)
    if len(result) > 2048:
        raise OSError('host inventory limit')
    return result


def write_host_baseline():
    atomic_json(HOST_BASELINE, {'schema': 1, 'files': host_snapshot(),
                              'approved_at': datetime.now(timezone.utc).isoformat()})


def host_configuration_check():
    try:
        baseline = json.loads(read_state(HOST_BASELINE))
        if not isinstance(baseline, dict) or baseline.get('schema') != 1 or not isinstance(baseline.get('files'), dict):
            raise ValueError('invalid host baseline')
        expected = baseline['files']
        if not expected or len(expected) > 4096 or any(not isinstance(name, str) or not isinstance(value, dict) for name, value in expected.items()):
            raise ValueError('invalid host baseline inventory')
        for value in expected.values():
            if value == {'missing': True}:
                continue
            if any(type(value.get(key)) is not int or value[key] < 0 for key in ('mode', 'uid', 'gid')):
                raise ValueError('invalid host metadata')
            if 'digest' in value and (not isinstance(value['digest'], str) or not re.fullmatch(r'[a-f0-9]{64}', value['digest'])):
                raise ValueError('invalid host digest')
        current = host_snapshot()
        changed = sorted(name for name in set(current) | set(expected) if current.get(name) != expected.get(name))
        return check('账户、SSH、Docker 与持久化配置', 'finding' if changed else 'ok',
                     f'固定配置清单 {len(current)} 项；差异 {len(changed)} 项；' + (', '.join(changed[:4]) if changed else '与本机批准基线一致'),
                     check_id='host.configuration', scope='host configs; local root/login-shell default SSH entry files; no shadow/private keys/NSS/custom auth paths',
                     evidence={'count': len(current), 'changed': changed})
    except (OSError, ValueError, TypeError):
        return check('账户、SSH、Docker 与持久化配置', 'unavailable', '主机配置基线缺失、读取失败、超限或扫描期间变化',
                     check_id='host.configuration', scope='fixed host configuration inventory')


def history_item(item):
    if not isinstance(item, dict) or item.get('state') not in CHECK_STATES:
        raise ValueError('invalid history state')
    if not isinstance(item.get('id'), str) or not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,79}', item['id']):
        raise ValueError('invalid history id')
    if not isinstance(item.get('evidence_digest'), str) or not re.fullmatch(r'[a-f0-9]{64}', item['evidence_digest']):
        raise ValueError('invalid history digest')
    if item.get('previous_state') is not None and item['previous_state'] not in CHECK_STATES:
        raise ValueError('invalid previous state')
    result = {key: bounded_text(item.get(key), limit) for key, limit in
              [('name', 60), ('detail', 180), ('id', 80), ('category', 32), ('severity', 16),
               ('checked_at', 40), ('scope', 120), ('evidence_digest', 64)]}
    if result['category'] not in {'host', 'container', 'permissions', 'ssh', 'network', 'malware'} or result['severity'] not in SEVERITIES:
        raise ValueError('invalid history classification')
    observed = datetime.fromisoformat(result['checked_at'].replace('Z', '+00:00'))
    if observed.tzinfo is None:
        raise ValueError('invalid history timestamp')
    result.update(state=item['state'], previous_state=item.get('previous_state'))
    return result


def save_history(checks):
    global EVENTS, PREVIOUS
    if not HISTORY_VALID:
        raise OSError('preserve unreadable history for operator inspection')
    events = list(EVENTS)
    previous = {}
    for item in checks:
        key = item['id']
        marker = {'state': item['state'], 'digest': item['evidence_digest']}
        old = PREVIOUS.get(key)
        if old != marker and (old is not None or item['state'] != 'ok'):
            events.append(history_item({**item, 'previous_state': old['state'] if old else None}))
        previous[key] = marker
    events = events[-MAX_HISTORY:]
    atomic_json(HISTORY_FILE, {'schema': 1, 'events': events, 'previous': previous})
    EVENTS, PREVIOUS = events, previous
    return events[-MAX_RESPONSE_HISTORY:]


def load_history():
    global EVENTS, PREVIOUS
    try:
        state = json.loads(read_state(HISTORY_FILE, 131072))
        if not isinstance(state, dict) or state.get('schema') != 1 or not isinstance(state.get('events'), list) or not isinstance(state.get('previous'), dict):
            raise ValueError('invalid history')
        if len(state['events']) > MAX_HISTORY:
            raise ValueError('history count limit')
        events = [history_item(item) for item in state['events']]
        previous = state['previous']
        if len(previous) > MAX_CHECKS:
            raise ValueError('previous count limit')
        for key, value in previous.items():
            if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,79}', key) or not isinstance(value, dict) or value.get('state') not in CHECK_STATES:
                raise ValueError('invalid previous state')
            if not isinstance(value.get('digest'), str) or not re.fullmatch(r'[a-f0-9]{64}', value['digest']):
                raise ValueError('invalid previous digest')
        EVENTS, PREVIOUS = events, previous
        return True
    except FileNotFoundError:
        EVENTS, PREVIOUS = [], {}
        return True
    except (OSError, ValueError, TypeError, AttributeError):
        EVENTS, PREVIOUS = [], {}
        return False


def file_identity(metadata):
    identity = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
    # Windows descriptor and named stats expose different ctime semantics.
    # Linux production retains ctime to detect same-size/mtime tampering.
    return identity + ((metadata.st_ctime_ns,) if os.name == 'posix' else ())


def daily_database_identity():
    """Read the embedded CVD/CLD build time; touching mtime cannot renew trust."""
    candidates = [CLAM_DATABASE / name for name in ('daily.cvd', 'daily.cld')]
    records = {}
    for path in candidates:
        try:
            before = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(before.st_mode):
            raise OSError('invalid daily database')
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            opened = os.fstat(descriptor)
            if file_identity(before) != file_identity(opened):
                raise OSError('database changed while opening')
            header = os.read(descriptor, 512).decode('ascii').strip(' \x00\r\n')
            fields = header.split(':')
            if len(fields) != 9 or fields[0] != 'ClamAV-VDB' or not fields[8].isdigit():
                raise ValueError('invalid daily database header')
            built_at = int(fields[8])
            if built_at < time.time() - 7 * 86400 or built_at > time.time() + 120:
                raise ValueError('stale or future daily database')
            if file_identity(opened) != file_identity(os.fstat(descriptor)):
                raise OSError('database changed while reading')
            records[str(path)] = file_identity(opened)
        finally:
            os.close(descriptor)
    if not records:
        raise OSError('missing daily database')
    return records


def validate_zip_budget(path, *, max_file_bytes=MAX_FILE_BYTES, max_scan_bytes=16 * 1024 * 1024):
    """Reject known ZIP coverage gaps before trusting an engine clean exit."""
    with Path(path).open('rb') as source:
        magic = source.read(4)
    if magic not in (b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'):
        return
    class MetadataReader:
        # ZipFile reads central-directory metadata before infolist limits can run.
        # Bound each read and the aggregate before allocating attacker-chosen sizes.
        def __init__(self, source):
            self.source, self.consumed = source, 0
        def __getattr__(self, name):
            return getattr(self.source, name)
        def read(self, size=-1):
            if size < 0:
                position = self.source.tell()
                self.source.seek(0, os.SEEK_END)
                size = self.source.tell() - position
                self.source.seek(position)
            if size > 1024 * 1024 - self.consumed:
                raise OSError('ZIP metadata read budget')
            payload = self.source.read(size)
            self.consumed += len(payload)
            return payload
    try:
        with Path(path).open('rb') as source, zipfile.ZipFile(MetadataReader(source)) as archive:
            entries = archive.infolist()
            if (len(entries) > 100 or any(item.file_size >= max_file_bytes or item.flag_bits & 1 for item in entries)
                    or sum(item.file_size for item in entries) >= max_scan_bytes):
                raise OSError('ZIP scan coverage limit or encryption')
    except (zipfile.BadZipFile, ValueError, NotImplementedError) as error:
        raise OSError('invalid ZIP scan target') from error


def malware_scan():
    """Bounded program scan only; missing coverage or stale DB never means clean."""
    scanner = SCANNER
    if not scanner.is_file() or not os.access(scanner, os.X_OK):
        return check('病毒特征查杀', 'unavailable', '未安装 ClamAV；请从 Linux 安全菜单安装引擎与特征库；不含业务数据与整个宿主机',
                     check_id='malware.program', scope='bounded program inventory')
    try:
        inventory = program_snapshot()
        root = release_root()
        selected = [str(root / name) for name in sorted(inventory)]
        if not selected or sum(len(name.encode('utf-8')) + 1 for name in selected) > 131072 or any('\n' in name or '\r' in name for name in selected):
            raise OSError('scan input limit')
        recorded = {name: file_identity(Path(name).lstat()) for name in selected}
        if any(not stat.S_ISREG(Path(name).lstat().st_mode) or Path(name).lstat().st_size >= MAX_FILE_BYTES for name in selected):
            raise OSError('unsupported scan target')
        for name in selected:
            validate_zip_budget(name)
        # clamscan validates the database content/signature; header age is an
        # additional freshness bound compatible with distribution ClamAV 1.0.
        database_identity = daily_database_identity()
        result = subprocess.run([
            str(scanner), '--no-summary', '--infected', '--max-filesize=8M',
            '--max-scansize=16M', '--max-files=100', '--max-recursion=8',
            '--alert-exceeds-max=yes', '--database=' + str(CLAM_DATABASE), '--follow-file-symlinks=0', '--follow-dir-symlinks=0', *selected,
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45, check=False)
        stable = all(file_identity(Path(name).lstat()) == recorded[name] for name in selected)
        # Re-enumeration detects added/deleted files while the engine was scanning.
        stable = stable and program_snapshot() == inventory and daily_database_identity() == database_identity
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return check('病毒特征查杀', 'unavailable', '清单不完整/超限、特征库缺失/过期、引擎失败或超过 45 秒；结果未知',
                     check_id='malware.program', scope='bounded program inventory')
    scope = f'程序清单 {len(selected)} 个文件；不包含业务数据、依赖目录和宿主机其他目录'
    if not stable:
        return check('病毒特征查杀', 'unavailable', '扫描期间文件或目录发生变化；结果不可采信',
                     check_id='malware.program', scope=scope)
    if result.returncode == 1:
        return check('病毒特征查杀', 'finding', 'ClamAV 报告疑似恶意特征或扫描限制；需人工复核，不自动删除',
                     check_id='malware.program', scope=scope)
    if result.returncode != 0:
        return check('病毒特征查杀', 'unavailable', 'ClamAV 扫描失败或特征库不可用', check_id='malware.program', scope=scope)
    return check('病毒特征查杀', 'ok', '本次程序清单未发现已知特征；此结论不能证明整机未入侵',
                 check_id='malware.program', scope=scope)


def business_docker_json(*args):
    """Fixed Docker commands: discard stderr and bound stdout while it is produced."""
    if os.name != 'posix':
        raise OSError('business inspection requires Linux')
    process = subprocess.Popen(['/usr/bin/docker', *args], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd='/',
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
    deadline = time.monotonic() + 5
    output = bytearray()
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not ready.select(remaining):
                    raise OSError('Docker inspection timed out')
                chunk = os.read(process.stdout.fileno(), min(65536, 262145 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > 262144:
                    raise OSError('Docker inspection output exceeded limit')
        if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            raise OSError('Docker inspection failed')
        return json.loads(output.decode('utf-8'))
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        process.stdout.close()


def business_volume_roots(*, database_only=False):
    """Only owned Compose local volumes; never accept a caller-supplied scan path."""
    docker_json = business_docker_json
    ids = docker_json('ps', '-a', '--no-trunc', '--filter', 'label=com.docker.compose.project=appgog',
                      '--filter', 'label=com.docker.compose.service=appgog', '--format', '{{json .ID}}')
    if not isinstance(ids, str) or not re.fullmatch(r'[a-f0-9]{64}', ids):
        raise ValueError('ambiguous business container')
    payload = docker_json('inspect', ids)
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise ValueError('invalid business container inspection')
    container = payload[0]
    if container.get('Id') != ids:
        raise ValueError('container identity mismatch')
    labels = container.get('Config', {}).get('Labels', {})
    if labels.get('com.docker.compose.project') != 'appgog' or labels.get('com.docker.compose.service') != 'appgog':
        raise ValueError('foreign business container')
    working = Path(labels.get('com.docker.compose.project.working_dir', ''))
    if not working.is_absolute():
        raise ValueError('missing installation identity')
    working = working.resolve(strict=True)
    if working != ROOT:
        working.relative_to(ROOT / 'releases')
    config_files = labels.get('com.docker.compose.project.config_files', '').split(',')
    if len(config_files) != 1:
        raise ValueError('ambiguous deployment role')
    compose = Path(config_files[0])
    if not compose.is_absolute() or compose.name not in {'compose.yaml', 'compose.license.yaml', 'compose.build.yaml'} or compose.resolve(strict=True).parent != working:
        raise ValueError('foreign deployment role')
    role = {'compose.yaml': 'all', 'compose.license.yaml': 'license', 'compose.build.yaml': 'build'}[compose.name]
    if database_only:
        expected = {} if role == 'build' else {'db': '/app/var/data'}
    else:
        expected = {'artifacts': '/app/var/artifacts'}
        if role != 'build':
            expected['uploads'] = '/app/var/uploads'
    docker_root = docker_json('info', '--format', '{{json .DockerRootDir}}')
    if not isinstance(docker_root, str) or not Path(docker_root).is_absolute() or Path(docker_root) == Path('/') or '..' in Path(docker_root).parts or str(Path(docker_root)) != docker_root:
        raise ValueError('invalid Docker data root')
    mounts = container.get('Mounts')
    if not isinstance(mounts, list) or len(mounts) > 64:
        raise ValueError('invalid mounts')
    roots = {}
    for category, destination in expected.items():
        selected = [item for item in mounts if isinstance(item, dict) and item.get('Destination') == destination]
        volume_name = 'appgog_appgog-' + category
        if len(selected) != 1 or selected[0].get('Type') != 'volume' or selected[0].get('Name') != volume_name:
            raise ValueError('unexpected business volume')
        volume = docker_json('volume', 'inspect', volume_name)
        if not isinstance(volume, list) or len(volume) != 1 or not isinstance(volume[0], dict):
            raise ValueError('invalid volume inspection')
        volume = volume[0]
        volume_labels = volume.get('Labels') or {}
        expected_root = Path(docker_root) / 'volumes' / volume_name / '_data'
        if volume.get('Name') != volume_name or volume.get('Driver') != 'local' or volume.get('Scope') != 'local' or volume.get('Options') not in (None, {}) or volume_labels.get('com.docker.compose.project') != 'appgog' or volume_labels.get('com.docker.compose.volume') != 'appgog-' + category:
            raise ValueError('untrusted volume contract')
        if volume.get('Mountpoint') != str(expected_root) or selected[0].get('Source') != str(expected_root):
            raise ValueError('volume source drift')
        for ancestor in reversed((expected_root, *expected_root.parents)):
            metadata = ancestor.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise OSError('unsafe business volume path')
        roots[category] = expected_root
    return {'container_id': ids, 'role': role, 'roots': roots}


def business_directory(path):
    """Pin each ancestor without following links; callers close the final descriptor."""
    if os.name != 'posix':
        return None  # Windows-only development fallback; Linux acceptance uses dirfds.
    target = Path(path).absolute()
    if '..' in target.parts:
        raise OSError('business path traversal')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(target.anchor, flags)
    try:
        for part in target.parts[1:]:
            opened = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = opened
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def business_snapshot(roots, copy_to=None):
    """Bounded no-follow copies; includes hidden directories and records empty dirs."""
    files, directories, total, count = {}, {}, 0, 0
    started = time.monotonic()
    for category, root in sorted(roots.items()):
        pending = [root]
        while pending:
            folder = pending.pop()
            before = folder.lstat()
            if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                raise OSError('unsafe business directory')
            descriptor = business_directory(folder)
            try:
                if descriptor is not None and file_identity(os.fstat(descriptor)) != file_identity(before):
                    raise OSError('business directory replaced')
                directories[category + '/' + folder.relative_to(root).as_posix()] = file_identity(before)
                with os.scandir(descriptor if descriptor is not None else folder) as entries:
                    for entry in entries:
                        count += 1
                        if count > 2048 or time.monotonic() - started > 15:
                            raise OSError('business inventory count/time limit')
                        path = folder / entry.name
                        metadata = entry.stat(follow_symlinks=False) if descriptor is not None else path.lstat()
                        if stat.S_ISDIR(metadata.st_mode):
                            pending.append(path)
                            continue
                        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size >= 64 * 1024 * 1024:
                            raise OSError('unsupported business file')
                        total += metadata.st_size
                        if total > 128 * 1024 * 1024:
                            raise OSError('business inventory byte limit')
                        payload = read_regular(path, 64 * 1024 * 1024)
                        if file_identity(metadata) != file_identity(path.lstat()) or len(payload) != metadata.st_size:
                            raise OSError('business file changed')
                        key = category + '/' + path.relative_to(root).as_posix()
                        files[key] = (file_identity(metadata), hashlib.sha256(payload).hexdigest())
                        if copy_to is not None:
                            # Numeric private names prevent option/newline injection and customer name leakage.
                            destination = Path(copy_to) / (str(len(files)).zfill(5) + '.scan')
                            with destination.open('xb') as stream:
                                stream.write(payload)
                            destination.chmod(0o600)
                if (file_identity(before) != file_identity(folder.lstat()) or
                        descriptor is not None and file_identity(before) != file_identity(os.fstat(descriptor))):
                    raise OSError('business directory changed')
            finally:
                if descriptor is not None:
                    os.close(descriptor)
    return {'files': files, 'directories': directories, 'bytes': total}


def business_malware_scan():
    name, identifier, scope = '上传与构建成品查杀', 'malware.business', 'owned uploads/artifacts volumes; bounded snapshot'
    try:
        if not SCANNER.is_file() or not os.access(SCANNER, os.X_OK):
            raise OSError('scanner unavailable')
        owned = business_volume_roots()
        database_identity = daily_database_identity()
        private_directory(STATE_DIR)
        with tempfile.TemporaryDirectory(prefix='.business-scan-', dir=str(STATE_DIR)) as temporary:
            inventory = business_snapshot(owned['roots'], copy_to=temporary)
            selected = sorted(str(path) for path in Path(temporary).iterdir())
            for path in selected:
                validate_zip_budget(path, max_file_bytes=64 * 1024 * 1024, max_scan_bytes=128 * 1024 * 1024)
            if selected:
                result = subprocess.run([
                    str(SCANNER), '--no-summary', '--infected', '--max-filesize=64M',
                    '--max-scansize=128M', '--max-files=100', '--max-recursion=8',
                    '--alert-exceeds-max=yes', '--alert-encrypted=yes', '--tempdir=' + temporary,
                    '--database=' + str(CLAM_DATABASE), '--follow-file-symlinks=0', '--follow-dir-symlinks=0', *selected,
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False)
                code = result.returncode
            else:
                # Still ask the actual engine to load/validate the database; an empty volume isn't DB validation.
                marker = Path(temporary) / 'empty.scan'
                marker.write_bytes(b'APPGOG empty business inventory')
                result = subprocess.run([str(SCANNER), '--no-summary', '--infected',
                    '--database=' + str(CLAM_DATABASE), str(marker)], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=60, check=False)
                code = result.returncode
            stable = (business_volume_roots() == owned and business_snapshot(owned['roots']) == inventory
                      and daily_database_identity() == database_identity)
        if not stable:
            raise OSError('business inventory/database changed during scan')
        scope = f"{owned['role']} 上传/成品快照 {len(inventory['files'])} 个文件；不含数据库、密钥、发布目录依赖和整个宿主机"
        if code == 1:
            return check(name, 'finding', '发现疑似特征、加密内容或引擎限制；须人工复核，不自动删除',
                         check_id=identifier, category='malware', scope=scope)
        if code != 0:
            raise OSError('engine failed')
        return check(name, 'ok', '本次有界上传/成品快照未发现已知特征；不代表整机清白',
                     check_id=identifier, category='malware', scope=scope,
                     evidence={'files': len(inventory['files']), 'bytes': inventory['bytes'], 'role': owned['role']})
    except (OSError, ValueError, TypeError, AttributeError, subprocess.TimeoutExpired):
        return check(name, 'unavailable', '归属不明、链接/特殊文件、清单超限或变化、加密 ZIP、病毒库/扫描失败；结果未知',
                     check_id=identifier, category='malware', scope=scope)


# Parse untrusted SQLite bytes in a bounded child against a private snapshot only.
# No SQL supplied by callers and no live database connection, checkpoint or repair.
SQLITE_PROBE = r'''
import json, sqlite3, sys, time
from pathlib import Path
try:
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (8, 8))
    except ImportError:
        pass
    deadline = time.monotonic() + 8
    db = sqlite3.connect(Path(sys.argv[1]).as_uri() + '?mode=ro', uri=True, timeout=0.1)
    db.enable_load_extension(False)
    db.execute('PRAGMA trusted_schema=OFF')
    db.execute('PRAGMA query_only=ON')
    db.execute('PRAGMA cache_size=-8192')
    db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
    if Path(sys.argv[1]).stat().st_size < 512:
        print(json.dumps({'state': 'finding'})); sys.exit(0)
    rows = db.execute('PRAGMA integrity_check(100)').fetchmany(101)
    print(json.dumps({'state': 'ok' if rows == [('ok',)] else 'finding'}))
    db.close()
except sqlite3.DatabaseError as error:
    code = getattr(error, 'sqlite_errorcode', 0) & 255
    print(json.dumps({'state': 'finding' if code in (sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB) else 'unavailable'}))
except Exception:
    print(json.dumps({'state': 'unavailable'}))
'''
SQLITE_NAMES = ('appgog.sqlite', 'appgog.sqlite-wal', 'appgog.sqlite-journal')
MAX_SQLITE_BYTES = 128 * 1024 * 1024


def sqlite_inventory(root):
    """Pin the fixed database names. Never read or create the live -shm file."""
    descriptor = business_directory(root)
    rows, total = {}, 0
    try:
        for name in SQLITE_NAMES:
            try:
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False) if descriptor is not None else (root / name).lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OSError('unsafe SQLite input')
            total += metadata.st_size
            if total > MAX_SQLITE_BYTES:
                raise OSError('SQLite snapshot limit exceeded')
            if name.endswith('-journal') and metadata.st_size:
                raise OSError('pending rollback journal')
            rows[name] = file_identity(metadata)
        if 'appgog.sqlite' not in rows:
            raise OSError('database absent')
        return rows
    finally:
        if descriptor is not None:
            os.close(descriptor)


def sqlite_snapshot(root, target, inventory):
    descriptor = business_directory(root)
    try:
        for name, identity in inventory.items():
            if name.endswith('-journal'):
                continue
            flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
            source = os.open(name, flags, dir_fd=descriptor) if descriptor is not None else os.open(root / name, flags)
            try:
                if file_identity(os.fstat(source)) != identity:
                    raise OSError('database identity changed')
                copied = 0
                with (target / name).open('xb') as output:
                    os.chmod(target / name, 0o600)
                    while True:
                        chunk = os.read(source, min(65536, MAX_SQLITE_BYTES + 1 - copied))
                        if not chunk:
                            break
                        copied += len(chunk)
                        if copied > MAX_SQLITE_BYTES:
                            raise OSError('database copy limit exceeded')
                        output.write(chunk)
                if file_identity(os.fstat(source)) != identity:
                    raise OSError('database changed during copy')
            finally:
                os.close(source)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def sqlite_health_check():
    name, identifier = '业务数据库完整性', 'database.sqlite'
    scope = 'owned SQLite database + WAL; structural integrity only; no business-data repair'
    try:
        owned = business_volume_roots(database_only=True)
        if owned['role'] == 'build' and not owned['roots']:
            return check(name, 'ok', '独立打包节点不持有授权数据库；此项不适用',
                         check_id=identifier, category='container', scope=scope,
                         evidence={'role': 'build', 'applicable': False})
        if owned['role'] not in ('all', 'license') or set(owned['roots']) != {'db'}:
            raise ValueError('invalid database volume')
        root = owned['roots']['db']
        inventory = sqlite_inventory(root)
        with tempfile.TemporaryDirectory(prefix='appgog-sqlite-') as folder:
            target = Path(folder)
            os.chmod(target, 0o700)
            sqlite_snapshot(root, target, inventory)
            if sqlite_inventory(root) != inventory:
                raise OSError('database changed during snapshot')
            result = subprocess.run([sys.executable, '-I', '-c', SQLITE_PROBE, str(target / 'appgog.sqlite')],
                                    capture_output=True, text=True, timeout=12, check=False)
            if result.returncode != 0 or len(result.stdout) > 256:
                raise OSError('database probe failed')
            payload = json.loads(result.stdout)
            state = payload.get('state') if isinstance(payload, dict) else None
            if state not in {'ok', 'finding', 'unavailable'}:
                raise ValueError('invalid database probe result')
            # Moving source or a changed volume/container invalidates even a corruption result.
            if sqlite_inventory(root) != inventory or business_volume_roots(database_only=True) != owned:
                raise OSError('database ownership or bytes changed')
        detail = {'ok': '只读副本完整性检查通过；不证明业务记录未被非法修改',
                  'finding': '业务数据库结构损坏；保留原数据并告警，需核验备份后人工恢复',
                  'unavailable': '数据库检查未取得可靠结论；未执行数据修复'}[state]
        return check(name, state, detail, check_id=identifier, category='container', scope=scope,
                     evidence={'role': owned['role'], 'wal': 'appgog.sqlite-wal' in inventory, 'state': state})
    except (OSError, ValueError, TypeError, AttributeError, subprocess.TimeoutExpired):
        return check(name, 'unavailable', '数据库归属不明、文件变化/不安全、超限、待恢复日志或检查失败；结果未知',
                     check_id=identifier, category='container', scope=scope)


def expected_platform_image():
    try:
        package = json.loads(read_regular(release_root() / 'package.json', 65536))
        version = package.get('version')
        if isinstance(version, str) and version and len(version) <= 40:
            return 'appgog-platform:' + version
    except (OSError, ValueError, TypeError):
        pass
    return None


def container_contract_check():
    """Inspect only the one Compose-labelled APPGOG service; never mutate Docker state."""
    ps_command = [
        'docker', 'ps',
        '--filter', 'label=com.docker.compose.project=appgog',
        '--filter', 'label=com.docker.compose.service=appgog',
        '--format', '{{.ID}}',
    ]
    try:
        listed = subprocess.run(ps_command, capture_output=True, text=True, timeout=5, check=False)
        if listed.returncode != 0:
            raise OSError('docker ps failed')
        identifiers = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
        if len(identifiers) != 1:
            return check('APPGOG 容器合同', 'finding' if identifiers else 'unavailable',
                         f'预期一个 APPGOG 主容器，实际发现 {len(identifiers)} 个',
                         check_id='container.contract', category='container', severity='high',
                         scope='compose project appgog / service appgog',
                         evidence={'container_count': len(identifiers)})
        inspected = subprocess.run(['docker', 'inspect', identifiers[0]], capture_output=True,
                                   text=True, timeout=5, check=False)
        if inspected.returncode != 0:
            raise OSError('docker inspect failed')
        payload = json.loads(inspected.stdout)
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise ValueError('invalid inspect response')
        container = payload[0]
    except (OSError, ValueError, TypeError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return check('APPGOG 容器合同', 'unavailable', 'Docker 不可用、响应异常或检查超时',
                     check_id='container.contract', category='container', severity='unknown',
                     scope='compose project appgog / service appgog', evidence={'inspect': 'unavailable'})

    config = container.get('Config') if isinstance(container.get('Config'), dict) else {}
    state = container.get('State') if isinstance(container.get('State'), dict) else {}
    host = container.get('HostConfig') if isinstance(container.get('HostConfig'), dict) else {}
    mounts = container.get('Mounts') if isinstance(container.get('Mounts'), list) else []
    issues = []
    image = bounded_text(config.get('Image'), 100)
    expected_image = expected_platform_image()
    if expected_image:
        if image != expected_image:
            issues.append('image-mismatch')
    elif not image.startswith('appgog-platform:') or len(image.split(':', 1)[1]) > 40:
        issues.append('image-invalid')
    user = bounded_text(config.get('User'), 40).strip().lower()
    if not user or user.split(':', 1)[0] in {'0', 'root'}:
        issues.append('root-user')
    if state.get('Status') != 'running':
        issues.append('not-running')
    health = state.get('Health') if isinstance(state.get('Health'), dict) else {}
    if health.get('Status') != 'healthy':
        issues.append('not-healthy')
    if host.get('Privileged') is not False:
        issues.append('privileged')
    if host.get('ReadonlyRootfs') is not True:
        issues.append('writable-rootfs')
    if host.get('CapAdd') not in (None, []):
        issues.append('added-capabilities')

    allowed_binds = {
        '/app/var/update-control': (os.path.normpath(str(ROOT / 'shared' / 'update-control')), False),
        '/app/runtime/security': (os.path.normpath(str(ROOT / 'shared' / 'security')), True),
        '/app/runtime/host-security': ('/run/appgog-security', True),
    }
    bind_evidence = []
    for mount in mounts:
        if not isinstance(mount, dict) or mount.get('Type') != 'bind':
            continue
        # Docker inspect always reports Linux container paths, even when the
        # contract test is executed from a non-Linux development workstation.
        source = posixpath.normpath(bounded_text(mount.get('Source'), 160))
        destination = posixpath.normpath(bounded_text(mount.get('Destination'), 160))
        read_only = mount.get('RW') is False
        if len(bind_evidence) < 64:
            bind_evidence.append({'destination': destination, 'read_only': read_only})
        if source.endswith('/docker.sock') or destination.endswith('/docker.sock'):
            issues.append('docker-socket')
            continue
        contract = allowed_binds.get(destination)
        if contract is None:
            issues.append('unexpected-bind')
            continue
        expected_source, must_be_read_only = contract
        if source != expected_source:
            issues.append('bind-source-drift')
        if must_be_read_only and not read_only:
            issues.append('writable-sensitive-bind')

    unique_issues = sorted(set(issues))
    return check('APPGOG 容器合同', 'finding' if unique_issues else 'ok',
                 '容器偏离加固合同：' + ', '.join(unique_issues)
                 if unique_issues else '唯一 APPGOG 主容器运行健康，镜像、用户、权限和挂载符合固定合同',
                 check_id='container.contract', category='container',
                 severity='critical' if any(item in unique_issues for item in ('privileged', 'docker-socket'))
                 else ('high' if unique_issues else 'info'),
                 scope='compose project appgog / service appgog',
                 evidence={'image': image, 'expected_image': expected_image or 'appgog-platform:<version>',
                           'user': user, 'status': state.get('Status'), 'health': health.get('Status'),
                           'issues': unique_issues, 'binds': bind_evidence})


def approved_baseline_pin(path):
    """Validate and bind semantic baseline contents, excluding approval timestamps."""
    baseline = json.loads(read_state(path, 1024 * 1024))
    if not isinstance(baseline, dict) or not isinstance(baseline.get('files'), dict):
        raise ValueError('invalid approved baseline inventory')
    files = baseline['files']
    if not files or len(files) > MAX_INVENTORY_FILES or any(not isinstance(name, str) or not name for name in files):
        raise ValueError('invalid approved baseline count or path')
    if baseline.get('schema') == 2:
        if not isinstance(baseline.get('version'), str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?', baseline['version']):
            raise ValueError('invalid approved program version')
        for name, digest in files.items():
            if not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest):
                raise ValueError('invalid approved program digest')
            parts = name.split('/')
            if any(part in {'', '.', '..'} for part in parts) or '\\' in name or name.startswith('/'):
                raise ValueError('invalid approved program path')
            if name not in PROGRAM_ROOT_FILES and (len(parts) < 2 or parts[0] not in PROGRAM_DIRS):
                raise ValueError('unexpected approved program path')
    elif baseline.get('schema') == 1:
        for value in files.values():
            if value == {'missing': True}:
                continue
            if not isinstance(value, dict) or any(type(value.get(key)) is not int or value[key] < 0 for key in ('mode', 'uid', 'gid')):
                raise ValueError('invalid approved host metadata')
            if value['mode'] > 0o7777 or ('link' in value and type(value['link']) is not bool):
                raise ValueError('invalid approved host mode or link')
            if 'digest' in value and (not isinstance(value['digest'], str) or not re.fullmatch(r'[a-f0-9]{64}', value['digest'])):
                raise ValueError('invalid approved host digest')
    else:
        raise ValueError('unsupported approved baseline schema')
    return hashlib.sha256(json.dumps({'schema': baseline.get('schema'), 'version': baseline.get('version'),
                                     'files': files}, sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


def approved_image_check(baseline_checks=None):
    """Read-only identity check against explicit local root approval; never enroll automatically."""
    name, identifier = 'APPGOG 镜像身份', 'container.approved-image'
    scope = 'full image ID and local-root-approved program/host baselines'
    pin_path = STATE_DIR / 'approved-image.json'
    if not pin_path.exists() and not pin_path.is_symlink():
        return check(name, 'warning', '尚未由 root 独立核验并批准完整镜像 ID；仅有版本名不足以证明镜像可信',
                     check_id=identifier, category='container', scope=scope,
                     evidence={'approval': 'missing'})
    try:
        pin = json.loads(read_state(pin_path, 32768))
        if not isinstance(pin, dict) or pin.get('schema') != 1 or pin.get('root') != str(ROOT) or \
                not isinstance(pin.get('version'), str) or \
                not re.fullmatch(r'sha256:[a-f0-9]{64}', pin.get('image_id', '')) or \
                any(not re.fullmatch(r'[a-f0-9]{64}', pin.get(field, ''))
                    for field in ('program_baseline', 'host_baseline')):
            raise ValueError('invalid approval')
        command = ['/usr/bin/docker', 'ps', '-aq', '--no-trunc',
                   '--filter', 'label=com.docker.compose.project=appgog',
                   '--filter', 'label=com.docker.compose.service=appgog']
        environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}
        listed = subprocess.run(command, capture_output=True, text=True, timeout=5,
                                check=False, env=environment)
        if listed.returncode != 0 or len(listed.stdout.encode()) > 4096:
            raise OSError('container discovery failed')
        ids = listed.stdout.split()
        if len(ids) != 1 or not re.fullmatch(r'[a-f0-9]{64}', ids[0]):
            raise ValueError('ambiguous full container identity')
        inspected = subprocess.run(['/usr/bin/docker', 'inspect', ids[0]], capture_output=True,
                                   text=True, timeout=5, check=False, env=environment)
        if inspected.returncode != 0 or len(inspected.stdout.encode()) > 262144:
            raise OSError('container inspection failed')
        payload = json.loads(inspected.stdout)
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise ValueError('invalid inspection')
        container = payload[0]
        if container.get('Id') != ids[0] or not re.fullmatch(r'sha256:[a-f0-9]{64}', container.get('Image', '')):
            raise ValueError('full container/image identity mismatch')
        labels = container.get('Config', {}).get('Labels', {})
        if labels.get('com.docker.compose.project') != 'appgog' or labels.get('com.docker.compose.service') != 'appgog':
            raise ValueError('foreign container')
        working = Path(labels.get('com.docker.compose.project.working_dir', ''))
        if not working.is_absolute():
            raise ValueError('missing installation identity')
        working = working.resolve(strict=True)
        if working != ROOT:
            working.relative_to(ROOT / 'releases')
        files = labels.get('com.docker.compose.project.config_files', '').split(',')
        if len(files) != 1 or Path(files[0]).name not in {'compose.yaml', 'compose.license.yaml', 'compose.build.yaml'} or \
                Path(files[0]).resolve(strict=True).parent != working:
            raise ValueError('foreign Compose configuration')
        drift = []
        if container['Image'] != pin['image_id']:
            drift.append('image-id-changed')
        if pin['version'] != installed_version():
            drift.append('version-changed')
        if pin['program_baseline'] != approved_baseline_pin(BASELINE):
            drift.append('program-baseline-changed')
        if pin['host_baseline'] != approved_baseline_pin(HOST_BASELINE):
            drift.append('host-baseline-changed')
        # A matching metadata pin alone cannot bless an incomplete or changed installation.
        checks = baseline_checks if baseline_checks is not None else [integrity_check(), host_configuration_check()]
        if len(checks) != 2 or any(row.get('state') not in {'ok', 'finding'} for row in checks):
            raise ValueError('current program/host coverage is unknown')
        for label, row in zip(('program-files-changed', 'host-files-changed'), checks):
            if row['state'] == 'finding':
                drift.append(label)
        return check(name, 'finding' if drift else 'ok',
                     '镜像身份或批准基线发生变化：' + ', '.join(drift) + '；须独立复核，禁止自动重新批准'
                     if drift else '完整镜像 ID 及程序/主机基线与本机 root 批准记录一致；仍非发布方镜像签名',
                     check_id=identifier, category='container', severity='high' if drift else 'info', scope=scope,
                     evidence={'container_id': ids[0], 'image_id': container['Image'],
                               'approved_image_id': pin['image_id'], 'drift': drift})
    except (OSError, ValueError, TypeError, AttributeError, subprocess.TimeoutExpired):
        return check(name, 'unavailable', '批准记录缺失字段、权限不安全、基线不可读或容器归属无法核验；不能判定可信',
                     check_id=identifier, category='container', scope=scope,
                     evidence={'approval': 'unverified'})


def evaluate_permission(path, *, name, check_id, metadata=None, max_mode=0o600,
                        expected_uid=0, expected_gid=0, expect_directory=False, required=True):
    """Evaluate metadata only. Secret contents are never opened, returned or hashed."""
    target = Path(path)
    try:
        item = metadata if metadata is not None else target.lstat()
    except OSError:
        return check(name, 'unavailable' if required else 'ok',
                     '路径缺失或元数据不可读' if required else '未配置该可选路径',
                     check_id=check_id, category='permissions', severity='unknown' if required else 'info',
                     scope=bounded_text(target, 120), evidence={'present': False})
    mode = stat.S_IMODE(item.st_mode)
    wrong_type = not (stat.S_ISDIR(item.st_mode) if expect_directory else stat.S_ISREG(item.st_mode))
    wrong_owner = expected_uid is not None and getattr(item, 'st_uid', expected_uid) != expected_uid
    wrong_group = expected_gid is not None and getattr(item, 'st_gid', expected_gid) != expected_gid
    too_wide = bool(mode & ~max_mode)
    unsafe = stat.S_ISLNK(item.st_mode) or wrong_type or wrong_owner or wrong_group or too_wide
    reasons = []
    if stat.S_ISLNK(item.st_mode):
        reasons.append('符号链接')
    if wrong_type:
        reasons.append('类型异常')
    if wrong_owner or wrong_group:
        reasons.append('所有者异常')
    if too_wide:
        reasons.append('权限过宽')
    return check(name, 'finding' if unsafe else 'ok',
                 '元数据风险：' + '、'.join(reasons) if unsafe else f'所有者和权限符合不宽于 {max_mode:04o} 的固定合同',
                 check_id=check_id, category='permissions', severity='high' if unsafe else 'info',
                 scope=bounded_text(target, 120),
                 evidence={'present': True, 'mode': f'{mode:04o}',
                           'uid': getattr(item, 'st_uid', None), 'gid': getattr(item, 'st_gid', None),
                           'kind': 'directory' if stat.S_ISDIR(item.st_mode) else
                           ('file' if stat.S_ISREG(item.st_mode) else 'other')})


def optional_metadata(path):
    try:
        return Path(path).lstat()
    except OSError:
        return None


def secret_permissions_check():
    """Check a fixed credential inventory through lstat only; never read credential bytes."""
    results = [
        evaluate_permission(ROOT / 'shared' / '.env', name='环境配置权限',
                            check_id='permissions.shared-env'),
        evaluate_permission(ROOT / 'shared' / '.backup-key', name='备份密钥权限',
                            check_id='permissions.backup-key'),
    ]
    security_root = ROOT / 'shared' / 'security'
    security_metadata = optional_metadata(security_root)
    if security_metadata is not None:
        results.append(evaluate_permission(security_root, name='云端凭据目录权限',
                                           check_id='permissions.cloud-directory',
                                           metadata=security_metadata, max_mode=0o700,
                                           expected_uid=None, expected_gid=None, expect_directory=True))
        for filename, max_mode in (('ca.crt', 0o644), ('license.crt', 0o644),
                                   ('license.key', 0o600), ('build.crt', 0o644),
                                   ('build.key', 0o600)):
            target = security_root / filename
            metadata = optional_metadata(target)
            if metadata is not None:
                results.append(evaluate_permission(target, name=f'云端凭据 {filename}',
                                                   check_id='permissions.cloud-' + filename.replace('.', '-'),
                                                   metadata=metadata, max_mode=max_mode,
                                                   expected_uid=None, expected_gid=None))
    system_security = Path('/etc/appgog-security')
    system_metadata = optional_metadata(system_security)
    if system_metadata is not None:
        results.append(evaluate_permission(system_security, name='安全服务配置目录权限',
                                           check_id='permissions.security-directory',
                                           metadata=system_metadata, max_mode=0o700,
                                           expect_directory=True))
        for filename, max_mode in (('config.json', 0o600), ('ca.crt', 0o644),
                                   ('server.crt', 0o644), ('server.key', 0o600)):
            target = system_security / filename
            metadata = optional_metadata(target)
            if metadata is not None:
                results.append(evaluate_permission(target, name=f'安全服务 {filename}',
                                                   check_id='permissions.security-' + filename.replace('.', '-'),
                                                   metadata=metadata, max_mode=max_mode))
    findings = [item for item in results if item['state'] == 'finding']
    unavailable = [item for item in results if item['state'] == 'unavailable']
    state_value = 'finding' if findings else ('unavailable' if unavailable else 'ok')
    affected = findings or unavailable
    detail = ('存在不安全的所有者、文件类型或权限：' + ', '.join(item['name'] for item in affected[:6])) \
        if affected else f'固定凭据清单共 {len(results)} 项，均通过仅元数据权限检查'
    return check('敏感配置与密钥权限', state_value, detail,
                 check_id='permissions.secret-inventory', category='permissions',
                 severity='high' if findings else ('unknown' if unavailable else 'info'),
                 scope='固定凭据路径，仅 lstat 元数据',
                 evidence={'checked': len(results),
                           'states': {item['id']: item['state'] for item in results[:24]}})


def sshd_effective_check():
    command = ['sshd', '-T', '-C', 'user=root,host=localhost,addr=127.0.0.1']
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
        if result.returncode != 0:
            raise OSError('sshd effective configuration failed')
    except (OSError, subprocess.TimeoutExpired):
        return check('SSH 生效配置', 'unavailable', '无法执行固定上下文的 sshd -T 检查',
                     check_id='ssh.effective', category='ssh', severity='unknown',
                     scope='root@localhost effective sshd configuration', evidence={'command': 'sshd -T'})
    values = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.strip().partition(' ')
        if separator and key in {'permitrootlogin', 'passwordauthentication', 'permitemptypasswords', 'port'}:
            values[key] = value.strip().lower()[:40]
    required = {'permitrootlogin', 'passwordauthentication', 'permitemptypasswords', 'port'}
    if not required.issubset(values):
        return check('SSH 生效配置', 'unavailable', 'sshd -T 输出缺少必要安全字段',
                     check_id='ssh.effective', category='ssh', severity='unknown',
                     scope='root@localhost effective sshd configuration',
                     evidence={'present_fields': sorted(values)})
    risky = (values['permitrootlogin'] == 'yes' or values['passwordauthentication'] == 'yes'
             or values['permitemptypasswords'] == 'yes')
    return check('SSH 生效配置', 'finding' if risky else 'ok',
                 '生效配置允许 root、密码或空密码登录' if risky
                 else f"生效配置已关闭密码/空密码直登，SSH 端口 {values['port']}",
                 check_id='ssh.effective', category='ssh', severity='high' if risky else 'info',
                 scope='root@localhost effective sshd configuration', evidence=values)


def proc_address(address, ipv6=False):
    raw = bytes.fromhex(address)
    if ipv6:
        network = b''.join(raw[offset:offset + 4][::-1] for offset in range(0, 16, 4))
    else:
        network = raw[::-1]
    return ipaddress.ip_address(network)


def listener_posture_from_text(ipv4_text, ipv6_text=''):
    listeners = []
    total = 0
    malformed = 0
    dangerous_ports = set()
    public_port_set = set()
    for family, text in ((4, ipv4_text), (6, ipv6_text)):
        for line in str(text).splitlines()[1:]:
            cells = line.split()
            if len(cells) <= 3 or cells[3] != '0A':
                continue
            try:
                address_hex, port_hex = cells[1].rsplit(':', 1)
                address = proc_address(address_hex, ipv6=family == 6)
                port = int(port_hex, 16)
                mapped = getattr(address, 'ipv4_mapped', None)
                loopback = address.is_loopback or (mapped is not None and mapped.is_loopback)
                exposure = 'loopback' if loopback else ('wildcard' if address.is_unspecified else 'public')
            except (ValueError, IndexError):
                malformed += 1
                continue
            total += 1
            if exposure != 'loopback':
                public_port_set.add(port)
                if port in DANGEROUS_PUBLIC_PORTS:
                    dangerous_ports.add(port)
            if len(listeners) < MAX_LISTENERS:
                listeners.append({'family': family, 'address': str(address),
                                  'port': port, 'exposure': exposure})
    dangerous = sorted(dangerous_ports)
    public_ports = sorted(public_port_set)
    if dangerous:
        state_value, severity = 'finding', 'critical' if 2375 in dangerous else 'high'
        summary = '危险端口暴露在公网或通配地址：' + ', '.join(map(str, dangerous))
    elif public_ports:
        state_value, severity = 'warning', 'medium'
        summary = '公网或通配地址 TCP 监听端口：' + ', '.join(map(str, public_ports[:20]))
    elif malformed:
        state_value, severity = 'unavailable', 'unknown'
        summary = 'TCP 监听数据格式异常，无法形成可信结论'
    else:
        state_value, severity = 'ok', 'info'
        loopback_ports = sorted({item['port'] for item in listeners})
        summary = '仅发现本机回环 TCP 监听：' + ', '.join(map(str, loopback_ports[:20])) \
            if loopback_ports else '未发现 TCP 监听端口'
    if total > MAX_LISTENERS:
        summary += f'；证据仅保留前 {MAX_LISTENERS}/{total} 项'
    return check('TCP 监听端口姿态', state_value, summary,
                 check_id='network.listeners', category='network', severity=severity,
                 scope='/proc/net/tcp and /proc/net/tcp6 fixed snapshot',
                 evidence={'listeners': listeners, 'total': total, 'malformed': malformed,
                           'dangerous_public_ports': dangerous})


def listener_posture_check():
    texts = {}
    missing = []
    for label, path in (('ipv4', Path('/proc/net/tcp')), ('ipv6', Path('/proc/net/tcp6'))):
        try:
            texts[label] = path.read_text(encoding='ascii')
        except OSError:
            texts[label] = ''
            missing.append(label)
    if len(missing) == 2:
        return check('TCP 监听端口姿态', 'unavailable', '无法读取固定的 /proc TCP 监听快照',
                     check_id='network.listeners', category='network', severity='unknown',
                     scope='/proc/net/tcp and /proc/net/tcp6 fixed snapshot',
                     evidence={'missing': missing})
    result = listener_posture_from_text(texts['ipv4'], texts['ipv6'])
    if missing and result['state'] != 'finding':
        return check('TCP 监听端口姿态', 'unavailable', '仅取得部分 TCP 监听快照，不能证明未暴露危险端口',
                     check_id='network.listeners', category='network', severity='unknown',
                     scope='/proc/net/tcp and /proc/net/tcp6 fixed snapshot',
                     evidence={'missing': missing, 'partial_state': result['state'],
                               'partial_digest': result['evidence_digest']})
    return result


NETWORK_BASELINE = STATE_DIR / 'network-baseline.json'
MAX_NETWORK_BYTES = 262144
MAX_ROUTES = 256
KERNEL_POLICY = {
    '/proc/sys/kernel/randomize_va_space': {2},
    '/proc/sys/fs/protected_hardlinks': {1},
    '/proc/sys/fs/protected_symlinks': {1},
    '/proc/sys/kernel/kptr_restrict': {1, 2},
    '/proc/sys/kernel/dmesg_restrict': {1},
}


def fixed_proc_text(path):
    # /proc/net and /proc/self are kernel symlinks. Use our numeric PID without
    # relaxing ancestor no-follow checks or accepting caller-selected paths.
    net_files = {'/proc/net/udp', '/proc/net/udp6', '/proc/net/route', '/proc/net/ipv6_route'}
    if path in net_files:
        target = Path('/proc') / str(os.getpid()) / 'net' / Path(path).name
    elif path in KERNEL_POLICY:
        target = Path(path)
    else:
        raise ValueError('unsupported proc inspection path')
    return read_regular(target, MAX_NETWORK_BYTES, proc_lookup=True).decode('ascii', errors='strict')


def udp_posture_from_text(ipv4_text, ipv6_text):
    total, ports, loopback, malformed = 0, set(), set(), 0
    for family, text in ((4, ipv4_text), (6, ipv6_text)):
        lines = text.splitlines()
        if not lines or lines[0].split()[:4] not in (['sl', 'local_address', 'rem_address', 'st'], ['sl', 'local_address', 'remote_address', 'st']):
            raise ValueError('missing UDP header')
        for line in lines[1:]:
            cells = line.split()
            if len(cells) < 4:
                malformed += 1
                continue
            try:
                local, port_hex = cells[1].rsplit(':', 1)
                peer, peer_port = cells[2].rsplit(':', 1)
                address = proc_address(local, ipv6=family == 6)
                remote = proc_address(peer, ipv6=family == 6)
                if address.version != family or remote.version != family or not re.fullmatch(r'[0-9A-Fa-f]{4}', port_hex) or not re.fullmatch(r'[0-9A-Fa-f]{4}', peer_port):
                    raise ValueError('invalid UDP endpoint')
                if cells[3] not in {'01', '07'}:
                    raise ValueError('invalid UDP state')
                # Unconnected bound sockets only; connected clients are outside this check.
                if cells[3] != '07' or not remote.is_unspecified or int(peer_port, 16) != 0:
                    continue
                total += 1
                port = int(port_hex, 16)
                mapped = getattr(address, 'ipv4_mapped', None)
                if address.is_loopback or (mapped is not None and mapped.is_loopback):
                    loopback.add(port)
                else:
                    ports.add(port)
            except (ValueError, IndexError):
                malformed += 1
    state = 'unavailable' if malformed else ('warning' if ports else 'ok')
    detail = 'UDP 快照格式异常，不能形成完整结论' if malformed else ('非回环地址 UDP 绑定端口：' + ', '.join(map(str, sorted(ports)[:20])) if ports else '未发现非回环地址的未连接 UDP 绑定')
    return check('UDP 绑定端口姿态', state, detail, check_id='network.udp-listeners', category='network',
        scope='host network namespace /proc/net/udp and udp6; no reachability proof',
        evidence={'total': total, 'public_ports': sorted(ports), 'loopback_ports': sorted(loopback), 'malformed': malformed})


def udp_posture_check():
    try:
        return udp_posture_from_text(fixed_proc_text('/proc/net/udp'), fixed_proc_text('/proc/net/udp6'))
    except (OSError, ValueError, UnicodeError):
        return check('UDP 绑定端口姿态', 'unavailable', 'UDP/UDP6 快照缺失、读取异常或超过 256 KiB；不能判断完整范围',
            check_id='network.udp-listeners', category='network', scope='fixed host UDP/UDP6 snapshots')


def route_snapshot_from_text(ipv4_text, ipv6_text):
    routes = []
    lines = ipv4_text.splitlines()
    if not lines or lines[0].split()[:4] != ['Iface', 'Destination', 'Gateway', 'Flags']:
        raise ValueError('invalid IPv4 route header')
    for line in lines[1:]:
        fields = line.split()
        if len(fields) != 11 or not re.fullmatch(r'[A-Za-z0-9_.:@-]{1,32}', fields[0]):
            raise ValueError('invalid IPv4 route')
        if any(not re.fullmatch(r'[A-Fa-f0-9]{8}', fields[pos]) for pos in (1, 2, 7)) or not re.fullmatch(r'[A-Fa-f0-9]{4}', fields[3]) or any(not re.fullmatch(r'[0-9]{1,10}', fields[pos]) for pos in (4, 5, 6, 8, 9, 10)):
            raise ValueError('invalid IPv4 route fields')
        # RefCnt and Use are traffic counters, not configuration.
        routes.append([4, fields[0], fields[1].upper(), fields[2].upper(), fields[3].upper(), int(fields[6]), fields[7].upper(), *map(int, fields[8:])])
        if len(routes) > MAX_ROUTES:
            raise ValueError('route coverage limit')
    for line in ipv6_text.splitlines():
        fields = line.split()
        if len(fields) != 10 or not re.fullmatch(r'[A-Za-z0-9_.:@-]{1,32}', fields[9]) or any(not re.fullmatch(r'[A-Fa-f0-9]{32}', fields[pos]) for pos in (0, 2, 4)) or any(not re.fullmatch(r'[A-Fa-f0-9]{2}', fields[pos]) or int(fields[pos], 16) > 128 for pos in (1, 3)) or any(not re.fullmatch(r'[A-Fa-f0-9]{8}', fields[pos]) for pos in (5, 6, 7, 8)):
            raise ValueError('invalid IPv6 route')
        routes.append([6, *[fields[pos].upper() for pos in (0, 1, 2, 3, 4, 5, 8)], fields[9]])
        if len(routes) > MAX_ROUTES:
            raise ValueError('route coverage limit')
    if not routes:
        raise ValueError('empty route inventory')
    routes.sort(key=lambda row: json.dumps(row, separators=(',', ':')))
    return {'digest': hashlib.sha256(json.dumps(routes, separators=(',', ':')).encode()).hexdigest(), 'count': len(routes)}


def route_snapshot():
    first = route_snapshot_from_text(fixed_proc_text('/proc/net/route'), fixed_proc_text('/proc/net/ipv6_route'))
    second = route_snapshot_from_text(fixed_proc_text('/proc/net/route'), fixed_proc_text('/proc/net/ipv6_route'))
    if first != second:
        raise ValueError('routes changed during observation')
    return first


def approve_network_baseline(expected):
    if not re.fullmatch(r'[a-f0-9]{64}', expected):
        raise ValueError('exact network fingerprint required')
    current = route_snapshot()
    if current['digest'] != expected:
        raise ValueError('network fingerprint changed; approval refused')
    atomic_json(NETWORK_BASELINE, {'schema': 1, 'root': str(ROOT), **current,
        'approved_at': datetime.now(timezone.utc).isoformat()})


def route_configuration_check():
    scope = 'host IPv4/IPv6 main route snapshots; explicit root approval; no firewall audit'
    try:
        current = route_snapshot()
        baseline = json.loads(read_state(NETWORK_BASELINE, 4096))
        if not isinstance(baseline, dict) or set(baseline) != {'schema', 'root', 'digest', 'count', 'approved_at'} or type(baseline['schema']) is not int or baseline['schema'] != 1 or baseline['root'] != str(ROOT) or not isinstance(baseline['digest'], str) or not re.fullmatch(r'[a-f0-9]{64}', baseline['digest']) or type(baseline['count']) is not int or not 1 <= baseline['count'] <= MAX_ROUTES or not isinstance(baseline['approved_at'], str):
            raise ValueError('invalid route baseline')
        changed = any(current[key] != baseline[key] for key in ('digest', 'count'))
        return check('主机路由配置变化', 'finding' if changed else 'ok',
            '路由与 root 批准基线不符；核对合法网络变更及入侵证据' if changed else '受控 IPv4/IPv6 路由与批准基线一致',
            check_id='network.routes', category='network', scope=scope, evidence=current)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        return check('主机路由配置变化', 'unavailable', '未批准路由基线、部分读取、超限或观察期间变化；不能判断安全',
            check_id='network.routes', category='network', scope=scope)


def kernel_security_check():
    values, missing, weakened = {}, [], []
    for path, permitted in KERNEL_POLICY.items():
        try:
            value = fixed_proc_text(path).strip()
            if not re.fullmatch(r'[0-9]{1,3}', value):
                raise ValueError('invalid kernel value')
            values[path] = int(value)
            if int(value) not in permitted:
                weakened.append(path.rsplit('/', 1)[1])
        except (OSError, ValueError, UnicodeError):
            missing.append(path.rsplit('/', 1)[1])
    state = 'unavailable' if missing else ('warning' if weakened else 'ok')
    detail = '内核防护参数低于建议值：' + ', '.join(weakened) if weakened else ('部分内核防护参数无法读取' if missing else '五项固定内核防护参数达到建议值')
    if weakened and missing:
        detail += '；另有参数未取得，不能形成完整结论'
    return check('内核基础防护参数', state, detail, check_id='host.kernel-security',
        scope='ASLR/hardlink/symlink/kptr/dmesg fixed parameters; no automatic changes',
        evidence={'values': values, 'missing': missing, 'weakened': weakened})


def containment_check():
    path = STATE_DIR / 'incident.json'
    if not path.exists() and not path.is_symlink():
        return check('本地事故隔离', 'ok', '没有活动隔离记录；这不代表整台主机无入侵',
                     check_id='response.containment', category='host', scope='independent local response')
    try:
        item = json.loads(read_state(path, 32768))
        if item.get('schema') != 1 or item.get('root') != str(ROOT) or item.get('state') not in {
            'isolating', 'contained', 'containment_failed', 'source_repaired', 'recovering', 'released'
        }:
            raise ValueError('invalid incident')
        active = item['state'] != 'released'
        return check('本地事故隔离', 'finding' if active else 'ok',
                     '隔离状态：' + item['state'] + ('；仅允许 root 经独立核验恢复' if active else '；已留存恢复记录'),
                     check_id='response.containment', category='host', severity='critical' if active else 'info',
                     scope='independent local response', evidence={'state': item['state'], 'updated_at': item.get('updated_at')})
    except (OSError, ValueError, TypeError):
        return check('本地事故隔离', 'unavailable', '独立隔离记录异常，普通恢复应保持禁止',
                     check_id='response.containment', category='host', scope='independent local response')



FIREWALL_SOURCES = frozenset(('nftables', 'iptables', 'ip6tables', 'iptables-legacy', 'ip6tables-legacy'))


def valid_firewall_snapshot(item):
    if not isinstance(item, dict) or set(item) != {'digest', 'sources', 'rules'} or not isinstance(item.get('digest'), str) or not re.fullmatch(r'[a-f0-9]{64}', item['digest']):
        return False
    sources = item['sources']
    if not isinstance(sources, dict) or not {'nftables', 'iptables', 'ip6tables'} <= sources.keys() <= FIREWALL_SOURCES:
        return False
    for value in sources.values():
        if not isinstance(value, dict) or set(value) != {'digest', 'rules'} or not isinstance(value.get('digest'), str) or not re.fullmatch(r'[a-f0-9]{64}', value['digest']) or type(value['rules']) is not int or not 0 <= value['rules'] <= 8192:
            return False
    canonical = json.dumps(sources, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    return type(item['rules']) is int and item['rules'] == sum(value['rules'] for value in sources.values()) and item['digest'] == hashlib.sha256(canonical).hexdigest()


def firewall_check():
    name, scope = '运行时防火墙规则', 'host netns nftables + IPv4/IPv6 iptables; read-only'
    unavailable = lambda: check(name, 'unavailable', '规则采集未配置、工具缺失、过期或快照不完整；请在 Linux 安全菜单核对', check_id='network.firewall', category='network', scope=scope)
    try:
        report = json.loads(read_state(STATE_DIR / 'firewall-report.json', 32768))
        if not isinstance(report, dict) or set(report) != {'schema', 'root', 'checked_at', 'state', 'snapshot'} or type(report['schema']) is not int or report['schema'] != 1 or report['root'] != str(ROOT) or report['state'] != 'finished' or not valid_firewall_snapshot(report['snapshot']):
            raise ValueError('invalid firewall report')
        timestamp = datetime.fromisoformat(report['checked_at'].replace('Z', '+00:00'))
        age = (datetime.now(timezone.utc) - timestamp).total_seconds()
        if timestamp.utcoffset().total_seconds() != 0 or not -120 <= age <= 900:
            raise ValueError('stale firewall report')
        current = report['snapshot']
        evidence = {'digest': current['digest'], 'rules': current['rules'], 'sources': sorted(current['sources'])}
        target = STATE_DIR / 'firewall-baseline.json'
        if not target.exists() and not target.is_symlink():
            return check(name, 'warning', '尚未批准实际规则基线；请独立检查规则后输入完整指纹，不自动学习', check_id='network.firewall', category='network', scope=scope, evidence=evidence)
        baseline = json.loads(read_state(target, 32768))
        if not isinstance(baseline, dict) or set(baseline) != {'schema', 'root', 'approved_at', 'snapshot'} or type(baseline['schema']) is not int or baseline['schema'] != 1 or baseline['root'] != str(ROOT) or not valid_firewall_snapshot(baseline['snapshot']):
            raise ValueError('invalid firewall baseline')
        approved = datetime.fromisoformat(baseline['approved_at'].replace('Z', '+00:00'))
        if approved.utcoffset().total_seconds() != 0 or approved > datetime.now(timezone.utc) + timedelta(seconds=120):
            raise ValueError('invalid firewall approval date')
        changed = current != baseline['snapshot']
        state = 'finding' if changed else ('warning' if current['rules'] == 0 else 'ok')
        detail = '实际防火墙规则或后端来源变化；保留证据并核验合法变更，不自动改规则' if changed else ('未检测到规则；匹配空基线不代表已建立防火墙防护' if current['rules'] == 0 else '当前有界规则快照与明确批准的基线一致；不等于公网可达性或所有命名空间验收')
        return check(name, state, detail, check_id='network.firewall', category='network', scope=scope, evidence=evidence, checked_at=report['checked_at'])
    except (OSError, ValueError, TypeError, AttributeError, KeyError, OverflowError, RecursionError):
        return unavailable()


def cloudflare_checks():
    """Read a root-private report from the separate network collector; never read its token."""
    identifiers = ('dns', 'workers', 'rules', 'settings')
    labels = ('Cloudflare DNS', 'Cloudflare Workers 路由', 'Cloudflare 重定向与安全规则', 'Cloudflare HTTPS 与站点设置')
    try:
        payload = json.loads(read_state(STATE_DIR / 'cloudflare-report.json', limit=8192))
        if not isinstance(payload, dict) or set(payload) != {'schema', 'checked_at', 'checks'} or payload['schema'] != 1:
            raise ValueError('invalid collector report')
        timestamp = datetime.fromisoformat(payload['checked_at'].replace('Z', '+00:00'))
        age = (datetime.now(timezone.utc) - timestamp).total_seconds()
        if timestamp.utcoffset().total_seconds() != 0 or not -120 <= age <= 900:
            raise ValueError('stale collector report')
        rows = payload['checks']
        if not isinstance(rows, list) or len(rows) != 4:
            raise ValueError('incomplete collector report')
        results = []
        for index, row in enumerate(rows):
            identifier = 'cloudflare.' + identifiers[index]
            if not isinstance(row, dict) or set(row) != {'id', 'name', 'state', 'detail', 'scope', 'evidence'} or row.get('id') != identifier or row.get('name') != labels[index] or row.get('state') not in {'ok', 'finding', 'unavailable'} or not isinstance(row.get('detail'), str) or len(row['detail']) > 180 or row.get('scope') != 'Cloudflare single zone; read-only':
                raise ValueError('invalid collector check')
            evidence = row['evidence']
            if evidence is not None and (not isinstance(evidence, dict) or set(evidence) != {'digest', 'count'} or not isinstance(evidence['digest'], str) or not re.fullmatch(r'[a-f0-9]{64}', evidence['digest']) or type(evidence['count']) is not int or not 0 <= evidence['count'] <= 5000):
                raise ValueError('invalid collector evidence')
            if row['state'] != 'unavailable' and evidence is None:
                raise ValueError('missing collector evidence')
            results.append(check(labels[index], row['state'], row['detail'], check_id=identifier,
                category='network', scope=row['scope'], evidence=evidence, checked_at=payload['checked_at']))
        return results
    except (OSError, ValueError, TypeError, AttributeError, KeyError, OverflowError):
        return [check(label, 'unavailable', 'Cloudflare 只读检查未配置、结果过期或采集报告不完整；请在 Linux 安全菜单配置',
            check_id='cloudflare.' + identifier, category='network', scope='Cloudflare single zone; read-only')
            for identifier, label in zip(identifiers, labels)]


def process_posture_check():
    """Bounded executable-path inspection; do not read command lines, environment or process memory."""
    scope = 'host /proc executable paths; <=2048 processes; 3 seconds'
    started = time.monotonic()
    count, mutable, deleted, inaccessible = 0, 0, 0, 0
    try:
        with os.scandir('/proc') as entries:
            for entry in entries:
                if not entry.name.isdigit():
                    continue
                count += 1
                if count > 2048 or time.monotonic() - started > 3:
                    raise ValueError('process inventory budget')
                try:
                    executable = os.readlink('/proc/' + entry.name + '/exe')
                    if executable.endswith(' (deleted)'):
                        deleted += 1
                        executable = executable[:-10]
                    if executable.startswith(('/tmp/', '/var/tmp/', '/dev/shm/')):
                        mutable += 1
                except FileNotFoundError:
                    # Exited processes and kernel threads have no exe; permission failures stay unknown.
                    continue
                except PermissionError:
                    inaccessible += 1
        if count == 0 or inaccessible:
            raise ValueError('process coverage incomplete')
        suspect = mutable + deleted
        return check('宿主进程执行路径', 'warning' if suspect else 'ok',
            f'检查 {count} 个进程；临时目录运行 {mutable}，执行文件已删除 {deleted}。合法更新也可能触发，需复核' if suspect
            else f'检查 {count} 个进程，未发现临时目录或已删除的执行文件；不含进程内存检测',
            check_id='host.process-executables', scope=scope, evidence={'count': count, 'mutable': mutable, 'deleted': deleted})
    except (OSError, ValueError, TypeError):
        return check('宿主进程执行路径', 'unavailable', '进程执行路径读取失败或超限；不报告整机干净',
            check_id='host.process-executables', scope=scope)


def failed_services_check():
    scope = 'systemd failed service/timer units; bounded 256 KiB'
    try:
        # Reuse the bounded pipe collector without invoking a shell or accepting external arguments.
        raw = bounded_command_output(['/usr/bin/systemctl', 'list-units', '--state=failed',
            '--type=service,timer', '--no-legend', '--no-pager', '--plain'])
        lines = raw.decode('utf-8', errors='strict').splitlines()
        if len(lines) > 128 or any(len(line) > 2048 for line in lines):
            raise ValueError('unit budget')
        units = []
        for line in lines:
            parts = line.split()
            if len(parts) < 4 or parts[2] != 'failed' or not re.fullmatch(r'[A-Za-z0-9_.@:\\-]+\.(?:service|timer)', parts[0]):
                raise ValueError('invalid systemd unit')
            units.append(parts[0])
        return check('失败服务与定时器', 'warning' if units else 'ok',
            f'发现 {len(units)} 个失败单元；请在本机核对服务日志，不自动停服务或修复' if units else '未发现处于 failed 状态的服务或定时器；配置变化另由主机基线核对',
            check_id='host.failed-units', scope=scope, evidence={'units': sorted(units)})
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        return check('失败服务与定时器', 'unavailable', '无法完整读取 systemd 服务/定时器状态',
            check_id='host.failed-units', scope=scope)


def bounded_command_output(command):
    """Fixed callers only; cap stdout allocation, elapsed time and reap the child on every path."""
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, cwd='/', env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
    output = bytearray()
    deadline = time.monotonic() + 5
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not ready.select(remaining):
                    raise ValueError('command timeout')
                chunk = os.read(process.stdout.fileno(), min(65536, 262145 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > 262144:
                    raise ValueError('command output budget')
        if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            raise ValueError('command failure')
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        process.stdout.close()

def scan():
    baseline_checks = [integrity_check(), host_configuration_check()]
    results = [*baseline_checks, container_contract_check(),
               approved_image_check(baseline_checks), containment_check()]
    try:
        info = Path('/etc/os-release').read_text(encoding='utf-8')
        distro = next((line[8:].strip('"') for line in info.splitlines() if line.startswith('PRETTY_NAME=')), 'Linux')
        results.append(check('Linux 系统', 'ok', distro[:80] + ' · ' + os.uname().release[:70], check_id='host.os-release'))
    except OSError:
        results.append(check('Linux 系统', 'unavailable', '无法读取系统版本', check_id='host.os-release'))
    try:
        output = subprocess.run(['systemctl', 'is-system-running'], capture_output=True, text=True, timeout=4, check=False)
        value = output.stdout.strip()
        results.append(check('systemd 状态', 'ok' if value == 'running' else 'warning', value or 'systemd 状态不可用', check_id='host.systemd-state'))
    except (OSError, subprocess.TimeoutExpired):
        results.append(check('systemd 状态', 'unavailable', '无法核对服务管理器', check_id='host.systemd-state'))
    results.append(sshd_effective_check())
    results.append(secret_permissions_check())
    for label, path, identifier in [('安装目录权限', ROOT, 'permissions.installation'), ('定时任务权限', Path('/etc/cron.d'), 'permissions.cron')]:
        try:
            mode = path.stat().st_mode
            results.append(check(label, 'finding' if mode & stat.S_IWOTH else 'ok', '目录允许所有用户写入' if mode & stat.S_IWOTH else '目录未开放全员写权限', check_id=identifier, category='permissions'))
        except OSError:
            results.append(check(label, 'unavailable', '无法读取路径或权限', check_id=identifier, category='permissions'))
    results.append(listener_posture_check())
    results.extend((udp_posture_check(), route_configuration_check(), kernel_security_check(), firewall_check()))
    results.append(malware_scan())
    results.append(business_malware_scan())
    results.append(sqlite_health_check())
    results.append(process_posture_check())
    results.append(failed_services_check())
    results.extend(cloudflare_checks())
    return results


def run_scan():
    global STATE
    try:
        checks = scan()
        if not complete_scan_checks(checks, datetime.now(timezone.utc).isoformat()):
            raise ValueError('Incomplete fixed scan report')
        history_state = 'ok'
        try:
            history = save_history(checks)
        except (OSError, ValueError, TypeError):
            history, history_state = [], 'unavailable'
            checks.append(check('本地告警历史', 'unavailable', '历史读取或保存失败；请由 root 检查状态目录，原有证据保留', check_id='host.history'))
        checked_at = datetime.now(timezone.utc).isoformat()
        if not complete_scan_checks(checks, checked_at):
            raise ValueError('Incomplete fixed scan report')
        with LOCK:
            STATE = {'state': 'finished', 'checked_at': checked_at,
                     'checks': checks, 'history': history, 'history_state': history_state}
    except Exception:
        with LOCK:
            STATE = {'state': 'failed', 'checked_at': datetime.now(timezone.utc).isoformat(), 'checks': []}


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(*args, **kwargs)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return connection, address

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, code, data):
        data = dict(data)
        if 'history' in data:
            data['history'] = list(data['history'])
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        while len(body) > MAX_RESPONSE_BYTES and data.get('history'):
            data['history'].pop(0)
            data['history_state'] = 'truncated'
            body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        if len(body) > MAX_RESPONSE_BYTES:
            code, body = 503, b'{"state":"unavailable"}'
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def empty_request(self):
        lengths = self.headers.get_all('Content-Length', [])
        return len(lengths) <= 1 and (not lengths or lengths[0] == '0') and not self.headers.get_all('Transfer-Encoding')

    def do_GET(self):
        if not self.empty_request():
            return self.reply(400, {'error': 'invalid body'})
        if self.path != '/status':
            return self.reply(404, {'error': 'unknown action'})
        with LOCK:
            report = dict(STATE)
        self.reply(200, report)

    def do_POST(self):
        if self.path != '/scan' or not self.empty_request():
            return self.reply(400, {'error': 'invalid action'})
        code = start_scan()
        self.reply(code, {'state': 'running' if code in (202, 409) else 'unavailable'})


def start_scan():
    """Share one scan lock and cooldown between scheduled and manual requests."""
    global LAST_START
    with LOCK:
        if STATE['state'] == 'running':
            return 409
        now = time.monotonic()
        if LAST_START is not None and now - LAST_START < 60:
            return 429
        LAST_START = now
        STATE.update(state='running', checks=[])
        threading.Thread(target=run_scan, daemon=True).start()
        return 202


def periodic_scans(stop_event, interval=SCAN_INTERVAL_SECONDS):
    start_scan()  # No clean result is reported before the first completed check.
    while not stop_event.wait(interval):
        start_scan()


def main():
    folder = Path(SOCKET).parent
    global HISTORY_VALID
    if os.geteuid() != 0:
        raise RuntimeError('host agent requires root')
    folder.mkdir(mode=0o750, parents=True, exist_ok=True)
    metadata = folder.lstat()
    if folder.is_symlink() or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o027:
        raise RuntimeError('unsafe socket directory')
    gid = int(os.environ.get('APPGOG_HOST_SECURITY_GID', '65532'))
    if gid <= 0 or gid > 2147483647 or metadata.st_gid != gid:
        raise RuntimeError('invalid socket group')
    HISTORY_VALID = load_history()
    if Path(SOCKET).exists():
        if not stat.S_ISSOCK(Path(SOCKET).lstat().st_mode):
            raise RuntimeError('socket path occupied')
        Path(SOCKET).unlink()
    with UnixHTTPServer(SOCKET, Handler) as server:
        os.chown(SOCKET, 0, gid)
        os.chmod(SOCKET, 0o660)
        threading.Thread(target=periodic_scans, args=(threading.Event(),), daemon=True).start()
        server.serve_forever()


if __name__ == '__main__':
    if sys.argv[1:] == ['--write-baseline'] and os.geteuid() == 0:
        write_baseline()
    elif sys.argv[1:] == ['--network-fingerprint'] and os.geteuid() == 0:
        print(route_snapshot()['digest'])
    elif len(sys.argv) == 3 and sys.argv[1] == '--approve-network-baseline' and os.geteuid() == 0:
        approve_network_baseline(sys.argv[2])
    elif sys.argv[1:] == ['--write-host-baseline'] and os.geteuid() == 0:
        write_host_baseline()
    elif sys.argv[1:] == ['--approve-host-baseline', 'APPROVE-HOST'] and os.geteuid() == 0:
        write_host_baseline()
    elif len(sys.argv) == 3 and sys.argv[1] == '--approve-baseline' and os.geteuid() == 0:
        if sys.argv[2] != installed_version():
            raise SystemExit('version confirmation mismatch')
        write_baseline()
    elif sys.argv[1:]:
        raise SystemExit('invalid action')
    else:
        main()
