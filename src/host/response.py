#!/usr/bin/env python3
"""Root-only bounded quarantine; local fixed-action controller or CLI, no cloud commands."""
import argparse, contextlib, datetime, hashlib, importlib.util, json, os, pathlib, re, stat, sys, time
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('response_agent', pathlib.Path(__file__).with_name('agent.py'))
a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)
try: import fcntl
except ImportError: fcntl = None
f = a.findings
MAX_ENTRIES = 128
MAX_VAULT_BYTES = 512 * 1024 * 1024
MAX_AGE = 900
DENIED = ['/etc', '/usr', '/bin', '/sbin', '/boot', '/proc', '/sys', '/dev', '/run', '/opt/ironcurtain', '/var/lib/docker', '/var/lib/ironcurtain', '/var/lib/ironcurtain-antivirus']


def identifier(value):
    if not isinstance(value, str) or not a.DIGEST.fullmatch(value): raise ValueError('请输入完整的 64 位证据 ID')
    return value


def timestamp(value):
    if not a.valid_timestamp(value): raise ValueError('证据时间无效')
    return datetime.datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def allowed(item, profile):
    path = item.get('path'); roots = profile['program_roots'] + profile['business_roots']
    if not f.path_allowed(path, roots): raise ValueError('目标不在当前保护范围')
    p = pathlib.PurePosixPath(path)
    if any(p.is_relative_to(root) for root in DENIED): raise ValueError('系统和安全程序目录禁止隔离')
    if path in profile['config_files'] + profile['secret_files'] + profile['sqlite_files']:
        raise ValueError('配置、凭据和数据库禁止自动隔离')
    name = p.name.lower()
    if name.startswith('.env') or name.endswith(('.db', '.sqlite', '.sqlite3', '.pem', '.key', '.crt', '.p12', '.enc', '-wal', '-shm')) or 'backup' in name:
        raise ValueError('配置、凭据、数据库和备份需人工处置')
    unsigned = {k: v for k, v in item.items() if k != 'id'}
    if hashlib.sha256(f.canonical(unsigned)).hexdigest() != identifier(item.get('id')): raise ValueError('证据摘要无效')
    if not isinstance(item.get('sha256'), str) or not a.DIGEST.fullmatch(item['sha256']) or not isinstance(item.get('signature'), str) or not f.SIGNATURE.fullmatch(item['signature']):
        raise ValueError('命中证据无效')
    keys = ['device', 'inode', 'size', 'mtime_ns', 'ctime_ns', 'mode', 'uid', 'gid', 'links']
    if any(type(item.get(k)) is not int or item[k] < 0 for k in keys) or item['size'] > f.MAX_BYTES:
        raise ValueError('文件身份无效')
    if item['links'] != 1 or item['uid'] != 0 or item['mode'] & 0o022: raise ValueError('仅支持 root 管理的单链接文件；共享可写文件须停服人工处置')


def open_source(item):
    parent, leaf = f.parent_fd(item['path'], controlled=True)
    fd = None
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or f.identity(info) != {k: item[k] for k in f.identity(info)}:
            raise ValueError('文件身份已变化，请重新扫描')
        if f.hash_fd(fd) != item['sha256'] or f.identity(os.fstat(fd)) != f.identity(info):
            raise ValueError('文件内容已变化，请重新扫描')
        return parent, leaf, fd
    except BaseException:
        if fd is not None: os.close(fd)
        os.close(parent); raise


class Vault:
    def __init__(self, directory):
        self.directory = pathlib.Path(directory)
        self.fd = None
    def __enter__(self):
        parent, leaf = f.parent_fd(str(self.directory), controlled=True)
        try:
            try: os.mkdir(leaf, 0o700, dir_fd=parent); os.fsync(parent)
            except FileExistsError: pass
            self.fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            info = os.fstat(self.fd)
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700: raise ValueError('隔离仓必须 root:700')
        except BaseException:
            if self.fd is not None: os.close(self.fd); self.fd = None
            raise
        finally: os.close(parent)
        return self
    def __exit__(self, *args): os.close(self.fd)
    def read(self, name):
        fd = self.open(name)
        with os.fdopen(fd, 'rb') as stream:
            data = stream.read(65537)
            if len(data) > 65536: raise ValueError('隔离记录超出预算')
            return json.loads(data)
    def open(self, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            os.close(fd); raise ValueError('隔离记录/副本权限或类型无效')
        return fd
    def write(self, name, value):
        temp = '.' + name + '.' + os.urandom(8).hex()
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, 'wb') as out: out.write(f.canonical(value)); out.flush(); os.fsync(out.fileno())
            os.replace(temp, name, src_dir_fd=self.fd, dst_dir_fd=self.fd); os.fsync(self.fd)
        finally:
            try: os.unlink(temp, dir_fd=self.fd)
            except FileNotFoundError: pass
    def usage(self):
        names = os.listdir(self.fd)
        if len(names) > MAX_ENTRIES * 3 + 16: raise ValueError('隔离仓条目超出预算')
        count = total = 0
        for name in names:
            if name.endswith('.json'): count += 1
            if name.endswith('.blob'):
                fd = self.open(name)
                try: total += os.fstat(fd).st_size
                finally: os.close(fd)
        return count, total
    def verify_blob(self, item):
        fd = self.open(identifier(item['id']) + '.blob')
        try:
            if os.fstat(fd).st_size != item['size'] or f.hash_fd(fd) != item['sha256']: raise ValueError('隔离副本损坏，保留现场')
            return fd
        except BaseException: os.close(fd); raise


def copy_fd(source, target):
    os.lseek(source, 0, os.SEEK_SET); digest = hashlib.sha256(); size = 0
    while True:
        block = os.read(source, 65536)
        if not block: break
        size += len(block)
        if size > f.MAX_BYTES: raise ValueError('隔离副本超出文件预算')
        digest.update(block)
        view = memoryview(block)
        while view:
            written = os.write(target, view)
            if written <= 0: raise OSError('short write')
            view = view[written:]
    os.fsync(target)
    return digest.hexdigest(), size


@contextlib.contextmanager
def response_lock(directory):
    if fcntl is None: raise ValueError('Linux required')
    parent, leaf = f.parent_fd(str(pathlib.Path(directory) / 'response.lock'), controlled=True)
    fd = None
    try:
        fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1: raise ValueError('处置锁无效')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)


def current_item(state, profile, evidence_id):
    value = a.private_json(pathlib.Path(state) / 'last-findings.json', 256 * 1024)
    if value.get('schema') != 'ironcurtain-findings/v1' or value.get('state') not in ['complete', 'partial'] or value.get('profile_digest') != hashlib.sha256(f.canonical(profile)).hexdigest():
        raise ValueError('当前检测配置或证据无效，请重新扫描')
    if not isinstance(value.get('items'), list) or len(value['items']) > f.MAX_FINDINGS: raise ValueError('检测记录超出预算')
    items = [item for item in value['items'] if isinstance(item, dict) and item.get('id') == evidence_id]
    if len(items) != 1: raise ValueError('没有此项已核实的命中，请重新扫描')
    item = items[0]; allowed(item, profile)
    age = time.time() - timestamp(item.get('observed_at'))
    if age < -30 or age > MAX_AGE: raise ValueError('命中证据超过 15 分钟，请重新扫描')
    return item


def quarantine(state, profile, evidence_id, hook=lambda phase: None):
    evidence_id = identifier(evidence_id)
    item = current_item(state, profile, evidence_id)
    with response_lock(state), Vault(str(pathlib.Path(state) / 'quarantine')) as vault:
        record_name = evidence_id + '.json'
        try:
            record = vault.read(record_name)
            if record.get('schema') != 'ironcurtain-quarantine/v1' or record.get('item') != item: raise ValueError('隔离记录不匹配')
            if record.get('state') == 'quarantined': return record
            if record.get('state') not in ['preparing', 'captured']: raise ValueError('此记录不可重复隔离')
        except FileNotFoundError:
            count, total = vault.usage()
            if count >= MAX_ENTRIES or total + item['size'] > MAX_VAULT_BYTES: raise ValueError('隔离仓容量已满')
            record = {'schema': 'ironcurtain-quarantine/v1', 'state': 'preparing', 'item': item, 'created_at': a.utc()}
            vault.write(record_name, record)
        parent = source = None
        try:
            try: parent, leaf, source = open_source(item)
            except FileNotFoundError:
                if record['state'] != 'captured': raise ValueError('源文件缺失，隔离尚未完成')
                blob = vault.verify_blob(item); os.close(blob)
                record.update(state='quarantined', completed_at=a.utc(), recovered=True)
                vault.write(record_name, record); return record
            if record['state'] == 'preparing':
                try:
                    dest = os.open(evidence_id + '.blob', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=vault.fd)
                except FileExistsError:
                    blob = vault.verify_blob(item); os.close(blob)
                else:
                    try:
                        digest, size = copy_fd(source, dest)
                        if digest != item['sha256'] or size != item['size']: raise ValueError('复制期间内容改变，停止处置')
                    finally: os.close(dest)
                    os.fsync(vault.fd)
                record['state'] = 'captured'; vault.write(record_name, record)
            blob = vault.verify_blob(item); os.close(blob)
            hook('captured')
            if f.identity(os.fstat(source)) != {k: item[k] for k in f.identity(os.fstat(source))} or f.identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) != f.identity(os.fstat(source)):
                raise ValueError('移除前文件身份改变，停止处置')
            if f.hash_fd(source) != item['sha256']: raise ValueError('移除前内容改变，停止处置')
            os.unlink(leaf, dir_fd=parent); os.fsync(parent)
            hook('removed')
            record.update(state='quarantined', completed_at=a.utc()); vault.write(record_name, record)
            return record
        finally:
            if source is not None: os.close(source)
            if parent is not None: os.close(parent)


def restore(state, profile, evidence_id, hook=lambda phase: None):
    evidence_id = identifier(evidence_id)
    with response_lock(state), Vault(str(pathlib.Path(state) / 'quarantine')) as vault:
        record = vault.read(evidence_id + '.json')
        if record.get('schema') != 'ironcurtain-quarantine/v1' or record.get('state') not in ['quarantined', 'restoring'] or record.get('item', {}).get('id') != evidence_id:
            raise ValueError('只可恢复已完成隔离的文件')
        item = record['item']; allowed(item, profile)
        source = vault.verify_blob(item); parent = None; own_temp = False; temp = '.ironcurtain-restore-' + evidence_id
        try:
            parent, leaf = f.parent_fd(item['path'], controlled=True)
            # No overwrite, including symlinks and destinations from interrupted restore.
            try: os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError: pass
            else: raise ValueError('目标已存在，保留现有文件和隔离副本；请人工核查')
            record.update(state='restoring', restore_started_at=a.utc()); vault.write(evidence_id + '.json', record)
            target = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            own_temp = True
            try:
                digest, size = copy_fd(source, target)
                if digest != item['sha256'] or size != item['size']: raise ValueError('隔离副本复制失败')
            finally: os.close(target)
            hook('restore-copied')
            os.link(temp, leaf, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            os.fsync(parent); os.unlink(temp, dir_fd=parent); os.fsync(parent)
            hook('restored')
            record.update(state='restored', restored_at=a.utc(), restored_mode='0600', restored_owner='root')
            vault.write(evidence_id + '.json', record)
            return record
        finally:
            os.close(source)
            if parent is not None:
                # Only the fixed root-private temporary filename, never the destination.
                if own_temp:
                    try: os.unlink(temp, dir_fd=parent); os.fsync(parent)
                    except FileNotFoundError: pass
                os.close(parent)


def inventory(state):
    with response_lock(state), Vault(str(pathlib.Path(state) / 'quarantine')) as vault:
        vault.usage(); items = []
        for name in sorted(os.listdir(vault.fd)):
            if not re.fullmatch(r'[a-f0-9]{64}\.json', name): continue
            record = vault.read(name)
            if record.get('schema') != 'ironcurtain-quarantine/v1' or record.get('item', {}).get('id') != name[:-5]: raise ValueError('隔离记录损坏，保留现场')
            item = record['item']
            items.append({'id': item['id'], 'path': item['path'], 'signature': item['signature'], 'state': record['state'], 'size': item['size']})
        return {'items': items, 'count': len(items), 'note': '隔离文件不等于结束进程；恢复为 root:0600，保留副本，不覆盖目标'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['findings', 'list', 'quarantine', 'restore'])
    parser.add_argument('evidence_id', nargs='?')
    parser.add_argument('--state', default='/var/lib/ironcurtain/local/agent')
    parser.add_argument('--profile', default='/etc/ironcurtain/local/profile.json')
    args = parser.parse_args()
    if os.name != 'posix' or os.geteuid() != 0: raise ValueError('必须在 Linux 本机以 root 运行')
    profile = a.profile_validate(a.private_json(args.profile))
    if args.action == 'findings': result = a.private_json(pathlib.Path(args.state) / 'last-findings.json', 256 * 1024)
    elif args.action == 'list': result = inventory(args.state)
    elif args.action == 'quarantine': result = quarantine(args.state, profile, args.evidence_id)
    else: result = restore(args.state, profile, args.evidence_id)
    print(json.dumps(result, ensure_ascii=False))

if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print('处置未完成：' + str(error), file=sys.stderr); sys.exit(1)
