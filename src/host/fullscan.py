#!/usr/bin/env python3
"""Disk-backed, resumable malware scan of administrator-enrolled directories.
Each file is pinned by openat and hashed; bounded batches reuse one engine load.
"""
import datetime, hashlib, json, os, pathlib, re, sqlite3, stat, time, uuid, copy
MAX_FILES = 200000
BATCH_FILES = 128
BATCH_BYTES = 64 * 1024 * 1024

class ScanInterrupted(Exception): pass
MAX_SIZE = 64 * 1024 * 1024
EXCLUDED = ('/proc', '/sys', '/dev', '/run', '/etc/ironcurtain', '/var/lib/ironcurtain', '/var/lib/ironcurtain-antivirus', '/opt/ironcurtain')

def utc(): return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
def identity(info): return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
def fingerprint(profile, engine):
    return hashlib.sha256(json.dumps({'profile': profile, 'database': {k: engine.get(k) for k in ('database_version', 'database_at', 'signatures', 'database_generation')}}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
def excluded(path): return any(path == x or path.startswith(x + '/') for x in EXCLUDED)

def profile_digest(profile):
    return hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def valid_finding(item):
    if not isinstance(item, dict): return False
    required = {'id','path','signature','sha256','observed_at','device','inode','size','mtime_ns','ctime_ns','mode','uid','gid','links'}
    if set(item) != required: return False
    if not isinstance(item['path'], str) or not item['path'].startswith('/') or len(item['path']) > 1024 or re.search(r'[\x00-\x1f\x7f]', item['path']): return False
    if '..' in pathlib.PurePosixPath(item['path']).parts: return False
    if not isinstance(item['signature'], str) or not re.fullmatch(r'[A-Za-z0-9_.:/()!+\-]{1,160}',item['signature']): return False
    if not isinstance(item['sha256'], str) or not re.fullmatch(r'[a-f0-9]{64}', item['sha256']): return False
    if any(type(item[k]) is not int or item[k] < 0 for k in ('device','inode','size','mtime_ns','ctime_ns','mode','uid','gid','links')): return False
    if item['size'] > MAX_SIZE or item['links'] < 1 or item['mode'] > 0o7777: return False
    if not valid_stamp(item['observed_at']): return False
    value = {k:v for k,v in item.items() if k != 'id'}
    return item['id'] == hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def valid_stamp(stamp):
    try:
        if not isinstance(stamp,str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z',stamp): return False
        datetime.datetime.fromisoformat(stamp.replace('Z','+00:00')); return True
    except ValueError: return False

def valid_report(value):
    if not isinstance(value, dict) or value.get('schema') != 'ironcurtain-full-scan/v1' or value.get('state') not in ('indexing','scanning','paused','finished','partial','failed'): return False
    keys=('indexed','processed','clean','infected','skipped','errors','bytes_scanned')
    if any(type(value.get(k)) is not int or value[k]<0 for k in keys): return False
    if value['indexed'] > MAX_FILES or value['processed']>value['indexed'] or value['clean']+value['infected']+value['errors']>value['processed'] or value['clean']+value['infected']+value['errors']+value['skipped']<value['processed']: return False
    if not isinstance(value.get('profile_digest'),str) or not re.fullmatch(r'[a-f0-9]{64}',value['profile_digest']): return False
    if value['state'] == 'finished' and (not value.get('index_complete') or not value['indexed'] or value['processed'] != value['indexed'] or value['errors'] or value['skipped']): return False
    if value.get('scope') != 'enrolled-directories-only' or type(value.get('index_complete')) is not bool: return False
    if not isinstance(value.get('findings'),list) or len(value['findings'])>32 or len(value['findings']) > value['infected'] or not all(valid_finding(x) for x in value['findings']): return False
    if not isinstance(value.get('reasons'),list) or len(value['reasons'])>16 or not all(isinstance(x,str) and len(x)<=180 for x in value['reasons']): return False
    for key in ('started_at','updated_at', *(('finished_at',) if value['state'] in ('finished','partial','failed') else ())):
        try:
            stamp=value[key]
            if not isinstance(stamp,str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z',stamp): return False
            datetime.datetime.fromisoformat(stamp.replace('Z','+00:00'))
        except (KeyError,ValueError,TypeError): return False
    return valid_progress(value)

def valid_progress(value):
    if 'task_id' in value and (not isinstance(value['task_id'], str) or not re.fullmatch(r'[a-f0-9]{32}', value['task_id'])): return False
    if 'resumed_from' in value and (not isinstance(value['resumed_from'], str) or not re.fullmatch(r'[a-f0-9]{32}', value['resumed_from'])): return False
    def valid_file(item, recent=False):
        if not isinstance(item, dict): return False
        path = item.get('path')
        if not isinstance(path, str) or not path.startswith('/') or len(path)>1024 or '..' in pathlib.PurePosixPath(path).parts or re.search(r'[\x00-\x1f\x7f]',path): return False
        if type(item.get('size')) is not int or not 0<=item['size']<=9007199254740991: return False
        if recent: return item.get('state') in ('clean','infected','skipped','errors') and valid_stamp(item.get('checked_at')) and (item.get('reason') is None or isinstance(item['reason'],str) and len(item['reason'])<=180 and not re.search(r'[\x00-\x1f\x7f]',item['reason']))
        return item.get('phase') in ('opening','hashing','engine') and type(item.get('bytes_read')) is int and 0<=item['bytes_read']<=item['size']
    if value.get('current_file') is not None and not valid_file(value['current_file']): return False
    recent = value.get('recent_files',[])
    return isinstance(recent,list) and len(recent)<=8 and all(valid_file(item,True) for item in recent)

class FullScan:
    def __init__(self, profile, state_dir, run, secure_fd, engine, database_dir, publish, stop=None, maximum=MAX_FILES, database_status=None, task_id=None, started_at=None, batch_size=BATCH_FILES):
        self.profile = profile; self.directory = pathlib.Path(state_dir); self.run_command = run; self.open_file = secure_fd
        self.engine = engine; self.database_dir = database_dir; self.publish = publish; self.stop = stop; self.maximum = min(MAX_FILES, maximum)
        self.database_status = database_status
        self.batch_size = max(1, min(BATCH_FILES, batch_size))
        self.db = None; self.report = {'schema': 'ironcurtain-full-scan/v1', 'state': 'indexing', 'started_at': started_at or utc(), 'task_id': task_id or uuid.uuid4().hex, 'current_file': None, 'recent_files': [],
            'indexed': 0, 'processed': 0, 'clean': 0, 'infected': 0, 'skipped': 0, 'errors': 0,
            'profile_digest': profile_digest(profile), 'bytes_scanned': 0, 'index_complete': True, 'reasons': [], 'findings': [], 'scope': 'enrolled-directories-only'}
    def reason(self, text):
        if text not in self.report['reasons'] and len(self.report['reasons']) < 16: self.report['reasons'].append(text)
    def emit(self):
        self.report['updated_at'] = utc(); self.publish(copy.deepcopy(self.report))
    def connect(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        for current in [self.directory, *self.directory.parents]:
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode): raise ValueError('unsafe state directory')
            if os.name == 'posix' and (info.st_uid != 0 or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
                raise ValueError('state must be root controlled')
        if os.name == 'posix' and self.directory.stat().st_mode & 0o077: raise ValueError('state directory must be private')
        file = self.directory / 'full-scan.sqlite'
        for suffix in ('-wal','-shm'):
            entry = pathlib.Path(str(file) + suffix)
            if entry.exists() or entry.is_symlink(): raise ValueError('unexpected SQLite WAL/SHM state')
        for entry in (file, pathlib.Path(str(file) + '-journal')):
            if entry.exists() or entry.is_symlink():
                info = entry.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or (os.name == 'posix' and (info.st_uid != 0 or info.st_mode & 0o077)): raise ValueError('unsafe queue file')
        self.db = sqlite3.connect(file)
        if os.name == 'posix': os.chmod(file, 0o600)
        self.db.execute('PRAGMA journal_mode=DELETE'); self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, identity TEXT NOT NULL, state TEXT NOT NULL, size INTEGER NOT NULL)')
    def save(self):
        self.report['updated_at'] = utc()
        self.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', ('report', json.dumps(self.report, ensure_ascii=False)))
        self.db.commit(); self.publish(copy.deepcopy(self.report))
    def index(self, roots):
        deadline = time.monotonic() + 120; seen = set(); aborted = False; emitted = time.monotonic()
        self.emit()
        def failure(error):
            self.report['index_complete'] = False; self.reason('目录不可读，文件清单不完整')
        for root in roots:
            try:
                p = pathlib.Path(root)
                if str(p.resolve(strict=True)) != root or not p.is_dir() or excluded(root): raise ValueError()
                root_device = p.stat().st_dev
            except (OSError, ValueError):
                self.report['index_complete'] = False; self.reason('扫描根目录不可读、包含链接或被排除'); continue
            for directory, dirs, names in os.walk(root, followlinks=False, onerror=failure):
                if time.monotonic() > deadline or self.report['indexed'] >= self.maximum or (self.stop and self.stop.is_set()):
                    self.report['index_complete'] = False; self.reason('建立清单达到时间/数量上限或服务停止'); aborted = True; break
                for name in dirs[:]:
                    child = os.path.join(directory, name)
                    try:
                        info = os.lstat(child)
                        if stat.S_ISLNK(info.st_mode) or info.st_dev != root_device or excluded(child):
                            dirs.remove(name); self.report['skipped'] += 1; self.reason('链接目录、跨文件系统或安全状态目录已跳过')
                    except OSError:
                        dirs.remove(name); failure(None)
                for name in names:
                    if time.monotonic() > deadline or self.report['indexed'] >= self.maximum or (self.stop and self.stop.is_set()):
                        self.report['index_complete'] = False; self.reason('建立清单达到时间/数量上限'); aborted = True; break
                    file = os.path.join(directory, name)
                    try:
                        if len(file) > 1024 or re.search(r'[\x00-\x1f\x7f]', file) or excluded(file): raise ValueError()
                        info = os.lstat(file)
                        if not stat.S_ISREG(info.st_mode) or info.st_dev != root_device: raise ValueError()
                        key = (info.st_dev, info.st_ino)
                        if key in seen: continue
                        seen.add(key)
                        self.db.execute('INSERT OR IGNORE INTO files VALUES (?,?,?,?)', (file, json.dumps(identity(info)), 'pending', info.st_size))
                        self.report['indexed'] += 1
                        if time.monotonic()-emitted>=1:
                            self.save(); emitted=time.monotonic()
                    except (OSError, ValueError):
                        self.report['skipped'] += 1; self.reason('特殊文件、链接或不可读取的文件已跳过')
                if aborted: break
                if self.report['indexed'] % 100 == 0: self.save()
            if aborted: break
        self.report['state'] = 'scanning'; self.save()
    def scan_file(self, path, planned):
        fd = self.open_file(path)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or identity(before) != json.loads(planned): raise ValueError('文件在建立清单后发生变化')
            if before.st_size > MAX_SIZE: return 'skipped', '超过单文件 64 MiB 扫描上限', None
            self.report['current_file']={'path':path,'size':before.st_size,'bytes_read':0,'phase':'hashing'}; self.emit()
            digest = hashlib.sha256(); total = 0; emitted = time.monotonic()
            for block in iter(lambda: stream.read(65536), b''):
                total += len(block)
                if total > MAX_SIZE or total > before.st_size: raise ValueError('文件在扫描中增长超过清单大小')
                digest.update(block)
                self.report['current_file']['bytes_read'] = total
                if time.monotonic()-emitted>=1:
                    self.emit(); emitted=time.monotonic()
            if identity(os.fstat(stream.fileno())) != identity(before): raise ValueError('文件在摘要读取中发生变化')
            stream.seek(0)
            self.report['current_file'].update(phase='engine'); self.emit()
            args = ['clamscan', '--database=' + self.database_dir, '--official-db-only=yes', '--infected',
                    '--max-filesize=64M', '--max-scansize=256M', '--max-files=10000', '--alert-exceeds-max=yes',
                    '--fail-if-cvd-older-than=7', '--', '-']
            code, text = self.run_command(args, seconds=60, maximum=65536, input_fd=stream.fileno())
            if identity(os.fstat(stream.fileno())) != identity(before): raise ValueError('文件在病毒扫描中发生变化')
            # Check the pathname still names the pinned inode. A rename/replacement is not a clean scan.
            replacement = self.open_file(path)
            try:
                if identity(os.fstat(replacement)) != identity(before): raise ValueError('扫描期间文件路径已替换')
            finally: os.close(replacement)
            if 'Heuristics.Limits.Exceeded' in text: return 'skipped', '引擎解包/文件扫描达到上限', None
            count = re.search(r'Scanned files:\s*(\d+)', text); infected = re.search(r'Infected files:\s*(\d+)', text)
            if code not in (0, 1) or not count or not infected or re.search(r'Errors:\s*[1-9]', text): raise ValueError('病毒引擎失败、超时或统计缺失')
            n = int(infected[1])
            if (code == 1) != (n > 0): raise ValueError('引擎返回与命中统计不一致')
            if int(count[1]) == 0: return 'skipped', '引擎没有实际检查此文件', None
            if not n: return 'clean', None, None
            signatures = re.findall(r'^stdin: ([A-Za-z0-9_.:/()!+\-]{1,160}) FOUND$', text, re.M)
            if not signatures: raise ValueError('命中缺少可核验特征名')
            item = {'path': path, 'signature': signatures[0], 'sha256': digest.hexdigest(), 'size': before.st_size,
                    'observed_at': utc(), **dict(zip(('device', 'inode', 'size', 'mtime_ns', 'ctime_ns'), identity(before)))}
            # Compatible pinned evidence fields used by the separate, root-only response service.
            item.update(mode=stat.S_IMODE(before.st_mode), uid=before.st_uid, gid=before.st_gid, links=before.st_nlink)
            if before.st_uid != 0 or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o022:
                self.reason('部分命中文件不符合隔离权限/单链接要求；保留告警，由管理员人工处置')
            item['id'] = hashlib.sha256(json.dumps(item, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
            return 'infected', None, item
    def scan_batch(self, rows):
        """Only inherited descriptors reach the engine; no business path is reopened by it."""
        entries = {}; outcomes = {}
        def interrupted():
            if self.stop and self.stop.is_set(): raise ScanInterrupted()
        def failed(): return ('errors', '文件读取失败、变化或引擎未完成', None)
        try:
            for path, planned in rows:
                interrupted(); fd = None
                self.report['current_file'] = {'path': path, 'size': json.loads(planned)[2], 'bytes_read': 0, 'phase': 'opening'}; self.emit()
                try:
                    fd = self.open_file(path); before = os.fstat(fd)
                    if not stat.S_ISREG(before.st_mode) or identity(before) != json.loads(planned): raise ValueError('file identity changed')
                    if before.st_size > MAX_SIZE:
                        outcomes[path] = ('skipped', '超过单文件 64 MiB 扫描上限', None); continue
                    self.report['current_file'].update(phase='hashing'); self.emit()
                    digest = hashlib.sha256(); total = 0; emitted = time.monotonic()
                    while True:
                        interrupted(); block = os.read(fd, 65536)
                        if not block: break
                        total += len(block)
                        if total > MAX_SIZE or total > before.st_size: raise ValueError('file grew')
                        digest.update(block); self.report['current_file']['bytes_read'] = total
                        if time.monotonic() - emitted >= 1: self.emit(); emitted = time.monotonic()
                    if total != before.st_size or identity(os.fstat(fd)) != identity(before): raise ValueError('file changed during hash')
                    if not total:
                        outcomes[path] = ('skipped', '引擎没有实际检查空文件', None); continue
                    os.lseek(fd, 0, os.SEEK_SET)
                    entries[fd] = (path, before, digest.hexdigest()); fd = None
                except (OSError, ValueError): outcomes[path] = failed()
                finally:
                    if fd is not None: os.close(fd)
            if not entries: return [(path, outcomes[path]) for path, _ in rows]
            descriptors = list(entries)
            def current(fd):
                path, before, _ = entries[fd]
                self.report['current_file'] = {'path': path, 'size': before.st_size, 'bytes_read': before.st_size, 'phase': 'engine'}; self.emit()
            current(descriptors[0])
            # Live engine output only identifies the current target. Counts are committed
            # after terminal statistics, file identity and database generation are verified.
            def line(value):
                match = re.fullmatch(r'/proc/self/fd/(\d+): (?:OK|[A-Za-z0-9_.:/()!+\-]{1,160} FOUND)', value)
                if match and int(match[1]) in entries:
                    index = descriptors.index(int(match[1]))
                    if index + 1 < len(descriptors): current(descriptors[index + 1])
            args = ['clamscan', '--database=' + self.database_dir, '--official-db-only=yes', '--follow-file-symlinks=2',
                    '--max-filesize=64M', '--max-scansize=256M', '--max-files=10000', '--alert-exceeds-max=yes',
                    '--fail-if-cvd-older-than=7', '--', *('/proc/self/fd/' + str(fd) for fd in descriptors)]
            code, text = self.run_command(args, seconds=180, maximum=65536, pass_fds=descriptors, stop=self.stop, on_line=line)
            interrupted()
            results = {}; matches = re.findall(r'^/proc/self/fd/(\d+): (.+)$', text, re.M)
            for number, result in matches:
                fd = int(number)
                if fd not in entries or fd in results: raise ValueError('unexpected or duplicate descriptor result')
                if result != 'OK' and not re.fullmatch(r'[A-Za-z0-9_.:/()!+\-]{1,160} FOUND', result): raise ValueError('invalid engine result')
                results[fd] = result
            count = re.findall(r'^Scanned files:\s*(\d+)\s*$', text, re.M)
            infected = re.findall(r'^Infected files:\s*(\d+)\s*$', text, re.M)
            hits = sum(value.endswith(' FOUND') for value in results.values())
            if code not in (0, 1) or set(results) != set(entries) or len(count) != 1 or len(infected) != 1 or int(count[0]) != len(entries) or int(infected[0]) != hits or (code == 1) != (hits > 0) or re.search(r'Errors:\s*[1-9]', text): raise ValueError('engine statistics mismatch')
            for fd, (path, before, digest) in entries.items():
                try:
                    if identity(os.fstat(fd)) != identity(before): raise ValueError('pinned file changed')
                    replacement = self.open_file(path)
                    try:
                        if identity(os.fstat(replacement)) != identity(before): raise ValueError('pathname replaced')
                    finally: os.close(replacement)
                    result = results[fd]
                    if result == 'OK': outcomes[path] = ('clean', None, None); continue
                    signature = result[:-6]
                    if signature.startswith('Heuristics.Limits.Exceeded'):
                        outcomes[path] = ('skipped', '引擎解包/文件扫描达到上限', None); continue
                    item = {'path': path, 'signature': signature, 'sha256': digest, 'size': before.st_size, 'observed_at': utc(), **dict(zip(('device','inode','size','mtime_ns','ctime_ns'), identity(before)))}
                    item.update(mode=stat.S_IMODE(before.st_mode), uid=before.st_uid, gid=before.st_gid, links=before.st_nlink)
                    if before.st_uid != 0 or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o022: self.reason('部分命中文件不符合隔离权限/单链接要求；保留告警，由管理员人工处置')
                    item['id'] = hashlib.sha256(json.dumps(item, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
                    outcomes[path] = ('infected', None, item)
                except (OSError, ValueError): outcomes[path] = failed()
        except (OSError, ValueError):
            for path, _, _ in entries.values(): outcomes[path] = failed()
        finally:
            for fd in entries: os.close(fd)
        return [(path, outcomes[path]) for path, _ in rows]

    def validate_resume(self, report):
        keys = ('indexed', 'processed', 'clean', 'infected', 'skipped', 'errors', 'bytes_scanned')
        if not valid_report(report) or report['profile_digest'] != profile_digest(self.profile) or any(type(report.get(k)) is not int or report[k] < 0 for k in keys): raise ValueError('invalid queue counters')
        if type(report.get('index_complete')) is not bool or not isinstance(report.get('reasons'), list) or len(report['reasons']) > 16 or not all(isinstance(x, str) for x in report['reasons']): raise ValueError('invalid queue report')
        if not isinstance(report.get('findings'), list) or len(report['findings']) > 32 or len(report['findings']) > report['infected']: raise ValueError('invalid queue findings')
        counts = dict(self.db.execute('SELECT state,COUNT(*) FROM files GROUP BY state'))
        if any(k not in ('pending', 'clean', 'infected', 'skipped', 'errors') for k in counts): raise ValueError('invalid queue state')
        if sum(counts.values()) != report['indexed'] or sum(v for k, v in counts.items() if k != 'pending') != report['processed']: raise ValueError('inconsistent queue progress')
        if any(counts.get(k, 0) != report[k] for k in ('clean', 'infected', 'errors')) or counts.get('skipped', 0) > report['skipped']: raise ValueError('inconsistent queue outcomes')
        scanned = self.db.execute("SELECT COALESCE(SUM(size),0) FROM files WHERE state IN ('clean','infected')").fetchone()[0]
        if scanned != report['bytes_scanned']: raise ValueError('inconsistent byte progress')
        for item in report['findings']:
            value = {k: v for k, v in item.items() if k != 'id'}
            if item.get('id') != hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest(): raise ValueError('invalid saved evidence')
    def database_unchanged(self, token):
        value = self.database_status()
        return value.get('state') == 'configured' and fingerprint(self.profile, value) == token
    def run(self):
        try:
            roots = sorted(set(self.profile.get('program_roots', []) + self.profile.get('business_roots', [])))
            if not roots: raise ValueError('请先通过 Linux 菜单纳管扫描目录')
            if not self.engine.get('installed') or self.engine.get('state') != 'configured': raise ValueError('病毒引擎/官方病毒库尚未就绪')
            self.connect(); token = fingerprint(self.profile, self.engine)
            old = self.db.execute('SELECT value FROM meta WHERE key=?', ('fingerprint',)).fetchone()
            saved = self.db.execute('SELECT value FROM meta WHERE key=?', ('report',)).fetchone()
            prior = json.loads(saved[0]) if saved else None
            if old and old[0] == token and prior and prior.get('state') in ('scanning', 'paused'):
                self.validate_resume(prior)
                task_id=self.report['task_id']; started=self.report['started_at']
                previous_id=prior.get('task_id')
                self.report=prior; self.report.update(state='scanning',task_id=task_id,started_at=started,current_file=None,recent_files=[])
                if previous_id and previous_id!=task_id: self.report['resumed_from']=previous_id
                self.reason('从已保存文件队列继续扫描；已处理计数包含前次结果'); self.save()
            else:
                self.db.execute('DELETE FROM files'); self.db.execute('DELETE FROM meta')
                self.db.execute('INSERT INTO meta VALUES (?,?)', ('fingerprint', token)); self.db.commit()
                self.index(roots)
            while True:
                if self.stop and self.stop.is_set(): self.report['state'] = 'paused'; self.save(); return self.report
                pending = self.db.execute("SELECT path,identity FROM files WHERE state='pending' ORDER BY path LIMIT ?", (self.batch_size,)).fetchall()
                if not pending: break
                rows = []; size = 0
                for row in pending:
                    planned_size = json.loads(row[1])[2]
                    if rows and size + planned_size > BATCH_BYTES: break
                    rows.append(row); size += min(planned_size, MAX_SIZE)
                if self.database_status and not self.database_unchanged(token):
                    self.report['current_file']=None; self.report['state']='partial'; self.report['finished_at']=utc(); self.reason('病毒库在扫描期间改变，请重新开始本次文件查杀'); self.save(); return self.report
                if self.batch_size == 1:
                    file, planned = rows[0]
                    self.report['current_file']={'path':file,'size':json.loads(planned)[2],'bytes_read':0,'phase':'opening'}; self.emit()
                    try: result = self.scan_file(file, planned)
                    except (OSError, ValueError): result = ('errors', '文件读取失败、变化或引擎未完成', None)
                    outcomes = [(file, result)]
                else: outcomes = self.scan_batch(rows)
                planned_sizes = {file:json.loads(planned)[2] for file, planned in rows}
                for file, (state, reason, finding) in outcomes:
                    if self.stop and self.stop.is_set() and self.batch_size > 1: raise ScanInterrupted()
                    if self.database_status and not self.database_unchanged(token):
                        self.report['current_file']=None; self.report['state']='partial'; self.report['finished_at']=utc(); self.reason('病毒库在扫描期间改变，请重新开始本次文件查杀'); self.save(); return self.report
                    # Batch validation may precede earlier per-file commits. Recheck
                    # the enrolled pathname immediately before committing a verdict.
                    if self.batch_size > 1 and state in ('clean', 'infected'):
                        verify_fd = None
                        try:
                            verify_fd = self.open_file(file)
                            if identity(os.fstat(verify_fd)) != json.loads(dict(rows)[file]): raise ValueError('file changed before commit')
                        except (OSError, ValueError): state, reason, finding = ('errors', '文件在结果提交前发生变化', None)
                        finally:
                            if verify_fd is not None: os.close(verify_fd)
                    self.report['current_file']=None
                    self.report['recent_files']=(self.report.get('recent_files',[])+[{'path':file,'size':planned_sizes[file],'state':state,'reason':reason,'checked_at':utc()}])[-8:]
                    self.report['processed'] += 1; self.report[state] += 1
                    if state in ('clean', 'infected'): self.report['bytes_scanned'] += planned_sizes[file]
                    if reason: self.reason(reason)
                    if finding and len(self.report['findings']) < 32: self.report['findings'].append(finding)
                    self.db.execute('UPDATE files SET state=? WHERE path=?', (state, file)); self.save()
            if self.database_status and not self.database_unchanged(token):
                self.report['current_file']=None; self.report['state'] = 'partial'; self.report['finished_at'] = utc(); self.reason('汇总前病毒库改变，请重新扫描'); self.save(); return self.report
            complete = self.report['index_complete'] and self.report['skipped'] == 0 and self.report['errors'] == 0 and self.report['indexed'] > 0
            self.report['current_file']=None
            self.report['state'] = 'finished' if complete else 'partial'; self.report['finished_at'] = utc()
            if not self.report['indexed']: self.reason('范围中没有可检查的文件')
            self.save(); return self.report
        except ScanInterrupted:
            self.report['current_file']=None; self.report['state']='paused'; self.save(); return self.report
        except Exception:
            self.report['current_file']=None; self.report['state'] = 'failed'; self.report['finished_at'] = utc(); self.reason('范围/引擎未就绪或受保护扫描队列不可用'); self.emit(); return self.report
        finally:
            if self.db: self.db.close()
