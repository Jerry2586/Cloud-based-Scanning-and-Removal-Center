"""One fixed local package-maintenance job; no client-controlled commands or sources."""
import datetime, importlib.util, json, os, pathlib, re, signal, stat, subprocess, threading, time, uuid
SCHEMA = 'ironcurtain-engine-maintenance/v1'
UNIT = 'ironcurtain-engine-install.service'
BASE = pathlib.Path('/opt/ironcurtain/local')
DATA = pathlib.Path('/var/lib/ironcurtain/local/engine-maintenance')
DETAILS = {
 'idle': '尚未运行文件引擎维护', 'queued': '文件引擎维护已排队',
 'installing': '正在从系统受信任软件源安装或修复文件引擎',
 'finished': '文件引擎维护完成；请重新核验依赖并运行文件扫描',
 'busy': '检测或其他管理任务正在运行；维护未执行，请稍后重试',
 'failed': '文件引擎维护失败；请检查系统软件源、网络和病毒库状态后重试',
 'interrupted': '维护任务已中断；请重新核验引擎并重试',
 'unavailable': '文件引擎维护服务无法核验',
 'cooldown': '请求过于频繁，请稍后重试'
}
ACTIVE = ('active', 'activating', 'reloading', 'deactivating')
def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
def valid_time(value):
    try:
        return isinstance(value, str) and bool(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z', value)) and datetime.datetime.fromisoformat(value.replace('Z', '+00:00')) <= datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=5)
    except ValueError: return False

def record(state, code, **fields): return dict(schema=SCHEMA, state=state, code=code, reason=DETAILS[code], **fields)
def clean(value):
    if not isinstance(value, dict) or value.get('schema') != SCHEMA: raise ValueError('invalid job')
    allowed = {'queued': ('queued',), 'running': ('installing',), 'finished': ('finished',), 'failed': ('failed', 'busy', 'interrupted')}
    if value.get('code') not in allowed.get(value.get('state'), ()) or not re.fullmatch(r'[a-f0-9]{32}', value.get('id', '')): raise ValueError('invalid state')
    if not valid_time(value.get('requested_at')): raise ValueError('invalid request time')
    result = record(value['state'], value['code'], id=value['id'], requested_at=value['requested_at'])
    for key in ('started_at', 'finished_at'):
        if key in value:
            if not valid_time(value[key]) or datetime.datetime.fromisoformat(value[key].replace('Z', '+00:00')) < datetime.datetime.fromisoformat(value['requested_at'].replace('Z', '+00:00')): raise ValueError('invalid job time')
            result[key] = value[key]
    if 'started_at' in result and 'finished_at' in result and datetime.datetime.fromisoformat(result['finished_at'].replace('Z', '+00:00')) < datetime.datetime.fromisoformat(result['started_at'].replace('Z', '+00:00')): raise ValueError('finish precedes start')
    if value['state'] == 'running' and 'started_at' not in result: raise ValueError('missing start')
    if value['state'] in ('finished', 'failed') and 'finished_at' not in result: raise ValueError('missing finish')
    return result

class Bridge:
    def __init__(self, read, atomic, *, run=subprocess.run, base=BASE, data=DATA, dispatch_lock=None, busy=lambda:True, clock=time.monotonic):
        self.read, self.atomic, self.run, self.base, self.data = read, atomic, run, base, data
        self.dispatch_lock = dispatch_lock if dispatch_lock is not None else threading.Lock()
        self.lock = threading.Lock(); self.busy = busy; self.clock = clock; self.last = None
    def unit(self):
        # Both the installed definition and effective systemd command must match.
        definition = self.read(pathlib.Path('/etc/systemd/system') / UNIT, 8192).decode('utf8')
        expected = '/usr/bin/python3 -B ' + str(self.base / 'current/src/host/engine_maintenance.py')
        if definition.count('ExecStart=') != 1 or ('ExecStart=' + expected + '\n') not in definition: raise ValueError('unexpected definition')
        result = self.run(['/usr/bin/systemctl', 'show', '--property=LoadState,FragmentPath,DropInPaths,User,Type,ExecStart,ActiveState,Result,KillMode,TimeoutStartUSec,TimeoutStopUSec', UNIT], timeout=2, capture_output=True, text=True)
        if result.returncode or len(result.stdout) > 8192: raise ValueError('service unavailable')
        properties = dict(row.split('=', 1) for row in result.stdout.splitlines() if '=' in row)
        command = properties.get('ExecStart', '')
        if properties.get('LoadState') != 'loaded' or properties.get('FragmentPath') != '/etc/systemd/system/' + UNIT or properties.get('DropInPaths') or properties.get('User') != 'root' or properties.get('Type') != 'oneshot' or not re.fullmatch(r'\{ path=/usr/bin/python3 ; argv\[\]=' + re.escape(expected) + r' ; ignore_errors=no ; [^{}]*\}', command): raise ValueError('unexpected service')
        if properties.get('KillMode') != 'control-group' or properties.get('TimeoutStartUSec') != '12min' or properties.get('TimeoutStopUSec') != '15s': raise ValueError('unexpected limits')
        if properties.get('ActiveState') not in (*ACTIVE, 'inactive', 'failed'): raise ValueError('unknown service state')
        return properties
    def _status(self):
        try:
            properties = self.unit()
            try: value = clean(json.loads(self.read(self.data / 'job.json', 4096)))
            except FileNotFoundError:
                return record('unavailable', 'unavailable') if properties['ActiveState'] in ACTIVE else record('idle', 'idle')
            if value['state'] in ('queued', 'running'):
                settling = value['state'] == 'queued' and (datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(value['requested_at'].replace('Z', '+00:00'))).total_seconds() < 5
                if properties['ActiveState'] not in ACTIVE and not settling:
                    value = record('failed', 'interrupted', id=value['id'], requested_at=value['requested_at'], finished_at=stamp())
            elif properties['ActiveState'] in ACTIVE:
                return record('unavailable', 'unavailable')
            return value
        except (OSError, ValueError, TypeError, UnicodeError, subprocess.SubprocessError): return record('unavailable', 'unavailable')
    def status(self):
        with self.lock: return self._status()
    def busy_status(self):
        # Older installations without this fixed unit retain read-only/scan use.
        try: self.read(pathlib.Path('/etc/systemd/system') / UNIT, 8192)
        except FileNotFoundError:
            try: self.read(self.data / 'job.json', 4096)
            except FileNotFoundError: return False
            except (OSError, ValueError): return True
            return True
        except (OSError, ValueError): return True
        return self.status()['state'] not in ('idle', 'finished', 'failed')
    def trigger(self):
        with self.dispatch_lock, self.lock:
            if self.last is not None and self.clock() - self.last < 10: return 429, record('unavailable', 'cooldown')
            value = self._status()
            if value['state'] in ('queued', 'running'): return 409, value
            if value['state'] == 'unavailable': return 503, value
            if self.busy(): return 409, record('unavailable', 'busy')
            job = record('queued', 'queued', id=uuid.uuid4().hex, requested_at=stamp())
            try:
                self.atomic(self.data / 'job.json', job)
                result = self.run(['/usr/bin/systemctl', 'start', '--no-block', UNIT], timeout=2, capture_output=True, text=True)
                if result.returncode: raise ValueError('start failed')
            except (OSError, ValueError, subprocess.SubprocessError):
                failed = record('failed', 'failed', id=job['id'], requested_at=job['requested_at'], finished_at=stamp())
                try: self.atomic(self.data / 'job.json', failed)
                except (OSError, ValueError): pass
                return 503, record('unavailable', 'unavailable')
            self.last = self.clock()
            return 202, job

def run_install(args, **kwargs):
    """Keep the management lease until timed-out package descendants are killed."""
    timeout = kwargs.pop('timeout')
    child = subprocess.Popen(args, start_new_session=True, **kwargs)
    try:
        return subprocess.CompletedProcess(args, child.wait(timeout=timeout))
    except subprocess.TimeoutExpired:
        try: os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        child.wait(timeout=5)
        raise

def work(host=None, *, run=run_install, data=DATA, base=BASE):
    if os.geteuid() != 0: raise ValueError('root required')
    if host is None:
        spec = importlib.util.spec_from_file_location('maintenance_host', pathlib.Path(__file__).with_name('agent.py'))
        host = importlib.util.module_from_spec(spec); spec.loader.exec_module(host)
    target = data / 'job.json'
    job = clean(json.loads(host.private_bytes(target, 4096)))
    if job['state'] != 'queued': raise ValueError('no queued job')
    locked = None
    try:
        import fcntl
        locked = host.secure_fd('/run/lock/ironcurtain-local.lock', root_controlled=True, flags=os.O_RDWR | os.O_CREAT)
        info = os.fstat(locked)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077: raise ValueError('lock invalid')
        try: fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            host.atomic_json(target, record('failed', 'busy', id=job['id'], requested_at=job['requested_at'], finished_at=stamp())); return 1
        # Do not replace a signed-source database or install while its updater writes.
        if host.antivirus.update_status() in ('running', 'unavailable') and (pathlib.Path('/etc/systemd/system/ironcurtain-antivirus-update.service').exists()): raise ValueError('updater busy')
        _, current = host.updates.receipt(host.private_bytes, base)
        state = record('running', 'installing', id=job['id'], requested_at=job['requested_at'], started_at=stamp())
        host.atomic_json(target, state)
        fd = host.secure_fd(data / 'install.log', root_controlled=True, flags=os.O_WRONLY | os.O_CREAT)
        with os.fdopen(fd, 'wb') as log:
            info = os.fstat(log.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077: raise ValueError('log invalid')
            os.ftruncate(log.fileno(), 0)
            result = run(['/bin/bash', str(current / 'scripts/antivirus-engine.sh'), 'install'], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, cwd='/', env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8','TERM':'dumb'}, timeout=660)
        if result.returncode: raise ValueError('install failed')
        installed = host.antivirus.engine_status()
        if installed.get('installed') is not True or installed.get('state') not in ('configured', 'stale'): raise ValueError('engine unavailable')
        host.atomic_json(target, record('finished', 'finished', id=job['id'], requested_at=job['requested_at'], started_at=state['started_at'], finished_at=stamp()))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        host.atomic_json(target, record('failed', 'failed', id=job['id'], requested_at=job['requested_at'], finished_at=stamp()))
        return 1
    finally:
        if locked is not None: os.close(locked)

if __name__ == '__main__':
    import sys
    sys.dont_write_bytecode = True
    raise SystemExit(work())
