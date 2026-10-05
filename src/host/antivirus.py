#!/usr/bin/env python3
"""Bounded metadata inspection; only a real ClamAV scan can confirm database loading."""
import datetime, hashlib, json, os, pathlib, re, shutil, stat, subprocess, time
DATABASE_DIR = '/var/lib/ironcurtain-antivirus/database'

def _header(directory, name):
    path = pathlib.PurePosixPath(directory)
    if not path.is_absolute() or '..' in path.parts: raise ValueError('unsafe database directory')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            nxt = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = nxt
            info = os.fstat(fd)
            if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX: raise ValueError('writable database parent')
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(file_fd, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size < 512 or info.st_mode & 0o022: raise ValueError('unsafe database file')
            parts = handle.read(512).decode('ascii').strip().split(':')
        if len(parts) != 9 or parts[0] != 'ClamAV-VDB': raise ValueError('invalid database header')
        version, signatures, timestamp = int(parts[2]), int(parts[3]), int(parts[8])
        if min(version, signatures, timestamp) <= 0: raise ValueError('invalid database metadata')
        return {'version': version, 'signatures': signatures, 'timestamp': timestamp,
                'identity': [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]}
    finally: os.close(fd)

def database_status(directory=None, clock=None):
    directory = directory or DATABASE_DIR; now = time.time() if clock is None else clock
    try:
        rows = {}
        for database in ['main', 'daily']:
            names = [database + ext for ext in ['.cvd', '.cld'] if os.path.lexists(os.path.join(directory, database + ext))]
            if len(names) != 1: raise ValueError('missing or ambiguous official database')
            rows[database] = _header(directory, names[0])
        names = ['bytecode' + ext for ext in ['.cvd','.cld'] if os.path.lexists(os.path.join(directory,'bytecode' + ext))]
        if len(names) > 1: raise ValueError('ambiguous bytecode database')
        if names: rows['bytecode'] = _header(directory,names[0])
        generation = hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        daily = rows['daily']; age = now - daily['timestamp']
        if age < -300: raise ValueError('database time is in the future')
        return {'state': 'stale' if age > 7*86400 else 'configured',
                'detail': '病毒库已过期，请更新' if age > 7*86400 else '病毒库元数据已配置，实际加载由扫描确认',
                'database_generation': generation, 'database_version': daily['version'], 'signatures': sum(r['signatures'] for r in rows.values()),
                'database_at': datetime.datetime.fromtimestamp(daily['timestamp'], datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')}
    except (OSError, ValueError, UnicodeError, OverflowError):
        return {'state': 'unavailable', 'detail': '官方病毒库缺失、格式异常或目录权限不安全'}

def updater_status():
    try:
        def properties(unit, fields):
            result = subprocess.run(['systemctl', 'show', '--property='+fields, unit], stdin=subprocess.DEVNULL, capture_output=True, timeout=2, check=True)
            if len(result.stdout)>4096: raise ValueError('updater response too large')
            return dict(line.split('=',1) for line in result.stdout.decode('ascii').splitlines() if '=' in line)
        timer = properties('ironcurtain-antivirus-update.timer', 'ActiveState,UnitFileState')
        service = properties('ironcurtain-antivirus-update.service', 'Result')
        if service.get('Result') not in [None,'','success']: return 'failed'
        if timer.get('ActiveState')=='active' and timer.get('UnitFileState')=='enabled': return 'scheduled'
        return 'disabled'
    except (OSError, ValueError, subprocess.SubprocessError): return 'unknown'

def database_source(directory=None):
    data=pathlib.PurePosixPath(directory or DATABASE_DIR).parent
    parent_fd=None
    try:
        if not data.is_absolute() or '..' in data.parts:raise ValueError('unsafe source directory')
        parent_fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
        walked=pathlib.PurePosixPath('/')
        for component in data.parts[1:]:
            nxt=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
            os.close(parent_fd);parent_fd=nxt
            info=os.fstat(parent_fd)
            walked=walked/component
            sticky_tmp=str(walked)=='/tmp' and walked!=data and info.st_mode & stat.S_ISVTX
            if info.st_uid!=0 or info.st_mode & 0o022 and not sticky_tmp:raise ValueError('untrusted source parent')
        # Resolve both markers under the verified directory descriptor. A broken
        # symlink or unfinished journal is still a present, untrusted marker.
        try:os.stat('activation.json',dir_fd=parent_fd,follow_symlinks=False)
        except FileNotFoundError:pass
        else:return 'unknown'
        try:fd=os.open('source.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent_fd)
        except FileNotFoundError:
            try:os.stat('source.json',dir_fd=parent_fd,follow_symlinks=False)
            except FileNotFoundError:return 'official-direct'
            return 'unknown'
        with os.fdopen(fd,'rb') as handle:
            info=os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode & 0o022 or not 0<info.st_size<=4096:raise ValueError('invalid source marker')
            value=json.loads(handle.read(4097))
        if not isinstance(value,dict) or set(value)!={'schema','source','snapshot'} or value['schema']!='ironcurtain-virus-db-source/v1' or value['source']!='xuanwu-signed' or not isinstance(value['snapshot'],str) or not re.fullmatch('[a-f0-9]{64}',value['snapshot']):raise ValueError('invalid source marker')
        return 'xuanwu-signed'
    except (OSError,ValueError,TypeError):return 'unknown'
    finally:
        if parent_fd is not None:os.close(parent_fd)

def engine_status(directory=None):
    installed = shutil.which('clamscan') is not None
    result = database_status(directory)
    if not installed: result = {'state':'unavailable', 'detail':'ClamAV 未安装，请在 Linux 菜单安装病毒引擎'}
    source=database_source(directory)
    if source=='unknown':result={'state':'unavailable','detail':'病毒库更新源异常或切换事务待恢复，请检查 Linux 菜单'}
    return {'engine':'ClamAV', 'installed': installed, 'updater':updater_status(), 'source':source, **result}

if __name__ == '__main__':
    print(json.dumps(engine_status(), ensure_ascii=False))
