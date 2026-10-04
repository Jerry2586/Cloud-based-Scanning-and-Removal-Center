#!/usr/bin/env python3
"""Bounded metadata inspection; only a real ClamAV scan can confirm database loading."""
import datetime, json, os, pathlib, shutil, stat, subprocess, time
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
        return {'version': version, 'signatures': signatures, 'timestamp': timestamp}
    finally: os.close(fd)

def database_status(directory=None, clock=None):
    directory = directory or DATABASE_DIR; now = time.time() if clock is None else clock
    try:
        rows = {}
        for database in ['main', 'daily']:
            names = [database + ext for ext in ['.cvd', '.cld'] if os.path.lexists(os.path.join(directory, database + ext))]
            if len(names) != 1: raise ValueError('missing or ambiguous official database')
            rows[database] = _header(directory, names[0])
        daily = rows['daily']; age = now - daily['timestamp']
        if age < -300: raise ValueError('database time is in the future')
        return {'state': 'stale' if age > 7*86400 else 'configured',
                'detail': '病毒库已过期，请更新' if age > 7*86400 else '病毒库元数据已配置，实际加载由扫描确认',
                'database_version': daily['version'], 'signatures': sum(r['signatures'] for r in rows.values()),
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

def engine_status(directory=None):
    installed = shutil.which('clamscan') is not None
    result = database_status(directory)
    if not installed: result = {'state':'unavailable', 'detail':'ClamAV 未安装，请在 Linux 菜单安装病毒引擎'}
    return {'engine':'ClamAV', 'installed': installed, 'updater':updater_status(), **result}

if __name__ == '__main__':
    print(json.dumps(engine_status(), ensure_ascii=False))
