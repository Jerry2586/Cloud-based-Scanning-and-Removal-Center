"""Single-use credentials shared only by explicit disposable official-database CI."""
import json
import os
from pathlib import Path
import stat

DIRECTORY = Path('/run/ironcurtain-ci-acceptance')
NAME = 'local-credentials.json'

def enabled():
    return (os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('IRONCURTAIN_ACCEPT_DISPOSABLE_RUNNER') == '1'
            and os.environ.get('IRONCURTAIN_ACCEPT_OFFICIAL_MAINTENANCE') == '1')

def directory(create=False):
    if not enabled():
        raise RuntimeError('Requires explicit disposable official-maintenance CI')
    if create:
        DIRECTORY.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    meta = os.fstat(fd)
    if meta.st_uid != 0 or meta.st_gid != 0 or stat.S_IMODE(meta.st_mode) != 0o700:
        os.close(fd)
        raise RuntimeError('Unsafe disposable credential directory')
    return fd

def save(username, password):
    fd = directory(create=True)
    try:
        out = os.open(NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(out, 'w') as stream:
            json.dump({'username': username, 'password': password}, stream)
        os.fsync(fd)
    finally:
        os.close(fd)

def consume():
    fd = directory()
    try:
        source = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(source, 'r') as stream:
            meta = os.fstat(stream.fileno())
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_gid != 0
                    or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_nlink != 1 or meta.st_size > 1024):
                raise RuntimeError('Unsafe disposable credential file')
            raw = stream.read(1025)
        os.unlink(NAME, dir_fd=fd)
        os.fsync(fd)
        value = json.loads(raw)
        if (set(value) != {'username', 'password'} or value['username'] != 'admin'
                or not isinstance(value['password'], str) or not 12 <= len(value['password']) <= 256):
            raise RuntimeError('Invalid disposable credentials')
        return value
    finally:
        os.close(fd)
