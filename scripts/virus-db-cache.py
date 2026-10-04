#!/usr/bin/env python3
"""Root-only vendor-signed CVD snapshots; no node commands or executable updates."""
import contextlib, fcntl, hashlib, json, os, pathlib, re, shutil, stat, subprocess, sys, tempfile, time
FAMILIES = ('main', 'daily', 'bytecode')
LIMIT = 512 * 1024 * 1024
TOTAL_LIMIT = 1024 * 1024 * 1024
SCHEMA = 'ironcurtain-virus-db/v1'

def trusted_dir(path):
    path = pathlib.Path(path)
    if not path.is_absolute() or '..' in path.parts: raise ValueError('DB_DIRECTORY')
    for item in (path, *path.parents):
        info = item.lstat()
        sticky_tmp = str(item) == '/tmp' and info.st_mode & stat.S_ISVTX
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 and not sticky_tmp:
            raise ValueError('DB_DIRECTORY')
    return path

@contextlib.contextmanager
def protected_file(path, maximum=LIMIT):
    trusted_dir(pathlib.Path(path).parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1 or not 0 < info.st_size <= maximum:
            raise ValueError('DB_FILE')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            yield handle, info
        after = os.fstat(fd)
        if (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('DB_FILE_CHANGED')
    finally: os.close(fd)

def bytes_json(path):
    with protected_file(path, 16384) as (handle, _): return json.load(handle)

def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'

def durable(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.pointer.', dir=path.parent)
    try:
        os.fchmod(fd, 0o640); os.fchown(fd, 0, 10001)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(canonical(value)); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.lexists(temporary): os.unlink(temporary)

def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)

def header(handle):
    pieces = handle.read(512).decode('ascii').strip().split(':')
    if len(pieces) != 9 or pieces[0] != 'ClamAV-VDB': raise ValueError('DB_HEADER')
    values = [int(pieces[i]) for i in (2, 3, 4, 8)]
    if min(values[0], values[1], values[3]) <= 0 or values[2] < 0 or max(values) > 2**53-1: raise ValueError('DB_HEADER')
    return dict(zip(('version', 'signatures', 'functionality', 'timestamp'), values))

def manifest_valid(value, clock=None):
    clock = time.time() if clock is None else clock
    if not isinstance(value, dict) or set(value) != {'schema','files'} or value['schema'] != SCHEMA or set(value['files']) != {f+'.cvd' for f in FAMILIES}: raise ValueError('DB_MANIFEST')
    total=0
    for name, entry in value['files'].items():
        if not isinstance(entry,dict) or set(entry) != {'version','signatures','functionality','timestamp','size','sha256'}: raise ValueError('DB_MANIFEST')
        if any(type(entry[k]) != int or not 0 <= entry[k] <= 2**53-1 for k in ('version','signatures','functionality','timestamp','size')): raise ValueError('DB_MANIFEST')
        if min(entry['version'],entry['signatures'],entry['timestamp']) <= 0 or not 512 <= entry['size'] <= LIMIT or not re.fullmatch('[a-f0-9]{64}', str(entry['sha256'])): raise ValueError('DB_MANIFEST')
        if entry['timestamp'] > clock + 300: raise ValueError('DB_FUTURE')
        total += entry['size']
    if total > TOTAL_LIMIT: raise ValueError('DB_LIMIT')
    if clock - value['files']['daily.cvd']['timestamp'] > 7*86400: raise ValueError('DB_STALE')
    return value

def existing(store):
    pointer=bytes_json(store/'active.json')
    if not isinstance(pointer,dict) or set(pointer) != {'schema','snapshot'} or pointer['schema'] != 'ironcurtain-virus-db-pointer/v1' or not re.fullmatch('[a-f0-9]{64}',str(pointer['snapshot'])): raise ValueError('DB_POINTER')
    snapshot=trusted_dir(store/pointer['snapshot'])
    value=bytes_json(snapshot/'manifest.json')
    # Expired current snapshots still enforce monotonic versions when refreshed.
    manifest_valid(value, clock=value['files']['daily.cvd']['timestamp'])
    if hashlib.sha256(canonical(value)).hexdigest() != pointer['snapshot']: raise ValueError('DB_POINTER_DIGEST')
    return value, pointer['snapshot']

def check_monotonic(old, new):
    for name in new['files']:
        before, after=old['files'][name],new['files'][name]
        if after['version'] < before['version'] or after['timestamp'] < before['timestamp']: raise ValueError('DB_DOWNGRADE')
        if after['version'] == before['version'] and after != before: raise ValueError('DB_SAME_VERSION_CHANGED')

def verify_publisher(directory, public_key, clock=None):
    public_key=pathlib.Path(public_key).resolve()
    with protected_file(public_key,32768): pass
    with protected_file(directory/'manifest.json',16384) as (handle,_): manifest=handle.read()
    with protected_file(directory/'manifest.json.sig',64) as (handle,info):
        if info.st_size != 64: raise ValueError('DB_PUBLISHER_SIGNATURE')
    openssl=pathlib.Path(shutil.which('openssl') or '/unavailable').resolve()
    with protected_file(openssl): pass
    result=subprocess.run([str(openssl),'pkeyutl','-verify','-pubin','-inkey',str(public_key),'-rawin','-in',str(directory/'manifest.json'),'-sigfile',str(directory/'manifest.json.sig')],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=15,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':'/nonexistent'})
    if result.returncode != 0: raise ValueError('DB_PUBLISHER_SIGNATURE')
    value=manifest_valid(json.loads(manifest),clock=clock)
    if canonical(value) != manifest: raise ValueError('DB_MANIFEST_ENCODING')
    return value

def import_database(input_directory, store, public_key):
    if sys.platform != 'linux' or os.getuid() != 0: raise ValueError('DB_ROOT_REQUIRED')
    source, store=trusted_dir(input_directory),trusted_dir(store)
    if source==store or source.is_relative_to(store) or store.is_relative_to(source): raise ValueError('DB_OVERLAP')
    if set(os.listdir(source)) != {f+'.cvd' for f in FAMILIES} | {'manifest.json','manifest.json.sig'}: raise ValueError('DB_FIXED_FILES')
    tool=shutil.which('sigtool')
    if not tool: raise ValueError('DB_VALIDATOR_UNAVAILABLE')
    # Resolve trusted distro symlinks; never choose an input-provided executable.
    tool=pathlib.Path(tool).resolve()
    with protected_file(tool): pass
    lock_path=store/'.import.lock'
    lockfd=os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info=os.fstat(lockfd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1: raise ValueError('DB_LOCK')
        fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _import_locked(source, store, tool, pathlib.Path(public_key))
    finally: os.close(lockfd)

def _import_locked(source, store, tool, public_key):
    old=None
    if os.path.lexists(store/'active.json'):
        old,old_digest=existing(store)
        verify_publisher(store/old_digest,public_key,clock=old['files']['daily.cvd']['timestamp'])
    elif any(re.fullmatch('[a-f0-9]{64}',p) for p in os.listdir(store)): raise ValueError('DB_POINTER_MISSING')
    stage=pathlib.Path(tempfile.mkdtemp(prefix='.import.',dir=store))
    try:
        # Snapshot metadata before verifying; source paths are never used by the verifier.
        for name in ('manifest.json','manifest.json.sig'):
            with protected_file(source/name,16384 if name=='manifest.json' else 64) as (handle,_): data=handle.read()
            with (stage/name).open('xb') as out:
                out.write(data); out.flush(); os.fsync(out.fileno())
            (stage/name).chmod(0o640); os.chown(stage/name,0,10001)
        signed=verify_publisher(stage,public_key)
        rows={}; total=0
        for family in FAMILIES:
            name=family+'.cvd'; target=stage/name
            with protected_file(source/name) as (handle,info):
                metadata=header(handle); handle.seek(0); digest=hashlib.sha256(); length=0
                with target.open('xb') as out:
                    while chunk:=handle.read(1024*1024):
                        length+=len(chunk)
                        if length > info.st_size or length > LIMIT: raise ValueError('DB_LIMIT')
                        digest.update(chunk); out.write(chunk)
                    if length != info.st_size: raise ValueError('DB_FILE_CHANGED')
                    out.flush(); os.fsync(out.fileno())
            total+=length
            if total > TOTAL_LIMIT: raise ValueError('DB_LIMIT')
            target.chmod(0o640); os.chown(target,0,10001)
            actual={**metadata,'size':length,'sha256':digest.hexdigest()}
            if actual != signed['files'][name]: raise ValueError('DB_SIGNED_DIGEST')
            # Hash must match the signed publisher offer before invoking the parser.
            completed=subprocess.run([str(tool),'--info',str(target)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':'/nonexistent'})
            if completed.returncode != 0 or len(completed.stdout)>32768 or b'Verification OK' not in completed.stdout: raise ValueError('DB_VENDOR_SIGNATURE')
            rows[name]=actual
        value=manifest_valid({'schema':SCHEMA,'files':rows})
        if value != signed: raise ValueError('DB_SIGNED_CONTENT_MISMATCH')
        if old: check_monotonic(old,value)
        digest=hashlib.sha256(canonical(value)).hexdigest(); target=store/digest
        if os.path.lexists(target):
            trusted_dir(target)
            if verify_publisher(target,public_key) != value: raise ValueError('DB_SNAPSHOT_CONFLICT')
            # Verify all retained bytes before reusing the snapshot.
            for name,row in rows.items():
                with protected_file(target/name) as (handle,info):
                    h=hashlib.sha256()
                    while chunk:=handle.read(1024*1024): h.update(chunk)
                    if info.st_size != row['size'] or h.hexdigest() != row['sha256']: raise ValueError('DB_SNAPSHOT_CONFLICT')
        else:
            durable(stage/'manifest.json',value)
            stage.chmod(0o750); os.chown(stage,0,10001); sync_directory(stage)
            os.rename(stage,target); sync_directory(store)
        durable(store/'active.json',{'schema':'ironcurtain-virus-db-pointer/v1','snapshot':digest})
        return {'state':'verified','snapshot':digest,'files':rows,'activation':'local-admin'}
    finally:
        if stage.exists(): shutil.rmtree(stage)

def status(store, public_key):
    try:
        store=trusted_dir(store); value,digest=existing(store); verify_publisher(store/digest,public_key)
        return {'state':'verified','snapshot':digest,'files':value['files'],'delivery':'pull-only','activation':'local-admin'}
    except FileNotFoundError: return {'state':'missing'}
    except (OSError,ValueError,KeyError,TypeError): return {'state':'unavailable'}

if __name__ == '__main__':
    try:
        if sys.platform != 'linux' or os.getuid() != 0: raise ValueError('DB_ROOT_REQUIRED')
        if len(sys.argv)==4 and sys.argv[1]=='import': result=import_database(sys.argv[2],sys.argv[3],pathlib.Path(__file__).resolve().parents[1]/'release-public.pem')
        elif len(sys.argv)==3 and sys.argv[1]=='status': result=status(sys.argv[2],pathlib.Path(__file__).resolve().parents[1]/'release-public.pem')
        else: raise ValueError('DB_FIXED_ACTION')
        print(json.dumps(result,ensure_ascii=False))
    except (OSError,ValueError,subprocess.SubprocessError,KeyError,TypeError) as error:
        print('Virus database operation refused: '+str(error),file=sys.stderr); sys.exit(1)
