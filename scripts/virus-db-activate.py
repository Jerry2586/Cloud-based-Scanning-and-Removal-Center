#!/usr/bin/env python3
"""Fixed local database activation with vendor validation, atomic exchange and recovery."""
import ctypes, hashlib, importlib.util, json, os, pathlib, pwd, shutil, stat, subprocess, sys, tempfile
spec=importlib.util.spec_from_file_location('virus_cache',pathlib.Path(__file__).with_name('virus-db-cache.py'))
cache=importlib.util.module_from_spec(spec);spec.loader.exec_module(cache)

def exchange(left,right):
    libc=ctypes.CDLL(None,use_errno=True)
    call=getattr(libc,'renameat2',None)
    if call is None: raise ValueError('DB_ATOMIC_EXCHANGE_UNAVAILABLE')
    call.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];call.restype=ctypes.c_int
    if call(-100,os.fsencode(left),-100,os.fsencode(right),2): raise OSError(ctypes.get_errno(),'DB_ATOMIC_EXCHANGE')

def safe_existing(directory):
    info=directory.lstat()
    owners={0}
    try:owners.add(pwd.getpwnam('ironcurtain-av').pw_uid)
    except KeyError:pass
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners or info.st_mode & 0o022: raise ValueError('DB_ACTIVE_DIRECTORY')
    rows={}
    for family in cache.FAMILIES:
        files=[directory/(family+suffix) for suffix in ('.cvd','.cld') if os.path.lexists(directory/(family+suffix))]
        if len(files)!=1: raise ValueError('DB_ACTIVE_FAMILY')
        fd=os.open(files[0],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid not in owners or before.st_nlink!=1 or before.st_mode & 0o022 or not 512<=before.st_size<=cache.LIMIT: raise ValueError('DB_ACTIVE_FILE')
            with os.fdopen(fd,'rb',closefd=False) as handle: rows[family+'.cvd']=cache.header(handle)
        finally:os.close(fd)
    return rows

def validated_snapshot(directory,public_key):
    directory=cache.trusted_dir(directory)
    value=cache.bytes_json(directory/'manifest.json')
    signed=cache.verify_publisher(directory,public_key,clock=value['files']['daily.cvd']['timestamp'])
    for name,row in signed['files'].items():
        with cache.protected_file(directory/name) as (handle,info):
            digest=hashlib.sha256()
            for chunk in iter(lambda:handle.read(1024*1024),b''):digest.update(chunk)
            if info.st_size!=row['size'] or digest.hexdigest()!=row['sha256']:raise ValueError('DB_RECOVERY_DIGEST')
    return signed

def highwater_check(path,signed):
    previous=cache.bytes_json(path)
    if not isinstance(previous,dict) or set(previous)!={'schema','snapshot','files'} or previous['schema']!='ironcurtain-virus-db-highwater/v1' or not cache.re.fullmatch('[a-f0-9]{64}',str(previous['snapshot'])):raise ValueError('DB_HIGHWATER')
    cache.manifest_valid({'schema':cache.SCHEMA,'files':previous['files']},clock=previous['files']['daily.cvd']['timestamp'])
    cache.check_monotonic(previous,signed)

def finish_recovery(data,public_key):
    journal=data/'activation.json'
    if not os.path.lexists(journal):return
    value=cache.bytes_json(journal)
    if not isinstance(value,dict) or set(value)!={'schema','snapshot','stage'} or value['schema']!='ironcurtain-virus-db-activation/v1' or not cache.re.fullmatch('[a-f0-9]{64}',str(value['snapshot'])) or not cache.re.fullmatch(r'\.candidate\.[a-zA-Z0-9_-]+',str(value['stage'])): raise ValueError('DB_ACTIVATION_JOURNAL')
    stage=data/value['stage'];active=data/'database'
    # Validate exchange evidence before writing recovery metadata. Persistence errors
    # must retain the journal rather than be mistaken for an uncommitted exchange.
    committed=None
    if os.path.lexists(active/'manifest.json'):
        try:
            signed=validated_snapshot(active,public_key)
            if hashlib.sha256(cache.canonical(signed)).hexdigest()==value['snapshot']:
                committed=signed
        except (OSError,ValueError,KeyError,TypeError):pass
    if committed is not None:
        highwater=data/'cloud-highwater.json'
        if os.path.lexists(highwater):highwater_check(highwater,committed)
        cache.durable(highwater,{'schema':'ironcurtain-virus-db-highwater/v1','snapshot':value['snapshot'],'files':committed['files']})
        cache.durable(data/'source.json',{'schema':'ironcurtain-virus-db-source/v1','source':'xuanwu-signed','snapshot':value['snapshot']})
        journal.unlink();cache.sync_directory(data);return
    # The exchange either never happened, or requires operator investigation.
    candidate=validated_snapshot(stage,public_key)
    if hashlib.sha256(cache.canonical(candidate)).hexdigest()!=value['snapshot']:raise ValueError('DB_RECOVERY_MANUAL')
    safe_existing(active);journal.unlink();cache.sync_directory(data)

def activate_database(input_directory,store,data,public_key):
    if sys.platform!='linux' or os.getuid()!=0:raise ValueError('DB_ROOT_REQUIRED')
    data=cache.trusted_dir(data);store=cache.trusted_dir(store);public_key=pathlib.Path(public_key)
    finish_recovery(data,public_key)
    imported=cache.import_database(input_directory,store,public_key)
    snapshot=imported['snapshot'];source=cache.trusted_dir(store/snapshot);signed=cache.verify_publisher(source,public_key)
    highwater=data/'cloud-highwater.json'
    if os.path.lexists(highwater):highwater_check(highwater,signed)
    elif os.path.lexists(data/'source.json'):raise ValueError('DB_HIGHWATER_MISSING')
    active=data/'database';old=safe_existing(active)
    for name,before in old.items():
        after=signed['files'][name]
        if after['version']<before['version'] or after['timestamp']<before['timestamp']:raise ValueError('DB_ACTIVE_DOWNGRADE')
    tool=pathlib.Path(shutil.which('clamscan') or '/unavailable').resolve()
    with cache.protected_file(tool):pass
    stage=pathlib.Path(tempfile.mkdtemp(prefix='.candidate.',dir=data));exchanged=False;journal=data/'activation.json'
    try:
        for name in [f+'.cvd' for f in cache.FAMILIES]+['manifest.json','manifest.json.sig']:
            with cache.protected_file(source/name,16384 if name=='manifest.json' else 64 if name.endswith('.sig') else cache.LIMIT) as (handle,_):
                with (stage/name).open('xb') as target:
                    shutil.copyfileobj(handle,target,1024*1024);target.flush();os.fsync(target.fileno())
            (stage/name).chmod(0o644 if name.endswith('.cvd') else 0o600)
        stage.chmod(0o755)
        with tempfile.TemporaryDirectory(prefix='.load-test.',dir=data) as testing:
            sample=pathlib.Path(testing)/'clean.txt';sample.write_text('IronCurtain database load validation\n');sample.chmod(0o600)
            scan=subprocess.run([str(tool),'--database='+str(stage),'--official-db-only=yes','--no-summary',str(sample)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=180,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':'/nonexistent'})
            if scan.returncode or len(scan.stdout)>32768:raise ValueError('DB_ENGINE_LOAD')
        cache.sync_directory(stage)
        cache.durable(journal,{'schema':'ironcurtain-virus-db-activation/v1','snapshot':snapshot,'stage':stage.name})
        # Directory exchange never exposes a partial set of database families.
        exchange(stage,active);exchanged=True;cache.sync_directory(data)
        cache.durable(highwater,{'schema':'ironcurtain-virus-db-highwater/v1','snapshot':snapshot,'files':signed['files']})
        cache.durable(data/'source.json',{'schema':'ironcurtain-virus-db-source/v1','source':'xuanwu-signed','snapshot':snapshot})
        journal.unlink();cache.sync_directory(data)
        return {'state':'activated','snapshot':snapshot,'daily_version':signed['files']['daily.cvd']['version'],'previous_directory':stage.name,'source':'xuanwu-signed','automatic_update':False}
    except Exception:
        # After exchange, retain the valid new database, old directory, journal and
        # highwater. The next root invocation completes this commit; no rollback
        # may leave an old active database behind a newer committed highwater.
        if not exchanged and os.path.lexists(journal):journal.unlink();cache.sync_directory(data)
        raise
    finally:
        # Retain the exchanged old database for recovery; never delete it on success.
        if not exchanged and stage.exists():shutil.rmtree(stage)

if __name__=='__main__':
    if len(sys.argv)!=2:raise ValueError('DB_FIXED_ACTION')
    print(json.dumps(activate_database(sys.argv[1],'/var/lib/ironcurtain/local/virus-db','/var/lib/ironcurtain-antivirus',pathlib.Path(__file__).resolve().parents[1]/'release-public.pem')))
