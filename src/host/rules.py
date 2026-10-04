"""Signed, data-only hash rules. No commands, paths, keys or baselines from the cloud."""
import base64, contextlib, hashlib, json, os, pathlib, re, stat, subprocess, tempfile, time
LIMIT = 196608
PUBLIC_KEY = pathlib.Path(__file__).resolve().parents[2] / 'release-public.pem'
VERSION = json.loads((PUBLIC_KEY.parent / 'package.json').read_bytes())['version']
OPENSSL = '/usr/bin/openssl' if os.name=='posix' else 'C:/Program Files/Git/usr/bin/openssl.exe'
SEMVER = re.compile(r'^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$')

def secure_read(filename, maximum=LIMIT):
    path = pathlib.Path(filename)
    if not path.is_absolute() or '..' in path.parts: raise ValueError('RULE_PATH')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY) if os.name == 'posix' else None
    try:
        if directory is not None:
            for component in path.parts[1:-1]:
                nxt = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                info = os.fstat(nxt)
                if info.st_uid != 0 or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                    os.close(nxt); raise ValueError('RULE_DIRECTORY')
                os.close(directory); directory = nxt
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        else:
            if path.is_symlink(): raise ValueError('RULE_LINK')
            fd = os.open(path, os.O_RDONLY)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum or (os.name == 'posix' and (before.st_uid != 0 or before.st_mode & 0o022)): raise ValueError('RULE_FILE')
            data = stream.read(maximum+1); after = os.fstat(stream.fileno())
            if len(data) > maximum or (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns): raise ValueError('RULE_CHANGED')
            return data
    finally:
        if directory is not None: os.close(directory)

def parse_json(data):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result: raise ValueError('RULE_JSON_DUPLICATE')
            result[key]=value
        return result
    return json.loads(data.decode('utf-8') if isinstance(data,bytes) else data, object_pairs_hook=pairs, parse_constant=lambda value: (_ for _ in ()).throw(ValueError('RULE_JSON_CONSTANT')))

def trusted_directory(directory):
    if os.name!='posix': raise ValueError('Linux rule activation required')
    path=pathlib.Path(directory)
    if not path.is_absolute() or '..' in path.parts: raise ValueError('RULE_PATH')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            info=os.fstat(nxt)
            if info.st_uid!=0 or (info.st_mode&0o022 and not info.st_mode&stat.S_ISVTX):
                os.close(nxt); raise ValueError('RULE_DIRECTORY')
            os.close(fd);fd=nxt
        if os.fstat(fd).st_mode&0o022: raise ValueError('RULE_DESTINATION')
        return fd
    except BaseException: os.close(fd);raise

def exact(value, keys): return isinstance(value, dict) and set(value) == set(keys)
def integer(value): return type(value) == int and 0 < value <= 9007199254740991

def validate(value, now=None, agent_version=VERSION, historical=False):
    now = int(time.time()) if now is None else now
    if not exact(value, ['schema','version','sequence','issued_at','expires_at','minimum_agent_version','indicators']) or value['schema'] != 'ironcurtain-threat-rules/v1' or not isinstance(value['version'],str) or not SEMVER.fullmatch(value['version']) or not isinstance(value['minimum_agent_version'],str) or not SEMVER.fullmatch(value['minimum_agent_version']): raise ValueError('RULE_SCHEMA')
    if not all(integer(value[k]) for k in ['sequence','issued_at','expires_at']) or value['expires_at'] <= value['issued_at'] or value['expires_at']-value['issued_at'] > 2678400: raise ValueError('RULE_TIME_OR_SEQUENCE')
    if not historical and (value['issued_at'] > now+300 or value['expires_at'] <= now): raise ValueError('RULE_EXPIRED_OR_FUTURE')
    if not isinstance(agent_version,str) or not SEMVER.fullmatch(agent_version): raise ValueError('RULE_COMPATIBILITY')
    if tuple(map(int,value['minimum_agent_version'].split('.'))) > tuple(map(int,agent_version.split('.'))): raise ValueError('RULE_COMPATIBILITY')
    if not isinstance(value['indicators'],list) or len(value['indicators']) > 1024: raise ValueError('RULE_INDICATORS')
    ids=set(); hashes=set()
    for item in value['indicators']:
        if not exact(item,['id','sha256','label']) or not isinstance(item['id'],str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',item['id']) or not isinstance(item['sha256'],str) or not re.fullmatch(r'[a-f0-9]{64}',item['sha256']) or not isinstance(item['label'],str) or not 1 <= len(item['label']) <= 128 or any(ord(c)<32 or ord(c)==127 or 0xd800<=ord(c)<=0xdfff for c in item['label']) or item['id'] in ids or item['sha256'] in hashes: raise ValueError('RULE_INDICATOR')
        ids.add(item['id']); hashes.add(item['sha256'])
    return value

def decode(value, maximum):
    if not isinstance(value,str): raise ValueError('RULE_ENCODING')
    try: data=base64.b64decode(value,validate=True)
    except Exception as error: raise ValueError('RULE_ENCODING') from error
    if len(data)>maximum or base64.b64encode(data).decode()!=value: raise ValueError('RULE_ENCODING')
    return data

def verify(data, public_key=None, now=None, historical=False):
    if len(data)>LIMIT: raise ValueError('RULE_LIMIT')
    envelope=parse_json(data)
    if not exact(envelope,['schema','payload','signature']) or envelope['schema']!='ironcurtain-signed-rules/v1': raise ValueError('RULE_ENVELOPE')
    payload=decode(envelope['payload'],131072); signature=decode(envelope['signature'],64)
    if len(signature)!=64: raise ValueError('RULE_SIGNATURE')
    key=secure_read(PUBLIC_KEY,8192) if public_key is None else public_key
    # Ed25519 SPKI DER has a fixed prefix; reject other algorithms before pkeyutl.
    lines=key.strip().splitlines()
    if len(lines)!=3 or lines[0]!=b'-----BEGIN PUBLIC KEY-----' or lines[-1]!=b'-----END PUBLIC KEY-----': raise ValueError('RULE_KEY')
    body=lines[1]
    der=base64.b64decode(body,validate=True)
    if len(der)!=44 or der[:12]!=bytes.fromhex('302a300506032b6570032100'): raise ValueError('RULE_KEY')
    with tempfile.TemporaryDirectory(prefix='ironcurtain-rule-') as directory:
        for name, content in [('key.pem',key),('payload',payload),('signature',signature)]:
            file=pathlib.Path(directory)/name
            with file.open('xb') as handle: os.chmod(file,0o600); handle.write(content)
        result=subprocess.run([OPENSSL,'pkeyutl','-verify','-pubin','-rawin','-inkey',str(pathlib.Path(directory)/'key.pem'),'-in',str(pathlib.Path(directory)/'payload'),'-sigfile',str(pathlib.Path(directory)/'signature')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5,check=False)
        if result.returncode!=0: raise ValueError('RULE_SIGNATURE')
    value=validate(parse_json(payload),now=now,historical=historical)
    return value,hashlib.sha256(payload).hexdigest()

def load(filename, public_key=None, now=None, historical=False):
    return verify(secure_read(filename),public_key,now,historical)

def summary(filename):
    if filename is None: return {'state':'missing','detail':'尚未安装签名哈希规则'}
    try:
        value,digest=load(filename)
        return {'state':'ready','version':value['version'],'sequence':value['sequence'],'issued_at':value['issued_at'],'expires_at':value['expires_at'],'indicators':len(value['indicators']),'payload_sha256':digest,'activated_at':int(os.stat(filename,follow_symlinks=False).st_mtime),'detail':'发布签名已验证；仅匹配固定 SHA-256 特征'}
    except FileNotFoundError: return {'state':'missing','detail':'尚未安装签名哈希规则'}
    except Exception: return {'state':'unavailable','detail':'规则签名、有效期、兼容性或本机权限校验失败；未启用'}

def atomic_rule(directory,name,data,group):
    fd=trusted_directory(directory); temporary='.rules-'+os.urandom(12).hex()
    try:
        handle=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        with os.fdopen(handle,'wb') as stream:
            os.fchown(stream.fileno(),0,group);os.fchmod(stream.fileno(),0o640 if group else 0o600)
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,name,src_dir_fd=fd,dst_dir_fd=fd);os.fsync(fd)
    finally:
        try: os.unlink(temporary,dir_fd=fd)
        except FileNotFoundError: pass
        os.close(fd)

@contextlib.contextmanager
def activation_lock(directory):
    # A separate descriptor lock serializes native callers as well as menu updates.
    # Root-only parent, no links and bounded acquisition prevent an untrusted lock.
    import fcntl
    parent=trusted_directory(directory);fd=None
    try:
        fd=os.open('.rules-activation.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=parent)
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077 or info.st_size!=0: raise ValueError('RULE_LOCK')
        deadline=time.monotonic()+5
        while True:
            try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
            except BlockingIOError:
                if time.monotonic()>deadline: raise TimeoutError('RULE_BUSY')
                time.sleep(0.025)
        yield
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)

def activate(destination, data, public_key=None, group=0):
    if os.name!='posix' or os.geteuid()!=0: raise ValueError('Linux root rule activation required')
    with activation_lock(pathlib.Path(destination).parent):
        return _activate_locked(destination,data,public_key,group)

def _activate_locked(destination, data, public_key=None, group=0):
    value,digest=verify(data,public_key)
    target=pathlib.Path(destination); watermark=target.with_name('rules.highwater.json')
    parent=trusted_directory(target.parent);os.close(parent)
    prior_states=[]; active_state=None
    for filename in [watermark,target]:
        try:
            prior=load(filename,public_key,historical=True);prior_states.append(prior)
            if filename==target: active_state=prior
        except FileNotFoundError: pass
    for prior,old_digest in prior_states:
        if value['sequence']<prior['sequence'] or tuple(map(int,value['version'].split('.')))<tuple(map(int,prior['version'].split('.'))) or (value['sequence']==prior['sequence'] and digest!=old_digest): raise ValueError('RULE_ROLLBACK_OR_EQUIVOCATION')
    # Write high-water first: after an interrupted activation, only the same or a
    # newer signed pack can finish the transaction. Deleting rules alone is no reset.
    atomic_rule(target.parent,watermark.name,data,0)
    unchanged=active_state is not None and active_state[0]['sequence']==value['sequence'] and active_state[1]==digest
    atomic_rule(target.parent,target.name,data,group)
    return 'unchanged' if unchanged else 'activated'
