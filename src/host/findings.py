"""Bounded local evidence. Pin and rescan the opened bytes before offering a target."""
import datetime, hashlib, json, os, pathlib, re, stat, time
MAX_FINDINGS = 32
MAX_BYTES = 64 * 1024 * 1024
SIGNATURE = re.compile(r'^[A-Za-z0-9_.:/()!+\-]{1,160}$')

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

def path_allowed(filename, roots):
    if not isinstance(filename, str) or len(filename) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in filename):
        return False
    p = pathlib.PurePosixPath(filename)
    return p.is_absolute() and str(p) == filename and '..' not in p.parts and any(p.is_relative_to(r) and str(p) != r for r in roots)

def parent_fd(filename, controlled=False):
    if os.name != 'posix': raise ValueError('Linux required')
    p = pathlib.PurePosixPath(filename)
    if not p.is_absolute() or '..' in p.parts: raise ValueError('unsafe path')
    current = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in p.parts[1:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            info = os.fstat(nxt)
            if controlled and (info.st_uid != 0 or info.st_mode & 0o022):
                os.close(nxt); raise ValueError('parent must be root-owned and not writable by others')
            os.close(current); current = nxt
        result = current; current = None
        return result, p.name
    finally:
        if current is not None: os.close(current)

def identity(info):
    return dict(device=info.st_dev, inode=info.st_ino, size=info.st_size, mtime_ns=info.st_mtime_ns,
                ctime_ns=info.st_ctime_ns, mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid, links=info.st_nlink)

def hash_fd(fd):
    os.lseek(fd, 0, os.SEEK_SET); digest = hashlib.sha256(); size = 0
    while True:
        block = os.read(fd, 65536)
        if not block: break
        size += len(block)
        if size > MAX_BYTES: raise ValueError('file budget exceeded')
        digest.update(block)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()

def alerts(text):
    result = []
    for line in text.splitlines():
        if not line.endswith(' FOUND'): continue
        if ': ' not in line: raise ValueError('malformed alert')
        filename, signature = line[:-6].rsplit(': ', 1)
        if not SIGNATURE.fullmatch(signature): raise ValueError('invalid signature name')
        result.append((filename, signature))
    return result

def collect(text, roots, run, scan_args, maximum=MAX_FINDINGS):
    """Recursive scan output is a hint; a second stdin scan pins exact local bytes."""
    result = []; complete = True; deadline = time.monotonic() + 20
    try: candidates = alerts(text)
    except ValueError: return [], False
    seen = set()
    for filename, signature in candidates:
        if filename in seen: continue
        seen.add(filename)
        if len(result) >= maximum or time.monotonic() >= deadline:
            complete = False; break
        if not path_allowed(filename, roots): complete = False; continue
        parent = fd = None
        try:
            parent, leaf = parent_fd(filename)
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES: raise ValueError('file outside budget')
            digest = hash_fd(fd)
            code, output = run([*scan_args, '--', '-'], seconds=max(1, min(10, deadline-time.monotonic())), input_fd=fd)
            matches = alerts(output)
            if code != 1 or not any(name == 'stdin' and sig == signature for name, sig in matches):
                raise ValueError('opened bytes were not independently confirmed')
            if 'Heuristics.Limits.Exceeded' in output or re.search(r'Errors:\s*[1-9]', output):
                raise ValueError('rescan incomplete')
            if identity(before) != identity(os.fstat(fd)): raise ValueError('file changed during scan')
            # The descriptor pins bytes, but renaming need not change file ctime.
            # Reopen the current absolute parent and verify the displayed path still
            # names the scanned inode, including a replaced ancestor directory.
            current_parent, current_leaf = parent_fd(filename)
            try:
                old_parent, new_parent = os.fstat(parent), os.fstat(current_parent)
                if (old_parent.st_dev, old_parent.st_ino) != (new_parent.st_dev, new_parent.st_ino):
                    raise ValueError('parent replaced during scan')
                if identity(before) != identity(os.stat(current_leaf, dir_fd=current_parent, follow_symlinks=False)):
                    raise ValueError('path replaced during scan')
            finally: os.close(current_parent)
            observed = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
            item = dict(path=filename, signature=signature, sha256=digest, observed_at=observed, **identity(before))
            item['id'] = hashlib.sha256(canonical(item)).hexdigest()
            result.append(item)
        except (OSError, ValueError): complete = False
        finally:
            if fd is not None: os.close(fd)
            if parent is not None: os.close(parent)
    return result, complete


def quarantine_status(state):
    """Read-only bounded journal summary. Does not create, approve or restore anything."""
    unavailable = {'state': 'unavailable', 'items': [], 'count': 0, 'pending': 0}
    directory = pathlib.Path(state) / 'quarantine'; fd = None
    try:
        fd, _ = parent_fd(str(directory / 'placeholder'), controlled=True)
        info = os.fstat(fd)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700: return unavailable
        names = os.listdir(fd)
        if len(names) > 400: return unavailable
        records = []; consumed = 0
        for name in names:
            if not re.fullmatch(r'[a-f0-9]{64}\.json', name): continue
            file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(file, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 65536:
                    return unavailable
                raw = stream.read(65537); consumed += len(raw)
                if len(raw) > 65536 or consumed > 1024 * 1024: return unavailable
                record = json.loads(raw)
            if not isinstance(record, dict) or not isinstance(record.get('item'), dict): return unavailable
            item = record['item']
            if record.get('schema') != 'ironcurtain-quarantine/v1' or record.get('state') not in ['preparing','captured','quarantined','restoring','restored'] or item.get('id') != name[:-5]: return unavailable
            if not path_allowed(item.get('path'), ['/']) or not isinstance(item.get('signature'), str) or not SIGNATURE.fullmatch(item['signature']): return unavailable
            if type(item.get('size')) != int or not 0 <= item['size'] <= MAX_BYTES: return unavailable
            if hashlib.sha256(canonical({k:v for k,v in item.items() if k!='id'})).hexdigest() != item['id']: return unavailable
            records.append({'id':item['id'], 'path':item['path'], 'signature':item['signature'], 'state':record['state'], 'size':item['size']})
        if len(records) > 128: return unavailable
        records.sort(key=lambda x:x['id'])
        return {'state':'recorded' if records else 'empty', 'items':records[-8:], 'count':len(records), 'pending':sum(x['state'] in ['preparing','captured','restoring'] for x in records)}
    except FileNotFoundError:
        return {'state':'empty', 'items':[], 'count':0, 'pending':0} if fd is None else unavailable
    except (OSError, ValueError, TypeError, KeyError): return unavailable
    finally:
        if fd is not None: os.close(fd)
