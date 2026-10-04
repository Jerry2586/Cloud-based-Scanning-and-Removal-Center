#!/usr/bin/env python3
"""Root menu copies six bounded release files into a protected snapshot."""
import os, pathlib, stat, json, re, sys
LIMIT=64*1024*1024

def directory(value):
    value=pathlib.Path(os.path.abspath(value))
    for item in [value,*value.parents]:
        info=item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or (info.st_mode&0o022 and not (str(item)=='/tmp' and info.st_mode&stat.S_ISVTX)):
            raise ValueError('Untrusted release directory')
    return value

def read(file,maximum):
    directory(file.parent)
    fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_nlink!=1 or before.st_mode&0o022 or not 0<before.st_size<=maximum:
            raise ValueError('Untrusted release file')
        chunks=[];size=0
        while size<=maximum:
            data=os.read(fd,min(65536,maximum+1-size))
            if not data: break
            size+=len(data);chunks.append(data)
        after=os.fstat(fd)
        if size!=before.st_size or (before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
            raise ValueError('Release changed during snapshot')
        return b''.join(chunks)
    finally: os.close(fd)

def snapshot(source,target):
    source=directory(source);target=directory(target)
    if list(target.iterdir()): raise ValueError('Snapshot must be empty')
    manifest=read(source/'release-manifest.json',65536)
    version=json.loads(manifest).get('version')
    if not isinstance(version,str) or not re.fullmatch(r'(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})',version): raise ValueError('Release version')
    prefix='APPGOG-Cloud-Security-Center-'+version
    names=[prefix+'.run',prefix+'.run.sha256',prefix+'.tar.gz',prefix+'.tar.gz.sha256','release-manifest.json','release-manifest.json.sig']
    if sorted(p.name for p in source.iterdir())!=sorted(names): raise ValueError('Exactly six assets required')
    for name in names:
        limit=64 if name.endswith('.sig') else 256 if name.endswith('.sha256') else 65536 if name.endswith('.json') else LIMIT
        data=read(source/name,limit)
        fd=os.open(target/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
if __name__=='__main__':
    if os.geteuid()!=0 or len(sys.argv)!=3: raise SystemExit('Root snapshot requires source and empty target')
    snapshot(*sys.argv[1:])
