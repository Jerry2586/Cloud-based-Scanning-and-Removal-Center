#!/usr/bin/env python3
"""Independent publishing environment only: sign vendor-verified CVD metadata."""
import argparse, hashlib, importlib.util, json, os, pathlib, shutil, subprocess, sys, tempfile
spec=importlib.util.spec_from_file_location('virus_cache',pathlib.Path(__file__).with_name('virus-db-cache.py'))
cache=importlib.util.module_from_spec(spec); spec.loader.exec_module(cache)

def sign_database(source, output, private_key):
    if sys.platform != 'linux' or os.getuid() != 0: raise ValueError('DB_PUBLISHER_ROOT_REQUIRED')
    source,output=cache.trusted_dir(source),cache.trusted_dir(output)
    if os.listdir(output) or set(os.listdir(source)) != {f+'.cvd' for f in cache.FAMILIES}: raise ValueError('DB_PUBLISHER_FIXED_FILES')
    private_key=pathlib.Path(private_key)
    with cache.protected_file(private_key,32768) as (_,info):
        if info.st_mode & 0o077: raise ValueError('DB_SIGNING_KEY_MODE')
    sigtool=pathlib.Path(shutil.which('sigtool') or '/unavailable').resolve()
    openssl=pathlib.Path(shutil.which('openssl') or '/unavailable').resolve()
    for tool in (sigtool,openssl):
        with cache.protected_file(tool): pass
    rows={}; total=0
    try:
        for family in cache.FAMILIES:
            name=family+'.cvd'; target=output/name
            with cache.protected_file(source/name) as (handle,info):
                metadata=cache.header(handle); handle.seek(0); digest=hashlib.sha256();length=0
                with target.open('xb') as out:
                    while chunk:=handle.read(1024*1024):
                        length+=len(chunk)
                        if length>info.st_size: raise ValueError('DB_FILE_CHANGED')
                        digest.update(chunk);out.write(chunk)
                    if length != info.st_size: raise ValueError('DB_FILE_CHANGED')
                    out.flush();os.fsync(out.fileno())
            target.chmod(0o600); total+=length
            if total>cache.TOTAL_LIMIT: raise ValueError('DB_LIMIT')
            checked=subprocess.run([str(sigtool),'--info',str(target)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':'/nonexistent'})
            if checked.returncode or len(checked.stdout)>32768 or b'Verification OK' not in checked.stdout: raise ValueError('DB_VENDOR_SIGNATURE')
            rows[name]={**metadata,'size':length,'sha256':digest.hexdigest()}
        value=cache.manifest_valid({'schema':cache.SCHEMA,'files':rows})
        (output/'manifest.json').write_bytes(cache.canonical(value));(output/'manifest.json').chmod(0o600)
        subprocess.run([str(openssl),'pkeyutl','-sign','-inkey',str(private_key),'-rawin','-in',str(output/'manifest.json'),'-out',str(output/'manifest.json.sig')],check=True,timeout=15,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (output/'manifest.json.sig').chmod(0o600)
        # Verify type/key match using a temporary public key, never copy the private key.
        with tempfile.TemporaryDirectory(prefix='.verify.',dir=output) as temporary:
            public=pathlib.Path(temporary)/'public.pem'
            subprocess.run([str(openssl),'pkey','-in',str(private_key),'-pubout','-out',str(public)],check=True,timeout=15,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            public.chmod(0o600);cache.verify_publisher(output,public)
        cache.sync_directory(output)
        return {'state':'signed','files':rows,'private_key_location':'publisher-only'}
    except Exception:
        for name in [f+'.cvd' for f in cache.FAMILIES]+['manifest.json','manifest.json.sig']:
            if os.path.lexists(output/name): os.unlink(output/name)
        raise

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--input',required=True);parser.add_argument('--output',required=True);parser.add_argument('--signing-key',required=True);args=parser.parse_args()
    print(json.dumps(sign_database(args.input,args.output,args.signing_key)))
