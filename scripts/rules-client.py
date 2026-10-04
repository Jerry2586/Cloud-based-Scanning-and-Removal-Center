#!/usr/bin/env python3
"""Fixed, root-only import/pull. Cloud cannot supply paths or execute actions."""
import argparse, hashlib, http.client, importlib.util, json, os, pathlib, re, signal, ssl, tempfile, threading, time, urllib.parse
_spec=importlib.util.spec_from_file_location('ironcurtain_rules',pathlib.Path(__file__).resolve().parents[1]/'src/host/rules.py')
rules=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(rules)

def cloud_config(data):
    config=rules.parse_json(data)
    if not rules.exact(config,['schema','node_id','endpoint']) or config['schema']!='ironcurtain-cloud/v1' or not isinstance(config['node_id'],str) or not (re.fullmatch(r'node-[a-z0-9][a-z0-9-]{0,63}',config['node_id']) or config['node_id'] in ['license-center','build-center']): raise ValueError('RULE_CLOUD_IDENTITY')
    if not isinstance(config['endpoint'],str): raise ValueError('RULE_CLOUD_ENDPOINT')
    endpoint=urllib.parse.urlsplit(config['endpoint'])
    if endpoint.scheme!='https' or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.path not in ['', '/'] or endpoint.query or endpoint.fragment or any(ord(c)<33 or ord(c)==127 for c in config['endpoint']): raise ValueError('RULE_CLOUD_ENDPOINT')
    endpoint.port  # validates port range before any connection
    return config,endpoint

PULL_TIMEOUT=20

def pull(directory):
    # Covers DNS, TLS, response headers and bodies even when called as a library.
    if os.name!='posix' or threading.current_thread() is not threading.main_thread(): raise ValueError('Native pull requires the Linux main thread')
    started=time.monotonic();previous=signal.getsignal(signal.SIGALRM);prior=signal.getitimer(signal.ITIMER_REAL)
    def deadline(signum,frame): raise TimeoutError('RULE_CLOUD_TIMEOUT')
    signal.signal(signal.SIGALRM,deadline)
    signal.setitimer(signal.ITIMER_REAL,min(PULL_TIMEOUT,prior[0]) if prior[0]>0 else PULL_TIMEOUT)
    try: return _pull(directory)
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
        if prior[0]>0: signal.setitimer(signal.ITIMER_REAL,max(0.001,prior[0]-(time.monotonic()-started)),prior[1])

def _pull(directory):
    directory=pathlib.Path(directory)
    config,endpoint=cloud_config(rules.secure_read(directory/'cloud.json',32768))
    inputs={name:rules.secure_read(directory/name,32768) for name in ['ca.crt','client.crt','client.key','token']}
    token=inputs['token'].decode().strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,256}',token): raise ValueError('RULE_NODE_TOKEN')
    with tempfile.TemporaryDirectory(prefix='ironcurtain-rule-identity-') as temporary:
        root=pathlib.Path(temporary)
        for name,data in inputs.items():
            with (root/name).open('xb') as stream: os.chmod(root/name,0o600);stream.write(data)
        context=ssl.create_default_context(cafile=str(root/'ca.crt'));context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(root/'client.crt'),str(root/'client.key'))
        deadline=time.monotonic()+15;peer=None
        def get(path,maximum):
            connection=http.client.HTTPSConnection(endpoint.hostname,endpoint.port or 443,context=context,timeout=5)
            try:
                nonlocal peer
                connection.connect()
                observed=hashlib.sha256(connection.sock.getpeercert(binary_form=True)).digest()
                if peer is not None and observed!=peer: raise ValueError('RULE_CLOUD_PEER_CHANGED')
                peer=observed
                connection.request('GET',path,headers={'Authorization':'Bearer '+token,'Accept':'application/json'})
                response=connection.getresponse()
                if response.status!=200 or not re.match(r'^application/json(?:;|$)',response.getheader('Content-Type',''),re.I): raise ValueError('RULE_CLOUD_REJECTED')
                content_length=response.getheader('Content-Length')
                if content_length and (not content_length.isdigit() or int(content_length)>maximum): raise ValueError('RULE_CLOUD_LIMIT')
                chunks=[];length=0
                while True:
                    if time.monotonic()>deadline: raise TimeoutError('RULE_CLOUD_TIMEOUT')
                    chunk=response.read(min(16384,maximum+1-length))
                    if not chunk: break
                    length+=len(chunk)
                    if length>maximum: raise ValueError('RULE_CLOUD_LIMIT')
                    chunks.append(chunk)
                return b''.join(chunks)
            finally: connection.close()
        identity=rules.parse_json(get('/v1/connectivity',4096))
        if not isinstance(identity,dict) or identity.get('identity')!=config['node_id']: raise ValueError('RULE_CLOUD_IDENTITY')
        return get('/v1/rules',rules.LIMIT)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('role',choices=['local','cloud']);parser.add_argument('action',choices=['status','update','import']);parser.add_argument('file',nargs='?');args=parser.parse_args()
    if os.name!='posix' or os.geteuid()!=0: raise ValueError('Root Linux menu required')
    conf=pathlib.Path('/etc/ironcurtain')/args.role
    fd=rules.trusted_directory(conf);os.close(fd)
    target=conf/'rules.json' if args.role=='local' else conf/'runtime/rules.json'
    if args.action=='status':
        if args.file: raise ValueError('Unexpected argument')
        print(json.dumps(rules.summary(target),ensure_ascii=False));return
    if args.action=='import' and args.role=='cloud' and args.file: data=rules.secure_read(args.file)
    elif args.action=='update' and args.role=='local' and not args.file:
        data=pull(conf/'runtime/cloud')
    else: raise ValueError('Unsupported rule action')
    result=rules.activate(target,data,group=10001 if args.role=='cloud' else 0)
    print(json.dumps({'result':result,**rules.summary(target)},ensure_ascii=False))
if __name__=='__main__':
    try: main()
    except Exception: raise SystemExit('规则操作失败：请检查签名、有效期、更新顺序、节点身份和文件权限；当前规则未被替换或高水位已保留。')
