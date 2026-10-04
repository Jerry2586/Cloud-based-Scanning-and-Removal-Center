import base64, hashlib, importlib.util, json, os, pathlib, shutil, ssl, subprocess, tempfile, threading, time, unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
ROOT=pathlib.Path(__file__).resolve().parents[1]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/file); value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
r=module('rules','src/host/rules.py');a=module('agent','src/host/agent.py');client=module('client','scripts/rules-client.py')
def write(path,data):
    path.write_bytes(data);path.chmod(0o600)
def command(*args):
    result=subprocess.run([r.OPENSSL,*map(str,args)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True);return result.stdout
class RulesTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='ironcurtain-rule-test-');self.root=pathlib.Path(self.temporary.name);self.root.chmod(0o700)
        command('genpkey','-algorithm','ED25519','-out',self.root/'key.pem')
        self.public=command('pkey','-in',self.root/'key.pem','-pubout');write(self.root/'public.pem',self.public)
        self.now=int(time.time());self.target=self.root/'rules.json'
    def tearDown(self): self.temporary.cleanup()
    def payload(self,**changes):
        return {'schema':'ironcurtain-threat-rules/v1','version':'0.2.0','sequence':1,'issued_at':self.now-5,'expires_at':self.now+3600,'minimum_agent_version':'0.2.0','indicators':[{'id':'fixture','sha256':hashlib.sha256(b'fixture').hexdigest(),'label':'测试恶意文件 🔐'}],**changes}
    def envelope(self,value=None,raw=None):
        data=raw if raw is not None else json.dumps(value or self.payload(),ensure_ascii=False,separators=(',',':')).encode()
        write(self.root/'payload',data);signature=command('pkeyutl','-sign','-rawin','-inkey',self.root/'key.pem','-in',self.root/'payload')
        return json.dumps({'schema':'ironcurtain-signed-rules/v1','payload':base64.b64encode(data).decode(),'signature':base64.b64encode(signature).decode()},separators=(',',':')).encode()
    def test_crypto_and_schema(self):
        data=self.envelope();self.assertEqual(r.verify(data,self.public)[0]['sequence'],1)
        parsed=json.loads(data);parsed['payload']=base64.b64encode(b'tampered').decode()
        with self.assertRaises(ValueError):r.verify(json.dumps(parsed).encode(),self.public)
        for changes in [{'command':'id'},{'sequence':True},{'sequence':9007199254740992},{'expires_at':self.now},{'issued_at':self.now+600},{'expires_at':self.now+2678401,'issued_at':self.now},{'minimum_agent_version':'0.2.1'},{'indicators':[{'id':'bad','sha256':'a'*64,'label':chr(10)}]}]:
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):r.verify(self.envelope(self.payload(**changes)),self.public)
        with self.assertRaises(ValueError):r.verify(data,b'-----BEGIN PRIVATE KEY-----'+bytes([10])+self.public.splitlines()[1]+bytes([10])+b'-----END PRIVATE KEY-----'+bytes([10]))
        with patch.object(r.subprocess,'run',wraps=subprocess.run) as called:r.verify(data,self.public)
        self.assertEqual(called.call_args.args[0][0],r.OPENSSL);self.assertTrue(pathlib.Path(r.OPENSSL).is_absolute())
    def test_strict_json_and_node_python_parity(self):
        valid=self.envelope();raw=json.dumps(self.payload(),ensure_ascii=False).replace('"sequence": 1','"sequence": 1,"sequence": 2').encode()
        invalid=[self.envelope(raw=raw),self.envelope(raw=json.dumps(self.payload()).replace('"sequence": 1','"sequence": 1.0').encode()),self.envelope(self.payload(command='id')),self.envelope(self.payload(expires_at=self.now))]
        for data in invalid:
            with self.assertRaises(ValueError):r.verify(data,self.public)
        node=shutil.which('node') or 'C:/Users/WDDN/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe'
        script="import{verifyRuleEnvelope,parseRuleJson}from'./src/rules.js';let s='';for await(const c of process.stdin)s+=c;const v=JSON.parse(s);console.log(JSON.stringify(v.packs.map(x=>{try{verifyRuleEnvelope(parseRuleJson(Buffer.from(x,'base64')),v.key);return true}catch{return false}})))"
        out=subprocess.run([node,'--input-type=module','-e',script],cwd=ROOT,input=json.dumps({'key':self.public.decode(),'packs':[base64.b64encode(x).decode() for x in [valid,*invalid]]}),text=True,capture_output=True,check=True)
        self.assertEqual(json.loads(out.stdout),[True,False,False,False,False])
        for raw in [b'{"x":1,"x":2}',b'{"x":NaN}',bytes([255])]:
            with self.assertRaises((ValueError,UnicodeError)):r.parse_json(raw)
    @unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'root POSIX activation required')
    def test_highwater_remains_after_deletion_and_rejects_regression(self):
        one=self.envelope();two=self.envelope(self.payload(sequence=2,version='0.2.1'))
        self.assertEqual(r.activate(self.target,one,self.public),'activated')
        self.assertEqual(r.activate(self.target,one,self.public),'unchanged')
        r.activate(self.target,two,self.public);self.target.unlink()
        for data in [one,self.envelope(self.payload(sequence=3,version='0.2.0')),self.envelope(self.payload(sequence=2,version='0.2.1',indicators=[]))]:
            with self.assertRaises(ValueError):r.activate(self.target,data,self.public)
        self.assertEqual(r.activate(self.target,two,self.public),'activated')
        self.assertEqual(self.target.stat().st_mode&0o777,0o600)
    @unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'root POSIX activation required')
    def test_interruption_retries_same_pack_and_blocks_older(self):
        one=self.envelope();two=self.envelope(self.payload(sequence=2))
        original=r.atomic_rule
        def interrupt(directory,name,data,group):
            if name=='rules.json':raise OSError('simulated interruption')
            return original(directory,name,data,group)
        with patch.object(r,'atomic_rule',side_effect=interrupt):
            with self.assertRaises(OSError):r.activate(self.target,two,self.public)
        with self.assertRaises(ValueError):r.activate(self.target,one,self.public)
        self.assertEqual(r.activate(self.target,two,self.public),'activated')
        write(self.root/'rules.highwater.json',b'corrupt')
        with self.assertRaises(ValueError):r.activate(self.target,two,self.public)
    @unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'root POSIX concurrency required')
    def test_concurrent_activations_cannot_undo_newer_sequence(self):
        two=self.envelope(self.payload(sequence=2));three=self.envelope(self.payload(sequence=3))
        original=r.atomic_rule;paused=threading.Event();release=threading.Event();attempted=threading.Event();errors=[]
        def write_paused(directory,name,data,group):
            if name=='rules.json' and data==two:
                paused.set()
                if not release.wait(2):raise TimeoutError('test coordination timeout')
            return original(directory,name,data,group)
        def activate(data,started=None):
            if started is not None:started.set()
            try:r.activate(self.target,data,self.public)
            except Exception as error:errors.append(error)
        with patch.object(r,'atomic_rule',side_effect=write_paused):
            first=threading.Thread(target=activate,args=(two,));first.start()
            self.assertTrue(paused.wait(2))
            second=threading.Thread(target=activate,args=(three,attempted));second.start()
            self.assertTrue(attempted.wait(1));release.set()
            first.join(3);second.join(3)
            self.assertFalse(first.is_alive());self.assertFalse(second.is_alive())
        self.assertEqual(errors,[])
        self.assertEqual(r.load(self.target,self.public)[0]['sequence'],3)
        self.assertEqual(r.load(self.root/'rules.highwater.json',self.public)[0]['sequence'],3)
        for invalid in ['garbage','9','9.9',None,9]:
            with self.assertRaises(ValueError):r.validate(self.payload(minimum_agent_version='9.9.9'),agent_version=invalid)
    @unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'root POSIX trust required')
    def test_filesystem_links_and_permissions_rejected(self):
        one=self.envelope();r.activate(self.target,one,self.public)
        self.target.chmod(0o666)
        with self.assertRaises(ValueError):r.load(self.target,self.public)
        self.target.chmod(0o600);os.link(self.target,self.root/'hardlink')
        with self.assertRaises(ValueError):r.load(self.target,self.public)
        (self.root/'hardlink').unlink();self.target.unlink();self.target.symlink_to(self.root/'public.pem')
        with self.assertRaises((ValueError,OSError)):r.activate(self.target,one,self.public)
        self.target.unlink();self.root.chmod(0o777)
        with self.assertRaises(ValueError):r.activate(self.target,one,self.public)
        self.root.chmod(0o700)
    def test_real_hash_scan_without_clamav_keeps_evidence_and_partial_coverage(self):
        business=self.root/'site';business.mkdir();(business/'suspicious.bin').write_bytes(b'fixture');write(self.target,self.envelope())
        with patch.object(a.rules,'PUBLIC_KEY',self.root/'public.pem'):
            scanner=a.Scanner({'schema':'ironcurtain-profile/v1'},rule_path=self.target)
            scanner.clamav=lambda paths:('unavailable','engine unavailable',{})
            state,_,evidence=scanner.malware([str(business)])
            self.assertEqual(state,'finding');self.assertEqual(evidence['hash_rules']['matched'],1);self.assertEqual(len(scanner.rule_hits),1)
            self.assertEqual(scanner.rule_hits[0]['sha256'],hashlib.sha256(b'fixture').hexdigest())
            scanner.hash_threats([]);self.assertFalse(scanner.rule_scan_complete)
            (business/'suspicious.bin').write_bytes(b'clean');scanner=a.Scanner({'schema':'ironcurtain-profile/v1'},rule_path=self.target);scanner.clamav=lambda paths:('unavailable','engine unavailable',{})
            self.assertEqual(scanner.malware([str(business)])[0],'unavailable')
            with patch.object(a,'digest_file',side_effect=ValueError('budget')):
                self.assertEqual(scanner.hash_threats([str(business)])[0],'unavailable');self.assertFalse(scanner.rule_scan_complete)
        self.assertEqual((business/'suspicious.bin').read_bytes(),b'clean')

@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'root Linux TLS identity files required')
class NativePullTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='ironcurtain-native-tls-');cls.root=pathlib.Path(cls.temporary.name);cls.root.chmod(0o700)
        command('req','-x509','-newkey','rsa:2048','-nodes','-keyout',cls.root/'ca.key','-out',cls.root/'ca.crt','-days','1','-subj','/CN=Rule test CA')
        for name,usage in [('server','serverAuth'),('server-alt','serverAuth'),('client','clientAuth')]:
            command('req','-newkey','rsa:2048','-nodes','-keyout',cls.root/(name+'.key'),'-out',cls.root/(name+'.csr'),'-subj','/CN='+name)
            (cls.root/(name+'.ext')).write_text('extendedKeyUsage='+usage+'\n'+('subjectAltName=DNS:localhost\n' if name.startswith('server') else ''))
            command('x509','-req','-in',cls.root/(name+'.csr'),'-CA',cls.root/'ca.crt','-CAkey',cls.root/'ca.key','-CAcreateserial','-out',cls.root/(name+'.crt'),'-days','1','-extfile',cls.root/(name+'.ext'))
        for file in cls.root.iterdir():file.chmod(0o600)
    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()
    def setUp(self):
        self.mode='ok';self.requests=[];outer=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                outer.requests.append(self.path)
                if self.headers.get('Authorization')!='Bearer '+'a'*64:self.send_error(403);return
                if outer.mode=='redirect':self.send_response(302);self.send_header('Location','https://example.invalid');self.end_headers();return
                if self.path=='/v1/connectivity':body=json.dumps({'identity':'node-test' if outer.mode!='wrong-id' else 'node-other'}).encode()
                else:body=b'{"signed":"fixture"}' if outer.mode!='oversize' else b' '*(r.LIMIT+1)
                self.send_response(200);self.send_header('Content-Type','application/json')
                if outer.mode=='chunked-oversize' and self.path=='/v1/rules':
                    self.send_header('Transfer-Encoding','chunked');self.end_headers()
                    body=b' '*(r.LIMIT+1)
                    try:self.wfile.write(('%x\r\n'%len(body)).encode()+body+b'\r\n0\r\n\r\n')
                    except (BrokenPipeError,ConnectionResetError):pass
                    return
                self.send_header('Content-Length',str(len(body)));self.end_headers()
                if outer.mode=='peer-change' and self.path=='/v1/connectivity':outer.server.socket.context=outer.alternate
                self.wfile.write(body)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler);self.server.daemon_threads=True
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(self.root/'server.crt',self.root/'server.key');context.verify_mode=ssl.CERT_REQUIRED;context.load_verify_locations(self.root/'ca.crt');self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        self.alternate=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);self.alternate.load_cert_chain(self.root/'server-alt.crt',self.root/'server-alt.key');self.alternate.verify_mode=ssl.CERT_REQUIRED;self.alternate.load_verify_locations(self.root/'ca.crt')
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.identity=self.root/'identity';self.identity.mkdir(mode=0o700)
        for name in ['ca.crt','client.crt','client.key']:write(self.identity/name,(self.root/name).read_bytes())
        write(self.identity/'token',b'a'*64);self.config('localhost')
    def config(self,host):write(self.identity/'cloud.json',json.dumps({'schema':'ironcurtain-cloud/v1','node_id':'node-test','endpoint':f'https://{host}:{self.server.server_port}'}).encode())
    def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join();shutil.rmtree(self.identity)
    def test_real_mtls_fixed_paths_no_redirect_and_identity_check(self):
        self.assertEqual(client.pull(self.identity),b'{"signed":"fixture"}');self.assertEqual(self.requests,['/v1/connectivity','/v1/rules'])
        for mode in ['redirect','wrong-id','oversize','chunked-oversize']:
            self.mode=mode
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):client.pull(self.identity)
    def test_same_ca_server_change_is_rejected(self):
        self.mode='peer-change'
        with self.assertRaisesRegex(ValueError,'RULE_CLOUD_PEER_CHANGED'):client.pull(self.identity)
        self.assertEqual(self.requests,['/v1/connectivity'])
    def test_dns_and_connect_are_bounded_by_native_total_timeout(self):
        with patch.object(client,'PULL_TIMEOUT',0.03),patch.object(client.http.client.HTTPSConnection,'connect',side_effect=lambda:time.sleep(0.2)):
            started=time.monotonic()
            with self.assertRaises(TimeoutError):client.pull(self.identity)
            self.assertLess(time.monotonic()-started,0.15)
    def test_hostname_token_and_client_certificate_fail_closed(self):
        self.config('127.0.0.1')
        with self.assertRaises(ssl.SSLError):client.pull(self.identity)
        self.config('localhost');write(self.identity/'token',b'b'*64)
        with self.assertRaises(ValueError):client.pull(self.identity)
        write(self.identity/'token',b'a'*64);write(self.identity/'client.crt',b'not a certificate')
        with self.assertRaises(ssl.SSLError):client.pull(self.identity)

if __name__=='__main__':
    required=os.environ.get('IRONCURTAIN_REQUIRE_LINUX_RULES_TESTS')=='1'
    if required and not (os.name=='posix' and os.geteuid()==0):raise SystemExit('Linux root rule acceptance required')
    result=unittest.main(exit=False).result
    raise SystemExit(0 if result.wasSuccessful() and not (required and result.skipped) else 1)
