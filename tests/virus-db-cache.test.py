#!/usr/bin/env python3
"""Root filesystem/transaction unit tests. Synthetic headers are NOT vendor acceptance."""
import importlib.util, json, os, pathlib, shutil, subprocess, sys, tempfile, time, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
SUPPORTED=sys.platform=='linux' and os.getuid()==0

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
if SUPPORTED:
    cache=load('cache','virus-db-cache.py');publisher=load('publisher','sign-virus-db.py');activation=load('activation','virus-db-activate.py')

@unittest.skipUnless(SUPPORTED,'Linux root filesystem required')
class CacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='ic-db-unit-');self.root=pathlib.Path(self.temporary.name);self.root.chmod(0o700)
        self.addCleanup(self.temporary.cleanup)
        self.tools=self.root/'tools';self.tools.mkdir(mode=0o700)
        # Controlled validator substitutes prove invocation ordering/atomicity only.
        for name,text in [('sigtool','printf "Verification OK\\n"'),('clamscan','exit 0')]:
            tool=self.tools/name;tool.write_text('#!/bin/sh\n'+text+'\n');tool.chmod(0o700)
        self.path=os.environ['PATH'];os.environ['PATH']=str(self.tools)+':'+self.path
        self.addCleanup(lambda:os.environ.__setitem__('PATH',self.path))
        self.key=self.root/'private.pem';self.public=self.root/'public.pem'
        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(self.key)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);self.key.chmod(0o600)
        subprocess.run(['openssl','pkey','-in',str(self.key),'-pubout','-out',str(self.public)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);self.public.chmod(0o600)
        self.store=self.root/'store';self.store.mkdir(mode=0o700);self.clock=int(time.time())
    def package(self,version=10,timestamp=None):
        base=pathlib.Path(tempfile.mkdtemp(dir=self.root));raw=base/'raw';raw.mkdir(mode=0o700);out=base/'signed';out.mkdir(mode=0o700)
        for family in cache.FAMILIES:
            header=f'ClamAV-VDB:today:{version}:1:1:hash:sig:builder:{timestamp or self.clock}'.encode().ljust(512,b' ')
            file=raw/(family+'.cvd');file.write_bytes(header+b'synthetic fixture');file.chmod(0o600)
        publisher.sign_database(raw,out,self.key);return out
    def test_signed_import_reuse_and_rejection_preserve_pointer(self):
        source=self.package();result=cache.import_database(source,self.store,self.public);pointer=(self.store/'active.json').read_bytes()
        self.assertEqual(result['state'],'verified');self.assertEqual(cache.import_database(source,self.store,self.public)['snapshot'],result['snapshot'])
        for bad in [self.package(9),self.package(10,self.clock-1)]:
            with self.assertRaises(ValueError):cache.import_database(bad,self.store,self.public)
            self.assertEqual(pointer,(self.store/'active.json').read_bytes())
        (source/'daily.cvd').write_bytes(b'x'*530)
        with self.assertRaises(ValueError):cache.import_database(source,self.store,self.public)
        self.assertEqual(pointer,(self.store/'active.json').read_bytes())
    def test_publisher_forgery_rejected_before_vendor_parser(self):
        source=self.package();(source/'manifest.json.sig').write_bytes(b'x'*64)
        (self.tools/'sigtool').write_text('#!/bin/sh\ntouch '+str(self.root/'called')+'\nexit 1\n')
        with self.assertRaisesRegex(ValueError,'PUBLISHER_SIGNATURE'):cache.import_database(source,self.store,self.public)
        self.assertFalse((self.root/'called').exists());self.assertFalse((self.store/'active.json').exists())
    def test_permissions_symlink_and_missing_pointer_fail_closed(self):
        source=self.package();file=source/'daily.cvd';file.chmod(0o666)
        with self.assertRaises(ValueError):cache.import_database(source,self.store,self.public)
        file.chmod(0o600);cache.import_database(source,self.store,self.public);(self.store/'active.json').unlink()
        with self.assertRaisesRegex(ValueError,'POINTER_MISSING'):cache.import_database(source,self.store,self.public)
        file.unlink();file.symlink_to(source/'main.cvd')
        with self.assertRaises((ValueError,OSError)):cache.import_database(source,self.store,self.public)
    def test_signature_age_versions_and_exact_metadata(self):
        source=self.package();v=cache.verify_publisher(source,self.public)
        with self.assertRaisesRegex(ValueError,'STALE'):cache.manifest_valid(v,self.clock+8*86400)
        v['files']['daily.cvd']['version']=True
        with self.assertRaisesRegex(ValueError,'MANIFEST'):cache.manifest_valid(v)
    def test_atomic_activation_engine_failure_and_highwater(self):
        data=self.root/'antivirus';data.mkdir(mode=0o700);active=data/'database';active.mkdir(mode=0o755)
        first=self.package(9)
        for family in cache.FAMILIES:shutil.copyfile(first/(family+'.cvd'),active/(family+'.cvd'));(active/(family+'.cvd')).chmod(0o644)
        source=self.package(10);result=activation.activate_database(source,self.store,data,self.public)
        self.assertEqual(result['state'],'activated');self.assertEqual(cache.bytes_json(data/'cloud-highwater.json')['files']['daily.cvd']['version'],10)
        before=(active/'daily.cvd').read_bytes();(self.tools/'clamscan').write_text('#!/bin/sh\nexit 2\n')
        with self.assertRaisesRegex(ValueError,'ENGINE_LOAD'):activation.activate_database(self.package(11),self.store,data,self.public)
        self.assertEqual(before,(active/'daily.cvd').read_bytes());self.assertFalse((data/'activation.json').exists())
        self.assertEqual(cache.bytes_json(data/'cloud-highwater.json')['files']['daily.cvd']['version'],10)
    def test_metadata_write_failure_preserves_journal_and_completes_on_retry(self):
        data=self.root/'partial';data.mkdir(mode=0o700);active=data/'database';active.mkdir(mode=0o755)
        old=self.package(9)
        for family in cache.FAMILIES:shutil.copyfile(old/(family+'.cvd'),active/(family+'.cvd'));(active/(family+'.cvd')).chmod(0o644)
        source=self.package(10);original=activation.cache.durable
        def fail_source(path,value):
            if path.name=='source.json':raise OSError('simulated metadata persistence failure')
            original(path,value)
        activation.cache.durable=fail_source
        try:
            with self.assertRaises(OSError):activation.activate_database(source,self.store,data,self.public)
        finally:activation.cache.durable=original
        self.assertTrue((data/'activation.json').exists())
        self.assertEqual(activation.safe_existing(active)['daily.cvd']['version'],10)
        self.assertEqual(cache.bytes_json(data/'cloud-highwater.json')['files']['daily.cvd']['version'],10)
        activation.finish_recovery(data,self.public)
        self.assertFalse((data/'activation.json').exists())
        self.assertEqual(cache.bytes_json(data/'source.json')['source'],'xuanwu-signed')

    def test_interrupted_exchange_commits_recovery_without_downgrade(self):
        data=self.root/'av';data.mkdir(mode=0o700);active=data/'database';active.mkdir(mode=0o755)
        source=self.package();stage=data/'.candidate.recovery';shutil.copytree(source,stage);stage.chmod(0o755)
        value=cache.verify_publisher(stage,self.public);snapshot=cache.hashlib.sha256(cache.canonical(value)).hexdigest()
        cache.durable(data/'activation.json',{'schema':'ironcurtain-virus-db-activation/v1','snapshot':snapshot,'stage':stage.name});activation.exchange(stage,active)
        activation.finish_recovery(data,self.public)
        self.assertFalse((data/'activation.json').exists());self.assertEqual(cache.bytes_json(data/'cloud-highwater.json')['snapshot'],snapshot)

    def test_corrupted_exchanged_bytes_keep_recovery_journal(self):
        data=self.root/'corrupt';data.mkdir(mode=0o700);active=data/'database';active.mkdir(mode=0o755)
        source=self.package();stage=data/'.candidate.corrupt';shutil.copytree(source,stage);stage.chmod(0o755)
        signed=cache.verify_publisher(stage,self.public);snapshot=cache.hashlib.sha256(cache.canonical(signed)).hexdigest()
        cache.durable(data/'activation.json',{'schema':'ironcurtain-virus-db-activation/v1','snapshot':snapshot,'stage':stage.name});activation.exchange(stage,active)
        (active/'daily.cvd').write_bytes(b'x'*530)
        with self.assertRaises((ValueError,OSError)):activation.finish_recovery(data,self.public)
        self.assertTrue((data/'activation.json').exists());self.assertFalse((data/'source.json').exists())
    def test_missing_local_highwater_never_reinitializes_cloud_source(self):
        data=self.root/'lost';data.mkdir(mode=0o700);active=data/'database';active.mkdir(mode=0o755)
        first=self.package(9)
        for family in cache.FAMILIES:shutil.copyfile(first/(family+'.cvd'),active/(family+'.cvd'));(active/(family+'.cvd')).chmod(0o644)
        source=self.package(10);activation.activate_database(source,self.store,data,self.public)
        (data/'cloud-highwater.json').unlink()
        with self.assertRaisesRegex(ValueError,'HIGHWATER_MISSING'):activation.activate_database(source,self.store,data,self.public)
        self.assertEqual(activation.safe_existing(active)['daily.cvd']['version'],10)
if __name__=='__main__':unittest.main()
