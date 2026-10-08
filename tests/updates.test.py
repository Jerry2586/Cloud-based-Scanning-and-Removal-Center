import importlib.util, pathlib, tempfile, json, hashlib, subprocess, os, unittest, contextlib, io
from unittest.mock import patch
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location('updates',pathlib.Path(__file__).parents[1]/'src/host/updates.py')
u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u)
class UpdatesTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=pathlib.Path(self.tmp.name)/'local';self.current=self.base/'releases/0.5.4';self.current.mkdir(parents=True)
  for folder in ['src','scripts','docker']:(self.current/folder).mkdir()
  for name in ['release-public.pem','.dockerignore','install.sh']:(self.current/name).write_text('fixture')
  (self.current/'package.json').write_text('{"version":"0.5.4"}')
  (self.current/'release-contract.json').write_text('{"artifact_prefix":"APPGOG-Cloud-Security-Center"}')
  try:(self.base/'current').symlink_to(self.current,target_is_directory=True)
  except OSError:self.skipTest('directory symlink unavailable')
  self.read=lambda p,limit:pathlib.Path(p).read_bytes() if pathlib.Path(p).stat().st_size<=limit else (_ for _ in ()).throw(ValueError('budget'))
  digest=u.payload_digest(self.current,self.read);(self.current/'.payload-sha256').write_text(digest)
  (self.base/'install.json').write_text(json.dumps({'schema':1,'role':'local','version':'0.5.4','host':'154.219.110.71','bind':'0.0.0.0','image':'ironcurtain-security:0.5.4-local-'+digest}))
 def release(self,v='0.5.5'):
  names=['APPGOG-Cloud-Security-Center-'+v+x for x in ['.run','.run.sha256','.tar.gz','.tar.gz.sha256']]+['release-manifest.json','release-manifest.json.sig']
  return {'draft':False,'prerelease':False,'tag_name':'v'+v,'assets':[{'id':i+1,'name':n,'state':'uploaded'} for i,n in enumerate(names)]}
 def check(self,release=None,fail=False):
  def get(url,limit,accept=None):
   if '/git/ref/heads/main' in url:return json.dumps({'object':{'type':'commit','sha':'c'*40}}).encode()
   if '/git/ref/tags/v' in url:return json.dumps({'object':{'type':'tag','sha':'e'*40}}).encode()
   if '/git/tags/' in url:return json.dumps({'object':{'type':'commit','sha':'d'*40}}).encode()
   if '/releases/latest' in url:
    if fail:raise ValueError('network')
    return json.dumps(release or self.release()).encode()
   return b'fixture'
  return u.check_release(self.read,self.base,get,verify=lambda *a:{'run_sha256':'a'*64})
 def test_cloud_receipt_and_jobs_never_use_local_role(self):
  saved=json.loads((self.base/'install.json').read_bytes());saved['role']='cloud';saved['image']=saved['image'].replace('-local-','-cloud-');(self.base/'install.json').write_text(json.dumps(saved))
  self.assertEqual(u.receipt(self.read,self.base,'cloud')[0]['role'],'cloud')
  with self.assertRaises(ValueError):u.receipt(self.read,self.base)
  calls=[]
  def run(args,**kw):calls.append(args);return SimpleNamespace(returncode=0,stdout='inactive')
  bridge=u.Bridge(self.read,None,run,self.base,self.base/'data',role='cloud')
  self.assertEqual(bridge.status()['installed_version'],'0.5.4')
  self.assertEqual(bridge.trigger('update')[0],202)
  self.assertEqual(calls[-1],['/usr/bin/systemctl','start','--no-block','ironcurtain-panel-cloud-update.service'])
  self.assertFalse(any(arg in ('ironcurtain-panel-update.service','ironcurtain-panel-check.service') for args in calls for arg in args))
  with self.assertRaises(ValueError):u.Bridge(None,None,role='../../local')
 def test_check_real_digest_and_source_survives_failed_release(self):
  good=self.check();self.assertEqual(good['state'],'verified');self.assertTrue(good['update_available']);self.assertTrue(good['source']['has_unreleased_changes'])
  failed=self.check(fail=True);self.assertEqual(failed['state'],'failed');self.assertEqual(failed['source']['commit'],'c'*40);self.assertFalse(failed['update_available'])
  (self.current/'src/injected.py').write_text('bad');changed=self.check();self.assertEqual(changed['installed_integrity'],'mismatch');self.assertFalse(changed['update_available'])
 def test_release_contract_and_downgrades_block(self):
  for change in [lambda r:r.update(draft=True),lambda r:r.update(prerelease=True),lambda r:r['assets'].pop(),lambda r:r['assets'][0].update(id=-1),lambda r:r['assets'].append(r['assets'][0])]:
   value=self.release();change(value);self.assertEqual(self.check(value)['state'],'failed')
  self.assertEqual(self.check(self.release('0.5.3'))['state'],'failed')
  same=self.check(self.release('0.5.4'));self.assertEqual(same['state'],'verified');self.assertFalse(same['update_available'])
 def test_bridge_fixed_jobs_busy_cooldown_and_interrupted_state(self):
  calls=[]
  def run(args,**kw):calls.append(args);return SimpleNamespace(returncode=0,stdout='inactive')
  bridge=u.Bridge(self.read,lambda *a:None,run,self.base,self.base/'data')
  self.assertEqual(bridge.trigger('shell')[0],400);self.assertEqual(calls,[])
  self.assertEqual(bridge.trigger('check')[0],202);self.assertEqual(calls[-1],['/usr/bin/systemctl','start','--no-block','ironcurtain-panel-check.service'])
  self.assertEqual(bridge.trigger('update')[0],429)
  data=self.base/'data/panel-update';data.mkdir(parents=True);(data/'job.json').write_text('{"state":"running"}')
  self.assertEqual(bridge.status()['job']['state'],'failed')
  busy=u.Bridge(self.read,None,lambda *a,**kw:SimpleNamespace(returncode=0,stdout='activating'),self.base,self.base/'data')
  self.assertEqual(busy.trigger('update')[0],409)
 def test_canonical_versions_and_private_status(self):
  for value in ['00.1.0','1.02.3',None,{},'1.0']:
   with self.assertRaises(ValueError):u.version(value)
  for kind in ['check','job']:
   state=u.public_record({'state':'failed','reason':'TOKEN','command':'sh','source':None},kind);self.assertNotIn('TOKEN',json.dumps(state));self.assertNotIn('command',state)
 @unittest.skipUnless(os.name=='posix' and pathlib.Path('/usr/bin/openssl').exists(),'Linux OpenSSL signing')
 def test_actual_ed25519_signature_tamper_and_wrong_key(self):
  key=pathlib.Path(self.tmp.name)/'key';pub=pathlib.Path(self.tmp.name)/'pub';data=pathlib.Path(self.tmp.name)/'manifest';sig=pathlib.Path(self.tmp.name)/'sig'
  subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(key)],check=True,capture_output=True)
  subprocess.run(['openssl','pkey','-in',str(key),'-pubout','-out',str(pub)],check=True,capture_output=True)
  contract={'artifact_prefix':'APPGOG-Cloud-Security-Center'}
  m={'schema':1,'product':'appgog-cloud-security-center','version':'0.5.5','run_name':'APPGOG-Cloud-Security-Center-0.5.5.run','run_sha256':'a'*64,'tar_name':'APPGOG-Cloud-Security-Center-0.5.5.tar.gz','tar_sha256':'b'*64,'environment':{'schema':1,'product':'appgog-cloud-security-center',**contract}}
  data.write_bytes(json.dumps(m).encode());subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(key),'-in',str(data),'-out',str(sig)],check=True,capture_output=True)
  self.assertEqual(u.signed_manifest(data.read_bytes(),sig.read_bytes(),pub.read_bytes(),'0.5.5',contract),m)
  for modified in [data.read_bytes()+b' ',b'{}']:
   with self.assertRaises(ValueError):u.signed_manifest(modified,sig.read_bytes(),pub.read_bytes(),'0.5.5',contract)
  with self.assertRaises(ValueError):u.signed_manifest(data.read_bytes(),sig.read_bytes(),pub.read_bytes(),'0.5.6',contract)
  other=pathlib.Path(self.tmp.name)/'other';otherpub=pathlib.Path(self.tmp.name)/'otherpub'
  subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(other)],check=True,capture_output=True)
  subprocess.run(['openssl','pkey','-in',str(other),'-pubout','-out',str(otherpub)],check=True,capture_output=True)
  with self.assertRaises(ValueError):u.signed_manifest(data.read_bytes(),sig.read_bytes(),otherpub.read_bytes(),'0.5.5',contract)
 @unittest.skipUnless(os.name=='posix','Linux shell digest contract')
 def test_payload_digest_matches_installer_and_rejects_symlinks(self):
  (self.current/'src/file.js').write_text('public source');(self.current/'src/__pycache__').mkdir();(self.current/'src/__pycache__/cache.pyc').write_bytes(b'ignored')
  script="(find src docker scripts -type f ! -path '*/__pycache__/*' -print0; printf 'package.json\\0release-contract.json\\0release-public.pem\\0.dockerignore\\0install.sh\\0') | sort -z | while IFS= read -r -d '' file; do sha256sum \"$file\"; done | sha256sum"
  actual=subprocess.run(['bash','-c',script],cwd=self.current,check=True,text=True,capture_output=True).stdout.split()[0]
  self.assertEqual(u.payload_digest(self.current,self.read),actual)
  (self.current/'src/link').symlink_to(self.current/'package.json')
  with self.assertRaises(ValueError):u.payload_digest(self.current,self.read)
class FixedJobTests(unittest.TestCase):
 @unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'Linux root fixed service job')
 def test_check_preflight_failure_records_time_and_redacts_exception(self):
  with tempfile.TemporaryDirectory(prefix='ironcurtain-job-test-',dir='/etc') as temporary:
   base=pathlib.Path(temporary)/'local';base.mkdir(mode=0o700)
   (base/'install.json').write_text('{}');(base/'install.json').chmod(0o600)
   diagnostics=io.StringIO()
   with patch.object(u,'BASE',base),patch.object(u,'DATA',base),patch.object(u,'check_release',side_effect=ValueError('secret-token-should-never-log')),contextlib.redirect_stderr(diagnostics):
    with self.assertRaises(SystemExit):u.work('check')
   record=json.loads((base/'panel-update/check.json').read_text())
   self.assertEqual(record['state'],'failed');self.assertTrue(record['checked_at']);self.assertEqual(record['installed_integrity'],'unavailable');self.assertFalse(record['update_available'])
   self.assertNotIn('secret-token',diagnostics.getvalue());self.assertIn('ValueError',diagnostics.getvalue())
   self.assertEqual((base/'panel-update/check.json').stat().st_mode & 0o777,0o600)
 def test_cloud_upgrade_validates_its_own_installed_receipt(self):
  with tempfile.TemporaryDirectory(prefix='ironcurtain-cloud-job-test-',dir='/etc') as temporary:
   base=pathlib.Path(temporary);(base/'install.json').write_text('{}');(base/'install.json').chmod(0o600)
   checked={'state':'verified','update_available':True,'latest_version':'0.6.6'}
   saved={'version':'0.6.5','host':'192.0.2.1','bind':'0.0.0.0'}
   def read_receipt(read,actual_base,actual_role):
    self.assertEqual(actual_base,base);self.assertEqual(actual_role,'cloud')
    return ({**saved,'version':'0.6.6'} if read_receipt.called else saved,base)
   read_receipt.called=False
   def install(args,**kwargs):
    self.assertEqual(args[args.index('--role')+1],'cloud');read_receipt.called=True
    return SimpleNamespace(returncode=0)
   with patch.object(u,'role_paths',return_value=(base,base)),patch.object(u,'check_release',return_value=checked) as check,patch.object(u,'receipt',side_effect=read_receipt),patch.object(u.subprocess,'run',side_effect=install):
    u.work('update','cloud')
   self.assertEqual(check.call_args.kwargs['role'],'cloud')
   record=json.loads((base/'panel-update/job.json').read_text())
   self.assertEqual(record['state'],'finished');self.assertEqual(record['version'],'0.6.6');self.assertEqual(record['result'],'updated')
class BoundaryTests(unittest.TestCase):
 def test_canonical_versions_without_filesystem(self):
  for value in ['00.1.0','1.02.3',None,{},'1.0']:
   with self.assertRaises(ValueError):u.version(value)
 def test_redirect_keeps_tls_repository_boundary_and_strips_token(self):
  request=u.urllib.request.Request(u.API+'/releases/assets/1',headers={'Authorization':'Bearer fixture-secret'})
  handler=u.Redirects()
  redirect=handler.redirect_request(request,None,302,'Found',{},'https://release-assets.githubusercontent.com/fixture')
  self.assertFalse(redirect.has_header('Authorization'))
  for url in ['http://release-assets.githubusercontent.com/fixture','https://attacker.invalid/file','https://api.github.com/repos/other/repo/file','https://user@api.github.com/repos/'+u.PROJECT+'/file']:
   with self.assertRaises(ValueError):handler.redirect_request(request,None,302,'Found',{},url)
 def test_compact_git_refs_resolve_annotated_tags_and_bound_depth(self):
  calls=[]
  def get(url,limit):
   calls.append((url,limit))
   return json.dumps({'object':{'type':'tag' if '/git/ref/' in url else 'commit','sha':'a'*40}}).encode()
  self.assertEqual(u.git_commit(get,'tags/v0.5.5'),'a'*40)
  self.assertEqual(len(calls),2);self.assertTrue(all(n==16384 for _,n in calls))
  with self.assertRaises(ValueError):u.git_commit(lambda *a:b'{"object":{"type":"tree","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}','heads/main')
  with self.assertRaises(ValueError):u.git_commit(lambda *a:b'{"object":{"type":"tag","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}','tags/v0.5.5')
 def test_task_timeout_returns_unavailable(self):
  bridge=u.Bridge(None,None,lambda *a,**kw:(_ for _ in ()).throw(subprocess.TimeoutExpired('systemctl',1)))
  self.assertEqual(bridge.trigger('update')[0],503)
if __name__=='__main__':unittest.main()
