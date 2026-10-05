import copy, importlib.util, json, pathlib, unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('inventory',pathlib.Path(__file__).parents[1]/'src/host/inventory.py')
i=importlib.util.module_from_spec(spec);spec.loader.exec_module(i)
class InventoryTests(unittest.TestCase):
 def setUp(self):
  self.image='sha256:'+'a'*64;self.diff='C /app/index.js\n';self.failed=False
  self.row={'Name':'/app','Image':self.image,'Config':{'User':'1000','Env':['TOKEN=DO_NOT_EXPOSE']},'State':{'Running':True},'HostConfig':{'Privileged':True,'NetworkMode':'host','ReadonlyRootfs':False},'Mounts':[{'Source':'/srv/data','Destination':'/data','RW':True,'Type':'bind'},{'Source':'/var/run/docker.sock','Destination':'/socket','RW':True,'Type':'bind'}]}
 def runner(self,args,**kw):
  if args[:2]==['docker','ps']:return 0,'app\n'
  if args[:2]==['docker','inspect']:return 0,json.dumps([self.row])
  if args[:2]==['docker','top']:return (1,'failure') if self.failed else (0,'PID COMMAND\n1 node\n')
  if args[:2]==['docker','diff']:return 0,self.diff
  if args[0]=='ss':return 0,'LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("node",pid=123,fd=4))\n' if '-t' in args else ''
  raise AssertionError(args)
 def discover(self,**kw):return i.discover(self.runner,roots=(),exists=lambda x:x=='/srv/data',**kw)
 def test_metadata_risks_processes_listeners_and_secret_exclusion(self):
  value=self.discover();self.assertTrue(i.valid_inventory(value));self.assertEqual(value['container_state'],'complete');self.assertEqual(value['listeners'][0]['processes'][0]['pid'],123)
  self.assertIn('特权容器',value['containers'][0]['risks']);self.assertIn('敏感宿主挂载',value['containers'][0]['risks']);self.assertNotIn('TOKEN',json.dumps(value));self.assertNotIn('image_id',i.public_inventory(value)['containers'][0])
 def test_drift_does_not_auto_approve_images(self):
  before=self.discover();self.image='sha256:'+'b'*64;self.row['Image']=self.image;after=self.discover(previous=before);self.assertTrue(any('镜像变化' in x for x in after['drift']))
  self.diff='A /app/other\n';changed=self.discover(previous=after);self.assertTrue(any('可写层变化' in x for x in changed['drift']))
 def test_failed_top_is_partial_and_not_ready(self):
  self.failed=True;value=self.discover();self.assertEqual(value['container_state'],'partial');self.assertIsNone(value['containers'][0]['process_count']);self.assertTrue(value['issues'])
 def test_enrollment_adds_scope_without_approving_baselines_or_images(self):
  value=self.discover();profile={'program_roots':[],'business_roots':[],'containers':[]}
  with patch.object(i,'real_directory',return_value=True):result=i.enroll(profile,value,[x['id'] for x in value['candidates']])
  self.assertEqual(result['containers'],[{'name':'app'}]);self.assertEqual(result['business_roots'],['/srv/data']);self.assertNotIn('baseline',result);self.assertEqual(profile['containers'],[])
 def test_stale_or_malformed_inventory_cannot_enroll(self):
  value=self.discover();value['observed_at']='2000-01-01T00:00:00.000Z'
  with self.assertRaises(ValueError):i.enroll({},value,[value['candidates'][0]['id']])
  for key,item in [('containers',None),('listeners',{}),('candidates',{})]:
   bad=self.discover();bad[key]=[item];self.assertFalse(i.valid_inventory(bad));self.assertEqual(i.public_inventory(bad),{'state':'unavailable'})
 def test_empty_scope_or_unverified_engine_never_ready(self):
  value=self.discover();checks=[{'state':'ok'}]*25
  p=i.protection({},value,{'installed':True,'state':'configured'},checks,i.now());self.assertNotEqual(p['state'],'ready');self.assertTrue(any('目录' in x for x in p['issues']))
 def test_rejects_broad_roots_links_and_pseudo_filesystems(self):
  for root in ['/','/etc','/var/lib/docker','/proc/1','/srv/../etc','/opt/ironcurtain/data']:self.assertFalse(i.safe_path(root))
  self.assertTrue(i.safe_path('/srv/site'))
 def test_malformed_metadata_and_hidden_mount_truncation_are_rejected(self):
  for key,field,value in [('containers','user','root\n'),('containers','changes_digest','bad')]:
   bad=self.discover();bad[key][0][field]=value;self.assertFalse(i.valid_inventory(bad))
  bad=self.discover();bad['listeners'][0]['processes'][0]['name']='node\n';self.assertFalse(i.valid_inventory(bad))
  bad=self.discover();bad['candidates'][0]['origin']='unsafe\n';self.assertFalse(i.valid_inventory(bad))
  self.row['Mounts']=self.row['Mounts']*17;self.assertEqual(self.discover()['container_state'],'partial')
  self.assertFalse(i.safe_path('/var/lib/ironcurtain-antivirus/database'))
if __name__=='__main__':unittest.main()
