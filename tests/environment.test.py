import copy, importlib.util, pathlib, unittest
spec=importlib.util.spec_from_file_location('environment',pathlib.Path(__file__).parents[1]/'src/host/environment.py')
e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)
class EnvironmentTests(unittest.TestCase):
 def setUp(self):
  self.package='ii \tapp\t1.0.0\n';self.service='ssh.service loaded active running SSH\n';self.calls=[];self.package_code=0;self.service_code=0
 def runner(self,args,**kw):
  self.calls.append(args)
  if args[0]=='dpkg-query':return self.package_code,self.package
  if args[0]=='rpm':return 0,'app.x86_64\t1.0-1\n'
  if args[0]=='systemctl':return self.service_code,self.service
  raise AssertionError(args)
 def scan(self,previous=None):return e.discover(self.runner,previous,lambda:{'ID':'ubuntu','VERSION_ID':'24.04','PRETTY_NAME':'Ubuntu'},lambda:'6.8.0')
 def test_first_observation_is_not_baseline(self):
  result=self.scan();self.assertTrue(e.valid(result));self.assertEqual(result['change_state'],'first-observation');self.assertEqual(result['packages'][0]['name'],'app');self.assertEqual(e.public(result)['running_services'],1)
 def test_added_removed_upgraded_and_service_changes(self):
  old=self.scan();self.package='ii \tapp\t2.0.0\nii \tnew-app\t1.0.0\n';self.service='ssh.service loaded failed failed SSH\nnew.service loaded active running New\n'
  result=self.scan(old);self.assertTrue(e.valid(result));self.assertEqual(result['change_state'],'compared')
  for marker in ['app','new-app','ssh.service','new.service']:self.assertTrue(any(marker in c for c in result['changes']))
  self.package='';self.service='';removed=self.scan(result);self.assertTrue(e.valid(removed));self.assertEqual(removed['changes_total'],4)
 def test_multiversion_rpm_and_reorder(self):
  old=self.scan();old['packages']=[{'name':'kernel.x86_64','version':'1-1'},{'name':'kernel.x86_64','version':'2-1'}];old['package_manager']='rpm';old['packages_digest']=e.digest(old['packages']);self.assertTrue(e.valid(old))
  self.package_code=None;self.package='dependency unavailable'
  run=self.runner
  def rpm(args,**kw):return (0,'kernel.x86_64\t2-1\nkernel.x86_64\t1-1\n') if args[0]=='rpm' else run(args,**kw)
  result=e.discover(rpm,old,lambda:old['os'],lambda:old['kernel']);self.assertEqual(result['changes'],[]);self.assertEqual(result['change_state'],'compared')
 def test_failed_query_is_unavailable_not_empty_and_no_rpm_fallback(self):
  old=self.scan();self.package_code=1;self.service_code=1;value=self.scan(old);self.assertTrue(e.valid(value));self.assertEqual(value['package_state'],'unavailable');self.assertEqual(value['service_state'],'unavailable');self.assertEqual(value['change_state'],'partial');self.assertFalse(any(x[0]=='rpm' for x in self.calls));self.assertTrue(value['issues'])
 def test_limits_invalid_tokens_and_private_input(self):
  rows,status=e.packages(''.join('ii \tp'+str(x)+'\t1\n' for x in range(4100)),'dpkg');self.assertEqual(len(rows),4096);self.assertEqual(status,'partial')
  with self.assertRaises(ValueError):e.packages('ii \tbad\\name\t1\n','dpkg')
  with self.assertRaises(ValueError):e.services('bad.service loaded active running\nbad.service loaded active running')
  for key,value in [('packages',None),('os',{'ID':'ubuntu\nTOKEN'}),('changes',['secret\n'])]:
   bad=copy.deepcopy(self.scan());bad[key]=value;self.assertFalse(e.valid(bad));self.assertEqual(e.public(bad),{'state':'unavailable'})
if __name__=='__main__':unittest.main()
