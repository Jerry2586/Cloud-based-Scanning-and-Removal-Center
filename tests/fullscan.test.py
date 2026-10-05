"""Fault and recovery coverage for a root-owned disk-backed scan queue."""
import copy, importlib.util, json, os, pathlib, sqlite3, tempfile, threading, unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('agent',pathlib.Path(__file__).parents[1]/'src/host/agent.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
f=a.fullscan
ENGINE={'installed':True,'state':'configured','database_version':7,'database_at':f.utc(),'signatures':10}
@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'requires root-owned Linux state and pinned openat')
class QueueTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name)
  self.scope=self.root/'scope';self.scope.mkdir();self.state=self.root/'state';self.published=[]
  self.profile={'schema':'ironcurtain-profile/v1','program_roots':[str(self.scope)],'business_roots':[]}
 def runner(self,args,**kwargs):
  self.assertIn('--official-db-only=yes',args);self.assertIn('--fail-if-cvd-older-than=7',args);self.assertEqual(args[-2:],['--','-'])
  data=os.read(kwargs['input_fd'],f.MAX_SIZE+1)
  hit=b'TEST_VIRUS' in data
  return (1 if hit else 0),('stdin: IronCurtain.Test FOUND\n' if hit else '')+'Scanned files: 1\nInfected files: '+str(int(hit))+'\n'
 def task(self,run=None,publish=None,**kw):
  return f.FullScan(self.profile,self.state,run or self.runner,a.secure_fd,dict(ENGINE),'/fixture/database',publish or (lambda r:self.published.append(copy.deepcopy(r))),**kw)
 def files(self):
  (self.scope/'a-clean').write_bytes(b'clean');(self.scope/'b-virus').write_bytes(b'TEST_VIRUS')
 def test_clean_infected_real_counts_and_pinned_evidence(self):
  self.files();r=self.task().run();self.assertEqual(r['state'],'finished');self.assertEqual((r['indexed'],r['processed'],r['clean'],r['infected'],r['bytes_scanned']),(2,2,1,1,15))
  self.assertTrue(f.valid_report(r));self.assertEqual(len(r['findings']),1);self.assertTrue(f.valid_finding(r['findings'][0]));self.assertEqual((self.scope/'b-virus').read_bytes(),b'TEST_VIRUS')
 def test_no_files_or_no_engine_is_never_clean(self):
  self.assertEqual(self.task().run()['state'],'partial');task=self.task();task.engine['state']='unavailable';self.assertEqual(task.run()['state'],'failed')
 def test_limits_and_missing_statistics_are_not_clean(self):
  self.files()
  for code,text,key in [(0,'', 'errors'),(None,'timeout','errors'),(0,'Scanned files: 0\nInfected files: 0\n','skipped'),(1,'Heuristics.Limits.Exceeded\nScanned files: 1\nInfected files: 1\n','skipped')]:
   with self.subTest(key=key,text=text):
    r=self.task(run=lambda *args,**kwargs:(code,text)).run();self.assertEqual(r['state'],'partial');self.assertEqual(r['clean'],0);self.assertEqual(r[key],2)
 def test_file_changed_after_index_cannot_be_clean(self):
  self.files()
  def publish(r):
   if r['state']=='scanning' and r['processed']==0:(self.scope/'a-clean').write_bytes(b'changed-size')
  r=self.task(publish=publish).run();self.assertEqual(r['errors'],1);self.assertEqual(r['clean'],0);self.assertEqual(r['state'],'partial')
 def test_path_replacement_while_engine_reads_is_error(self):
  (self.scope/'a-clean').write_bytes(b'clean')
  def run(args,**kw):
   (self.scope/'a-clean').rename(self.scope/'old');(self.scope/'a-clean').write_bytes(b'clean');return self.runner(args,**kw)
  r=self.task(run=run).run();self.assertEqual(r['errors'],1);self.assertEqual(r['bytes_scanned'],0)
 def test_database_changed_during_scan_rejects_result(self):
  self.files();changed=dict(ENGINE)
  def run(args,**kw):
   result=self.runner(args,**kw);changed['database_version']=8;return result
  r=self.task(run=run,database_status=lambda:changed).run();self.assertEqual(r['state'],'partial');self.assertEqual(r['processed'],0);self.assertEqual(r['infected'],0)
 def test_pause_resume_retains_counts_and_committed_timestamp(self):
  self.files();stop=threading.Event()
  def run(args,**kw):
   result=self.runner(args,**kw);stop.set();return result
  first=self.task(run=run,stop=stop).run();self.assertEqual(first['state'],'paused');self.assertEqual(first['processed'],1)
  db=sqlite3.connect(self.state/'full-scan.sqlite');saved=json.loads(db.execute("SELECT value FROM meta WHERE key='report'").fetchone()[0]);db.close()
  self.assertEqual(saved['updated_at'],first['updated_at']);self.assertTrue(f.valid_report(saved))
  second=self.task().run();self.assertEqual(second['state'],'finished');self.assertEqual(second['processed'],2);self.assertEqual(second['bytes_scanned'],15);self.assertTrue(any('继续' in x for x in second['reasons']))
 def test_corrupt_resume_counters_fail_closed(self):
  self.files();stop=threading.Event();stop.set();self.task(stop=stop).run()
  db=sqlite3.connect(self.state/'full-scan.sqlite');r=json.loads(db.execute("SELECT value FROM meta WHERE key='report'").fetchone()[0]);r['indexed']+=1
  db.execute("UPDATE meta SET value=? WHERE key='report'",(json.dumps(r),));db.commit();db.close()
  self.assertEqual(self.task().run()['state'],'failed')
 def test_crash_after_queue_commit_can_resume_without_losing_file(self):
  self.files()
  def publish(r):
   if r['processed']==1:raise RuntimeError('simulated JSON publication interruption')
  with self.assertRaises(RuntimeError):self.task(publish=publish).run()
  resumed=self.task().run();self.assertEqual(resumed['state'],'finished');self.assertEqual(resumed['processed'],2);self.assertEqual(resumed['infected'],1)
 def test_symlink_and_hardlink_queue_rejected(self):
  self.state.mkdir(mode=0o700);target=self.root/'target';target.write_bytes(b'not sqlite');os.chmod(target,0o600)
  (self.state/'full-scan.sqlite').symlink_to(target);self.assertEqual(self.task().run()['state'],'failed');(self.state/'full-scan.sqlite').unlink()
  os.link(target,self.state/'full-scan.sqlite');self.assertEqual(self.task().run()['state'],'failed');self.assertEqual(target.read_bytes(),b'not sqlite')
 def test_index_limit_symlink_and_large_file_are_visible_gaps(self):
  self.files();r=self.task(maximum=1).run();self.assertEqual(r['state'],'partial');self.assertFalse(r['index_complete'])
  (self.scope/'linked').symlink_to(self.scope/'a-clean');r=self.task().run();self.assertEqual(r['state'],'partial');self.assertGreater(r['skipped'],0)
  (self.scope/'linked').unlink()
  with (self.scope/'big').open('wb') as stream:stream.truncate(f.MAX_SIZE+1)
  r=self.task().run();self.assertEqual(r['state'],'partial');self.assertEqual(r['skipped'],1)
 def test_wal_and_shared_memory_sidecars_are_rejected_without_following_links(self):
  self.files();self.state.mkdir(mode=0o700)
  for suffix in ['-wal','-shm']:
   sidecar=self.state/('full-scan.sqlite'+suffix);sidecar.symlink_to(self.root/'missing')
   self.assertEqual(self.task().run()['state'],'failed');self.assertTrue(sidecar.is_symlink());sidecar.unlink()
 def test_final_database_check_prevents_finished_after_last_publish(self):
  self.files();changed=dict(ENGINE)
  def publish(r):
   if r['processed']==2:changed['database_generation']='b'*64
  r=self.task(publish=publish,database_status=lambda:changed).run();self.assertEqual(r['processed'],2);self.assertEqual(r['state'],'partial');self.assertTrue(any('汇总' in x for x in r['reasons']))
 def test_same_version_database_replacement_invalidates_resume(self):
  self.files();stop=threading.Event()
  def run(args,**kw):
   result=self.runner(args,**kw);stop.set();return result
  first=self.task(run=run,stop=stop).run();self.assertEqual(first['processed'],1)
  task=self.task();task.engine['database_generation']='b'*64;second=task.run();self.assertEqual(second['state'],'finished');self.assertFalse(any('继续' in x for x in second['reasons']))
 def test_profile_change_reindexes_instead_of_reusing_old_queue(self):
  self.files();stop=threading.Event();stop.set();self.task(stop=stop).run();self.profile['name']='changed';r=self.task().run();self.assertEqual(r['state'],'finished');self.assertFalse(any('继续' in x for x in r['reasons']))
class ReportTests(unittest.TestCase):
 def test_malformed_reports_are_rejected(self):
  self.assertFalse(f.valid_report(None));self.assertFalse(f.valid_report({'schema':'ironcurtain-full-scan/v1','state':'finished'}));self.assertFalse(f.valid_finding({'id':'fake'}))
if __name__=='__main__':unittest.main()
