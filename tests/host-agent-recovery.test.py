"""Linux-root restart, profile, concurrency and local socket boundary acceptance."""
import copy, importlib.util, json, os, pathlib, tempfile, threading, unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('agent',pathlib.Path(__file__).parents[1]/'src/host/agent.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'Linux root agent persistence')
class AgentRecoveryTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name);self.root.chmod(0o700)
  self.scope=self.root/'site';self.scope.mkdir();self.state=self.root/'state'
  self.agent=a.Agent({'schema':'ironcurtain-profile/v1','program_roots':[str(self.scope)]},self.state)
  self.engine={'installed':True,'state':'configured','database_version':7,'database_at':a.utc(),'signatures':10,'database_generation':'a'*64}
 def runner(self,args,**kw):
  os.read(kw['input_fd'],65536);return 1,'stdin: IronCurtain.Test FOUND\nScanned files: 1\nInfected files: 1\n'
 def scan(self,stop=None):
  (self.scope/'bad.txt').write_bytes(b'test fixture')
  def publish(r):a.atomic_json(self.state/'full-scan-report.json',r)
  return a.fullscan.FullScan(self.agent.profile,self.state,self.runner,a.secure_fd,self.engine,'/fixture/db',publish,stop).run()
 def test_full_evidence_restored_without_separate_findings_write(self):
  r=self.scan();self.assertEqual(r['state'],'finished')
  restored=a.Agent(self.agent.profile,self.state)
  with patch.object(a.antivirus,'engine_status',return_value=self.engine):status=restored.status()
  self.assertEqual(status['findings_source'],'full');self.assertEqual(status['findings_total'],1);self.assertEqual(status['findings'][0]['path'],str(self.scope/'bad.txt'));self.assertNotIn('findings',status['full_scan'])
 def test_interrupted_full_report_restores_as_paused_and_profile_change_is_rejected(self):
  stop=threading.Event();stop.set();self.scan(stop)
  restored=a.Agent(self.agent.profile,self.state);self.assertEqual(restored.full_result['state'],'paused')
  changed=copy.deepcopy(self.agent.profile);changed['approved_tcp_ports']=[443]
  another=a.Agent(changed,self.state);self.assertEqual(another.full_result['state'],'idle');self.assertEqual(another.findings_bundle['state'],'unavailable')
 def test_corrupt_pinned_evidence_is_not_restored_or_overwritten(self):
  self.scan();file=self.state/'full-scan-report.json';value=json.loads(file.read_text());value['findings'][0]['sha256']='b'*64;a.atomic_json(file,value);before=file.read_bytes()
  restored=a.Agent(self.agent.profile,self.state);self.assertEqual(restored.full_result['state'],'idle');self.assertEqual(file.read_bytes(),before)
 def test_scan_concurrency_cooldown_and_unready_engine(self):
  with patch.object(a.antivirus,'engine_status',return_value=self.engine),patch.object(a.threading,'Thread'):
   self.assertEqual(self.agent.trigger_full()[0],202);self.assertEqual(self.agent.trigger_full()[0],409);self.assertEqual(self.agent.trigger()[0],409)
   self.agent.full_running=False;self.assertEqual(self.agent.trigger_full()[0],429)
   self.agent.last=0;self.agent.result['state']='running';self.assertEqual(self.agent.trigger_full()[0],409)
  self.agent.result['state']='idle'
  with patch.object(a.antivirus,'engine_status',return_value={'installed':False,'state':'unavailable'}):self.assertEqual(self.agent.trigger_full()[0],503)
 def test_quick_report_from_changed_profile_is_archived_and_rechecked(self):
  checks=a.Scanner(self.agent.profile,lambda *args,**kw:(None,'missing')).run_checks()
  observed={'schema':'ironcurtain-inventory/v1','state':'unavailable'}
  with patch.object(a.inventory,'discover',return_value=observed),patch.object(a.Scanner,'run_checks',return_value=checks):self.agent.scan()
  self.assertEqual(self.agent.result['state'],'finished')
  changed=copy.deepcopy(self.agent.profile);changed['approved_tcp_ports']=[443]
  restored=a.Agent(changed,self.state);self.assertEqual(restored.result['state'],'idle');self.assertTrue(restored.history_available);self.assertTrue((self.state/'previous-profile-report.json').is_file())
  with patch.object(a.inventory,'discover',return_value=observed),patch.object(a.Scanner,'run_checks',return_value=checks):restored.scan()
  saved=json.loads((self.state/'last-report.json').read_text());self.assertEqual(saved['profile_digest'],a.fullscan.profile_digest(restored.profile))
 def test_socket_parent_rejects_links_writes_nonroot_and_regular_leaf(self):
  directory=self.root/'socket';directory.mkdir(mode=0o750);leaf=directory/'scan.sock';self.assertEqual(a.prepare_socket_parent(str(leaf)),leaf)
  alias=self.root/'alias';alias.symlink_to(directory,target_is_directory=True)
  with self.assertRaises(ValueError):a.prepare_socket_parent(str(alias/'scan.sock'))
  directory.chmod(0o777)
  with self.assertRaises(ValueError):a.prepare_socket_parent(str(leaf))
  directory.chmod(0o750);os.chown(directory,65534,-1)
  with self.assertRaises(ValueError):a.prepare_socket_parent(str(leaf))
  os.chown(directory,0,-1);leaf.write_text('not a socket')
  with self.assertRaises(ValueError):a.prepare_socket_parent(str(leaf))

 def environment(self):
  checks=a.Scanner(self.agent.profile,lambda *args,**kw:(None,'missing')).run_checks()
  for check in checks: check['state']='unavailable' if check['id'].startswith('cloudflare.') else 'ok'
  observed={k:'complete' for k in ('container_state','listener_state','directory_state')};observed['environment']={k:'complete' for k in ('system_state','package_state','service_state')}
  return patch.object(a.inventory,'discover',return_value=observed),patch.object(a.Scanner,'run_checks',return_value=checks)
 def test_checkup_reserves_both_phases_and_local_updater(self):
  with patch.object(a.threading,'Thread'):
   self.assertEqual(self.agent.trigger_checkup()[0],202)
   for action in [self.agent.trigger,self.agent.trigger_full,self.agent.trigger_checkup,self.agent.trigger_engine_update]:self.assertEqual(action()[0],409)
  self.assertTrue(self.agent.full_running)
  self.agent.full_running=False;self.agent.result['state']='idle'
  self.assertEqual(self.agent.trigger_checkup()[0],429)
 def test_checkup_without_cloud_or_engine_preserves_environment_results(self):
  patches=self.environment()
  with patch.object(a.threading,'Thread'):self.assertEqual(self.agent.trigger_checkup()[0],202)
  with patches[0],patches[1],patch.object(a.antivirus,'engine_status',return_value={'installed':False,'state':'unavailable'}):self.agent.scan_checkup()
  self.assertEqual(self.agent.result['state'],'finished');self.assertEqual(len(self.agent.result['checks']),25)
  self.assertEqual(self.agent.checkup['state'],'partial');self.assertFalse(self.agent.full_running)
  self.assertTrue(any('病毒引擎' in x for x in self.agent.checkup['reasons']))
 def test_checkup_file_stage_retains_reservation_and_finishes(self):
  patches=self.environment()
  with patch.object(a.threading,'Thread'):self.agent.trigger_checkup()
  def files(engine,release):
   self.assertFalse(release);self.assertTrue(self.agent.full_running);self.assertEqual(self.agent.checkup['stage'],'files')
   self.agent.full_result={'state':'finished'}
  with patches[0],patches[1],patch.object(a.antivirus,'engine_status',return_value=self.engine),patch.object(self.agent,'scan_full',side_effect=files):self.agent.scan_checkup()
  self.assertEqual(self.agent.checkup['state'],'finished');self.assertFalse(self.agent.full_running)
  self.assertEqual(self.agent.checkup['environment_at'],self.agent.result['checked_at'])
 def test_checkup_missing_scope_and_file_faults_are_partial(self):
  self.agent.profile['program_roots']=[];patches=self.environment()
  with patch.object(a.threading,'Thread'):self.agent.trigger_checkup()
  with patches[0],patches[1],patch.object(a.antivirus,'engine_status',return_value=self.engine):self.agent.scan_checkup()
  self.assertEqual(self.agent.checkup['state'],'partial');self.assertTrue(any('尚未纳管' in x for x in self.agent.checkup['reasons']))
 def test_checkup_environment_failure_and_persistence_failure_release(self):
  with patch.object(a.threading,'Thread'):self.agent.trigger_checkup()
  with patch.object(a.inventory,'discover',side_effect=OSError('fixture')):self.agent.scan_checkup()
  self.assertEqual(self.agent.checkup['state'],'failed');self.assertFalse(self.agent.full_running)
  self.agent.last=0
  with patch.object(a,'atomic_json',side_effect=OSError('fixture')):self.assertEqual(self.agent.trigger_checkup()[0],503)
  self.assertFalse(self.agent.full_running)
 def test_all_scan_thread_start_failures_do_not_leave_a_running_task(self):
  for name in ('trigger','trigger_full','trigger_checkup'):
   agent=a.Agent(self.agent.profile,self.root/name)
   with patch.object(a.threading,'Thread') as thread,patch.object(a.antivirus,'engine_status',return_value=self.engine):
    thread.return_value.start.side_effect=RuntimeError('fixture')
    self.assertEqual(getattr(agent,name)()[0],503);self.assertFalse(agent.full_running);self.assertNotEqual(agent.result['state'],'running')
 def test_checkup_restart_profile_binding_and_separate_scan_invalidation(self):
  with patch.object(a.threading,'Thread'):self.agent.trigger_checkup()
  restored=a.Agent(self.agent.profile,self.state);self.assertEqual(restored.checkup['state'],'paused')
  changed=copy.deepcopy(self.agent.profile);changed['approved_tcp_ports']=[443]
  self.assertEqual(a.Agent(changed,self.state).checkup['state'],'idle')
  restored.last=0
  with patch.object(a.threading,'Thread'):self.assertEqual(restored.trigger()[0],202)
  self.assertEqual(a.Agent(self.agent.profile,self.state).checkup['state'],'idle')
 def test_unbound_finished_checkup_not_restored(self):
  stamp=a.utc();value={'schema':'ironcurtain-checkup/v1','profile_digest':a.fullscan.profile_digest(self.agent.profile),'state':'finished','stage':'complete','started_at':stamp,'environment_at':stamp,'updated_at':stamp,'reasons':[]}
  a.atomic_json(self.state/'checkup-report.json',value)
  self.assertEqual(a.Agent(self.agent.profile,self.state).checkup['state'],'idle')
 def test_local_engine_update_busy_cooldown_failure_and_fixed_action(self):
  with patch.object(a.antivirus,'update_status',return_value='idle'),patch.object(a.antivirus,'request_official_update') as request:
   self.assertEqual(self.agent.trigger_engine_update()[0],202);request.assert_called_once_with()
   self.assertEqual(self.agent.trigger_engine_update()[0],429)
   self.agent.engine_update_last=0;request.side_effect=ValueError('fixture');self.assertEqual(self.agent.trigger_engine_update()[0],503)
  with patch.object(a.antivirus,'update_status',return_value='running'):
   self.assertEqual(self.agent.trigger_engine_update()[0],409)

 def test_running_database_updater_refuses_file_and_combined_scan(self):
  with patch.object(a.antivirus,'update_status',return_value='running'),patch.object(a.antivirus,'engine_status',return_value={**self.engine,'update_state':'running'}):
   self.assertEqual(self.agent.trigger_checkup()[0],409)
   self.assertEqual(self.agent.trigger_full()[0],409)
   self.assertFalse(self.agent.full_running)
  patches=self.environment()
  with patch.object(a.threading,'Thread'),patch.object(a.antivirus,'update_status',return_value='idle'): self.assertEqual(self.agent.trigger_checkup()[0],202)
  with patches[0],patches[1],patch.object(a.antivirus,'engine_status',return_value={**self.engine,'update_state':'running'}),patch.object(self.agent,'scan_full') as files:
   self.agent.scan_checkup();files.assert_not_called()
  self.assertEqual(self.agent.checkup['state'],'partial')
  self.assertTrue(any('正在更新' in reason for reason in self.agent.checkup['reasons']))

if __name__=='__main__':unittest.main()
