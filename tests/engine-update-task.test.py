"""Portable task association tests; systemd commands are controlled, not live acceptance."""
import importlib.util, pathlib, subprocess, threading, time, unittest
from unittest.mock import patch, Mock
ROOT=pathlib.Path(__file__).parents[1]
spec=importlib.util.spec_from_file_location('engine_task_agent',ROOT/'src/host/agent.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
class EngineTaskTests(unittest.TestCase):
 def setUp(self):
  self.saved={}
  def read(path,*args):
   if str(path) in self.saved:return self.saved[str(path)].copy()
   raise FileNotFoundError(str(path))
  self.read=read
  def write(path,value):self.saved[str(path)]=value.copy()
  self.write=write
  for p in [patch.object(a,'private_json',side_effect=read),patch.object(a,'atomic_json',side_effect=write)]:p.start();self.addCleanup(p.stop)
  self.agent=a.Agent({'schema':'ironcurtain-profile/v1','program_roots':['/srv/site']},pathlib.Path('/fixture/state'))
  self.agent.maintenance=lambda:False
  self.lease=Mock();self.lease.run.side_effect=lambda target: self.execute(target)
  self.agent.management_lease=lambda:self.lease
 def execute(self,target):
  try:target()
  finally:self.lease.close()
 def wait(self):
  end=time.monotonic()+2
  while (self.agent.engine_update['state']=='running' or not self.lease.close.called) and time.monotonic()<end:time.sleep(.005)
  self.assertNotEqual(self.agent.engine_update['state'],'running')
 def test_receipt_remains_bound_until_real_worker_returns_and_persists(self):
  entered,release=threading.Event(),threading.Event()
  def update(**kw):
   self.assertEqual(kw,{'wait':True});entered.set();release.wait(2)
  with patch.object(a.antivirus,'check_official_updater'),patch.object(a.antivirus,'update_status',return_value='idle'),patch.object(a.antivirus,'request_official_update',side_effect=update):
   code,receipt=self.agent.trigger_engine_update();self.assertEqual(code,202);self.assertRegex(receipt['task_id'],r'^[a-f0-9]{32}$');self.assertTrue(entered.wait(1))
   self.assertEqual(self.agent.engine_update['task_id'],receipt['task_id']);self.assertEqual(self.agent.engine_update['state'],'running');self.lease.close.assert_not_called()
   with patch.object(self.agent,'management_lease',return_value=Mock()):self.assertEqual(self.agent.trigger_engine_update()[0],409)
   for trigger in [self.agent.trigger,self.agent.trigger_full,self.agent.trigger_checkup]:
    with patch.object(self.agent,'management_lease',return_value=Mock()):self.assertEqual(trigger()[0],409)
   release.set();self.wait()
   self.assertEqual(self.agent.engine_update['state'],'finished');self.assertEqual(self.agent.engine_update['task_id'],receipt['task_id']);self.lease.close.assert_called_once()
   restored=a.Agent(self.agent.profile,self.agent.state_dir);self.assertEqual(restored.engine_update,self.agent.engine_update)
 def test_failure_is_persisted_with_the_same_id_and_cooldown_remains(self):
  with patch.object(a.antivirus,'check_official_updater'),patch.object(a.antivirus,'update_status',return_value='idle'),patch.object(a.antivirus,'request_official_update',side_effect=subprocess.CalledProcessError(1,['systemctl'])):
   code,r=self.agent.trigger_engine_update();self.assertEqual(code,202);self.wait();self.assertEqual(self.agent.engine_update['state'],'failed');self.assertEqual(self.agent.engine_update['task_id'],r['task_id'])
   self.assertEqual(self.agent.trigger_engine_update()[0],429)
 def test_failed_preflight_and_persistence_never_start_worker(self):
  with patch.object(a.antivirus,'check_official_updater',side_effect=ValueError('unit')),patch.object(a.antivirus,'update_status',return_value='idle'),patch.object(a.antivirus,'request_official_update') as updater:
   self.assertEqual(self.agent.trigger_engine_update()[0],503);updater.assert_not_called();self.lease.close.assert_called_once()
  self.lease.reset_mock()
  with patch.object(a.antivirus,'check_official_updater'),patch.object(a.antivirus,'update_status',return_value='idle'),patch.object(a,'atomic_json',side_effect=OSError('disk')),patch.object(a.antivirus,'request_official_update') as updater:
   self.assertEqual(self.agent.trigger_engine_update()[0],503);updater.assert_not_called();self.lease.close.assert_called_once()
 def test_timeout_does_not_confirm_a_successful_database_update(self):
  with patch.object(a.antivirus,'check_official_updater'),patch.object(a.antivirus,'update_status',return_value='idle'),patch.object(a.antivirus,'request_official_update',side_effect=subprocess.TimeoutExpired(['systemctl'],270)):
   code,r=self.agent.trigger_engine_update();self.assertEqual(code,202);self.wait()
   self.assertEqual(self.agent.engine_update['state'],'paused');self.assertEqual(self.agent.engine_update['task_id'],r['task_id'])
   self.assertTrue(a.valid_engine_update(self.agent.engine_update))
 def test_terminal_persistence_failure_never_exposes_success(self):
  entered,release=threading.Event(),threading.Event()
  def update(**kw):entered.set();release.wait(2)
  with patch.object(a.antivirus,'check_official_updater'),patch.object(a.antivirus,'update_status',return_value='idle'),patch.object(a.antivirus,'request_official_update',side_effect=update):
   code,r=self.agent.trigger_engine_update();self.assertEqual(code,202);self.assertTrue(entered.wait(1))
   with patch.object(a,'atomic_json',side_effect=OSError('disk')):
    release.set();end=time.monotonic()+2
    while not self.lease.close.called and time.monotonic()<end:time.sleep(.005)
    self.assertTrue(self.lease.close.called)
   self.assertEqual(self.agent.engine_update['state'],'paused');self.assertTrue(a.valid_engine_update(self.agent.engine_update));self.assertEqual(self.agent.engine_update['task_id'],r['task_id'])
   self.assertIn('保存失败',self.agent.engine_update['detail'])
   self.assertEqual(self.saved[str(self.agent.state_dir/'engine-update-report.json')]['state'],'running')
 def test_thread_start_failure_releases_lease_and_records_failure(self):
  with patch.object(a.antivirus,'check_official_updater'),patch.object(a.antivirus,'update_status',return_value='idle'),patch.object(a.threading.Thread,'start',side_effect=RuntimeError('thread')),patch.object(a.antivirus,'request_official_update') as updater:
   self.assertEqual(self.agent.trigger_engine_update()[0],503);updater.assert_not_called();self.lease.close.assert_called_once()
   self.assertEqual(self.agent.engine_update['state'],'failed');self.assertTrue(a.valid_engine_update(self.agent.engine_update))
 def test_restart_never_calls_a_previous_running_update_successful(self):
  now=a.utc();value={'schema':'ironcurtain-engine-update/v1','state':'running','task_id':'a'*32,'started_at':now,'updated_at':now,'detail':'updating'}
  self.saved[str(self.agent.state_dir/'engine-update-report.json')]=value
  restored=a.Agent(self.agent.profile,self.agent.state_dir);self.assertEqual(restored.engine_update['task_id'],value['task_id']);self.assertEqual(restored.engine_update['state'],'paused')
  self.assertTrue(a.valid_engine_update(restored.engine_update));self.assertEqual(self.saved[str(restored.state_dir/'engine-update-report.json')],restored.engine_update)
  bad={**value,'task_id':'malformed'};self.saved[str(restored.state_dir/'engine-update-report.json')]=bad
  self.assertEqual(a.Agent(self.agent.profile,self.agent.state_dir).engine_update['state'],'unavailable')
if __name__=='__main__':unittest.main()
