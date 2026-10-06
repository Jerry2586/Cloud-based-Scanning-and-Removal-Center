"""Portable report/queue tests; Linux/root executable checks run in Go CI."""
import copy, importlib.util, json, pathlib, tempfile, threading, unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('multi',pathlib.Path(__file__).parents[1]/'src/host/multi_engine.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
DIGEST='a'*64

def report():
    now=m.stamp()
    return dict(schema='ironcurtain-multi-engine/v1',job_id='b'*64,profile_digest=DIGEST,state='running',started_at=now,updated_at=now,completed=0,total=4,coverage=0,
      engines=[dict(id=i,state='queued',detail='queued',completed=0,total=0,finding_total=0,findings=[]) for i in m.IDS])

class Agent:
    def __init__(self,path):
        self.state_dir=path;self.profile={};self.lock=threading.Lock();self.full_running=False;self.result={'state':'idle'};self.inventory={};self.clear=True
    def clear_checkup(self):return self.clear

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=pathlib.Path(self.temp.name);self.agent=Agent(self.path)
        self.saved=[]
        def missing(*a):raise FileNotFoundError()
        self.tools={'read':missing,'write':lambda p,v:self.saved.append(copy.deepcopy(v)),'digest':lambda p:DIGEST,'updating':lambda:'idle'}
    def tearDown(self):self.temp.cleanup()
    def bridge(self):return m.Bridge(self.agent,'/etc/ironcurtain/local/profile.json',self.tools)
    def test_report_rejects_forged_coverage_category_order_and_time(self):
        good=report();self.assertTrue(m.valid(good,DIGEST))
        for edit in (lambda x:x.update(coverage=4),lambda x:x.update(profile_digest='x'),lambda x:x.update(updated_at='broken'),lambda x:x['engines'].reverse(),lambda x:x['engines'][0].update(finding_total=True)):
            bad=copy.deepcopy(good);edit(bad);self.assertFalse(m.valid(bad,DIGEST))
        bad=copy.deepcopy(good);bad['engines'][2].update(findings=[dict(kind='malware',severity='high',target='p',rule='r',detail='d')],finding_total=1)
        self.assertFalse(m.valid(bad,DIGEST))
    def test_restart_keeps_terminal_evidence_and_marks_interrupted_work(self):
        saved=report();saved['engines'][0].update(state='complete',completed=1,total=1,finding_total=1,findings=[dict(kind='malware',severity='high',target='/site/test',rule='EICAR',detail='digest')]);saved.update(completed=1,coverage=1)
        self.tools['read']=lambda *a:copy.deepcopy(saved)
        bridge=self.bridge();value=bridge.status();self.assertEqual(value['state'],'failed');self.assertEqual(value['engines'][0],saved['engines'][0]);self.assertTrue(m.valid(value,DIGEST));self.assertEqual(value['completed'],4)
    def test_damaged_saved_report_is_not_clean(self):
        self.tools['read']=lambda *a:{'state':'finished'}
        self.assertEqual(self.bridge().status()['state'],'unavailable')
    def test_conflicts_shutdown_and_persistence_failure_never_launch(self):
        for kind,expected in [('full',409),('legacy',409),('update',409),('closing',503),('clear',503),('write',503)]:
            self.agent.full_running=kind=='full';self.agent.result['state']='running' if kind=='legacy' else 'idle';self.agent.clear=kind!='clear'
            self.tools['updating']=lambda:'running' if kind=='update' else 'idle'
            self.tools['write']=lambda *a:None
            if kind=='write':
                def fail(*a):raise OSError('disk full')
                self.tools['write']=fail
            bridge=self.bridge();bridge.closing=kind=='closing'
            with patch.object(m.threading,'Thread') as thread:
                self.assertEqual(bridge.trigger()[0],expected,kind);thread.assert_not_called()
    def test_accepted_request_has_fixed_targets_and_cooldown(self):
        bridge=self.bridge()
        with patch.object(m.threading,'Thread') as thread:
            status,value=bridge.trigger();self.assertEqual(status,202);self.assertTrue(m.valid(value,DIGEST));thread.assert_called_once();self.assertEqual(bridge.trigger()[0],409)
            bridge.running=False;self.assertEqual(bridge.trigger()[0],429)
    def test_snapshot_copy_and_failed_start(self):
        bridge=self.bridge();bridge.value=report();snap=bridge.status();snap['engines'][0]['state']='complete';self.assertEqual(bridge.status()['engines'][0]['state'],'queued')
        with patch.object(m.threading,'Thread',side_effect=RuntimeError('cannot start')):
            status,value=bridge.trigger();self.assertEqual(status,503);self.assertEqual(value['state'],'failed');self.assertFalse(bridge.running)
    def test_close_prevents_future_start(self):
        bridge=self.bridge();bridge.close();self.assertEqual(bridge.trigger()[0],503)

if __name__=='__main__':unittest.main()
