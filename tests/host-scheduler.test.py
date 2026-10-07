"""Periodic work must preserve real evidence, mutual exclusion and restart history."""
import copy, importlib.util, threading, unittest
from pathlib import Path
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('schedule', Path(__file__).parents[1] / 'src/host/scheduler.py')
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)

class SchedulerTest(unittest.TestCase):
    def setUp(self):
        self.now=1700000000; self.mono=1000; self.saved=None; self.writes=[]; self.starts=[]; self.failure=False
        self.code=202; self.observed='running'
        self.scheduler=self.make()
    def read(self, file, maximum):
        if self.saved is None: raise FileNotFoundError()
        return copy.deepcopy(self.saved)
    def write(self, file, value):
        if self.failure: raise OSError('disk unavailable')
        self.saved=copy.deepcopy(value); self.writes.append(copy.deepcopy(value))
    def start(self, kind):
        self.starts.append(kind)
        # Dispatch identity is committed before an external task may run.
        self.assertEqual(self.saved['records'][kind]['state'], 'dispatching')
        return self.code, {'job_id' if kind=='engines' else 'task_id': 'a'*(64 if kind=='engines' else 32)}
    def observe(self, kind, task): return self.observed
    def make(self): return s.Scheduler('/state', self.read, self.write, self.start, self.observe, lambda:self.mono, lambda:self.now)
    def advance(self, seconds): self.mono+=seconds; self.now+=seconds
    def test_default_offline_quick_check_is_real_and_serial(self):
        self.scheduler.tick(); self.scheduler.tick()
        self.assertEqual(self.starts, ['quick'])
        self.assertEqual(self.scheduler.status()['records']['quick']['state'], 'running')
        self.observed='partial'; self.scheduler.tick()
        self.assertEqual(self.scheduler.status()['records']['quick']['state'], 'partial')
        self.advance(299); self.scheduler.tick(); self.assertEqual(len(self.starts),1)
        self.advance(1); self.scheduler.tick(); self.assertEqual(len(self.starts),2)
    def test_busy_or_cooldown_defers_without_claiming_completion(self):
        for code in (409,429):
            self.code=code; self.scheduler=self.make(); self.scheduler.due['quick']=self.mono
            self.scheduler.tick()
            self.assertEqual(self.scheduler.status()['records']['quick']['state'],'deferred')
            self.assertIsNone(self.scheduler.status()['records']['quick']['task_id'])
            before=len(self.starts); self.advance(59); self.scheduler.tick(); self.assertEqual(len(self.starts),before)
            self.advance(1); self.scheduler.tick(); self.assertEqual(len(self.starts),before+1)
    def test_write_failure_before_dispatch_never_starts_work(self):
        self.failure=True; self.scheduler.tick()
        self.assertEqual(self.starts,[]); self.assertEqual(self.scheduler.status()['state'],'unavailable')
    def test_missing_engine_or_bad_identity_retries_at_interval(self):
        self.code=503; self.scheduler.tick()
        self.assertEqual(self.scheduler.status()['records']['quick']['state'],'unavailable')
        self.assertEqual(self.scheduler.due['quick'],self.mono+300)
        self.scheduler.start=lambda kind:(202,{'task_id':'fake'})
        self.advance(300); self.scheduler.tick()
        self.assertEqual(self.scheduler.status()['records']['quick']['state'],'unavailable')
    def test_revision_and_strict_bounds_reject_untrusted_configuration(self):
        value=copy.deepcopy(self.scheduler.config)
        code,_=self.scheduler.configure(value); self.assertEqual(code,200)
        self.assertEqual(self.scheduler.configure(value)[0],409)
        for field, bad in (('enabled',1),('interval_seconds',True),('interval_seconds',1),('interval_seconds',86401)):
            value=copy.deepcopy(self.scheduler.config); value['jobs']['quick'][field]=bad
            self.assertEqual(self.scheduler.configure(value)[0],400)
        value=copy.deepcopy(self.scheduler.config); value['command']='rm'
        self.assertEqual(self.scheduler.configure(value)[0],400)
    def test_reconfigure_cannot_race_running_or_dispatching_job(self):
        self.scheduler.tick(); self.assertEqual(self.scheduler.configure(copy.deepcopy(self.scheduler.config))[0],409)
        self.scheduler.gate.acquire()
        try: self.assertEqual(self.scheduler.configure(copy.deepcopy(self.scheduler.config))[0],409)
        finally: self.scheduler.gate.release()
    def test_restart_marks_running_and_dispatching_interrupted(self):
        self.scheduler.tick(); restored=self.make()
        self.assertEqual(restored.status()['records']['quick']['state'],'interrupted')
        self.assertEqual(restored.due['quick'],self.mono+300)
        self.saved['records']['quick'].update(state='dispatching',task_id=None,last_started_at=None,last_finished_at=None,next_at=None)
        self.assertEqual(self.make().status()['records']['quick']['state'],'interrupted')
    def test_impossible_records_fail_closed_without_overwriting_storage(self):
        mutations = [
            {'state':'running'},
            {'state':'complete','attempts':1,'last_attempt_at':s.stamp(self.now),'last_finished_at':s.stamp(self.now)},
            {'state':'dispatching','attempts':1,'last_attempt_at':s.stamp(self.now),'last_finished_at':s.stamp(self.now)},
            {'state':'deferred','attempts':1,'task_id':'a'*32,'last_attempt_at':s.stamp(self.now),'last_started_at':s.stamp(self.now),'last_finished_at':s.stamp(self.now)},
            {'state':'idle','attempts':1},
            {'state':'unavailable','attempts':1,'last_attempt_at':s.stamp(self.now),'last_finished_at':s.stamp(self.now-1)},
        ]
        initial=copy.deepcopy(self.saved)
        for changes in mutations:
            with self.subTest(changes=changes):
                self.saved=copy.deepcopy(initial); self.saved['records']['quick'].update(changes)
                snapshot=copy.deepcopy(self.saved); restored=self.make(); restored.tick()
                self.assertEqual(restored.status()['state'],'unavailable')
                self.assertEqual(self.saved,snapshot); self.assertEqual(self.starts,[])
    def test_corrupt_storage_preserved_and_fail_closed(self):
        self.saved['records']['quick']['state']='invented'; snapshot=copy.deepcopy(self.saved)
        restored=self.make(); restored.tick()
        self.assertEqual(restored.status()['state'],'unavailable'); self.assertEqual(self.saved,snapshot)
        self.assertEqual(self.starts,[])
    def test_monotonic_deadline_survives_wall_clock_change(self):
        self.scheduler.tick(); self.observed='complete'; self.scheduler.tick()
        self.now-=10000; self.mono+=299; self.scheduler.tick(); self.assertEqual(len(self.starts),1)
        self.mono+=1; self.scheduler.tick(); self.assertEqual(len(self.starts),2)
        self.observed='complete'; self.scheduler.tick()
        record=self.scheduler.status()['records']['quick']
        self.assertGreaterEqual(record['last_finished_at'],record['last_started_at'])
    def test_disabled_jobs_have_no_deadline_and_three_jobs_never_overlap(self):
        value=copy.deepcopy(self.scheduler.config)
        for kind, job in value['jobs'].items():
            job['enabled']=True; job['interval_seconds']=s.LIMITS[kind][0]
        self.assertEqual(self.scheduler.configure(value)[0],200)
        self.advance(3600); self.scheduler.tick(); self.scheduler.tick(); self.assertEqual(self.starts,['quick'])
        self.observed='complete'; self.scheduler.tick(); self.assertEqual(self.starts,['quick','engines'])
        self.scheduler.tick(); self.assertEqual(self.starts,['quick','engines','files'])
        self.scheduler.tick(); value=copy.deepcopy(self.scheduler.config)
        for job in value['jobs'].values(): job['enabled']=False
        self.assertEqual(self.scheduler.configure(value)[0],200)
        self.assertTrue(all(record['next_at'] is None for record in self.scheduler.status()['records'].values()))
        self.advance(604800); count=len(self.starts); self.scheduler.tick(); self.assertEqual(len(self.starts),count)
    def test_dispatching_restart_survives_wall_clock_rollback(self):
        self.scheduler.tick()
        record=self.saved['records']['quick']
        record.update(state='dispatching', task_id=None, last_started_at=None)
        attempt=record['last_attempt_at']; self.now-=10000
        restored=self.make()
        self.assertEqual(restored.status()['state'],'ready')
        self.assertEqual(self.saved['records']['quick']['state'],'interrupted')
        self.assertGreaterEqual(self.saved['records']['quick']['last_finished_at'],attempt)
        self.assertEqual(self.make().status()['state'],'ready')
    def test_dispatching_interrupt_survives_wall_clock_rollback(self):
        self.scheduler.tick()
        record=self.scheduler.records['quick']
        record.update(state='dispatching', task_id=None, last_started_at=None)
        attempt=record['last_attempt_at']; self.now-=10000
        self.scheduler.interrupt()
        self.assertEqual(self.saved['records']['quick']['state'],'interrupted')
        self.assertGreaterEqual(self.saved['records']['quick']['last_finished_at'],attempt)
        self.assertEqual(self.make().status()['state'],'ready')
    def test_shutdown_persists_interruption(self):
        self.scheduler.tick(); stop=threading.Event(); stop.set(); self.scheduler.run(stop)
        self.assertEqual(self.saved['records']['quick']['state'],'interrupted')
    def test_observation_failure_cannot_become_success(self):
        self.scheduler.tick(); self.scheduler.observe=lambda *args:(_ for _ in ()).throw(OSError())
        self.scheduler.tick(); self.assertEqual(self.scheduler.status()['records']['quick']['state'],'unavailable')

class AgentContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('host',Path(__file__).parents[1]/'src/host/agent.py')
        cls.host=importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.host)
    def test_updates_use_nested_check_and_job_records(self):
        for key in ('check','job'):
            self.assertTrue(self.host.maintenance_active({key:{'state':'running'}},lambda:False))
            self.assertTrue(self.host.maintenance_active({key:{'state':'unavailable'}},lambda:False))
        self.assertFalse(self.host.maintenance_active({'check':{'state':'idle'},'job':{'state':'finished'}},lambda:False))
        self.assertTrue(self.host.maintenance_active({},lambda:True))
    def test_scheduled_result_is_bound_to_task_and_coverage(self):
        agent=object.__new__(self.host.Agent); agent.lock=threading.Lock()
        agent.result={'task_id':'a'*32,'state':'finished','checks':[{'state':'ok'} for _ in self.host.IDS]}
        self.assertEqual(agent.scheduled_observe('quick','a'*32),'complete')
        self.assertEqual(agent.scheduled_observe('quick','b'*32),'interrupted')
        agent.result['checks'][0]['state']='unavailable'
        self.assertEqual(agent.scheduled_observe('quick','a'*32),'partial')
        agent.full_result={'task_id':'a'*32,'state':'finished','index_complete':False,'errors':0,'skipped':0}
        self.assertEqual(agent.scheduled_observe('files','a'*32),'partial')
    def test_active_maintenance_defers_before_any_scan(self):
        agent=object.__new__(self.host.Agent); agent.maintenance=lambda:True
        self.assertEqual(agent.scheduled_start('quick')[0],409)

if __name__=='__main__': unittest.main()
