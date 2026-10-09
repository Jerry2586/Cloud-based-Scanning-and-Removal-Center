"""Portable report/queue tests; Linux/root executable checks run in Go CI."""
import copy, datetime, hashlib, importlib.util, json, os, pathlib, sys, tempfile, threading, unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('multi',pathlib.Path(__file__).parents[1]/'src/host/multi_engine.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
fspec=importlib.util.spec_from_file_location('file_scan',pathlib.Path(__file__).parents[1]/'src/host/fullscan.py')
f=importlib.util.module_from_spec(fspec);fspec.loader.exec_module(f)
DIGEST='a'*64
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def file_report():
    now=m.stamp()
    item=dict(path='/site/'+('a'*270)+'/test',signature='IronCurtain.Test',sha256='c'*64,observed_at=now,device=1,inode=2,size=3,mtime_ns=4,ctime_ns=5,mode=0o600,uid=0,gid=0,links=1)
    item['id']=digest(item)
    return dict(schema='ironcurtain-full-scan/v1',state='finished',profile_digest=DIGEST,multi_job_id='b'*64,started_at=now,updated_at=now,finished_at=now,
        indexed=2,processed=2,clean=1,infected=1,skipped=0,errors=0,bytes_scanned=6,index_complete=True,reasons=[],findings=[item],scope='enrolled-directories-only')
def with_file(value):
    summary=report();summary.update(state='partial',started_at=value['started_at'],updated_at=value['updated_at'],finished_at=value['updated_at'],completed=4,coverage=1)
    for e in summary['engines']:e.update(state='unavailable')
    summary['engines'][0].update(state='complete' if value['state']=='finished' else 'partial',completed=value['processed'],total=value['indexed'],finding_total=value['infected'],evidence_digest=digest(value))
    if value['state']!='finished':summary['coverage']=0
    return summary

def report():
    now=m.stamp()
    return dict(schema='ironcurtain-multi-engine/v1',job_id='b'*64,profile_digest=DIGEST,state='running',started_at=now,updated_at=now,completed=0,total=4,coverage=0,
      engines=[dict(id=i,state='queued',detail='queued',completed=0,total=0,finding_total=0,findings=[]) for i in m.IDS])

class Agent:
    def __init__(self,path):
        self.state_dir=path;self.profile={};self.lock=threading.Lock();self.full_running=False;self.result={'state':'idle'};self.inventory={};self.clear=True;self.findings_bundle={'checked_at':'','items':[]};self.findings_source='quick'
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

class FileEvidenceTests(unittest.TestCase):
    setUp=Tests.setUp
    tearDown=Tests.tearDown
    bridge=Tests.bridge
    def bind(self,value):
        summary=with_file(value)
        self.tools['read']=lambda p,*a:copy.deepcopy(value) if pathlib.Path(p).name=='full-scan-report.json' else (_ for _ in ()).throw(FileNotFoundError())
        self.tools['valid_file_report']=f.valid_report
        return self.bridge(),summary
    def test_complete_file_evidence_preserves_full_path_and_identity(self):
        value=file_report();bridge,summary=self.bind(value)
        self.assertTrue(bridge.publish_file_evidence(summary));self.assertEqual(self.agent.findings_source,'multi')
        self.assertEqual(self.agent.findings_bundle['items'],value['findings']);self.assertGreater(len(self.agent.findings_bundle['items'][0]['path']),256)
        self.assertEqual(self.agent.findings_bundle['state'],'complete');self.assertEqual(self.saved[-1]['items'][0]['id'],value['findings'][0]['id'])
    def test_wrong_job_profile_hash_time_counters_and_state_rejected(self):
        for mutate in (lambda x:x.update(multi_job_id='d'*64),lambda x:x.update(profile_digest='d'*64),lambda x:x.update(infected=2),
                lambda x:x.update(state='scanning'),lambda x:x.update(started_at='2099-01-01T00:00:00.000Z'),
                lambda x:x.update(updated_at='2000-01-01T00:00:00.000Z'),lambda x:x['findings'][0].update(path='/replaced')):
            value=file_report();bridge,summary=self.bind(value);mutate(value)
            with self.subTest(value=value):
                with self.assertRaises(ValueError):bridge.publish_file_evidence(summary)
                self.assertEqual(self.agent.findings_source,'quick');self.assertEqual(self.saved,[])
    def test_stale_finding_duplicate_and_future_time_rejected_even_with_matching_digest(self):
        for mode in ('stale','future','duplicate'):
            value=file_report()
            if mode=='duplicate':value['findings']*=2;value.update(indexed=2,processed=2,clean=0,infected=2)
            else:
                item=value['findings'][0];item['observed_at']='2000-01-01T00:00:00.000Z' if mode=='stale' else '2099-01-01T00:00:00.000Z'
                item['id']=digest({k:v for k,v in item.items() if k!='id'})
            bridge,summary=self.bind(value)
            with self.subTest(mode=mode),self.assertRaises(ValueError):bridge.publish_file_evidence(summary)
    def test_partial_evidence_stays_partial_and_other_engines_never_become_files(self):
        value=file_report();value.update(state='partial',indexed=3);bridge,summary=self.bind(value)
        self.assertTrue(bridge.publish_file_evidence(summary));self.assertEqual(self.agent.findings_bundle['state'],'partial')
        before=copy.deepcopy(self.agent.findings_bundle);summary['engines'][0].update(state='unavailable',evidence_digest=None);summary['coverage']=0
        self.assertFalse(bridge.publish_file_evidence(summary));self.assertEqual(self.agent.findings_bundle,before)
    def test_restart_restores_bound_current_evidence_but_not_stale_or_newer_replacement(self):
        value=file_report();bridge,summary=self.bind(value)
        self.tools['read']=lambda p,*a:copy.deepcopy(value if pathlib.Path(p).name=='full-scan-report.json' else summary)
        self.bridge();self.assertEqual(self.agent.findings_source,'multi')
        self.agent.findings_source='full';self.agent.findings_bundle={'checked_at':'2099-01-01T00:00:00.000Z','items':[]}
        self.bridge();self.assertEqual(self.agent.findings_source,'full')
        old='2000-01-01T00:00:00.000Z'
        value.update(started_at=old,updated_at=old,finished_at=old);summary=with_file(value)
        self.agent.findings_source='quick';self.agent.findings_bundle={'checked_at':'','items':[]}
        self.bridge();self.assertEqual(self.agent.findings_source,'quick')
    def test_expired_or_unwritable_file_evidence_never_rewrites_terminal_task(self):
        for stale in (True,False):
            value=file_report()
            if stale:
                old='2000-01-01T00:00:00.000Z'
                value.update(started_at=old,updated_at=old,finished_at=old)
            bridge,summary=self.bind(value);bridge.value=copy.deepcopy(summary)
            if not stale:
                def fail(*a):raise OSError('disk full')
                self.tools['write']=fail
            bridge.transfer_file_evidence(summary)
            status=bridge.status()
            self.assertEqual(status['state'],'partial');self.assertEqual(status['engines'],summary['engines'])
            self.assertEqual(status['file_evidence']['state'],'unavailable')
            self.assertEqual(self.agent.findings_source,'quick')
    def test_actionable_evidence_expires_without_changing_scan_coverage(self):
        value=file_report();bridge,summary=self.bind(value);bridge.value=copy.deepcopy(summary)
        bridge.transfer_file_evidence(summary)
        self.assertEqual(bridge.status()['file_evidence']['state'],'ready')
        with patch.object(m.time,'time',return_value=bridge.evidence_until+1):
            status=bridge.status()
        self.assertEqual(status['state'],'partial');self.assertEqual(status['coverage'],1)
        self.assertEqual(status['file_evidence']['state'],'unavailable')
        self.agent.profile={'changed':True};self.tools['digest']=digest
        self.assertEqual(bridge.status()['file_evidence']['state'],'unavailable')
    def test_replaced_file_evidence_no_longer_claims_actionable_current_report(self):
        value=file_report();bridge,summary=self.bind(value);bridge.value=copy.deepcopy(summary)
        bridge.transfer_file_evidence(summary)
        self.assertEqual(bridge.status()['file_evidence']['state'],'ready')
        self.agent.findings_source='quick'
        self.assertEqual(bridge.status()['file_evidence']['state'],'superseded')
        self.agent.findings_source='multi';self.agent.findings_bundle['checked_at']=m.stamp()+'changed'
        self.assertEqual(bridge.status()['file_evidence']['state'],'superseded')
        self.assertEqual(bridge.status()['engines'],summary['engines'])
    def test_failure_clears_actionable_note_without_erasing_engine_evidence(self):
        value=file_report();bridge,summary=self.bind(value);bridge.value=copy.deepcopy(summary)
        bridge.transfer_file_evidence(summary);bridge.fail('output interrupted')
        status=bridge.status()
        self.assertEqual(status['state'],'failed');self.assertNotIn('file_evidence',status)
        self.assertEqual(status['engines'],summary['engines']);self.assertTrue(m.valid(status,DIGEST))
    def test_failed_persistence_does_not_expose_uncommitted_findings(self):
        value=file_report();bridge,summary=self.bind(value)
        def fail(*a):raise OSError('disk full')
        self.tools['write']=fail
        with self.assertRaises(OSError):bridge.publish_file_evidence(summary)
        self.assertEqual(self.agent.findings_source,'quick')
        self.tools['write']=lambda *a:None;self.agent.profile={'changed':True};self.tools['digest']=digest
        with self.assertRaises(ValueError):bridge.publish_file_evidence(summary)

@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'requires real root Linux file evidence and quarantine')
class JointQuarantineTests(unittest.TestCase):
    def test_file_queue_evidence_can_be_quarantined_and_changed_file_is_rejected(self):
        sys.dont_write_bytecode=True
        spec=importlib.util.spec_from_file_location('joint_operations',pathlib.Path(__file__).parents[1]/'src/host/operations.py')
        o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            base=pathlib.Path(directory);scope=base/'scope';scope.mkdir(mode=0o700);state=base/'state';state.mkdir(mode=0o700)
            profile=o.a.profile_validate({'schema':'ironcurtain-profile/v1','program_roots':[str(scope)]})
            agent=Agent(state);agent.profile=profile
            tools={'read':o.a.private_json,'write':o.a.atomic_json,'digest':f.profile_digest,'valid_file_report':f.valid_report,'updating':lambda:'idle'}
            bridge=m.Bridge(agent,base/'profile.json',tools)
            engine={'installed':True,'state':'configured','database_version':7,'database_at':f.utc(),'signatures':10}
            def run(args,**kw):
                data=os.read(kw['input_fd'],f.MAX_SIZE+1)
                return 1,'stdin: IronCurtain.Test FOUND\nScanned files: 1\nInfected files: 1\n'
            for change in (False,True):
                target=scope/'sample';target.write_bytes(b'fixture-virus')
                job=('b' if not change else 'c')*64
                def publish(value):o.a.atomic_json(state/'multi-clamav'/'full-scan-report.json',{**value,'multi_job_id':job})
                f.FullScan(profile,state/'multi-clamav',run,o.a.secure_fd,engine,'/fixture/database',publish,batch_size=1).run()
                value=o.a.private_json(state/'multi-clamav'/'full-scan-report.json');summary=with_file(value)
                summary.update(job_id=job,profile_digest=f.profile_digest(profile))
                self.assertTrue(bridge.publish_file_evidence(summary));item=value['findings'][0]
                if change:
                    target.write_bytes(b'changed-after-scan')
                    with self.assertRaises(ValueError):o.r.quarantine(state,profile,item['id'])
                    self.assertTrue(target.exists())
                else:
                    record=o.r.quarantine(state,profile,item['id'])
                    self.assertEqual(record['state'],'quarantined');self.assertFalse(target.exists())

if __name__=='__main__':unittest.main()
