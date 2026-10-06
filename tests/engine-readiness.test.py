import copy, importlib.util, pathlib, threading, unittest
spec=importlib.util.spec_from_file_location('readiness',pathlib.Path(__file__).parents[1]/'src/host/engine_readiness.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def rows():
    now=m.datetime.datetime.now(m.datetime.timezone.utc)
    iso=lambda t:t.isoformat().replace('+00:00','Z')
    return [dict(id='trivy',state='ready',detail='local database',version='0.65.0',database_at=iso(now-m.datetime.timedelta(hours=1)),next_update=iso(now+m.datetime.timedelta(hours=1))),dict(id='osquery',state='ready',detail='query passed',version='5.19.0'),dict(id='falco',state='partial',detail='events are not live coverage')]
def antivirus():return dict(engine='ClamAV',installed=True,state='configured',version='1.4.3.vendor',database_at=m.stamp(),signatures=1,database_version=1,source='official-direct',detail='metadata configured')
class ReadinessTests(unittest.TestCase):
    def test_native_rejects_counterfeit_health_and_missing_evidence(self):
        def report():return dict(schema=m.SCHEMA,checked_at=m.stamp(),engines=rows())
        self.assertEqual(len(m.validate_native(report())),3)
        def missing(v):del v['engines'][0]['next_update']
        for edit in (lambda v:v['engines'].reverse(),lambda v:v['engines'][2].update(state='ready'),lambda v:v['engines'][1].update(version='secret / shell'),lambda v:v.update(checked_at='2000-01-01T00:00:00Z'),lambda v:v['engines'][0].update(next_update='2000-01-01T00:00:00Z'),missing):
            v=report();edit(v)
            with self.assertRaises(ValueError):m.validate_native(v)
    def test_clamav_requires_installed_engine_trusted_source_and_database(self):
        v=antivirus();self.assertEqual(m.clamav_row(v)['state'],'ready')
        v['state']='stale';self.assertEqual(m.clamav_row(v)['state'],'stale')
        for edit in (lambda v:v.update(installed=False),lambda v:v.update(signatures=0),lambda v:v.update(database_version=True),lambda v:v.update(database_at='bad'),lambda v:v.update(source='unknown')):
            v=antivirus();edit(v);self.assertEqual(m.clamav_row(v)['state'],'unavailable')
    def test_cache_cooldown_and_expiry_do_not_forge_readiness(self):
        clock=[0];calls=[];busy=[False]
        release=threading.Event();self.addCleanup(release.set)
        def probe():
            calls.append(1)
            release.wait(2)
            return rows()
        b=m.Bridge(probe,antivirus,lambda:busy[0],clock=lambda:clock[0]);self.addCleanup(b.close)
        self.assertEqual(b.status()['state'],'checking');release.set();b.thread.join(2)
        self.assertEqual(b.status()['ready_count'],3);self.assertEqual(len(calls),1)
        self.assertEqual(b.trigger()[0],429)
        clock[0]=61;b.status();b.thread.join(2);self.assertEqual(len(calls),2)
        clock[0]=200;busy[0]=True;self.assertEqual(b.status()['state'],'unavailable');self.assertEqual(b.trigger()[0],409)
    def test_single_concurrent_check_and_closing(self):
        entered=threading.Event();release=threading.Event()
        def probe():entered.set();release.wait(2);return rows()
        b=m.Bridge(probe,antivirus);self.addCleanup(b.close)
        self.assertEqual(b.trigger()[0],202);self.assertTrue(entered.wait(1));self.assertEqual(b.trigger()[0],409)
        release.set();b.thread.join(2);b.close();self.assertEqual(b.trigger()[0],503)
    def test_invalid_or_failed_native_report_never_preserves_ready_rows(self):
        for probe in (lambda:[dict(id='falco',state='ready')],lambda:(_ for _ in ()).throw(ValueError('SECRET'))):
            b=m.Bridge(probe,antivirus);b.trigger();b.thread.join(2);v=b.status();b.close()
            self.assertEqual(v['state'],'unavailable');self.assertEqual(v['ready_count'],0);self.assertNotIn('SECRET',str(v))
    def test_shutdown_closes_fixed_probe(self):
        class Probe:
            closed=False
            def __call__(self):return rows()
            def close(self):self.closed=True
        p=Probe();b=m.Bridge(p,antivirus);b.close();self.assertTrue(p.closed)
if __name__=='__main__':unittest.main()
