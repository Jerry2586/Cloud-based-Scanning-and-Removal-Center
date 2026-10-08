"""Real clamscan with a deterministic test-only signature, not official DB acceptance."""
import importlib.util, os, pathlib, shutil, tempfile, unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('agent',pathlib.Path(__file__).parents[1]/'src/host/agent.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
@unittest.skipUnless(os.name=='posix' and shutil.which('clamscan'),'requires real Linux ClamAV')
class EngineTests(unittest.TestCase):
    def test_real_engine_clean_infected_and_missing_official_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); scope=root/'scope'; scope.mkdir(); db=root/'db'; db.mkdir()
            pattern=b'IRONCURTAIN_DETERMINISTIC_ANTIVIRUS_TEST_ONLY'
            (db/'fixture.ndb').write_text('IronCurtain.TestOnly:0:*:'+pattern.hex()+'\n')
            clean=scope/'clean.txt';clean.write_bytes(b'clean fixture')
            def runner(args, **kwargs):
                # Explicit fixture DB seam: no test signature can enter the managed official database.
                args=[x for x in args if x not in ['--official-db-only=yes','--fail-if-cvd-older-than=7']]
                args=[('--database='+str(db)) if x.startswith('--database=') else x for x in args]
                return a.Runner()(args, **kwargs)
            scanner=a.Scanner({'schema':'ironcurtain-profile/v1'},runner)
            with patch.object(a.antivirus,'database_status',return_value={'state':'configured'}):
                state,_,data=scanner.malware([str(scope)]);self.assertEqual(state,'ok');self.assertGreater(data['files_scanned'],0)
                (scope/'infected.txt').write_bytes(pattern)
                state,_,data=scanner.malware([str(scope)]);self.assertEqual(state,'finding');self.assertEqual(data['infected'],1)
                self.assertEqual(len(scanner.findings),1);self.assertTrue(scanner.findings_complete)
                self.assertEqual(scanner.findings[0]['path'],str(scope/'infected.txt'))
                self.assertEqual(scanner.findings[0]['signature'],'IronCurtain.TestOnly.UNOFFICIAL')
            with patch.object(a.antivirus,'DATABASE_DIR',str(root/'missing')):
                self.assertEqual(scanner.malware([str(scope)])[0],'unavailable')
    def test_real_engine_full_queue_counts_progress_and_restart_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); root.chmod(0o700); scope=root/'scope'; scope.mkdir(); db=root/'fixture-db'; db.mkdir()
            pattern=b'IRONCURTAIN_FULL_QUEUE_TEST_ONLY'; (db/'fixture.ndb').write_text('IronCurtain.FullQueue:0:*:'+pattern.hex()+'\n')
            (scope/'clean.txt').write_bytes(b'clean fixture'); (scope/'infected.txt').write_bytes(pattern)
            agent=a.Agent({'schema':'ironcurtain-profile/v1','program_roots':[str(scope)]},root/'state')
            engine={'installed':True,'state':'configured','database_version':1,'database_at':a.utc(),'signatures':1,'database_generation':'a'*64}
            reports=[]
            def runner(args,**kwargs):
                self.assertIn('--official-db-only=yes',args); self.assertIn('--fail-if-cvd-older-than=7',args)
                self.assertIn('--follow-file-symlinks=2',args)
                fds=kwargs['pass_fds']; self.assertEqual(len(fds),2)
                self.assertEqual(args[args.index('--')+1:],['/proc/self/fd/'+str(fd) for fd in fds])
                self.assertNotIn('input_fd',kwargs)
                fixture=[x for x in args if x not in ['--official-db-only=yes','--fail-if-cvd-older-than=7']]
                fixture=[('--database='+str(db)) if x.startswith('--database=') else x for x in fixture]
                return a.Runner()(fixture,**kwargs)
            def publish(report):
                reports.append(dict(report));a.atomic_json(agent.state_dir/'full-scan-report.json',report)
            result=a.fullscan.FullScan(agent.profile,agent.state_dir,runner,a.secure_fd,engine,str(db),publish,database_status=lambda:engine).run()
            self.assertEqual(result['state'],'finished'); self.assertEqual((result['indexed'],result['processed'],result['clean'],result['infected']),(2,2,1,1));self.assertGreater(result['bytes_scanned'],0)
            self.assertTrue(a.fullscan.valid_report(result)); self.assertTrue(any(r['processed']==1 for r in reports));self.assertEqual(result['findings'][0]['signature'],'IronCurtain.FullQueue.UNOFFICIAL')
            restored=a.Agent(agent.profile,agent.state_dir)
            with patch.object(a.antivirus,'engine_status',return_value=engine):self.assertEqual(restored.status()['findings_total'],1)
            self.assertEqual((scope/'infected.txt').read_bytes(),pattern)
    def test_real_engine_checkup_runs_without_cloud_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); root.chmod(0o700); scope=root/'scope'; scope.mkdir(); db=root/'fixture-db'; db.mkdir()
            pattern=b'IRONCURTAIN_OFFLINE_CHECKUP_TEST_ONLY'
            (db/'fixture.ndb').write_text('IronCurtain.OfflineCheckup:0:*:'+pattern.hex()+'\n')
            (scope/'clean.txt').write_bytes(b'clean fixture'); (scope/'infected.txt').write_bytes(pattern)
            agent=a.Agent({'schema':'ironcurtain-profile/v1','program_roots':[str(scope)]},root/'state')
            engine={'installed':True,'state':'configured','database_version':1,'database_at':a.utc(),'signatures':1,'database_generation':'a'*64}
            real_runner=a.Runner
            def runner(args,**kwargs):
                if args and pathlib.Path(args[0]).name=='clamscan':
                    args=[x for x in args if x not in ['--official-db-only=yes','--fail-if-cvd-older-than=7']]
                    args=[('--database='+str(db)) if x.startswith('--database=') else x for x in args]
                return real_runner()(args,**kwargs)
            # Agent dispatch fails closed until the maintenance probe is wired.
            # This isolated fixture has no management operation; redirect only its
            # lease inode instead of touching the host's real installation lock.
            lockfile=root/'management.lock'; real_secure_fd=a.secure_fd
            agent.maintenance=lambda:False
            real_thread=a.threading.Thread; workers=[]
            def worker(*args,**kwargs):
                thread=real_thread(*args,**kwargs);workers.append(thread);return thread
            def secure(file,**kwargs):
                return real_secure_fd(str(lockfile) if str(file)=='/run/lock/ironcurtain-local.lock' else file,**kwargs)
            # Actual worker thread, environment commands and clamscan. Only test
            # database metadata is substituted; no cloud client or identity exists.
            with patch.object(a,'secure_fd',side_effect=secure),patch.object(a.threading,'Thread',side_effect=worker),patch.object(a,'Runner',return_value=runner),patch.object(a.antivirus,'engine_status',return_value=engine),patch.object(a.antivirus,'database_status',return_value=engine),patch.object(a.antivirus,'DATABASE_DIR',str(db)):
                self.assertEqual(agent.trigger_checkup()[0],202)
                self.assertEqual(len(workers),1);workers[0].join(30)
                self.assertFalse(workers[0].is_alive(),'real offline checkup did not finish')
                status=agent.status()
            import fcntl
            fd=os.open(lockfile,os.O_RDWR)
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(fd)
            self.assertEqual(status['state'],'finished');self.assertEqual(len(status['checks']),25)
            self.assertIn(status['checkup']['state'],['finished','partial']);self.assertEqual(status['checkup']['stage'],'complete')
            self.assertEqual(status['checkup']['environment_at'],status['checked_at'])
            self.assertEqual(status['full_scan']['state'],'finished')
            self.assertEqual((status['full_scan']['processed'],status['full_scan']['clean'],status['full_scan']['infected']),(2,1,1))
            self.assertEqual(status['findings_total'],1);self.assertFalse(agent.full_running)
            self.assertEqual((scope/'infected.txt').read_bytes(),pattern)
if __name__=='__main__':unittest.main()
