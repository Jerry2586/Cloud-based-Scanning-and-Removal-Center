import importlib.util, pathlib, unittest, tempfile, hashlib, json, sqlite3, copy, subprocess, os, threading
spec=importlib.util.spec_from_file_location('agent',pathlib.Path(__file__).parents[1]/'src/host/agent.py')
a=importlib.util.module_from_spec(spec); spec.loader.exec_module(a)

def profile(**kwargs): return {'schema':'ironcurtain-profile/v1',**kwargs}
class ScannerTests(unittest.TestCase):
    def test_profile_rejects_unknown_fields_and_unsafe_scope(self):
        for value in [[],profile(program_roots=['/']),profile(program_roots=['/srv/../etc']),profile(program_roots=['/srv//site']),profile(command='rm'),profile(cloudflare={'enabled':True,'token':'secret'}),profile(cloudflare={'enabled':'true'}),profile(approved_tcp_ports=[True]),profile(baseline=[]),profile(containers=[{'name':'a;id'}])]:
            with self.subTest(value=value):
                with self.assertRaises((ValueError,TypeError)): a.profile_validate(value)
    def test_service_check_targets_the_installed_agent_unit(self):
        calls=[]
        def run(args,**kwargs):
            calls.append(args)
            return 0,'active'
        scanner=a.Scanner(profile(),run)
        self.assertEqual(scanner.check('host.systemd-state')[0],'ok')
        self.assertEqual(calls,[['systemctl','is-active','ironcurtain-agent.service']])
    def test_file_hash_and_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            file=pathlib.Path(directory)/'file'; file.write_bytes(b'trusted')
            self.assertEqual(a.digest_file(file),hashlib.sha256(b'trusted').hexdigest())
            original=a.MAX_FILE
            try:
                a.MAX_FILE=3
                with self.assertRaises(ValueError): a.digest_file(file)
            finally: a.MAX_FILE=original
    def test_integrity_detects_added_and_modified_and_ignores_config_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory); program=root/'app.js'; config=root/'config.json'
            program.write_bytes(b'app'); config.write_bytes(b'config')
            scanner=a.Scanner(profile()); scanner.profile['program_roots']=[str(root)]; scanner.profile['config_files']=[str(config)]
            scanner.baseline={'files':{str(program):a.digest_file(program),str(config):a.digest_file(config)}}
            self.assertEqual(scanner.integrity()[0],'ok'); self.assertEqual(scanner.integrity(True)[0],'ok')
            program.write_bytes(b'changed'); (root/'webshell.php').write_text('test file')
            state,_,evidence=scanner.integrity(); self.assertEqual(state,'finding'); self.assertEqual(evidence['changed'],1); self.assertEqual(evidence['added'],1)
    @__import__('unittest.mock',fromlist=['patch']).patch.object(a.antivirus,'database_status',return_value={'state':'configured'})
    def test_clamav_failure_limits_and_real_counts(self, database):
        with tempfile.TemporaryDirectory() as root:
            for code,text,expected in [(0,'Scanned files: 4\nInfected files: 0','ok'),(1,'Scanned files: 4\nInfected files: 1','finding'),(1,'Heuristics.Limits.Exceeded FOUND\nScanned files: 4\nInfected files: 1','unavailable'),(0,'Scanned files: 0\nInfected files: 0','unavailable'),(2,'error','unavailable'),(0,'Scanned files: 4\nInfected files: 0\nErrors: 1','unavailable'),(1,'Scanned files: 4\nInfected files: 0','unavailable')]:
                with self.subTest(text=text):
                    scanner=a.Scanner(profile(),lambda *args,**kw:(code,text)); self.assertEqual(scanner.malware([root])[0],expected)
    def test_tcp_udp_ports_and_malformed_output(self):
        for udp,text,expected in [(False,'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*','ok'),(False,'LISTEN 0 128 [::]:443 [::]:*','warning'),(True,'UNCONN 0 0 127.0.0.1:53 0.0.0.0:*','ok'),(False,'tcp LISTEN 0 128 [::]:22 [::]:*','ok'),(False,'unexpected output','unavailable')]:
            scanner=a.Scanner(profile(approved_tcp_ports=[22],approved_udp_ports=[53]),lambda *args,**kw:(0,text))
            self.assertEqual(scanner.check('network.udp-listeners' if udp else 'network.listeners')[0],expected)
    def test_docker_requires_all_protection_and_approved_image(self):
        item={'Name':'/site','Image':'sha256:'+'a'*64,'Config':{'User':'10001'},'HostConfig':{'ReadonlyRootfs':True,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true']},'Mounts':[]}
        scanner=a.Scanner(profile(containers=[{'name':'site','image_id':'sha256:'+'a'*64}]),lambda *args,**kw:(0,json.dumps([item])))
        self.assertEqual(scanner.check('container.contract')[0],'ok'); self.assertEqual(scanner.check('container.approved-image')[0],'ok')
        item['HostConfig']['Privileged']=True; scanner.container_cache=None; self.assertEqual(scanner.check('container.contract')[0],'finding')
        item['Image']='sha256:'+'b'*64; scanner.container_cache=None; self.assertEqual(scanner.check('container.approved-image')[0],'finding')
    def test_sqlite_readonly_never_creates_missing_database(self):
        with tempfile.TemporaryDirectory() as directory:
            file=pathlib.Path(directory)/'data.db'; connection=sqlite3.connect(file); connection.execute('CREATE TABLE test(id)'); connection.close()
            scanner=a.Scanner(profile()); scanner.profile['sqlite_files']=[str(file)]
            before=file.read_bytes(); self.assertEqual(scanner.check('database.sqlite')[0],'ok'); self.assertEqual(file.read_bytes(),before)
            file.unlink(); self.assertEqual(scanner.check('database.sqlite')[0],'unavailable'); self.assertFalse(file.exists())
    def test_progress_is_completed_checks_and_dependencies_not_success(self):
        scanner=a.Scanner(profile()); scanner.check=lambda id:('unavailable','not configured',{})
        steps=[]; report=scanner.run_checks(lambda checks,current:steps.append((len(checks),current)))
        self.assertEqual(len(report),25); self.assertEqual(steps[0],(0,a.IDS[0])); self.assertEqual(steps[-1],(25,None))
        self.assertTrue(all(check['state']=='unavailable' for check in report))
    @unittest.skipUnless(os.name=='posix','POSIX openat/symlink required')
    def test_parent_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory); (root/'real').mkdir(); (root/'real'/'file').write_text('data'); (root/'link').symlink_to(root/'real',target_is_directory=True)
            with self.assertRaises(OSError): a.digest_file(root/'link'/'file')
    def test_unreadable_hash_is_unknown_and_missing_root_not_complete(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory); file=root/'app.js'; file.write_text('app')
            scanner=a.Scanner(profile()); scanner.profile['program_roots']=[str(root)]; scanner.baseline={'files':{str(file):a.digest_file(file)}}
            with patch.object(a,'digest_file',side_effect=PermissionError('denied')):
                self.assertEqual(scanner.integrity()[0],'unavailable'); self.assertFalse(scanner.files_complete)
            file.unlink(); root.rmdir()
            self.assertEqual(scanner.integrity()[0],'finding'); self.assertFalse(scanner.files_complete)
    def test_added_files_share_aggregate_hash_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory); file=root/'app.js'; file.write_bytes(b'app'); (root/'extra').write_bytes(b'123456')
            scanner=a.Scanner(profile()); scanner.profile['program_roots']=[str(root)]; scanner.baseline={'files':{str(file):a.digest_file(file)}}
            scanner.hash_budget['maximum']=5
            self.assertNotEqual(scanner.integrity()[0],'ok'); self.assertFalse(scanner.files_complete)
    def test_cloudflare_fixed_scope_one_collection_and_disabled_never_calls(self):
        rows=[{'id':id,'state':'finding' if id=='cloudflare.dns' else 'ok','detail':'approved snapshot comparison','evidence':{'digest':'a'*64,'count':1}} for id in a.IDS if id.startswith('cloudflare.')]
        calls=[]
        def collect(): calls.append(1); return {'checks':rows}
        scanner=a.Scanner(profile(cloudflare={'enabled':True}),cloudflare_collect=collect)
        for row in rows: self.assertEqual(scanner.check(row['id'])[0],row['state'])
        self.assertEqual(len(calls),1)
        disabled=a.Scanner(profile(),cloudflare_collect=collect); self.assertEqual(disabled.check('cloudflare.dns')[0],'unavailable'); self.assertEqual(len(calls),1)
        scanner=a.Scanner(profile(cloudflare={'enabled':True}),cloudflare_collect=lambda:{'checks':[]})
        self.assertEqual(scanner.check('cloudflare.dns')[0],'unavailable')
    def test_invalid_persisted_timestamp_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            checks=a.Scanner(profile(),lambda *args,**kw:(None,'missing')).run_checks()
            report={'state':'finished','checked_at':'wrong','checks':checks,'history':[],'history_state':'ok'}
            file=pathlib.Path(directory)/'last-report.json'; file.write_text(json.dumps(report)); saved=file.read_bytes()
            agent=a.Agent(profile(),directory); self.assertFalse(agent.history_available); self.assertEqual(file.read_bytes(),saved)
    def test_runner_bounds_and_missing_dependency(self):
        self.assertEqual(a.Runner()(['ironcurtain-not-installed'])[0],None)
    def test_ed25519_baseline_tamper_never_auto_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory); private=root/'private.pem'; public=root/'public.pem'; baseline=root/'baseline.json'; signature=root/'baseline.sig'
            binary=os.environ.get('IRONCURTAIN_TEST_OPENSSL','openssl')
            def cmd(*args): subprocess.run([binary,*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            cmd('genpkey','-algorithm','ED25519','-out',str(private)); cmd('pkey','-in',str(private),'-pubout','-out',str(public))
            baseline.write_bytes(a.canonical({'schema':'ironcurtain-baseline/v1','roots':['/srv/site'],'files':{'/srv/site/app.js':'a'*64}}))
            cmd('pkeyutl','-sign','-inkey',str(private),'-rawin','-in',str(baseline),'-out',str(signature))
            def run(args,**kw): return a.Runner()([binary,*args[1:]],**kw)
            scanner=a.Scanner(profile(program_roots=['/srv/site'])); scanner.run=run; scanner.profile['baseline']={'path':str(baseline),'signature':str(signature),'public_key':str(public)}
            scanner.load_baseline(); self.assertIsNotNone(scanner.baseline)
            baseline.write_bytes(baseline.read_bytes().replace(b'a'*64,b'b'*64))
            scanner=a.Scanner(profile(program_roots=['/srv/site'])); scanner.run=run; scanner.profile['baseline']={'path':str(baseline),'signature':str(signature),'public_key':str(public)}
            scanner.load_baseline(); self.assertIsNone(scanner.baseline); self.assertIn('签名',scanner.baseline_error)
    def test_history_persists_changes_and_does_not_repeat_unchanged_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            scanner=a.Scanner(profile()); scanner.check=lambda id:('ok','initial',{})
            checks=scanner.run_checks()
            from unittest.mock import patch
            with patch.object(a.Scanner,'run_checks',return_value=checks):
                agent=a.Agent(profile(),directory); agent.scan()
                self.assertEqual(agent.status()['history_state'],'ok'); self.assertEqual(agent.status()['history'],[])
            changed=copy.deepcopy(checks); changed[0].update(state='finding',detail='modified',evidence_digest='a'*64)
            with patch.object(a.Scanner,'run_checks',return_value=changed):
                agent.scan(); self.assertEqual(len(agent.status()['history']),1)
                agent.scan(); self.assertEqual(len(agent.status()['history']),1)
                restored=a.Agent(profile(),directory); self.assertEqual(restored.status()['history'][0]['previous_state'],'ok')
            saved=pathlib.Path(directory)/'last-report.json'; saved.write_text('damaged evidence')
            with patch.object(a.Scanner,'run_checks',return_value=checks):
                damaged=a.Agent(profile(),directory); damaged.scan()
                self.assertEqual(damaged.status()['history_state'],'unavailable'); self.assertEqual(saved.read_text(),'damaged evidence')
if __name__=='__main__': unittest.main()
