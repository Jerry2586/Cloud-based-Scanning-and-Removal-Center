import datetime, hashlib, importlib.util, json, os, pathlib, stat, tempfile, unittest
spec=importlib.util.spec_from_file_location('response',pathlib.Path(__file__).parents[1]/'src/host/response.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)

@unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0, 'Linux root controlled directories required')
class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='ironcurtain-response-',dir='/root')
        self.root=pathlib.Path(self.tmp.name);self.scope=self.root/'scope';self.scope.mkdir(mode=0o700)
        self.state=self.root/'agent';self.state.mkdir(mode=0o700)
        self.file=self.scope/'suspect.js';self.file.write_bytes(b'test-evidence');self.file.chmod(0o600)
        self.profile=r.a.profile_validate({'schema':'ironcurtain-profile/v1','program_roots':[str(self.scope)]})
        self.observe()
    def tearDown(self):self.tmp.cleanup()
    def observe(self, **extra):
        item={'path':str(self.file),'signature':'Test.Signature','sha256':hashlib.sha256(self.file.read_bytes()).hexdigest(),'observed_at':r.a.utc(),**r.f.identity(self.file.stat()),**extra}
        item['id']=hashlib.sha256(r.f.canonical(item)).hexdigest();self.item=item
        self.bundle={'schema':'ironcurtain-findings/v1','state':'complete','items':[item],'total':1,'profile_digest':hashlib.sha256(r.f.canonical(self.profile)).hexdigest()}
        self.save()
    def save(self):r.a.atomic_json(self.state/'last-findings.json',self.bundle)
    def isolate(self,**kwargs):return r.quarantine(str(self.state),self.profile,self.item['id'],**kwargs)
    def restore(self,**kwargs):return r.restore(str(self.state),self.profile,self.item['id'],**kwargs)
    def test_copy_before_remove_and_restore_without_permissions_or_evidence_loss(self):
        content=self.file.read_bytes();record=self.isolate();self.assertEqual(record['state'],'quarantined');self.assertFalse(self.file.exists())
        blob=self.state/'quarantine'/(self.item['id']+'.blob');self.assertEqual(blob.read_bytes(),content);self.assertEqual(stat.S_IMODE(blob.stat().st_mode),0o600)
        self.assertEqual(r.inventory(str(self.state))['items'][0]['state'],'quarantined')
        self.assertEqual(self.restore()['state'],'restored');self.assertEqual(self.file.read_bytes(),content);self.assertEqual(stat.S_IMODE(self.file.stat().st_mode),0o600);self.assertTrue(blob.exists())
        with self.assertRaises(ValueError):self.restore()
    def test_changed_profile_identity_hash_and_stale_evidence_leave_file(self):
        self.file.write_bytes(b'changed');content=self.file.read_bytes()
        with self.assertRaises(ValueError):self.isolate()
        self.assertEqual(self.file.read_bytes(),content)
        self.observe(observed_at=(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(hours=1)).isoformat())
        with self.assertRaises(ValueError):self.isolate()
        self.observe();self.profile['approved_tcp_ports']=[22]
        with self.assertRaises(ValueError):self.isolate()
        self.assertEqual(self.file.read_bytes(),content)
    def test_symlinks_hardlinks_and_writable_parents_are_rejected(self):
        content=self.file.read_bytes();self.file.rename(self.scope/'old');self.file.symlink_to(self.scope/'old')
        with self.assertRaises((ValueError,OSError)):self.isolate()
        self.assertEqual((self.scope/'old').read_bytes(),content)
        self.file.unlink();self.file.write_bytes(content);os.link(self.file,self.scope/'hard');self.observe()
        with self.assertRaises(ValueError):self.isolate()
        (self.scope/'hard').unlink();self.observe();self.scope.chmod(0o777)
        with self.assertRaises(ValueError):self.isolate()
        self.scope.chmod(0o700);self.assertEqual(self.file.read_bytes(),content)
    def test_config_database_and_unconfirmed_targets_rejected(self):
        self.profile['config_files']=[str(self.file)];self.observe()
        with self.assertRaises(ValueError):self.isolate()
        self.profile['config_files']=[];self.file.rename(self.scope/'data.sqlite');self.file=self.scope/'data.sqlite';self.observe()
        with self.assertRaises(ValueError):self.isolate()
        with self.assertRaises(ValueError):r.quarantine(str(self.state),self.profile,'a'*64)
        self.assertTrue(self.file.exists())
    def test_no_overwrite_restoring_and_existing_temporary_file_is_preserved(self):
        self.isolate();self.file.write_bytes(b'new-good-file')
        with self.assertRaises(ValueError):self.restore()
        self.assertEqual(self.file.read_bytes(),b'new-good-file');self.file.unlink()
        temp=self.scope/('.ironcurtain-restore-'+self.item['id']);temp.write_bytes(b'existing-temp')
        with self.assertRaises(FileExistsError):self.restore()
        self.assertEqual(temp.read_bytes(),b'existing-temp');self.assertFalse(self.file.exists())
        temp.unlink();self.assertEqual(self.restore()['state'],'restored')
    def test_destination_race_and_mutation_before_unlink_leave_existing_data(self):
        def mutate(phase):
            if phase=='captured':self.file.write_bytes(b'changed-during-response')
        with self.assertRaises(ValueError):self.isolate(hook=mutate)
        self.assertEqual(self.file.read_bytes(),b'changed-during-response')
        self.observe();self.isolate()
        def create(phase):
            if phase=='restore-copied':self.file.write_bytes(b'concurrent-new-file')
        with self.assertRaises(FileExistsError):self.restore(hook=create)
        self.assertEqual(self.file.read_bytes(),b'concurrent-new-file')
    def test_crash_after_capture_and_after_remove_are_explicit_and_retryable(self):
        def captured(phase):
            if phase=='captured':raise RuntimeError('simulated crash')
        with self.assertRaises(RuntimeError):self.isolate(hook=captured)
        self.assertTrue(self.file.exists());self.assertEqual(r.inventory(str(self.state))['items'][0]['state'],'captured')
        self.assertEqual(self.isolate()['state'],'quarantined')
        self.restore();self.observe()
        def removed(phase):
            if phase=='removed':raise RuntimeError('simulated crash')
        with self.assertRaises(RuntimeError):self.isolate(hook=removed)
        self.assertFalse(self.file.exists());self.assertEqual(self.isolate()['state'],'quarantined')
    def test_corrupt_copy_never_removed_or_restored(self):
        def stop(phase):raise RuntimeError('stop before removal')
        with self.assertRaises(RuntimeError):self.isolate(hook=stop)
        blob=self.state/'quarantine'/(self.item['id']+'.blob');blob.write_bytes(b'corrupt')
        with self.assertRaises(ValueError):self.isolate()
        self.assertTrue(self.file.exists())
    def test_read_only_journal_status_and_corrupt_record(self):
        before = sorted(p.name for p in self.state.iterdir())
        self.assertEqual(r.f.quarantine_status(str(self.state))['state'], 'empty')
        self.assertEqual(before, sorted(p.name for p in self.state.iterdir()))
        def captured(phase):
            if phase == 'captured': raise RuntimeError('interrupted')
        with self.assertRaises(RuntimeError): self.isolate(hook=captured)
        status = r.f.quarantine_status(str(self.state))
        self.assertEqual(status['pending'], 1); self.assertEqual(status['items'][0]['state'], 'captured')
        self.isolate(); self.assertEqual(r.f.quarantine_status(str(self.state))['pending'], 0)
        record = self.state/'quarantine'/(self.item['id']+'.json')
        record.write_text('[]'); self.assertEqual(r.f.quarantine_status(str(self.state))['state'], 'unavailable')
    def test_capacity_limit_retains_source_without_creating_evidence_record(self):
        with r.Vault(str(self.state/'quarantine')) as vault:
            for index in range(r.MAX_ENTRIES): vault.write(format(index,'064x')+'.json', {})
        with self.assertRaises(ValueError): self.isolate()
        self.assertTrue(self.file.exists()); self.assertFalse((self.state/'quarantine'/(self.item['id']+'.blob')).exists())
    def test_capacity_and_forged_identity_never_remove(self):
        self.bundle['items'][0]['sha256']='0'*64;self.save()
        with self.assertRaises(ValueError):self.isolate()
        self.assertTrue(self.file.exists())

if __name__=='__main__':unittest.main()
