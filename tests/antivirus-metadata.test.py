import importlib.util, pathlib, tempfile, unittest, time, os, json
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('av',pathlib.Path(__file__).parents[1]/'src/host/antivirus.py')
av=importlib.util.module_from_spec(spec);spec.loader.exec_module(av)

@unittest.skipUnless(os.name=='posix','POSIX database trust checks')
class DatabaseTests(unittest.TestCase):
    def headers(self, root, timestamp):
        for name in ['main','daily']:
            data=f'ClamAV-VDB:date:123:42:1:md5:signature:builder:{timestamp}'
            (root/(name+'.cvd')).write_bytes(data.encode().ljust(512,b' ')); (root/(name+'.cvd')).chmod(0o644)
    def test_fresh_stale_future_missing_and_ambiguous(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); now=int(time.time())
            self.assertEqual(av.database_status(tmp,now)['state'],'unavailable')
            self.headers(root,now)
            self.assertEqual(av.database_status(tmp,now)['state'],'configured')
            self.assertEqual(av.database_status(tmp,now+8*86400)['state'],'stale')
            self.assertEqual(av.database_status(tmp,now-600)['state'],'unavailable')
            (root/'daily.cld').write_bytes((root/'daily.cvd').read_bytes())
            self.assertEqual(av.database_status(tmp,now)['state'],'unavailable')
    def test_symlinks_and_group_writable_files_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); self.headers(root,int(time.time()))
            (root/'daily.cvd').chmod(0o666)
            self.assertEqual(av.database_status(tmp)['state'],'unavailable')
            (root/'daily.cvd').chmod(0o644); (root/'real.cvd').write_bytes((root/'daily.cvd').read_bytes())
            (root/'daily.cvd').unlink(); (root/'daily.cvd').symlink_to(root/'real.cvd')
            self.assertEqual(av.database_status(tmp)['state'],'unavailable')
    def test_same_metadata_replacement_changes_generation_and_bytecode_is_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp); now=int(time.time()); self.headers(root,now)
            before=av.database_status(tmp,now); replacement=root/'replacement'
            replacement.write_bytes((root/'daily.cvd').read_bytes()); replacement.chmod(0o644); replacement.replace(root/'daily.cvd')
            after=av.database_status(tmp,now)
            self.assertEqual(before['database_version'],after['database_version']); self.assertNotEqual(before['database_generation'],after['database_generation'])
            (root/'bytecode.cvd').write_bytes((root/'daily.cvd').read_bytes()); (root/'bytecode.cvd').chmod(0o644)
            bytecode=av.database_status(tmp,now); self.assertEqual(bytecode['signatures'],126); self.assertNotEqual(after['database_generation'],bytecode['database_generation'])
            (root/'bytecode.cld').write_bytes((root/'daily.cvd').read_bytes()); (root/'bytecode.cld').chmod(0o644)
            self.assertEqual(av.database_status(tmp,now)['state'],'unavailable')
    def test_uninstalled_never_claims_configured(self):
        with patch.object(av.shutil,'which',return_value=None),patch.object(av,'updater_status',return_value='unknown'),patch.object(av,'database_status',return_value={'state':'configured'}):
            self.assertEqual(av.engine_status()['state'],'unavailable')


@unittest.skipUnless(os.name=='posix' and os.getuid()==0,'Linux root source metadata checks')
class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ic-source-');self.addCleanup(self.temp.cleanup)
        self.root=pathlib.Path(self.temp.name);self.root.chmod(0o700)
        self.database=self.root/'database';self.database.mkdir(mode=0o755)
        self.marker=self.root/'source.json'
    def marker_write(self):
        self.marker.write_text(json.dumps({'schema':'ironcurtain-virus-db-source/v1','source':'xuanwu-signed','snapshot':'a'*64}));self.marker.chmod(0o600)
    def test_direct_signed_and_unfinished_transaction(self):
        self.assertEqual(av.database_source(self.database),'official-direct')
        self.marker_write();self.assertEqual(av.database_source(self.database),'xuanwu-signed')
        journal=self.root/'activation.json';journal.symlink_to(self.root/'absent')
        self.assertEqual(av.database_source(self.database),'unknown')
        with patch.object(av.shutil,'which',return_value='/usr/bin/clamscan'),patch.object(av,'database_status',return_value={'state':'configured'}),patch.object(av,'updater_status',return_value='disabled'):
            self.assertEqual(av.engine_status(self.database)['state'],'unavailable')
    def test_untrusted_parent_rejected_even_without_marker(self):
        self.root.chmod(0o777);self.assertEqual(av.database_source(self.database),'unknown')
        self.root.chmod(0o700)
        alias=self.root/'alias';alias.symlink_to(self.root,target_is_directory=True)
        self.assertEqual(av.database_source(alias/'database'),'unknown')
        os.chown(self.root,65534,-1);self.assertEqual(av.database_source(self.database),'unknown');os.chown(self.root,0,-1)
    def test_marker_permissions_links_owner_and_size(self):
        self.marker_write();self.marker.chmod(0o666);self.assertEqual(av.database_source(self.database),'unknown')
        self.marker.chmod(0o600);os.chown(self.marker,65534,-1);self.assertEqual(av.database_source(self.database),'unknown');os.chown(self.marker,0,-1)
        hard=self.root/'hard';os.link(self.marker,hard);self.assertEqual(av.database_source(self.database),'unknown');hard.unlink()
        self.marker.unlink();self.marker.symlink_to(self.root/'absent');self.assertEqual(av.database_source(self.database),'unknown')
        self.marker.unlink();self.marker.write_bytes(b'x'*4097);self.marker.chmod(0o600);self.assertEqual(av.database_source(self.database),'unknown')
    def test_invalid_content_and_cloud_updater_disabled_are_distinct(self):
        self.marker_write()
        with patch.object(av.shutil,'which',return_value='/usr/bin/clamscan'),patch.object(av,'database_status',return_value={'state':'configured'}),patch.object(av,'updater_status',return_value='disabled'):
            status=av.engine_status(self.database);self.assertEqual(status['state'],'configured');self.assertEqual(status['source'],'xuanwu-signed');self.assertEqual(status['updater'],'disabled')
        self.marker.write_text('{broken');self.assertEqual(av.database_source(self.database),'unknown')
        self.marker.write_text(json.dumps({'schema':'ironcurtain-virus-db-source/v1','source':'xuanwu-signed','snapshot':'bad'}));self.assertEqual(av.database_source(self.database),'unknown')

if __name__=='__main__': unittest.main()
