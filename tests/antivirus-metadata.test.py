import importlib.util, pathlib, tempfile, unittest, time, os
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
    def test_uninstalled_never_claims_configured(self):
        with patch.object(av.shutil,'which',return_value=None),patch.object(av,'updater_status',return_value='unknown'),patch.object(av,'database_status',return_value={'state':'configured'}):
            self.assertEqual(av.engine_status()['state'],'unavailable')

if __name__=='__main__': unittest.main()
