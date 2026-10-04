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
            with patch.object(a.antivirus,'DATABASE_DIR',str(root/'missing')):
                self.assertEqual(scanner.malware([str(scope)])[0],'unavailable')
if __name__=='__main__':unittest.main()
