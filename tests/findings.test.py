import datetime, hashlib, importlib.util, os, pathlib, tempfile, unittest
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('findings', pathlib.Path(__file__).parents[1]/'src/host/findings.py')
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)

class ParsingTests(unittest.TestCase):
    def test_rejects_unbounded_paths_and_bad_alerts(self):
        for path in ['/safe/../other/file','/safe//file','/safe/\nfile','/safe','relative','/other/file']:
            self.assertFalse(f.path_allowed(path, ['/safe']))
        self.assertTrue(f.path_allowed('/safe/sub/file', ['/safe']))
        self.assertEqual(f.alerts('/safe/a: Test.Signature FOUND\nScanned files: 1'), [('/safe/a','Test.Signature')])
        for text in ['not-parsable FOUND','/safe/a: Bad Signature FOUND']:
            with self.assertRaises(ValueError): f.alerts(text)

@unittest.skipUnless(os.name == 'posix', 'POSIX descriptors required')
class FindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = pathlib.Path(self.tmp.name)
        self.file = self.root/'sample'; self.file.write_bytes(b'test-infected-content')
    def tearDown(self): self.tmp.cleanup()
    def collect(self, run, **kwargs):
        return f.collect(str(self.file)+': Test.Signature FOUND', [str(self.root)], run, ['clamscan'], **kwargs)
    def test_exact_open_bytes_and_bounded_evidence(self):
        def run(args, **kwargs):
            self.assertEqual(args, ['clamscan','--','-']); self.assertEqual(os.read(kwargs['input_fd'],1024), self.file.read_bytes())
            return 1, 'stdin: Test.Signature FOUND'
        items, complete = self.collect(run)
        self.assertTrue(complete); self.assertEqual(len(items),1)
        item=items[0]; self.assertEqual(item['sha256'],hashlib.sha256(self.file.read_bytes()).hexdigest())
        self.assertEqual(item['id'],hashlib.sha256(f.canonical({k:v for k,v in item.items() if k!='id'})).hexdigest())
    def test_leaf_parent_links_and_fifo_never_offered(self):
        target=self.root/'target'; self.file.rename(target); self.file.symlink_to(target)
        self.assertEqual(self.collect(lambda *args,**kwargs:(1,'stdin: Test.Signature FOUND')), ([],False))
        self.file.unlink(); os.mkfifo(self.file)
        self.assertEqual(self.collect(lambda *args,**kwargs:(1,'stdin: Test.Signature FOUND')), ([],False))
        self.file.unlink(); real=self.root/'real';real.mkdir(); (real/'sample').write_text('fixture'); link=self.root/'link';link.symlink_to(real, target_is_directory=True)
        items, complete=f.collect(str(link/'sample')+': Test.Signature FOUND',[str(self.root)],lambda *args,**kw:(1,'stdin: Test.Signature FOUND'),['clamscan'])
        self.assertFalse(complete);self.assertEqual(items,[])
    def test_changed_bytes_wrong_signature_and_budget_not_complete(self):
        def change(*args,**kwargs): self.file.write_bytes(b'changed');return 1,'stdin: Test.Signature FOUND'
        self.assertEqual(self.collect(change),([],False))
        for result in [(0,'stdin: Test.Signature FOUND'),(1,'stdin: Another.Signature FOUND'),(1,'stdin: Test.Signature FOUND\nErrors: 1'),(None,'timeout')]:
            self.assertEqual(self.collect(lambda *args,**kwargs:result),([],False))
        self.assertEqual(self.collect(lambda *args,**kwargs:(1,'stdin: Test.Signature FOUND'),maximum=0),([],False))
    def test_path_replacement_does_not_scan_replacement_bytes(self):
        old=self.file.read_bytes()
        def replace(*args,**kwargs):
            self.file.rename(self.root/'old');self.file.write_bytes(b'clean-replacement')
            self.assertEqual(os.read(kwargs['input_fd'],1024),old)
            return 1,'stdin: Test.Signature FOUND'
        # Path must still name the scanned inode, regardless of rename ctime behavior.
        self.assertEqual(self.collect(replace),([],False))

    def test_parent_replacement_never_offers_stale_path(self):
        directory=self.root/'protected';directory.mkdir()
        self.file=directory/'sample';self.file.write_bytes(b'test-infected-content')
        old=self.file.read_bytes()
        def replace(*args,**kwargs):
            directory.rename(self.root/'old-parent');directory.mkdir()
            self.file.write_bytes(b'clean-replacement')
            self.assertEqual(os.read(kwargs['input_fd'],1024),old)
            return 1,'stdin: Test.Signature FOUND'
        self.assertEqual(self.collect(replace),([],False))

if __name__=='__main__':unittest.main()
