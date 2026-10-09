"""Disposable CI credential handoff must stay private, gated and single-use."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('ci_credentials', Path(__file__).parent / 'helpers/ci_credentials.py')
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)

@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'Linux root handoff boundary')
class Handoff(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'handoff'
        self.gates = {'GITHUB_ACTIONS': 'true', 'IRONCURTAIN_ACCEPT_DISPOSABLE_RUNNER': '1', 'IRONCURTAIN_ACCEPT_OFFICIAL_MAINTENANCE': '1'}
        self.env = patch.dict(os.environ, self.gates)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.directory = patch.object(ci, 'DIRECTORY', self.root)
        self.directory.start()
        self.addCleanup(self.directory.stop)

    def test_private_single_use(self):
        ci.save('admin', 'disposable-test-only')
        self.assertEqual((self.root / ci.NAME).stat().st_mode & 0o777, 0o600)
        self.assertEqual(ci.consume(), {'username': 'admin', 'password': 'disposable-test-only'})
        with self.assertRaises(FileNotFoundError):
            ci.consume()

    def test_every_gate_required(self):
        for key in self.gates:
            with patch.dict(os.environ, {key: '0'}), self.assertRaises(RuntimeError):
                ci.save('admin', 'disposable-test-only')
        self.assertFalse(self.root.exists())

    def test_stale_file_not_overwritten(self):
        ci.save('admin', 'disposable-test-only')
        with self.assertRaises(FileExistsError):
            ci.save('admin', 'replacement-test-only')
        self.assertEqual(ci.consume()['password'], 'disposable-test-only')

    def test_untrusted_directory_and_links_rejected(self):
        target = Path(self.temp.name) / 'other'
        target.mkdir(mode=0o700)
        self.root.symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError):
            ci.save('admin', 'disposable-test-only')
        self.root.unlink()
        self.root.mkdir(mode=0o755)
        with self.assertRaises(RuntimeError):
            ci.save('admin', 'disposable-test-only')

    def test_unsafe_file_rejected(self):
        ci.save('admin', 'disposable-test-only')
        file = self.root / ci.NAME
        file.chmod(0o644)
        with self.assertRaises(RuntimeError):
            ci.consume()
        file.chmod(0o600)
        os.link(file, self.root / 'alias')
        with self.assertRaises(RuntimeError):
            ci.consume()
        (self.root / 'alias').unlink()
        file.unlink()
        file.symlink_to(Path(self.temp.name) / 'absent')
        with self.assertRaises(OSError):
            ci.consume()

if __name__ == '__main__':
    unittest.main()
