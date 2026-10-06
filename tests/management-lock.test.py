#!/usr/bin/env python3
"""Real Linux flock contention; temporary files only, no Docker/systemd calls."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

if sys.platform == 'linux':
    import fcntl

ROOT = Path(__file__).resolve().parents[1]

@unittest.skipUnless(sys.platform == 'linux' and shutil.which('flock') and shutil.which('bash'), 'requires Linux flock')
class MaintenanceLockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ironcurtain-lock-test.')
        self.addCleanup(self.temp.cleanup)
        self.lock = Path(self.temp.name) / 'lock'
        self.lock.write_text('original-lock-content')
        self.marker = Path(self.temp.name) / 'entered'
        self.inode = self.lock.stat().st_ino

    def invoke(self):
        script = ('source ' + shlex.quote(str(ROOT / 'scripts/lib/independent.sh')) + '\nROLE=local\n'
                  + 'exec 9<> ' + shlex.quote(str(self.lock)) + '\n'
                  + 'ic_wait_management_lock 9 ' + shlex.quote(str(self.lock)) + '\n'
                  + 'touch ' + shlex.quote(str(self.marker)))
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=22)

    def unchanged(self):
        self.assertEqual(self.lock.stat().st_ino, self.inode)
        self.assertEqual(self.lock.read_text(), 'original-lock-content')

    def test_free_lock_proceeds(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.marker.exists())
        self.assertNotIn('等待', result.stderr)
        self.unchanged()

    def test_short_contention_waits_then_proceeds(self):
        with self.lock.open('r+') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            timer = threading.Timer(0.5, fcntl.flock, args=(held, fcntl.LOCK_UN))
            timer.start()
            try:
                result = self.invoke()
            finally:
                timer.join()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('管理锁已释放', result.stderr)
        self.assertTrue(self.marker.exists())
        self.unchanged()

    def test_persistent_owner_is_preserved_and_operation_stops(self):
        with self.lock.open('r+') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            start = time.monotonic()
            result = self.invoke()
            elapsed = time.monotonic() - start
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.marker.exists())
            self.assertIn('等待 15 秒后', result.stderr)
            self.assertIn('sudo lslocks', result.stderr)
            self.assertGreaterEqual(elapsed, 14.5)
            self.assertLess(elapsed, 20)
            with self.lock.open('r+') as second:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.unchanged()

if __name__ == '__main__':
    unittest.main()
