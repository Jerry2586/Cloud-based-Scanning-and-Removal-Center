"""Runtime entry points must not mutate signed source with Python bytecode."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class ImmutableHostCodeTests(unittest.TestCase):
    def test_entry_points_keep_copied_release_free_of_bytecode(self):
        with tempfile.TemporaryDirectory() as directory:
            release = pathlib.Path(directory)
            host = release / 'src' / 'host'
            for name in ('package.json', 'release-public.pem'):
                shutil.copy2(ROOT / name, release / name)
            shutil.copytree(ROOT / 'src/host', host, ignore=shutil.ignore_patterns('__pycache__'))
            scripts = release / 'scripts'
            scripts.mkdir()
            shutil.copy2(ROOT / 'scripts/rules-client.py', scripts / 'rules-client.py')
            environment = dict(os.environ)
            environment.pop('PYTHONDONTWRITEBYTECODE', None)
            environment.pop('PYTHONPYCACHEPREFIX', None)
            entries = [(host / name, 0) for name in ('agent.py', 'updates.py', 'response.py', 'inventory.py')]
            entries += [(host / 'clamav-worker.py', 2), (scripts / 'rules-client.py', 0)]
            for entry, expected in entries:
                for _ in range(2):
                    result = subprocess.run([sys.executable, str(entry), '--help'], env=environment,
                                            capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, expected, (entry.name, result.stderr))
                    self.assertFalse(list(release.rglob('__pycache__')), entry.name)
                    self.assertFalse(list(release.rglob('*.pyc')), entry.name)

if __name__ == '__main__':
    unittest.main()
