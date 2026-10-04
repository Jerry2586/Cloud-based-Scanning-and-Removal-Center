"""Real SQLite engine/snapshots; Docker ownership is mocked only in unit cases."""
from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socketserver
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

if not hasattr(socketserver, 'UnixStreamServer'):
    socketserver.UnixStreamServer = socketserver.TCPServer
spec = importlib.util.spec_from_file_location('sqlite_agent', Path(__file__).resolve().parents[2] / 'scripts/host-security-agent.py')
a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)

class SQLiteHealthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.db = self.root / 'appgog.sqlite'
        with closing(sqlite3.connect(self.db)) as db:
            db.execute('BEGIN')
            db.execute('CREATE TABLE secrets(value TEXT)')
            db.execute("INSERT INTO secrets VALUES ('private-database-value')")
            db.commit()
        self.owned = {'container_id': 'a' * 64, 'role': 'all', 'roots': {'db': self.root}}
        self.addCleanup(patch.stopall)
        patch.object(a, 'business_volume_roots', lambda **kwargs: self.owned).start()

    def fingerprint(self):
        return {p.name: (a.file_identity(p.stat()), hashlib.sha256(p.read_bytes()).hexdigest()) for p in self.root.iterdir() if p.is_file()}

    def test_real_database_no_live_changes_or_secret_output(self):
        before = self.fingerprint()
        result = a.sqlite_health_check()
        self.assertEqual(result['state'], 'ok')
        self.assertEqual(result['id'], 'database.sqlite')
        self.assertEqual(before, self.fingerprint())
        self.assertNotIn('private-database-value', json.dumps(result))
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_real_wal_preserved_and_parsed(self):
        db = sqlite3.connect(self.db); self.addCleanup(db.close)
        db.execute('PRAGMA journal_mode=WAL'); db.execute('PRAGMA wal_autocheckpoint=0')
        db.execute('CREATE TABLE only_in_wal(value TEXT)')
        db.execute("INSERT INTO only_in_wal VALUES ('private-wal-value')"); db.commit()
        before = self.fingerprint()
        original = a.subprocess.run
        def verify_copy(args, **kwargs):
            copied = Path(args[-1])
            self.assertTrue(Path(str(copied) + '-wal').is_file())
            with closing(sqlite3.connect(copied.as_uri() + '?mode=ro', uri=True)) as probe:
                self.assertEqual(probe.execute('SELECT value FROM only_in_wal').fetchone(), ('private-wal-value',))
            return original(args, **kwargs)
        with patch.object(a.subprocess, 'run', verify_copy):
            self.assertEqual(a.sqlite_health_check()['state'], 'ok')
        self.assertEqual(before, self.fingerprint())

    def test_corruption_and_empty_file_are_findings_without_repair(self):
        for content in (b'invalid-database' * 400, b''):
            self.db.write_bytes(content); before = self.fingerprint()
            self.assertEqual(a.sqlite_health_check()['state'], 'finding')
            self.assertEqual(before, self.fingerprint())

    def test_actual_sqlite_page_corruption_is_finding_without_changes(self):
        content = bytearray(self.db.read_bytes())
        self.assertEqual(content[:16], b'SQLite format 3\x00')
        content[100] = 0xff  # Invalid page type, preserving the SQLite header.
        self.db.write_bytes(content)
        before = self.fingerprint()
        self.assertEqual(a.sqlite_health_check()['state'], 'finding')
        self.assertEqual(before, self.fingerprint())

    def test_unowned_missing_journal_and_size_limit_are_unknown(self):
        with patch.object(a, 'business_volume_roots', side_effect=ValueError('foreign')):
            self.assertEqual(a.sqlite_health_check()['state'], 'unavailable')
        journal = self.root / 'appgog.sqlite-journal'; journal.write_bytes(b'pending')
        self.assertEqual(a.sqlite_health_check()['state'], 'unavailable'); journal.unlink()
        with patch.object(a, 'MAX_SQLITE_BYTES', 1):
            self.assertEqual(a.sqlite_health_check()['state'], 'unavailable')
        self.db.unlink(); self.assertEqual(a.sqlite_health_check()['state'], 'unavailable')

    def test_source_change_and_volume_change_override_clean_or_corrupt_probe(self):
        original = a.subprocess.run
        def moving(args, **kwargs):
            result = original(args, **kwargs)
            self.db.write_bytes(b'x' * self.db.stat().st_size)
            return result
        with patch.object(a.subprocess, 'run', moving):
            self.assertEqual(a.sqlite_health_check()['state'], 'unavailable')
        foreign = {**self.owned, 'container_id': 'b' * 64}
        with patch.object(a, 'business_volume_roots', side_effect=[self.owned, foreign]):
            self.assertEqual(a.sqlite_health_check()['state'], 'unavailable')

    def test_timeouts_and_invalid_output_fail_closed(self):
        for error in (subprocess.TimeoutExpired('fixed', 12), OSError('failed')):
            with patch.object(a.subprocess, 'run', side_effect=error):
                self.assertEqual(a.sqlite_health_check()['state'], 'unavailable')
        for output in ('not-json', '{"state":"clean"}', 'x' * 257):
            with patch.object(a.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output, 'private-error')):
                self.assertEqual(a.sqlite_health_check()['state'], 'unavailable')

    def test_build_only_role_is_explicitly_not_applicable(self):
        with patch.object(a, 'business_volume_roots', return_value={'role': 'build', 'roots': {}}):
            result = a.sqlite_health_check()
        self.assertEqual(result['state'], 'ok'); self.assertIn('不适用', result['detail'])

    @unittest.skipUnless(os.name == 'posix', 'real Unix symlink/hardlink checks in Linux CI')
    def test_symlink_hardlink_and_ancestor_link_are_rejected(self):
        content = self.db.read_bytes(); self.db.unlink()
        other = self.root / 'other'; other.write_bytes(content)
        self.db.symlink_to(other)
        self.assertEqual(a.sqlite_health_check()['state'], 'unavailable'); self.db.unlink()
        os.link(other, self.db)
        self.assertEqual(a.sqlite_health_check()['state'], 'unavailable'); self.db.unlink(); other.unlink()
        self.db.write_bytes(content)
        linked = self.root / 'linked'; linked.symlink_to(self.root, target_is_directory=True)
        with patch.object(a, 'business_volume_roots', return_value={**self.owned, 'roots': {'db': linked}}):
            self.assertEqual(a.sqlite_health_check()['state'], 'unavailable')

if __name__ == '__main__':
    unittest.main()
