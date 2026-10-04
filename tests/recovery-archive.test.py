#!/usr/bin/env python3
"""Real encrypted archive checks; no service or production file modifications."""
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('recovery', Path(__file__).resolve().parents[1] / 'scripts/recovery-archive.py')
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Requires Linux root archive semantics')
class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.previous_umask = os.umask(0o077)
        self.temp = tempfile.TemporaryDirectory(prefix='ironcurtain-recovery-test-')
        self.root = Path(self.temp.name)
        self.key = self.root / 'key'
        self.key.write_bytes(os.urandom(64))
        self.key.chmod(0o600)
        self.install = self.root / 'install.json'
        self.install.write_text(json.dumps({'schema': 1, 'role': 'local', 'host': '127.0.0.1', 'bind': '127.0.0.1',
                                            'image': 'ironcurtain-security:0.2.0-local-' + 'a' * 64, 'version': '0.2.0'}))
        self.install.chmod(0o600)
        self.machine = self.root / 'machine-id'
        self.machine.write_text('0123456789abcdef' * 2)
        self.expected = recovery.binding(self.install, 'local', self.machine)
        self.secret = b'PRIVATE-RECOVERY-IDENTITY-NOT-PUBLIC'
        self.snapshot = self.root / 'snapshot'
        self.snapshot.mkdir(mode=0o700)
        for prefix, filename in [('conf', 'config.tar'), ('data', 'data.tar')]:
            with tarfile.open(self.snapshot / filename, 'w') as archive:
                for path in ['.', './runtime']:
                    entry = tarfile.TarInfo(path)
                    entry.type = tarfile.DIRTYPE
                    entry.mode = 0o750
                    archive.addfile(entry)
                entry = tarfile.TarInfo('./runtime/identity')
                entry.uid = entry.gid = 10001
                entry.mode = 0o600
                entry.size = len(self.secret)
                archive.addfile(entry, io.BytesIO(self.secret))
            (self.snapshot / filename).chmod(0o600)
        self.plain = self.root / 'archive.tar.gz'
        self.cipher = self.root / 'cipher'
        self.backup = self.root / 'role.icbackup'
        self.raw_key = recovery.read_key(self.key)
        recovery.create_tar(self.snapshot, self.expected, self.plain)

    def tearDown(self):
        self.temp.cleanup()
        os.umask(self.previous_umask)

    def seal(self):
        recovery.crypt(self.raw_key, self.plain, self.cipher)
        recovery.seal(self.cipher, self.backup, self.raw_key)

    def test_round_trip_preserves_modes_and_identity_without_cleartext(self):
        self.seal()
        self.assertNotIn(self.secret, self.backup.read_bytes())
        recovery.unseal(self.backup, self.root / 'verified.cipher', self.raw_key)
        recovery.crypt(self.raw_key, self.root / 'verified.cipher', self.root / 'verified.tar.gz', decrypt=True)
        metadata, entries = recovery.inspect_tar(self.root / 'verified.tar.gz', self.expected)
        self.assertEqual(metadata['install']['version'], '0.2.0')
        target = self.root / 'target'
        target.mkdir(mode=0o700)
        recovery.extract(self.root / 'verified.tar.gz', target, entries)
        file = target / 'conf/runtime/identity'
        self.assertEqual(file.read_bytes(), self.secret)
        self.assertEqual(file.stat().st_uid, 10001)
        self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)

    def test_wrong_key_tampering_and_truncation_rejected_before_decrypt(self):
        self.seal()
        original = self.backup.read_bytes()
        for index, payload in enumerate([original[:-1], original[:len(recovery.MAGIC) + 32],
                                          original[:-1] + bytes([original[-1] ^ 1]), b'BAD' + original[3:]]):
            with self.subTest(index=index):
                self.backup.write_bytes(payload)
                with self.assertRaises(ValueError):
                    recovery.unseal(self.backup, self.root / f'rejected-{index}', self.raw_key)
        self.backup.write_bytes(original)
        with self.assertRaises(ValueError):
            recovery.unseal(self.backup, self.root / 'wrong-key', os.urandom(64))

    def test_binding_rejects_other_machine_role_host_version_and_image(self):
        for key, value in [('role', 'cloud'), ('machine', 'b' * 64)]:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    recovery.inspect_tar(self.plain, {**self.expected, key: value})
        for field in ['version', 'host', 'bind', 'image']:
            with self.subTest(field=field):
                expected = {**self.expected, 'install': {**self.expected['install'], field: 'changed'}}
                with self.assertRaises(ValueError):
                    recovery.inspect_tar(self.plain, expected)

    def test_key_and_backup_require_private_single_regular_files(self):
        self.seal()
        self.key.chmod(0o644)
        with self.assertRaises(ValueError):
            recovery.read_key(self.key)
        self.key.chmod(0o600)
        link = self.root / 'linked-key'
        link.symlink_to(self.key)
        with self.assertRaises(OSError):
            recovery.read_key(link)
        link.unlink()
        os.link(self.key, link)
        with self.assertRaises(ValueError):
            recovery.read_key(self.key)
        link.unlink()
        self.backup.chmod(0o644)
        with self.assertRaises(ValueError):
            recovery.unseal(self.backup, self.root / 'bad-mode', self.raw_key)

    def test_unsafe_archive_entries_and_duplicate_names_rejected(self):
        for name in ['/etc/shadow', 'conf/../escape', 'conf//double', './conf/file', 'other/file']:
            with self.subTest(name=name):
                entry = tarfile.TarInfo(name)
                entry.mode = 0o600
                with self.assertRaises(ValueError):
                    recovery.check_member(entry, {}, 0)
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE]:
            with self.subTest(kind=kind):
                entry = tarfile.TarInfo('data/file')
                entry.type, entry.mode = kind, 0o600
                with self.assertRaises(ValueError):
                    recovery.check_member(entry, {}, 0)
        entry = tarfile.TarInfo('conf/file'); entry.mode = 0o600
        names = {}
        recovery.check_member(entry, names, 0)
        with self.assertRaises(ValueError):
            recovery.check_member(entry, names, 0)
        nested = tarfile.TarInfo('conf/file/child'); nested.mode = 0o600
        with self.assertRaises(ValueError):
            recovery.check_member(nested, names, 0)

    def test_owner_permissions_and_capacity_rejected(self):
        for field, value in [('mode', 0o777), ('mode', 0o4600), ('uid', 101), ('gid', 101), ('size', recovery.MAX_FILE + 1)]:
            with self.subTest(field=field):
                entry = tarfile.TarInfo('data/runtime/file'); entry.mode = 0o600
                setattr(entry, field, value)
                with self.assertRaises(ValueError):
                    recovery.check_member(entry, {}, 0)
        entry = tarfile.TarInfo('conf/ca.key'); entry.mode = 0o600; entry.uid = 10001
        with self.assertRaises(ValueError):
            recovery.check_member(entry, {}, 0)
        entry.uid = 0; entry.size = 1
        with self.assertRaises(ValueError):
            recovery.check_member(entry, {}, recovery.MAX_BYTES)

    def test_extraction_refuses_existing_files_and_preserves_them(self):
        _, entries = recovery.inspect_tar(self.plain, self.expected)
        target = self.root / 'existing'
        target.mkdir(mode=0o700)
        evidence = target / 'existing-data'
        evidence.write_bytes(b'preserve')
        with self.assertRaises(ValueError):
            recovery.extract(self.plain, target, entries)
        self.assertEqual(evidence.read_bytes(), b'preserve')

    def test_pair_exports_are_not_reactivated_from_backup(self):
        with tarfile.open(self.snapshot / 'config.tar', 'a') as archive:
            entry = tarfile.TarInfo('./exports/node-fixture.icpair')
            entry.mode = 0o600; entry.size = len(self.secret)
            archive.addfile(entry, io.BytesIO(self.secret))
        recovery.create_tar(self.snapshot, self.expected, self.root / 'without-exports.tar.gz')
        _, entries = recovery.inspect_tar(self.root / 'without-exports.tar.gz', self.expected)
        self.assertFalse(any(item.name.startswith('conf/exports') for item in entries))


if __name__ == '__main__':
    unittest.main()
