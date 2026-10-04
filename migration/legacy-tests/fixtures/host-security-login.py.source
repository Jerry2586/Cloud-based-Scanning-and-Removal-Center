"""Fixed SSH login entry inventory regression fixtures; never read real keys."""
import importlib.util
import json
import os
from pathlib import Path
import socketserver
import tempfile
import unittest
from unittest.mock import patch

if not hasattr(socketserver, 'UnixStreamServer'):
    socketserver.UnixStreamServer = socketserver.TCPServer
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('login_test_agent', ROOT / 'scripts/host-security-agent.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
POSIX = os.name == 'posix'

class LoginTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(patch.stopall)
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / 'login-home'
        self.home.mkdir(mode=0o700)
        self.ssh = self.home / '.ssh'
        self.ssh.mkdir(mode=0o700)
        self.key = self.ssh / 'authorized_keys'
        self.key.write_text('initial-test-public-key')
        self.key.chmod(0o600)
        self.passwd = self.root / 'passwd'
        home_text = self.home.as_posix()
        if not POSIX:
            home_text = home_text.split(':', 1)[1]
        self.uid = os.getuid() if POSIX else 0
        self.row = f'localuser:x:{self.uid}:0::{home_text}:/bin/sh\n'
        self.passwd.write_text(self.row)
        patch.object(a, 'LOCAL_PASSWD', self.passwd).start()
        patch.object(a, 'HOST_FILES', (str(self.passwd),)).start()
        patch.object(a, 'HOST_DIRS', ()).start()
        patch.object(a, 'ROOT', self.root).start()
        state = self.root / 'state'
        state.mkdir(mode=0o700)
        patch.object(a, 'HOST_BASELINE', state / 'host-baseline.json').start()
        for name in ('MAX_LOCAL_ACCOUNTS', 'MAX_LOGIN_HOMES', 'MAX_LOGIN_FILE_BYTES', 'MAX_LOGIN_BYTES'):
            patch.object(a, name, getattr(a, name)).start()
        a.write_host_baseline()
        self.baseline = a.HOST_BASELINE.read_bytes()

    def assertUnknown(self):
        self.assertEqual(a.host_configuration_check()['state'], 'unavailable')
        self.assertEqual(a.HOST_BASELINE.read_bytes(), self.baseline)
        with self.assertRaises((OSError, ValueError)):
            a.write_host_baseline()
        self.assertEqual(a.HOST_BASELINE.read_bytes(), self.baseline)

    def test_changed_added_removed_entry_and_directory_preserve_baseline(self):
        self.assertEqual(a.host_configuration_check()['state'], 'ok')
        self.key.write_text('attacker-test-public-key')
        report = a.host_configuration_check()
        self.assertEqual(report['state'], 'finding')
        self.assertNotIn('attacker-test-public-key', json.dumps(report))
        self.assertNotIn('initial-test-public-key', json.dumps(report))
        self.key.write_text('initial-test-public-key')
        self.assertEqual(a.host_configuration_check()['state'], 'ok')
        for entry in a.SSH_LOGIN_FILES:
            target = self.ssh / entry
            if target == self.key:
                continue
            target.write_text('sensitive-test-entry'); target.chmod(0o600)
            self.assertEqual(a.host_configuration_check()['state'], 'finding')
            self.assertNotIn('sensitive-test-entry', json.dumps(a.host_configuration_check()))
            target.unlink()
            self.assertEqual(a.host_configuration_check()['state'], 'ok')
        self.key.unlink()
        self.assertEqual(a.host_configuration_check()['state'], 'finding')
        self.ssh.rmdir()
        self.assertEqual(a.host_configuration_check()['state'], 'finding')
        self.assertEqual(a.HOST_BASELINE.read_bytes(), self.baseline)

    def test_missing_home_and_ssh_are_tracked_until_created(self):
        self.key.unlink(); self.ssh.rmdir(); self.home.rmdir()
        a.write_host_baseline()
        self.assertEqual(a.host_configuration_check()['state'], 'ok')
        self.home.mkdir(mode=0o700)
        self.assertEqual(a.host_configuration_check()['state'], 'finding')
        a.write_host_baseline()
        self.ssh.mkdir(mode=0o700)
        self.assertEqual(a.host_configuration_check()['state'], 'finding')

    def test_old_host_inventory_requires_explicit_approval_and_pin_changes(self):
        old = json.loads(self.baseline)
        old['files'] = {str(self.passwd): old['files'][str(self.passwd)]}
        a.atomic_json(a.HOST_BASELINE, old)
        before = a.approved_baseline_pin(a.HOST_BASELINE)
        self.assertEqual(a.host_configuration_check()['state'], 'finding')
        self.assertEqual(json.loads(a.HOST_BASELINE.read_bytes()), old)
        a.write_host_baseline()
        self.assertEqual(a.host_configuration_check()['state'], 'ok')
        self.assertNotEqual(a.approved_baseline_pin(a.HOST_BASELINE), before)

    def test_excluded_shells_and_shared_home_are_bounded_and_private_files_unread(self):
        (self.ssh / 'id_ed25519').write_text('NEVER-READ-PRIVATE-KEY')
        (self.ssh / 'private-unbounded').write_bytes(b'x' * (a.MAX_LOGIN_FILE_BYTES + 1))
        self.passwd.write_text(self.row + f'alias:x:{self.uid}:0::{self.home.as_posix() if POSIX else self.home.as_posix().split(":",1)[1]}:/bin/sh\n' +
                               'nologin:x:100:100::/bin:/usr/sbin/nologin\nsync:x:4:4::/bin:/bin/sync\n')
        actual = []
        original = a.read_regular
        def recording(path, *args, **kwargs):
            actual.append(str(path))
            return original(path, *args, **kwargs)
        with patch.object(a, 'read_regular', recording):
            snapshot = a.local_login_inventory()
        self.assertNotIn(str(self.ssh / 'id_ed25519'), snapshot)
        self.assertNotIn(str(self.ssh / 'id_ed25519'), actual)
        self.assertNotIn(str(self.ssh / 'private-unbounded'), actual)
        self.assertNotIn('/bin/', snapshot)
        self.assertEqual(len(snapshot), 7)

    @unittest.skipIf(POSIX and os.getuid() != 0, 'root fixture ownership required')
    def test_root_accounts_are_included_even_with_disabled_shell(self):
        self.passwd.write_text(self.row.replace(':/bin/sh', ':/usr/sbin/nologin').replace(f':{self.uid}:0:', ':0:0:'))
        snapshot = a.local_login_inventory()
        self.assertTrue(any(Path(name).absolute() == self.key for name in snapshot))

    def test_malformed_duplicate_and_noncanonical_login_home_rejected(self):
        for row in ('broken\n', self.row + self.row, self.row.replace(':x:', ':x:bad:'),
                    self.row.replace(':/bin/sh', '/../bad:/bin/sh'),
                    'bad:x:0:0::/:/bin/sh\n', 'bad:x:0:0::/home/../root:/bin/sh\n',
                    'bad:x:0:0:://home/local:/bin/sh\n', 'bad:x:0:0::relative:/bin/sh\n',
                    'bad:x:4294967295:0::/root:/bin/sh\n'):
            self.passwd.write_text(row)
            self.assertUnknown()

    def test_account_home_file_and_total_byte_limits(self):
        a.MAX_LOCAL_ACCOUNTS = 0; self.assertUnknown(); a.MAX_LOCAL_ACCOUNTS = 256
        a.MAX_LOGIN_HOMES = 0; self.assertUnknown(); a.MAX_LOGIN_HOMES = 64
        a.MAX_LOGIN_FILE_BYTES = 1; self.assertUnknown(); a.MAX_LOGIN_FILE_BYTES = 65536
        a.MAX_LOGIN_BYTES = 1; self.assertUnknown()

    def test_passwd_host_digest_must_match_login_inventory(self):
        self.key.write_text('not-a-private-key')
        with self.assertRaises(OSError):
            a.local_login_inventory('a' * 64)
        self.assertEqual(a.HOST_BASELINE.read_bytes(), self.baseline)

    def test_combined_inventory_cap_includes_missing_environment(self):
        inventory = {f'/login-limit-{index}': {'missing': True} for index in range(2047)}
        with patch.object(a, 'local_login_inventory', return_value=inventory):
            self.assertUnknown()

    def test_account_replacement_during_inventory_rejected(self):
        original = a.read_regular
        calls = 0
        def changed(path, *args, **kwargs):
            nonlocal calls
            data = original(path, *args, **kwargs)
            if Path(path) == self.passwd:
                calls += 1
                if calls % 3 == 0:
                    return data + b'changed'
            return data
        with patch.object(a, 'read_regular', changed):
            self.assertUnknown()

    @unittest.skipUnless(POSIX, 'POSIX modes required')
    def test_modes_and_directory_owner_cannot_be_approved(self):
        for target in (self.home, self.ssh, self.key):
            mode = target.stat().st_mode & 0o777
            target.chmod(0o777)
            self.assertUnknown()
            target.chmod(mode)
        if os.getuid() == 0:
            os.chown(self.ssh, 23456, 0)
            self.assertUnknown()
            os.chown(self.ssh, 0, 0)
            os.chown(self.key, 23456, 0)
            self.assertUnknown()
            os.chown(self.key, 0, 0)

    @unittest.skipUnless(POSIX, 'POSIX modes required')
    def test_safe_directory_and_file_mode_changes_are_still_findings(self):
        self.key.chmod(0o644)
        self.assertEqual(a.host_configuration_check()['state'], 'finding')
        self.key.chmod(0o600); self.ssh.chmod(0o755)
        self.assertEqual(a.host_configuration_check()['state'], 'finding')

    @unittest.skipUnless(POSIX, 'POSIX special entries required')
    def test_entry_symlink_hardlink_fifo_and_directory_rejected(self):
        self.key.unlink()
        outside = self.root / 'outside'; outside.write_text('do-not-read')
        self.key.symlink_to(outside); self.assertUnknown(); self.key.unlink()
        os.link(outside, self.key); self.assertUnknown(); self.key.unlink()
        os.mkfifo(self.key); self.assertUnknown(); self.key.unlink()
        self.key.mkdir(); self.assertUnknown(); self.key.rmdir()
        self.key.symlink_to(self.root / 'missing'); self.assertUnknown()

    @unittest.skipUnless(POSIX, 'POSIX symlinks required')
    def test_home_ssh_and_missing_child_under_symlink_ancestor_rejected(self):
        moved = self.root / 'moved'
        self.home.rename(moved); self.home.symlink_to(moved, target_is_directory=True)
        self.assertUnknown(); self.home.unlink(); moved.rename(self.home)
        moved_ssh = self.home / 'moved-ssh'
        self.ssh.rename(moved_ssh); self.ssh.symlink_to(moved_ssh, target_is_directory=True)
        self.assertUnknown(); self.ssh.unlink(); moved_ssh.rename(self.ssh)
        self.key.unlink(); self.ssh.rmdir()
        self.home.rename(moved); self.home.symlink_to(moved, target_is_directory=True)
        self.assertUnknown()

    @unittest.skipUnless(POSIX, 'POSIX atomic directory rename required')
    def test_directory_replacement_during_entry_read_rejected(self):
        original = a.read_regular
        swapped = False
        def reading(path, *args, **kwargs):
            nonlocal swapped
            data = original(path, *args, **kwargs)
            if Path(path) == self.key and not swapped:
                swapped = True
                old = self.home / 'old-ssh'; self.ssh.rename(old)
                self.ssh.mkdir(mode=0o700)
                (self.ssh / 'authorized_keys').write_bytes(data)
                (self.ssh / 'authorized_keys').chmod(0o600)
            return data
        with patch.object(a, 'read_regular', reading):
            self.assertEqual(a.host_configuration_check()['state'], 'unavailable')
        self.assertEqual(a.HOST_BASELINE.read_bytes(), self.baseline)

if __name__ == '__main__':
    unittest.main()
