"""Root Linux credential transaction tests; all paths isolated under /root."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import fcntl
import multiprocessing
import socket
import http.client
import time

SOURCE = Path(os.environ.get('IRONCURTAIN_ACCOUNT_TEST_SOURCE', Path(__file__).resolve().parents[1] / 'scripts/account_control.py'))
spec = importlib.util.spec_from_file_location('account_control', SOURCE)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
OLD = 'original-Test-Password-123'
NEW = 'new-Custom-Password-456'

@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'requires root Linux')
class AccountTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ironcurtain-account-test.', dir='/root')
        self.base = Path(self.tmp.name)
        self.c = a.AccountControl('local')
        self.c.conf = self.base / 'conf'
        self.c.base = self.base / 'program'
        self.c.control = self.c.conf / 'account-control'
        self.c.runtime = self.c.conf / 'runtime/panel-auth.json'
        self.c.recovery = self.c.conf / 'credentials/panel-auth.json'
        self.c.initial = self.c.recovery.parent / 'initial-credentials.txt'
        self.c.journal = self.c.control / 'transaction.json'
        self.c.lock_path = self.base / 'lock/control.lock'
        self.c.socket_dir = self.base / 'socket'
        for p in [self.c.control, self.c.runtime.parent, self.c.recovery.parent, self.c.base, self.c.lock_path.parent, self.c.socket_dir]:
            p.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.previous = {'schema': 1, 'username': 'admin', 'salt': 'a'*64, 'hash': a.digest(OLD, 'a'*64)}
        a.atomic(self.c.runtime, a.encode(self.previous), 10001)
        a.atomic(self.c.recovery, a.encode(self.previous))
        a.atomic(self.c.initial, ('admin\n'+OLD+'\n').encode())
    def tearDown(self):
        self.tmp.cleanup()
    def change(self):
        return self.c.change({'current_password': OLD, 'new_password': NEW})
    def unchanged(self):
        self.assertEqual(self.c.record(), self.previous)
        self.assertEqual(json.loads(self.c.recovery.read_bytes()), self.previous)
    def test_node_scrypt_unicode_compatible(self):
        self.assertEqual(a.digest('中文Unicode🔐password','a'*64), '1b6accbf6a608dfa0c5cb2751e8ff02deb005904a94dd7788eea222552294736854bbe611e0ae88d574f627fd25be5c14f1fae0eb5b5511ba06894431a9d316c')
    def test_change_persists_mirrors_without_plaintext(self):
        self.assertTrue(self.change()['changed'])
        self.assertEqual(self.c.record()['hash'], a.digest(NEW, self.c.record()['salt']))
        self.assertEqual(json.loads(self.c.recovery.read_bytes()), self.c.record())
        for p in [self.c.runtime,self.c.recovery,self.c.initial]:
            self.assertNotIn(NEW.encode(),p.read_bytes())
            self.assertEqual(p.stat().st_mode & 0o777,0o600)
        self.assertEqual(self.c.runtime.stat().st_uid,10001)
        self.assertFalse(self.c.journal.exists())
    def test_root_recovery_needs_no_old_password(self):
        self.c.change({'new_password': NEW},root=True)
        self.assertEqual(self.c.record()['hash'],a.digest(NEW,self.c.record()['salt']))
    def test_wrong_current_same_password_rejected(self):
        for value in [{'current_password':'wrong','new_password':NEW},{'current_password':OLD,'new_password':OLD}]:
            with self.assertRaises(a.AccountError): self.c.change(value)
            self.unchanged()
    def test_strict_schema_and_passwords(self):
        for value in [None,{},[],{'new_password':NEW},{'current_password':OLD,'new_password':NEW,'path':'/etc/passwd'}]:
            with self.assertRaises(a.AccountError):self.c.change(value)
        for p in ['short','x'*257,'x'*12+'\n','x'*12+'\0','x'*12+'\r','x'*12+'\ud800']:
            with self.assertRaises(a.AccountError): self.c.change({'current_password':OLD,'new_password':p})
        self.unchanged()
    def test_unsafe_file_owner_link_and_mode_rejected(self):
        for mode in [0o644,0o660]:
            self.c.runtime.chmod(mode)
            with self.assertRaises(a.AccountError):self.change()
        self.c.runtime.chmod(0o600)
        os.chown(self.c.runtime,0,0)
        with self.assertRaises(a.AccountError):self.change()
        os.chown(self.c.runtime,10001,10001)
        link=self.c.runtime.parent/'hardlink';os.link(self.c.runtime,link)
        with self.assertRaises(a.AccountError):self.change()
        link.unlink()
        self.c.runtime.rename(link);self.c.runtime.symlink_to(link)
        with self.assertRaises(OSError):self.change()
    def test_untrusted_parent_rejected(self):
        self.c.control.chmod(0o777)
        with self.assertRaises(a.AccountError):self.change()
        self.unchanged()
    def test_lock_busy_and_installer_journal_rejected(self):
        with self.c.lock_path.open('w') as f:
            fcntl.flock(f,fcntl.LOCK_EX)
            with self.assertRaises(a.AccountError) as e:self.change()
            self.assertEqual(e.exception.status,409)
            self.assertTrue(self.c.ready()['ready'])
        for name in ['transaction.json','admin-transaction.json']:
            p=self.c.base/name;p.write_text('{}')
            with self.assertRaises(a.AccountError) as e:self.change()
            self.assertEqual(e.exception.status,409);p.unlink()
        self.unchanged()
    def test_precommit_failure_restores_old_password(self):
        original=a.atomic;failed=False
        def fault(path,value,uid=0):
            nonlocal failed
            if Path(path)==self.c.runtime and not failed:
                failed=True;raise OSError('injected before runtime rename')
            return original(path,value,uid)
        with patch.object(a,'atomic',fault):
            with self.assertRaises(a.AccountError):self.change()
        self.unchanged();self.assertFalse(self.c.journal.exists())
    def test_postcommit_failure_reconciles_new_password(self):
        original=a.atomic;failed=False
        def fault(path,value,uid=0):
            nonlocal failed
            result=original(path,value,uid)
            if Path(path)==self.c.runtime and not failed:
                failed=True;raise OSError('injected after runtime commit')
            return result
        with patch.object(a,'atomic',fault):self.assertTrue(self.change()['changed'])
        self.assertEqual(self.c.record()['hash'],a.digest(NEW,self.c.record()['salt']))
        self.assertEqual(json.loads(self.c.recovery.read_bytes()),self.c.record())
    def test_pending_journal_restart_recovery_before_and_after_commit(self):
        next_record={'schema':1,'username':'admin','salt':'b'*64,'hash':a.digest(NEW,'b'*64)}
        for committed in [False,True]:
            a.atomic(self.c.runtime,a.encode(next_record if committed else self.previous),10001)
            a.atomic(self.c.journal,a.encode({'old_runtime':self.previous,'old_recovery':self.previous,'old_initial':'admin\nold\n','next':next_record}))
            self.c.lock_path.touch(mode=0o600)
            self.assertTrue(self.c.ready()['ready'])
            expected=next_record if committed else self.previous
            self.assertEqual(self.c.record(),expected)
            self.assertEqual(json.loads(self.c.recovery.read_bytes()),expected)
            self.assertFalse(self.c.journal.exists())
    def test_real_unix_identity_and_http_boundaries(self):
        # Reachable directory only for this isolated test; production is root:10001 0750.
        self.base.chmod(0o755);self.c.socket_dir.chmod(0o755)
        proc=multiprocessing.Process(target=self.c.serve);proc.start()
        address=str(self.c.socket_dir/'control.sock')
        def request(method,path,body=None,headers=None):
            conn=http.client.HTTPConnection('localhost',timeout=3)
            conn.sock=socket.socket(socket.AF_UNIX);conn.sock.connect(address)
            conn.request(method,path,body,headers or {})
            r=conn.getresponse();result=(r.status,json.loads(r.read()));conn.close();return result
        try:
            for _ in range(50):
                if Path(address).exists():break
                time.sleep(.02)
            self.assertEqual(request('GET','/account')[0],200)
            self.assertEqual(request('GET','/unknown')[0],404)
            self.assertEqual(request('POST','/account/password','{}',{'Content-Type':'text/plain'})[0],400)
            self.assertEqual(request('POST','/account/password',json.dumps({'current_password':OLD,'new_password':NEW}),{'Content-Type':'application/json'})[0],200)
            # Enter /root before dropping identity; no relaxation of root's home permissions.
            code='import socket,http.client; c=http.client.HTTPConnection("localhost");c.sock=socket.socket(socket.AF_UNIX);c.sock.connect('+repr(address)+');c.request("GET","/account");print(c.getresponse().status)'
            def peer(uid):
                return subprocess.check_output(['setpriv','--reuid='+str(uid),'--regid=10001','--clear-groups',sys.executable,'-c',code],cwd=self.base,text=True).strip()
            # Relative socket avoids /root traversal by non-root identities.
            code=code.replace(repr(address),repr('socket/control.sock'))
            self.assertEqual(peer(10001),'200')
            self.assertEqual(peer(65534),'403')
        finally:
            proc.terminate();proc.join(5)
            self.assertFalse(proc.is_alive())

if __name__ == '__main__': unittest.main(verbosity=2)
