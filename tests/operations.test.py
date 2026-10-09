#!/usr/bin/env python3
"""Real Linux filesystem, advisory-lock and Unix-peer checks; no host service mutation."""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

LINUX_ROOT = sys.platform == 'linux' and os.geteuid() == 0
if LINUX_ROOT:
    spec = importlib.util.spec_from_file_location('operations', Path(__file__).parents[1] / 'src/host/operations.py')
    o = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(o)


@unittest.skipUnless(LINUX_ROOT, 'requires a root Linux runner')
class OperationsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ic-operations-', dir='/root')
        self.base = Path(self.temp.name)
        self.scope = self.base / 'business'
        self.scope.mkdir(mode=0o700)
        self.state = self.base / 'agent'
        self.state.mkdir(mode=0o700)
        self.profile_file = self.base / 'profile.json'
        self.profile = o.a.profile_validate({'schema': 'ironcurtain-profile/v1', 'program_roots': [str(self.scope)], 'approved_tcp_ports': [22]})
        o.persist(self.profile_file, self.profile)
        self.restarts = []
        self.lock = self.base / 'management.lock'
        self.ops = self.controller()
        self.ops.pending = []

    def tearDown(self):
        if self.ops.thread:
            self.ops.thread.join(timeout=10)
            self.assertFalse(self.ops.thread.is_alive(), 'operation leaked a worker')
        self.temp.cleanup()

    def controller(self, restart=None):
        return o.Operations(self.profile_file, self.state, self.lock, restart or (lambda: self.restarts.append('restart')))

    def submit(self, value, expected='complete'):
        self.ops.last_action = 0
        status, receipt = self.ops.trigger(value)
        self.assertEqual(status, 202)
        self.ops.thread.join(timeout=10)
        self.assertFalse(self.ops.thread.is_alive())
        self.assertEqual(self.ops.job['state'], expected, self.ops.job['reason'])
        self.assertEqual(self.ops.snapshot()['audit'][-1]['id'], receipt['job']['id'])
        return self.ops.job

    def ports(self, **changes):
        return {**dict(action='ports', revision=o.digest(self.ops.config()), tcp=[443, 22], udp=[53]), **changes}

    def transaction(self, phase='applied', **changes):
        candidate = {**self.profile, 'approved_tcp_ports': [22, 443], **changes}
        journal = {'schema': 'ironcurtain-port-transaction/v1', 'previous': self.profile, 'candidate': candidate, 'phase': phase}
        o.persist(self.ops.transaction_file, journal)
        o.persist(self.profile_file, candidate)
        return candidate

    def observe(self):
        self.file = self.scope / 'sample.php'
        self.file.write_bytes(b'fixture-suspect-code')
        self.file.chmod(0o600)
        item = {'path': str(self.file), 'signature': 'Test.Signature', 'sha256': hashlib.sha256(self.file.read_bytes()).hexdigest(), 'observed_at': o.a.utc(), **o.r.f.identity(self.file.stat())}
        item['id'] = o.digest(item)
        bundle = {'schema': 'ironcurtain-findings/v1', 'state': 'complete', 'items': [item], 'total': 1, 'profile_digest': o.digest(self.ops.config())}
        o.persist(self.state / 'last-findings.json', bundle)
        return item

    def test_fixed_action_validation_rejects_commands_paths_and_malformed_types(self):
        for value in [None, [], {'action': []}, {'action': {}}, {'action': '__proto__'}, {**self.ports(), 'command': 'sh'}, {**self.ports(), 'tcp': [True]}, {**self.ports(), 'tcp': [22, 22]}, {**self.ports(), 'tcp': [0]}, {**self.ports(), 'tcp': list(range(1,130))}, {'action': 'restore', 'id': 'a'*64, 'confirm': 'yes'}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                o.validate(value)
        self.assertEqual(o.ports([443,22]), [22,443])

    def test_ports_transaction_is_durable_and_does_not_change_other_profile_fields(self):
        self.submit(self.ports())
        self.assertEqual(self.ops.config(), dict(self.profile, approved_tcp_ports=[22,443], approved_udp_ports=[53]))
        self.assertEqual(self.restarts, ['restart'])
        self.assertFalse(self.ops.transaction_file.exists())
        self.assertEqual(stat.S_IMODE(self.profile_file.stat().st_mode), 0o600)
        self.assertIn('不关闭端口', self.ops.job['reason'])

    def test_stale_revision_does_not_write_or_restart(self):
        value=self.ports();value['revision']='f'*64
        self.submit(value, 'failed')
        self.assertEqual(self.ops.config(), self.profile)
        self.assertFalse(self.ops.transaction_file.exists())
        self.assertEqual(self.restarts, [])

    def test_failed_restart_rolls_back_and_failed_rollback_retains_recovery_journal(self):
        attempts=[]
        def once():
            attempts.append(True)
            if len(attempts)==1: raise RuntimeError('new-service-failed')
        self.ops.restart=once
        self.submit(self.ports(), 'failed')
        self.assertEqual(len(attempts),2)
        self.assertEqual(self.ops.config(),self.profile)
        self.assertFalse(self.ops.transaction_file.exists())
        def always(): raise RuntimeError('rollback-service-failed')
        self.ops.restart=always
        self.submit(self.ports(), 'failed')
        self.assertTrue(self.ops.transaction_file.exists())
        self.ops.restart=lambda:None
        with o.lease(self.lock): self.ops.recover_ports()
        self.assertEqual(self.ops.config(),self.profile)
        self.assertFalse(self.ops.transaction_file.exists())

    def test_crash_recovery_rolls_back_uncommitted_and_retains_committed(self):
        self.transaction()
        with o.lease(self.lock): self.ops.recover_ports()
        self.assertEqual(self.ops.config(),self.profile)
        candidate=self.transaction('committed')
        with o.lease(self.lock): self.ops.recover_ports()
        self.assertEqual(self.ops.config(),candidate)
        self.assertEqual(len(self.restarts),1)

    def test_corrupt_or_expanded_transaction_is_retained_without_restarting(self):
        for journal in [[], {'schema':'unknown'}, {'schema':'ironcurtain-port-transaction/v1','previous':self.profile,'candidate':dict(self.profile,business_roots=[str(self.scope)]),'phase':'applied'}]:
            o.persist(self.ops.transaction_file,journal)
            with self.assertRaises((ValueError,TypeError)), o.lease(self.lock): self.ops.recover_ports()
            self.assertTrue(self.ops.transaction_file.exists())
            self.assertEqual(self.restarts,[])
        self.transaction()
        o.persist(self.profile_file,dict(self.profile,approved_tcp_ports=[80]))
        with self.assertRaises(ValueError), o.lease(self.lock): self.ops.recover_ports()
        self.assertEqual(self.ops.config()['approved_tcp_ports'],[80])

    def test_shared_scan_lease_and_existing_management_transaction_reject_before_execution(self):
        import fcntl
        fd=os.open(self.lock,os.O_CREAT|os.O_RDWR,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
            self.assertEqual(self.ops.trigger(self.ports())[0],409)
            self.assertEqual(self.ops.job,{'state':'idle'})
        finally: os.close(fd)
        pending=self.base/'pending.json';pending.write_text('{}')
        self.ops.pending=[pending]
        self.assertEqual(self.ops.trigger(self.ports())[0],409)
        self.assertEqual(self.restarts,[])

    def test_running_job_blocks_new_actions_and_restart_marks_interrupted(self):
        entered=threading.Event();release=threading.Event()
        def restart():
            entered.set()
            if not release.wait(5): raise RuntimeError('test-timeout')
        self.ops.restart=restart
        self.assertEqual(self.ops.trigger(self.ports())[0],202)
        try:
            self.assertTrue(entered.wait(2))
            self.assertEqual(self.ops.trigger(self.ports())[0],409)
        finally: release.set()
        self.ops.thread.join(5)
        saved=dict(self.ops.job,state='running');saved.pop('finished_at',None)
        o.persist(self.ops.job_file,saved)
        recovered=self.controller()
        self.assertEqual(recovered.job['state'],'interrupted')
        self.assertEqual(recovered.snapshot()['audit'][-1]['state'],'interrupted')

    def test_real_isolation_and_original_restore_preserve_evidence_and_never_overwrite(self):
        item=self.observe();content=self.file.read_bytes()
        self.submit({'action':'quarantine','id':item['id'],'confirm':'quarantine'})
        self.assertFalse(self.file.exists())
        self.assertEqual(self.ops.snapshot()['quarantine']['items'][0]['state'],'quarantined')
        self.file.write_bytes(b'new-business-data')
        self.submit({'action':'restore','id':item['id'],'confirm':'restore-original'},'failed')
        self.assertEqual(self.file.read_bytes(),b'new-business-data')
        self.file.unlink()
        self.submit({'action':'restore','id':item['id'],'confirm':'restore-original'})
        self.assertEqual(self.file.read_bytes(),content)
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode),0o600)
        self.assertTrue((self.state/'quarantine'/(item['id']+'.blob')).exists())
        self.assertIn('不能视为干净恢复',self.ops.job['reason'])

    def test_changed_sample_is_not_removed_and_failure_is_audited(self):
        item=self.observe();self.file.write_bytes(b'new-content')
        self.submit({'action':'quarantine','id':item['id'],'confirm':'quarantine'},'failed')
        self.assertEqual(self.file.read_bytes(),b'new-content')
        self.assertEqual(self.ops.snapshot()['audit'][-1]['state'],'failed')

    def test_reviews_require_fresh_matching_evidence_without_accepting_stale_reports(self):
        risk={'id':'a'*64,'evidence':'b'*64,'fresh':True}
        self.ops.risk_snapshot=lambda profile:([risk],{})
        value={'action':'review','id':risk['id'],'evidence':risk['evidence'],'status':'accepted','reason':'业务临时需要'}
        self.submit(value)
        self.assertEqual(self.ops.reviews()[risk['id']]['status'],'accepted')
        risk['evidence']='c'*64
        self.submit(value,'failed')
        risk['evidence']=value['evidence'];risk['fresh']=False
        self.submit(value,'failed')
        self.assertEqual(self.ops.reviews()[risk['id']]['evidence'],value['evidence'])

    def test_missing_sources_and_utf8_response_budget_never_become_full_coverage(self):
        status=self.ops.snapshot()
        self.assertEqual(status['sources'],{'environment':'unavailable','engines':'unavailable','engine_coverage':'0/4','truncated':False})
        sources=dict(status['sources'])
        self.ops.risk_snapshot=lambda profile:([{'detail':'界'*3000,'id':format(i,'064x')} for i in range(96)],dict(sources))
        limited=self.ops.snapshot()
        self.assertLessEqual(len(o.a.canonical(limited)),262144)
        self.assertTrue(limited['sources']['truncated'])
        self.assertEqual(limited['sources']['engine_coverage'],'0/4')

    def test_untrusted_state_symlink_hardlink_permissions_and_corrupt_audit_fail_closed(self):
        target=self.base/'elsewhere.json';o.persist(target,[])
        self.ops.audit_file.symlink_to(target)
        with self.assertRaises((OSError,ValueError)):self.ops.snapshot()
        self.ops.audit_file.unlink();os.link(target,self.ops.audit_file)
        with self.assertRaises(ValueError):self.ops.snapshot()
        self.ops.audit_file.unlink();o.persist(self.ops.audit_file,[]);self.ops.audit_file.chmod(0o666)
        with self.assertRaises(ValueError):self.ops.snapshot()
        self.ops.audit_file.chmod(0o600);o.persist(self.ops.audit_file,[{'state':'complete'}])
        with self.assertRaises(ValueError):self.ops.snapshot()
        other=self.base/'other';other.mkdir(mode=0o700)
        import shutil
        shutil.rmtree(self.ops.directory)
        self.ops.directory.symlink_to(other,target_is_directory=True)
        with self.assertRaises(ValueError):self.controller()

    def test_native_unix_credentials_and_http_framing(self):
        with tempfile.TemporaryDirectory(prefix='ic-op-socket-') as temporary:
            directory=Path(temporary);directory.chmod(0o755)
            path=directory/'control.sock'
            server=socketserver.UnixStreamServer(str(path),o.handler(self.ops))
            path.chmod(0o666)  # Test-only access, so SO_PEERCRED is independently exercised.
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            def request(raw):
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(5);client.connect(str(path));client.sendall(raw)
                    parts=[]
                    while True:
                        part=client.recv(65536)
                        if not part:break
                        parts.append(part)
                    return b''.join(parts)
            try:
                self.assertIn(b'200 OK',request(b'GET /operations HTTP/1.0\r\n\r\n'))
                for uid,expected in [(10001,'200 OK'),(10002,'403 Forbidden')]:
                    code='import os,socket,sys;os.setgroups([]);os.setgid(int(sys.argv[2]));os.setuid(int(sys.argv[2]));s=socket.socket(socket.AF_UNIX);s.settimeout(5);s.connect(sys.argv[1]);s.sendall(b"GET /operations HTTP/1.0\\r\\n\\r\\n");print(s.recv(4096).decode())'
                    result=subprocess.run([sys.executable,'-c',code,str(path),str(uid)],capture_output=True,text=True,timeout=10)
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertIn(expected,result.stdout)
                for headers,body in [(b'Content-Length: 2\r\nContent-Length: 2',b'{}'),(b'Transfer-Encoding: chunked\r\nContent-Length: 2',b'{}'),(b'Content-Length: 4097',b'{}'),(b'Content-Length: 38',b'{"action":"ports","action":"restore"}')]:
                    # Use actual duplicate-body length while preserving over-budget header.
                    if body.startswith(b'{"action"'):headers=b'Content-Length: '+str(len(body)).encode()
                    response=request(b'POST /operations HTTP/1.0\r\nContent-Type: application/json\r\n'+headers+b'\r\n\r\n'+body)
                    self.assertIn(b'400 Bad Request',response)
                self.assertEqual(self.ops.job,{'state':'idle'})
            finally:
                server.shutdown();server.server_close();thread.join(5)



    def scope_inventory(self, container=False):
        self.target = self.base / 'new-site'
        self.target.mkdir(mode=0o700, exist_ok=True)
        candidates = [o.a.inventory.candidate('business_roots', str(self.target), '测试业务目录')]
        rows = []
        if container:
            candidates.append(o.a.inventory.candidate('containers', 'app', '容器'))
            rows = [{'name':'app','container_id':'a'*64,'image_id':'sha256:'+'b'*64,'running':True,'readonly':False,'user':'','risks':[], 'process_count':1,'filesystem_state':'observed','changed_paths':0,'changes_digest':'c'*64,'mounts':[]}]
        return {'schema':'ironcurtain-inventory/v1','observed_at':o.a.utc(),'containers':rows,'listeners':[],'candidates':candidates,'issues':[], 'container_state':'complete','listener_state':'complete','directory_state':'complete','drift':[],'drift_state':'first-observation'}

    def discover(self, inventory):
        with patch.object(o.a.inventory, 'discover', return_value=inventory): self.submit({'action':'discover'})
        snapshot = self.ops.snapshot()
        self.assertEqual(snapshot['scope']['discovery']['state'], 'ready')
        return {'action':'enroll','revision':snapshot['policy']['revision'],'inventory':snapshot['scope']['discovery']['revision'],'ids':[v['id'] for v in inventory['candidates']]}

    def test_scope_enrollment_restarts_atomically_preserves_policy_and_never_approves_images(self):
        inventory = self.scope_inventory(container=True)
        value = self.discover(inventory)
        calls=[]
        def inspect(args, **limits):
            calls.append((args, limits));return 0,json.dumps([{'Name':'/app','Id':'a'*64,'Image':'sha256:'+'b'*64}])
        self.ops.runner=inspect
        self.submit(value)
        self.assertEqual(self.ops.config(),dict(self.profile,business_roots=[str(self.target)],containers=[{'name':'app'}]))
        self.assertEqual(self.restarts,['restart']);self.assertFalse(self.ops.transaction_file.exists())
        self.assertEqual(calls[0][0],['docker','inspect','--type','container','--','app'])
        self.assertLessEqual(calls[0][1]['seconds'],3)
        self.assertEqual(stat.S_IMODE(self.ops.discovery_file.stat().st_mode),0o600)
        scope=self.ops.snapshot()['scope'];self.assertEqual(scope['discovery']['state'],'stale');self.assertTrue(all(c['enrolled'] for c in scope['discovery']['candidates']))
        self.assertIn('重新扫描',self.ops.job['reason'])

    def test_stale_unknown_conflicting_and_replaced_directory_candidates_never_write(self):
        inventory=self.scope_inventory();value=self.discover(inventory)
        for change in [dict(inventory='d'*64),dict(revision='e'*64),dict(ids=['f'*16])]:
            self.submit(dict(value,**change),'failed');self.assertEqual(self.ops.config(),self.profile)
        record=self.ops.discovery_record();record['inventory']['observed_at']='2000-01-01T00:00:00.000Z';o.persist(self.ops.discovery_file,record)
        self.submit(dict(value,inventory=o.digest(record)),'failed');self.assertEqual(self.ops.config(),self.profile)
        value=self.discover(inventory)
        original=self.target.with_name('original');self.target.rename(original);self.target.mkdir()
        self.submit(value,'failed');self.assertIn('替换',self.ops.job['reason'])
        self.target.rmdir();self.target.symlink_to(original,target_is_directory=True)
        self.submit(value,'failed');self.assertEqual(self.ops.config(),self.profile);self.assertEqual(self.restarts,[])

    def test_changed_container_identity_or_image_and_missing_identity_refuse_enrollment(self):
        inventory=self.scope_inventory(container=True);value=self.discover(inventory)
        for changes in [{'Id':'d'*64},{'Image':'sha256:'+'e'*64},{'Name':'/other'}]:
            self.ops.runner=lambda args,**limits:(0,json.dumps([{**dict(Name='/app',Id='a'*64,Image='sha256:'+'b'*64),**changes}]))
            self.submit(value,'failed');self.assertEqual(self.ops.config(),self.profile)
        inventory['containers'][0].pop('container_id')
        with patch.object(o.a.inventory,'discover',return_value=inventory): self.submit({'action':'discover'},'failed')
        self.assertEqual(self.ops.snapshot()['scope']['discovery']['revision'],value['inventory'])
        self.assertEqual(self.ops.snapshot()['scope']['discovery']['state'],'ready')
        self.assertEqual(self.restarts,[])

    def test_enrollment_restart_failure_rolls_back_and_recovery_rejects_baseline_approval(self):
        value=self.discover(self.scope_inventory());attempts=[]
        def restart():
            attempts.append(True)
            if len(attempts)==1:raise RuntimeError('new agent failed')
        self.ops.restart=restart;self.submit(value,'failed')
        self.assertEqual(self.ops.config(),self.profile);self.assertEqual(len(attempts),2);self.assertFalse(self.ops.transaction_file.exists())
        candidate=dict(self.profile,business_roots=[str(self.target)])
        for phase in ['prepared','applied','committed']:
            o.persist(self.ops.transaction_file,{'schema':'ironcurtain-scope-transaction/v1','previous':self.profile,'candidate':candidate,'phase':phase})
            o.persist(self.profile_file,candidate)
            with o.lease(self.lock):self.ops.recover_ports()
            self.assertEqual(self.ops.config(),candidate if phase=='committed' else self.profile)
        o.persist(self.profile_file,self.profile)
        for bad in [dict(candidate,approved_tcp_ports=[80]),dict(candidate,program_roots=[]),dict(candidate,containers=[{'name':'app','image_id':'sha256:'+'a'*64}])]:
            o.persist(self.ops.transaction_file,{'schema':'ironcurtain-scope-transaction/v1','previous':self.profile,'candidate':bad,'phase':'applied'})
            with self.assertRaises(ValueError),o.lease(self.lock):self.ops.recover_ports()
            self.assertTrue(self.ops.transaction_file.exists());self.assertEqual(self.ops.config(),self.profile)

    def test_candidate_limit_duplicate_and_client_paths_are_rejected_before_worker(self):
        base={'action':'enroll','revision':'a'*64,'inventory':'b'*64,'ids':['c'*16]}
        for value in [dict(base,ids=[]),dict(base,ids=['c'*16]*2),dict(base,ids=[format(n,'016x') for n in range(33)]),dict(base,path=str(self.scope)),{'action':'discover','command':'sh'}]:
            with self.assertRaises(ValueError):o.validate(value)
        value=self.discover(self.scope_inventory());o.persist(self.profile_file,dict(self.profile,approved_tcp_ports=[443]))
        self.submit(value,'failed');self.assertEqual(self.ops.config()['approved_tcp_ports'],[443]);self.assertEqual(self.restarts,[])

if __name__ == '__main__':
    unittest.main()
