"""Actual Linux flock, Unix SO_PEERCRED and SIGTERM; workers are explicit test instrumentation."""
import copy, fcntl, http.client, importlib.util, json, os, pathlib, socket, stat, subprocess, sys, tempfile, threading, time, unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).parents[1]
spec=importlib.util.spec_from_file_location('lifecycle_host',ROOT/'src/host/agent.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'actual Linux root boundary test')
class LeaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='ironcurtain-lease-');self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name);self.lockfile=self.root/'management.lock'
        self.original=a.secure_fd
        opened=patch.object(a,'secure_fd',side_effect=lambda file,**kw:self.original(str(self.lockfile) if str(file)=='/run/lock/ironcurtain-local.lock' else file,**kw))
        opened.start();self.addCleanup(opened.stop)
        self.agent=a.Agent({'schema':'ironcurtain-profile/v1','program_roots':[str(self.root)]},self.root/'state');self.agent.maintenance=lambda:False
        self.agent.multi=a.multi_engine.Bridge(self.agent,self.root/'profile.json',{'digest':a.fullscan.profile_digest,'read':a.private_json,'write':a.atomic_json,'updating':lambda:'idle'})
        self.engine={'installed':True,'state':'configured'}
    def exclusive(self):
        fd=os.open(self.lockfile,os.O_RDWR|os.O_CREAT,0o600)
        try:
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:return False
            return True
        finally:os.close(fd)
    def test_all_detection_workers_hold_same_inode_until_actual_exit(self):
        for trigger,worker in [('trigger','scan'),('trigger_full','scan_full'),('trigger_checkup','scan_checkup'),('trigger_multi','run')]:
            with self.subTest(trigger=trigger):
                self.agent.last=0;self.agent.result['state']='idle';self.agent.full_running=False;self.agent.multi.last=0;self.agent.multi.running=False
                started,release,finished=threading.Event(),threading.Event(),threading.Event()
                def hold(*args):
                    started.set()
                    try:release.wait(5)
                    finally:finished.set()
                target=self.agent.multi if worker=='run' else self.agent
                before=self.lockfile.stat().st_ino if self.lockfile.exists() else None
                with patch.object(target,worker,side_effect=hold),patch.object(a.antivirus,'engine_status',return_value=self.engine):
                    self.assertEqual(getattr(self.agent,trigger)()[0],202);self.assertTrue(started.wait(2));self.assertFalse(self.exclusive())
                    if before:self.assertEqual(self.lockfile.stat().st_ino,before)
                    release.set();self.assertTrue(finished.wait(2))
                    deadline=time.monotonic()+2
                    while not self.exclusive() and time.monotonic()<deadline:time.sleep(.01)
                    self.assertTrue(self.exclusive())
    def test_official_update_holds_real_management_lease_until_worker_exit(self):
        entered,release=threading.Event(),threading.Event()
        def updating(**kw):
            self.assertEqual(kw,{'wait':True});entered.set();release.wait(5)
        with patch.object(a.antivirus,'check_official_updater'),patch.object(a.antivirus,'update_status',return_value='idle'),patch.object(a.antivirus,'request_official_update',side_effect=updating):
            code,receipt=self.agent.trigger_engine_update();self.assertEqual(code,202);self.assertTrue(entered.wait(2))
            try:
                self.assertFalse(self.exclusive());self.assertEqual(self.agent.trigger()[0],409)
                self.assertEqual(self.agent.trigger_engine_update()[0],409)
                self.assertEqual(self.agent.status()['engine_update']['task_id'],receipt['task_id'])
            finally:release.set()
            deadline=time.monotonic()+2
            while not self.exclusive() and time.monotonic()<deadline:time.sleep(.01)
            self.assertTrue(self.exclusive());self.assertEqual(self.agent.engine_update['state'],'finished')
    def test_combined_checkup_holds_lease_across_environment_and_files(self):
        entered,release,done=threading.Event(),threading.Event(),threading.Event()
        def environment():
            self.assertFalse(self.exclusive());self.agent.result={'state':'finished','checked_at':a.utc(),'checks':[]}
            self.agent.inventory={k:'complete' for k in ('container_state','listener_state','directory_state')};self.agent.inventory['environment']={k:'complete' for k in ('system_state','package_state','service_state')}
        def files(engine,release):
            self.assertFalse(release);self.assertFalse(self.exclusive());entered.set();gate.wait(5);self.agent.full_result={'state':'finished'};done.set()
        gate=release
        with patch.object(self.agent,'scan',side_effect=environment),patch.object(self.agent,'scan_full',side_effect=files),patch.object(a.antivirus,'engine_status',return_value=self.engine):
            self.assertEqual(self.agent.trigger_checkup()[0],202);self.assertTrue(entered.wait(2));self.assertFalse(self.exclusive());release.set();self.assertTrue(done.wait(2))
            deadline=time.monotonic()+2
            while not self.exclusive() and time.monotonic()<deadline:time.sleep(.01)
            self.assertTrue(self.exclusive());self.assertEqual(self.agent.checkup['state'],'finished')
    def test_update_rejects_actual_detection_lease_without_starting_a_job(self):
        calls=[]
        def run(args,**kw):
            calls.append(args)
            return type('Result',(),{'returncode':0,'stdout':'inactive'})()
        bridge=a.updates.Bridge(a.private_bytes,a.atomic_json,run,dispatch_lock=self.agent.dispatch_lock,management_check=a.management_busy)
        entered,release,finished=threading.Event(),threading.Event(),threading.Event()
        def scan(*args):
            entered.set()
            try:release.wait(5)
            finally:finished.set()
        with patch.object(self.agent,'scan',side_effect=scan):
            self.assertEqual(self.agent.trigger()[0],202);self.assertTrue(entered.wait(2))
            try:
                self.assertEqual(bridge.trigger('update'),(409,{'state':'unavailable','conflict':'management-active'}))
                self.assertFalse(any('start' in args for args in calls));self.assertEqual(bridge.pending,{})
            finally:release.set()
            self.assertTrue(finished.wait(2))
        deadline=time.monotonic()+2
        while not self.exclusive() and time.monotonic()<deadline:time.sleep(.01)
        self.assertTrue(self.exclusive());self.assertEqual(bridge.trigger('update')[0],202)
    def maintenance_bridge(self):
        m=a.engine_maintenance;calls=[]
        expected='/usr/bin/python3 -B '+str(m.BASE/'current/src/host/engine_maintenance.py')
        def read(file,maximum):
            if str(file).endswith(m.UNIT):return ('[Service]\nExecStart='+expected+'\n').encode()
            return a.private_bytes(file,maximum)
        def run(args,**kw):
            calls.append(args)
            if 'start' in args:return type('Result',(),{'returncode':0})()
            props=dict(LoadState='loaded',FragmentPath='/etc/systemd/system/'+m.UNIT,DropInPaths='',User='root',Type='oneshot',ExecStart='{ path=/usr/bin/python3 ; argv[]='+expected+' ; ignore_errors=no ; pid=0 ; status=0/0 }',ActiveState='inactive',Result='success',KillMode='control-group',TimeoutStartUSec='12min',TimeoutStopUSec='15s')
            return type('Result',(),{'returncode':0,'stdout':'\n'.join(k+'='+v for k,v in props.items())})()
        return m.Bridge(read,a.atomic_json,data=self.root/'maintenance',run=run,dispatch_lock=self.agent.dispatch_lock,busy=a.management_busy),calls
    def test_maintenance_acceptance_excludes_all_detection_and_writers(self):
        bridge,calls=self.maintenance_bridge()
        self.assertEqual(bridge.trigger()[0],202)
        self.agent.maintenance=bridge.busy_status
        readiness=a.engine_readiness.Bridge(lambda:[],lambda:self.engine,busy=bridge.busy_status,dispatch_lock=self.agent.dispatch_lock)
        update_calls=[]
        def run(args,**kw):
            update_calls.append(args);return type('Result',(),{'returncode':0,'stdout':'inactive'})()
        updater=a.updates.Bridge(a.private_bytes,a.atomic_json,run,dispatch_lock=self.agent.dispatch_lock,management_check=bridge.busy_status)
        with patch.object(a.antivirus,'request_official_update') as official:
            for name in ('trigger','trigger_full','trigger_checkup','trigger_multi','trigger_engine_update'):
                self.assertEqual(getattr(self.agent,name)()[0],409,name)
            official.assert_not_called()
        self.assertEqual(readiness.trigger()[0],409)
        self.assertEqual(updater.trigger('update')[0],409)
        self.assertFalse(any('start' in args for args in update_calls))
        self.assertTrue(self.exclusive())
        # Concurrent polling / blocked writer dispatch must terminate with a consistent pending identity.
        results=[];threads=[]
        for operation in (bridge.status,readiness.status,lambda:updater.trigger('update'),self.agent.trigger_engine_update):
            thread=threading.Thread(target=lambda op=operation:results.append(op()),daemon=True);threads.append(thread);thread.start()
        for thread in threads:thread.join(3);self.assertFalse(thread.is_alive(),'maintenance lock-order deadlock')
        self.assertEqual(len(results),4);self.assertEqual(bridge.status()['state'],'queued')
    def test_maintenance_rejects_actual_scan_lease_without_package_dispatch(self):
        bridge,calls=self.maintenance_bridge();entered=threading.Event();release=threading.Event();finished=threading.Event()
        def scan(*args):
            entered.set()
            try:release.wait(5)
            finally:finished.set()
        with patch.object(self.agent,'scan',side_effect=scan):
            self.assertEqual(self.agent.trigger()[0],202);self.assertTrue(entered.wait(2))
            try:
                self.assertEqual(bridge.trigger()[0],409);self.assertFalse(any('start' in args for args in calls))
                self.assertEqual(bridge.status()['state'],'idle')
            finally:release.set()
            self.assertTrue(finished.wait(2))
    def test_update_acceptance_excludes_detection_dispatch(self):
        calls=[]
        def run(args,**kw):
            if 'start' in args:
                self.assertFalse(self.agent.dispatch_lock.acquire(blocking=False))
                self.assertEqual(bridge.pending['job']['unit'],'update')
            calls.append(args)
            return type('Result',(),{'returncode':0,'stdout':'inactive'})()
        bridge=a.updates.Bridge(a.private_bytes,a.atomic_json,run,dispatch_lock=self.agent.dispatch_lock,management_check=a.management_busy)
        self.assertEqual(bridge.trigger('update')[0],202)
        self.agent.maintenance=lambda:a.maintenance_active(bridge.status(),lambda:False)
        self.assertEqual(self.agent.trigger()[0],409);self.assertTrue(self.exclusive())
    def test_rejection_exception_and_start_failure_release_lease(self):
        self.agent.maintenance=lambda:True;self.assertEqual(self.agent.trigger()[0],409);self.assertTrue(self.exclusive())
        self.agent.maintenance=lambda:False
        for trigger in ('trigger','trigger_full','trigger_checkup','trigger_multi'):
            self.agent.last=0;self.agent.result['state']='idle';self.agent.full_running=False;self.agent.multi.running=False;self.agent.multi.last=0
            with patch.object(a.threading.Thread,'start',side_effect=RuntimeError('explicit test failure')),patch.object(a.antivirus,'engine_status',return_value=self.engine):
                self.assertEqual(getattr(self.agent,trigger)()[0],503);self.assertTrue(self.exclusive())
        @a.managed_detection
        def broken(agent,lease):raise RuntimeError('dispatch failure')
        with self.assertRaises(RuntimeError):broken(self.agent)
        self.assertTrue(self.exclusive())
        lease=a.ManagementLease.acquire()
        with self.assertRaises(RuntimeError):lease.run(lambda:(_ for _ in ()).throw(RuntimeError('worker failure')))
        self.assertTrue(self.exclusive());lease.close()
    def test_exclusive_manager_defers_detection_and_unsafe_inode_fails_closed(self):
        fd=os.open(self.lockfile,os.O_RDWR|os.O_CREAT,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.assertEqual(self.agent.trigger()[0],409)
        finally:os.close(fd)
        self.lockfile.chmod(0o666);self.assertEqual(self.agent.trigger()[0],503)
        self.lockfile.chmod(0o600);self.lockfile.unlink();self.lockfile.symlink_to(self.root/'other');self.assertEqual(self.agent.trigger()[0],503)
    def test_missing_or_malformed_maintenance_status_is_never_idle(self):
        for value in (None,{}, {'check':{'state':'idle'}},{'check':{'state':'idle'},'job':{'state':'unknown'}},{'check':{'state':'verified'},'job':{'state':'unavailable'}}):
            self.assertTrue(a.maintenance_active(value,lambda:False))
        self.assertFalse(a.maintenance_active({'check':{'state':'verified'},'job':{'state':'finished'}},lambda:False))

@unittest.skipUnless(sys.platform=='linux' and os.geteuid()==0,'actual Linux root boundary test')
class UnixLifecycleTest(unittest.TestCase):
    def test_peer_identity_strict_json_and_sigterm_persist_interruption(self):
        with tempfile.TemporaryDirectory(prefix='ironcurtain-agent-lifecycle-') as directory:
            folder=pathlib.Path(directory);folder.chmod(0o755);profile=folder/'profile.json';state=folder/'state';sock=folder/'run/scan.sock';lockfile=folder/'management.lock'
            a.atomic_json(profile,{'schema':'ironcurtain-profile/v1','program_roots':[]})
            harness=folder/'harness.py'
            harness.write_text('''import importlib.util,pathlib,sys,time
spec=importlib.util.spec_from_file_location("instrumented_agent",pathlib.Path(sys.argv[1])/"src/host/agent.py")
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
original=a.secure_fd
a.secure_fd=lambda file,**kw:original(sys.argv[5] if str(file)=="/run/lock/ironcurtain-local.lock" else file,**kw)
a.updates.Bridge.status=lambda self:{"check":{"state":"idle"},"job":{"state":"idle"}}
a.antivirus.update_status=lambda:"idle"
def held_scan(self):
    self.stop.wait(20)
a.Agent.scan=held_scan
a.serve(sys.argv[2],sys.argv[3],sys.argv[4],10001,10001)
''')
            proc=subprocess.Popen([sys.executable,'-B',str(harness),str(ROOT),str(profile),str(state),str(sock),str(lockfile)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            def request(method='GET',body=None):
                conn=http.client.HTTPConnection('localhost',timeout=2);conn.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);conn.sock.settimeout(2);conn.sock.connect(str(sock))
                try:
                    conn.request(method,'/schedule',body=body,headers={'Content-Type':'application/json'} if body is not None else {});r=conn.getresponse();return r.status,json.loads(r.read())
                finally:conn.close()
            try:
                deadline=time.monotonic()+5
                while time.monotonic()<deadline:
                    if proc.poll() is not None:self.fail(proc.stderr.read().decode())
                    if sock.exists():
                        code,value=request()
                        if value['records']['quick']['state']=='running':break
                    time.sleep(.025)
                else:self.fail('instrumented scheduler did not start')
                self.assertEqual(code,200);self.assertEqual(value['records']['quick']['state'],'running')
                self.assertEqual(request('POST',json.dumps(value['config']))[0],409)
                self.assertEqual(request('POST','{"revision":1,"revision":2,"jobs":{}}')[0],400)
                self.assertEqual(request('POST',json.dumps({**value['config'],'command':'bad'}))[0],400)
                # Make only this disposable socket reachable, so SO_PEERCRED (not filesystem denial) is exercised.
                sock.parent.chmod(0o755);sock.chmod(0o666)
                client='import http.client,socket,sys; c=http.client.HTTPConnection("localhost",timeout=2); c.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); c.sock.connect(sys.argv[1]); c.request("GET","/schedule"); r=c.getresponse(); print(r.status); r.read(); c.close()'
                def uid(number):
                    def demote():os.setgroups([]);os.setgid(number);os.setuid(number)
                    return demote
                for user,expected in ((65534,'403'),(10001,'200')):
                    result=subprocess.run([sys.executable,'-c',client,str(sock)],preexec_fn=uid(user),capture_output=True,text=True,timeout=3)
                    self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout.strip(),expected)
                fd=os.open(lockfile,os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(fd)
                proc.terminate();out,err=proc.communicate(timeout=12);self.assertEqual(proc.returncode,0,err.decode())
                saved=json.loads((state/'schedule.json').read_text());self.assertEqual(saved['records']['quick']['state'],'interrupted');self.assertIsNotNone(saved['records']['quick']['task_id'])
                self.assertFalse(sock.exists());fd=os.open(lockfile,os.O_RDWR)
                try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(fd)
            finally:
                if proc.poll() is None:proc.kill();proc.communicate(timeout=3)


@unittest.skipUnless(sys.platform=='linux','requires actual descriptor inheritance and process groups')
class RunnerTest(unittest.TestCase):
    def test_pinned_descriptor_and_live_output(self):
        with tempfile.TemporaryFile() as file:
            file.write(b'pinned');file.seek(0);lines=[]
            program='import os,sys; print(os.read(int(sys.argv[1]),64).decode(),flush=True)'
            code,text=a.Runner()([sys.executable,'-c',program,str(file.fileno())],pass_fds=[file.fileno()],on_line=lines.append)
            self.assertEqual((code,text),(0,'pinned\n'));self.assertEqual(lines,['pinned'])
    def test_cancellation_reaps_actual_child(self):
        stop=threading.Event();pids=[]
        def line(value):pids.append(int(value));stop.set()
        program='import os,time; print(os.getpid(),flush=True); time.sleep(30)'
        started=time.monotonic();code,text=a.Runner()([sys.executable,'-c',program],stop=stop,on_line=line)
        self.assertIsNone(code);self.assertIn('interrupted',text);self.assertLess(time.monotonic()-started,3);self.assertEqual(len(pids),1)
        with self.assertRaises(ProcessLookupError):os.kill(pids[0],0)
    def test_callback_error_reaps_child_and_does_not_hide_error(self):
        pids=[]
        def line(value):pids.append(int(value));raise ValueError('report failure')
        program='import os,time; print(os.getpid(),flush=True); time.sleep(30)'
        with self.assertRaisesRegex(ValueError,'report failure'):a.Runner()([sys.executable,'-c',program],on_line=line)
        self.assertEqual(len(pids),1)
        with self.assertRaises(ProcessLookupError):os.kill(pids[0],0)
    def test_output_budget_and_timeout_stay_bounded(self):
        code,text=a.Runner()([sys.executable,'-c','import sys; sys.stdout.write("x"*70000)'],maximum=1000)
        self.assertIsNone(code);self.assertIn('budget',text)
        code,text=a.Runner()([sys.executable,'-c','import time; time.sleep(30)'],seconds=.1)
        self.assertIsNone(code);self.assertIn('budget',text)

if __name__=='__main__':unittest.main()
