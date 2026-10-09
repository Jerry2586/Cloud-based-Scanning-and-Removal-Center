import datetime, importlib.util, json, os, pathlib, signal, subprocess, sys, tempfile, threading, time, unittest
from types import SimpleNamespace
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('engine_maintenance',ROOT/'src/host/engine_maintenance.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class BridgeTests(unittest.TestCase):
 def setUp(self):
  self.store={};self.active='inactive';self.extra={};self.calls=[];self.busy=False;self.tick=0;self.start_failed=False
  self.expected='/usr/bin/python3 -B '+str(m.BASE/'current/src/host/engine_maintenance.py')
  self.b=m.Bridge(self.read,self.write,run=self.fake_run,busy=lambda:self.busy,clock=lambda:self.tick)
 def read(self,p,n):
  if str(p).endswith(m.UNIT):return ('[Service]\nExecStart='+self.expected+'\n').encode()
  if str(p) not in self.store:raise FileNotFoundError()
  return json.dumps(self.store[str(p)]).encode()
 def write(self,p,v):self.store[str(p)]=v
 def fake_run(self,args,**kwargs):
  self.calls.append(args)
  if args[1]=='start':return SimpleNamespace(returncode=int(self.start_failed))
  props=dict(LoadState='loaded',FragmentPath='/etc/systemd/system/'+m.UNIT,DropInPaths='',User='root',Type='oneshot',ExecStart='{ path=/usr/bin/python3 ; argv[]='+self.expected+' ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }',ActiveState=self.active,Result='success',KillMode='control-group',TimeoutStartUSec='12min',TimeoutStopUSec='15s');props.update(self.extra)
  return SimpleNamespace(returncode=0,stdout='\n'.join(k+'='+v for k,v in props.items()))
 def test_fixed_dispatch_persists_before_start_and_restart_observes_pending(self):
  self.assertEqual(self.b.status()['state'],'idle');code,v=self.b.trigger();self.assertEqual(code,202);self.assertEqual(v['state'],'queued')
  self.assertEqual(self.calls[-1],['/usr/bin/systemctl','start','--no-block',m.UNIT]);self.assertEqual(self.b.status()['state'],'queued');self.assertEqual(self.b.trigger()[0],429)
  self.tick=11;self.assertEqual(self.b.trigger()[0],409)
  newer=m.Bridge(self.read,self.write,run=self.fake_run,busy=lambda:False);self.assertEqual(newer.status()['id'],v['id'])
 def test_systemd_tampering_and_unknown_states_rejected(self):
  for key,value in [('User','nobody'),('DropInPaths','/tmp/evil.conf'),('FragmentPath','/tmp/evil.service'),('ExecStart',self.expected),('Type','simple'),('KillMode','process'),('TimeoutStartUSec','infinity'),('ActiveState','unknown')]:
   self.extra={key:value};self.assertEqual(self.b.trigger()[0],503,key);self.assertFalse(any(x[1]=='start' for x in self.calls))
 def test_maintenance_conflict_never_dispatches(self):
  self.busy=True;self.assertEqual(self.b.trigger()[0],409);self.assertEqual(self.b.status()['state'],'idle');self.assertFalse(any(x[1]=='start' for x in self.calls))
 def test_failed_start_and_interruption_are_not_success(self):
  self.start_failed=True;self.assertEqual(self.b.trigger()[0],503);self.assertEqual(self.b.status()['state'],'failed')
  old=(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(seconds=30)).isoformat().replace('+00:00','Z');self.write(self.b.data/'job.json',m.record('queued','queued',id='a'*32,requested_at=old));self.assertEqual(self.b.status()['code'],'interrupted')
 def test_corrupt_time_identity_and_state_fail_closed(self):
  code,v=self.b.trigger();self.assertEqual(code,202)
  for key,value in [('requested_at','invalid'),('id','x'*32),('state','finished'),('code','shell')]:
   self.write(self.b.data/'job.json',{**v,key:value});self.assertEqual(self.b.status()['state'],'unavailable')
 def test_absent_unit_keeps_existing_readonly_scans_usable(self):
  def absent(*args):raise FileNotFoundError()
  old=m.Bridge(absent,self.write,run=self.fake_run);self.assertFalse(old.busy_status());self.assertEqual(old.trigger()[0],503)
 def test_active_unit_without_job_fails_closed(self):
  self.active='activating';self.assertEqual(self.b.status()['state'],'unavailable');self.assertTrue(self.b.busy_status())
@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'Linux root worker gate')
class WorkerTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name);self.data=self.root/'data';self.data.mkdir();os.chmod(self.data,0o700);self.lock=self.root/'management.lock';self.calls=[];self.rc=0;self.installed={'installed':True,'state':'configured'}
  self.job=m.record('queued','queued',id='a'*32,requested_at=m.stamp());self.write(self.data/'job.json',self.job)
  self.host=SimpleNamespace(private_bytes=lambda p,n:p.read_bytes(),atomic_json=self.write,secure_fd=self.fd,antivirus=SimpleNamespace(update_status=lambda:'idle',engine_status=lambda:self.installed),updates=SimpleNamespace(receipt=lambda *args:({},self.root/'release')))
 def write(self,p,v):p.write_text(json.dumps(v));os.chmod(p,0o600)
 def fd(self,p,root_controlled=False,flags=os.O_RDONLY):return os.open(self.lock if str(p).startswith('/run/lock') else p,flags,0o600)
 def fake_run(self,args,**kw):
  self.calls.append((args,kw));self.assertEqual(json.loads((self.data/'job.json').read_text())['state'],'running');return SimpleNamespace(returncode=self.rc)
 def test_fixed_command_and_honest_success(self):
  self.assertEqual(m.work(self.host,run=self.fake_run,data=self.data,base=self.root),0);args,kw=self.calls[0];self.assertEqual(args,['/bin/bash',str(self.root/'release/scripts/antivirus-engine.sh'),'install']);self.assertEqual(kw['timeout'],660);self.assertEqual(kw['cwd'],'/');self.assertEqual(json.loads((self.data/'job.json').read_text())['state'],'finished')
 def test_package_failure_and_missing_database_fail(self):
  for rc,meta in [(1,self.installed),(0,{'installed':True,'state':'unavailable'}),(0,{'installed':False,'state':'configured'})]:
   self.rc=rc;self.installed=meta;self.write(self.data/'job.json',self.job);self.assertEqual(m.work(self.host,run=self.fake_run,data=self.data,base=self.root),1);self.assertEqual(json.loads((self.data/'job.json').read_text())['state'],'failed')
 def test_held_management_lock_never_invokes_package_manager(self):
  import fcntl
  fd=os.open(self.lock,os.O_CREAT|os.O_RDWR,0o600)
  try:
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.assertEqual(m.work(self.host,run=self.fake_run,data=self.data,base=self.root),1);self.assertEqual(self.calls,[]);self.assertEqual(json.loads((self.data/'job.json').read_text())['code'],'busy')
  finally:os.close(fd)
 def test_timeout_remains_failed(self):
  def timeout(*args,**kw):raise subprocess.TimeoutExpired(args[0],660)
  self.assertEqual(m.work(self.host,run=timeout,data=self.data,base=self.root),1);self.assertEqual(json.loads((self.data/'job.json').read_text())['state'],'failed')
 def test_untrusted_log_never_invokes_package_manager(self):
  (self.data/'install.log').write_text('existing');os.chmod(self.data/'install.log',0o644);self.assertEqual(m.work(self.host,run=self.fake_run,data=self.data,base=self.root),1);self.assertEqual(self.calls,[])
 def test_real_package_descendants_stop_before_management_lease_releases(self):
  import fcntl
  marker=self.root/'heartbeat';pidfile=self.root/'descendant.pid';harness=self.root/'package-harness.py'
  harness.write_text("""import pathlib,subprocess,sys,time
marker,pidfile=map(pathlib.Path,sys.argv[1:])
code='import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); '+chr(10)+'while True:'+chr(10)+' p.write_text(str(time.time_ns())); time.sleep(.02)'
child=subprocess.Popen([sys.executable,'-c',code,str(marker)])
pidfile.write_text(str(child.pid))
while True: time.sleep(.02)
""")
  def actual(args,**kwargs):
   fd=os.open(self.lock,os.O_RDWR)
   try:
    with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   finally:os.close(fd)
   kwargs['timeout']=1
   return m.run_install([sys.executable,'-B',str(harness),str(marker),str(pidfile)],**kwargs)
  try:
   self.assertEqual(m.work(self.host,run=actual,data=self.data,base=self.root),1)
   self.assertEqual(json.loads((self.data/'job.json').read_text())['state'],'failed')
   self.assertTrue(pidfile.exists());self.assertTrue(marker.exists())
   pid=int(pidfile.read_text());before=marker.read_text();time.sleep(.12);self.assertEqual(marker.read_text(),before)
   status=pathlib.Path('/proc')/str(pid)/'stat'
   self.assertTrue(not status.exists() or status.read_text().split(') ',1)[1].split()[0]=='Z','package descendant still running')
   fd=os.open(self.lock,os.O_RDWR)
   try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   finally:os.close(fd)
  finally:
   if pidfile.exists():
    try:os.kill(int(pidfile.read_text()),signal.SIGKILL)
    except ProcessLookupError:pass
if __name__=='__main__':unittest.main()
