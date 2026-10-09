"""Disposable CI: real installed systemd unit and root management lease; no package repair runs."""
import datetime, fcntl, importlib.util, json, os, pathlib, subprocess, sys, time
ROOT=pathlib.Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('installed_host',ROOT/'src/host/agent.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
m=a.engine_maintenance
b=m.Bridge(a.private_bytes,a.atomic_json,busy=lambda:False)
assert b.unit()['KillMode']=='control-group'
assert subprocess.run(['systemctl','is-enabled','--quiet',m.UNIT]).returncode!=0
assert subprocess.run(['systemctl','is-active','--quiet',m.UNIT]).returncode!=0
if len(sys.argv)>2 and sys.argv[2]=='ready':
 print('Installed maintenance unit after upgrade/recovery: verified, inactive and not enabled.')
 sys.exit(0)
assert b.status()['state']=='idle', b.status()
fd=a.secure_fd('/run/lock/ironcurtain-local.lock',root_controlled=True,flags=os.O_RDWR|os.O_CREAT)
try:
 fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 # Dispatch despite this test's external lock: the real root worker must recheck and fail busy.
 code,job=b.trigger();assert code==202,(code,job)
 deadline=time.monotonic()+20
 while time.monotonic()<deadline:
  result=b.status()
  if result['state']=='failed':break
  time.sleep(.1)
 assert result['code']=='busy',result
 assert not (m.DATA/'install.log').exists(),'package manager was invoked under another management lease'
finally:os.close(fd)
# A failed systemd invocation and old persisted jobs must be retryable, never reported successful.
subprocess.run(['systemctl','reset-failed',m.UNIT],check=True)
old=(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(seconds=30)).isoformat().replace('+00:00','Z')
for state in ('queued','running'):
 fields=dict(id='a'*32,requested_at=old)
 if state=='running':fields['started_at']=old
 a.atomic_json(m.DATA/'job.json',m.record(state,'queued' if state=='queued' else 'installing',**fields))
 assert b.status()['code']=='interrupted',b.status()
# A new bridge models agent restart. A new request obtains a fresh identity; the worker still respects the lock.
newer=m.Bridge(a.private_bytes,a.atomic_json,busy=lambda:False)
fd=a.secure_fd('/run/lock/ironcurtain-local.lock',root_controlled=True,flags=os.O_RDWR)
try:
 fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 code,retry=newer.trigger();assert code==202 and retry['id']!='a'*32,(code,retry)
 deadline=time.monotonic()+20
 while time.monotonic()<deadline:
  result=newer.status()
  if result['state']=='failed':break
  time.sleep(.1)
 assert result['code']=='busy' and result['id']==retry['id'],result
finally:os.close(fd)
subprocess.run(['systemctl','reset-failed',m.UNIT],check=True)
assert not (m.DATA/'install.log').exists()
print('Actual installed maintenance unit: properties, exclusion, restart and explicit retry passed.')
