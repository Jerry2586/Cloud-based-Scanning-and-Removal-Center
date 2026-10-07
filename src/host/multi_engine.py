"""Fixed host-only bridge for the signed Go detector. No user supplied targets."""
import copy, datetime, json, os, pathlib, platform, re, secrets, signal, stat, subprocess, threading, time
IDS = ('clamav','trivy','osquery','falco')
TERMINAL = ('complete','partial','unavailable','failed','cancelled')

def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
def timestamp(x):
    try: return isinstance(x,str) and bool(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z',x)) and datetime.datetime.fromisoformat(x.replace('Z','+00:00')) is not None
    except ValueError: return False
def safe_text(x,n): return isinstance(x,str) and len(x)<=n and not re.search(r'[\x00-\x1f\x7f]',x)
def count(x,limit=200000): return type(x) is int and 0<=x<=limit

def valid(value,profile_digest):
    if not isinstance(value,dict) or value.get('schema')!='ironcurtain-multi-engine/v1' or value.get('profile_digest')!=profile_digest or not re.fullmatch(r'[a-f0-9]{64}',str(profile_digest)) or not re.fullmatch(r'[a-f0-9]{64}',str(value.get('job_id',''))): return False
    if value.get('state') not in ('running','finished','partial','cancelled','failed'): return False
    if not timestamp(value.get('started_at')) or not timestamp(value.get('updated_at')) or value['updated_at']<value['started_at']: return False
    if not count(value.get('completed'),4) or value.get('total')!=4 or not count(value.get('coverage'),4): return False
    if not isinstance(value.get('engines'),list) or [x.get('id') for x in value['engines'] if isinstance(x,dict)]!=list(IDS): return False
    completed=coverage=0
    for e in value['engines']:
        if e.get('state') not in ('queued','running',*TERMINAL) or not safe_text(e.get('detail'),180): return False
        if not count(e.get('completed')) or not count(e.get('total')) or e['completed']>e['total']: return False
        if e['state']=='complete' and e['completed']!=e['total']: return False
        items=e.get('findings')
        if not isinstance(items,list) or len(items)>16 or not count(e.get('finding_total')) or e['finding_total']<len(items): return False
        if e.get('evidence_digest') is not None and not re.fullmatch(r'[a-f0-9]{64}',str(e['evidence_digest'])): return False
        allowed={'clamav':'malware','trivy':'vulnerability','osquery':'asset','falco':'behavior'}
        for f in items:
            if not isinstance(f,dict) or f.get('kind')!=allowed[e['id']] or f.get('severity') not in ('info','low','medium','high','critical') or not all(safe_text(f.get(k),n) for k,n in (('target',256),('rule',160),('detail',180))): return False
        completed+=e['state'] in TERMINAL;coverage+=e['state']=='complete'
    if completed!=value['completed'] or coverage!=value['coverage']: return False
    if value['state']!='running':
        if completed!=4 or not timestamp(value.get('finished_at')) or not value['started_at']<=value['finished_at']<=value['updated_at']: return False
    if value['state']=='finished' and coverage!=4: return False
    if value['state']=='partial' and coverage==4: return False
    return True

class Bridge:
    def __init__(self,agent,profile_file,tools):
        self.agent=agent;self.profile_file=str(profile_file);self.tools=tools;self.running=False;self.last=0;self.child=None;self.closing=False;self.thread=None
        self.file=agent.state_dir/'multi-engine-report.json'
        self.digest=tools['digest'](agent.profile)
        self.value={'schema':'ironcurtain-multi-engine/v1','state':'idle'}
        try:
            saved=tools['read'](self.file,65536)
            if not valid(saved,self.digest): raise ValueError('invalid saved report')
            self.value=saved
            if saved['state']=='running': self.fail('代理重启中断任务，请重新检测')
        except FileNotFoundError: pass
        except (OSError,ValueError,TypeError): self.value={'schema':'ironcurtain-multi-engine/v1','state':'unavailable','reason':'上次任务记录无法核验'}
    def status(self):
        with self.agent.lock: return copy.deepcopy(self.value)
    def trigger(self, lease=None):
        with self.agent.lock:
            if self.closing: return 503,{'state':'unavailable','reason':'代理正在停止'}
            if self.running: return 409,{**copy.deepcopy(self.value),'response_status':409}
            if self.agent.full_running or self.agent.result['state']=='running' or self.tools['updating']()=='running': return 409,{'state':'unavailable','reason':'已有本机任务执行中'}
            if self.last and time.monotonic()-self.last<60: return 429,{'state':'unavailable','reason':'检测请求过于频繁'}
            if not self.agent.clear_checkup(): return 503,{'state':'unavailable','reason':'任务保存失败'}
            now=stamp()
            value={'schema':'ironcurtain-multi-engine/v1','job_id':secrets.token_hex(32),'profile_digest':self.digest,'state':'running','started_at':now,'updated_at':now,'completed':0,'total':4,'coverage':0,
                'engines':[{'id':i,'state':'queued','detail':'等待 Go 主控执行','completed':0,'total':0,'finding_total':0,'findings':[]} for i in IDS]}
            try: self.tools['write'](self.file,value)
            except (OSError,ValueError): return 503,{'state':'unavailable','reason':'任务保存失败'}
            self.running=True;self.value=value;self.last=time.monotonic()
        try:
            self.thread=threading.Thread(target=lease.run if lease else self.run,args=(self.run,) if lease else (),daemon=True)
            self.thread.start()
        except RuntimeError:
            self.fail('检测线程无法启动')
            with self.agent.lock: self.running=False
            return 503,self.status()
        return 202,{**copy.deepcopy(value),'response_status':202}
    def fail(self,reason):
        with self.agent.lock:
            value=copy.deepcopy(self.value)
            if value.get('state') not in ('running','finished','partial'): return
            for e in value['engines']:
                if e['state'] in ('running','queued'): e['state']='failed';e['detail']=reason
            value.update(state='failed',completed=4,coverage=sum(e['state']=='complete' for e in value['engines']),updated_at=stamp(),finished_at=stamp())
            value['updated_at']=value['finished_at']
            self.value=value
        try: self.tools['write'](self.file,value)
        except (OSError,ValueError): pass
    def run(self):
        fd=None
        try:
            arch={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
            if platform.system()!='Linux' or not arch: raise ValueError('Linux manager required')
            binary=pathlib.Path(__file__).resolve().parents[1]/'manager'/'bin'/('ironcurtain-manager-linux-'+arch)
            fd=self.tools['open'](binary,root_controlled=True);info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or not info.st_mode&0o111: raise ValueError('untrusted manager')
            observed=self.tools['discover'](self.tools['runner'](),previous=self.agent.inventory)
            images=sorted({c['image_id'] for c in observed['containers']})
            request={'job_id':self.value['job_id'],'profile_digest':self.digest,'profile_file':self.profile_file,'state_dir':str(self.agent.state_dir),
                'worker_file':str(pathlib.Path(__file__).resolve().with_name('clamav-worker.py')),'images':images,'discovery_complete':observed['container_state']=='complete'}
            with self.agent.lock: self.agent.inventory=observed
            with subprocess.Popen(['/proc/self/fd/'+str(fd)],pass_fds=(fd,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                cwd='/',env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},start_new_session=True) as child:
                with self.agent.lock:
                    self.child=child
                    closing=self.closing
                if closing:
                    self.kill(child)
                    raise ValueError('agent stopping')
                child.stdin.write(json.dumps(request).encode());child.stdin.close()
                deadline=threading.Timer(32*60+10,lambda:self.kill(child));deadline.daemon=True;deadline.start()
                try:
                    total=0;last=self.value;manager_start=None
                    while True:
                        line=child.stdout.readline(65537)
                        if not line: break
                        total+=len(line)
                        if len(line)>65536 or total>16*1024*1024: raise ValueError('manager response exceeds budget')
                        value=json.loads(line)
                        if not valid(value,self.digest) or value['job_id']!=request['job_id'] or value['started_at']<last['started_at'] or value['updated_at']<last['updated_at'] or value['completed']<last['completed'] or value['coverage']<last['coverage'] or (last['state']!='running') or (manager_start is not None and value['started_at']!=manager_start) or any(old['state'] in TERMINAL and new!=old for old,new in zip(last['engines'],value['engines'])): raise ValueError('invalid manager snapshot')
                        manager_start=value['started_at']
                        self.tools['write'](self.file,value)
                        with self.agent.lock: self.value=value
                        last=value
                    if child.wait(timeout=5)!=0 or last['state']=='running': raise ValueError('manager interrupted')
                except BaseException:
                    self.kill(child);raise
                finally:
                    deadline.cancel()
                    with self.agent.lock: self.child=None
        except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError): self.fail('Go 主控未就绪或执行失败；请核对签名程序与主机日志')
        finally:
            if fd is not None: os.close(fd)
            with self.agent.lock: self.running=False
    def kill(self,child):
        try: child.send_signal(signal.SIGTERM)
        except ProcessLookupError: return
        try: child.wait(timeout=4)
        except subprocess.TimeoutExpired:
            try: os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError: pass
    def close(self):
        with self.agent.lock:
            self.closing=True
            child=self.child
        if child: self.kill(child)
        if self.thread and self.thread is not threading.current_thread():
            try: self.thread.join(timeout=6)
            except RuntimeError: pass  # close may race Thread.start; run checks closing before I/O
