"""Cached, bounded, read-only dependency check. No install or arbitrary command API."""
import copy, datetime, json, os, pathlib, platform, re, signal, stat, subprocess, threading, time
IDS=('clamav','trivy','osquery','falco')
SCHEMA='ironcurtain-engine-readiness/v1'
STATES=('ready','partial','stale','unavailable')
def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
def safe_text(value,limit): return isinstance(value,str) and len(value)<=limit and not re.search(r'[\x00-\x1f\x7f]',value)
def valid_time(value):
    try:
        return isinstance(value,str) and bool(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z',value)) and datetime.datetime.fromisoformat(value.replace('Z','+00:00')) is not None
    except ValueError: return False

def validate_native(value):
    if not isinstance(value,dict) or value.get('schema')!=SCHEMA or not valid_time(value.get('checked_at')): raise ValueError('invalid readiness report')
    now=datetime.datetime.now(datetime.timezone.utc)
    checked=datetime.datetime.fromisoformat(value['checked_at'].replace('Z','+00:00'))
    if abs((now-checked).total_seconds())>60: raise ValueError('stale readiness report')
    rows=value.get('engines')
    if not isinstance(rows,list) or len(rows)!=3 or [x.get('id') for x in rows if isinstance(x,dict)]!=list(IDS[1:]): raise ValueError('invalid engine order')
    clean=[]
    for row in rows:
        if row.get('state') not in STATES or not safe_text(row.get('detail'),180): raise ValueError('invalid engine result')
        if row['id']=='falco' and row['state']!='unavailable' and row['state']!='partial': raise ValueError('unproven probe health')
        e={k:row[k] for k in ('id','state','detail')}
        if row.get('version'):
            if not safe_text(row['version'],64) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?',row['version']): raise ValueError('invalid version')
            e['version']=row['version']
        for k in ('database_at','next_update'):
            if k in row:
                if not valid_time(row[k]): raise ValueError('invalid db time')
                e[k]=row[k]
        if e['id']=='trivy' and e['state'] in ('ready','stale') and not all(k in e for k in ('version','database_at','next_update')): raise ValueError('missing db evidence')
        if e['id']=='osquery' and e['state']=='ready' and 'version' not in e: raise ValueError('missing query version')
        if e['id']=='trivy' and e['state'] in ('ready','stale'):
            updated=datetime.datetime.fromisoformat(e['database_at'].replace('Z','+00:00'))
            deadline=datetime.datetime.fromisoformat(e['next_update'].replace('Z','+00:00'))
            if updated>now+datetime.timedelta(minutes=5) or not updated<deadline<=updated+datetime.timedelta(hours=48): raise ValueError('invalid db interval')
            if e['state']=='ready' and (deadline<=now or now-updated>datetime.timedelta(hours=48)): raise ValueError('expired db treated as ready')
        clean.append(e)
    return clean

def clamav_row(value):
    r={'id':'clamav','state':'unavailable','detail':'ClamAV 与病毒库状态无法核验'}
    if not isinstance(value,dict) or value.get('engine')!='ClamAV': return r
    if safe_text(value.get('detail'),180): r['detail']=value['detail']
    v=value.get('version')
    if isinstance(v,str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9.-]{1,32})?',v): r['version']=v
    if value.get('source') in ('official-direct','xuanwu-signed'): r['source']=value['source']
    if value.get('installed') is True and 'version' in r and 'source' in r and value.get('state') in ('configured','stale') and valid_time(value.get('database_at')) and type(value.get('signatures')) is int and value['signatures']>0 and type(value.get('database_version')) is int and value['database_version']>0:
        r['state']='ready' if value['state']=='configured' else 'stale';r['database_at']=value['database_at']
    return r

class NativeProbe:
    def __init__(self,secure_open): self.open=secure_open; self.child=None; self.lock=threading.Lock();self.closed=False
    def kill(self,child):
        try: os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError: pass
    def __call__(self):
        arch={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
        if platform.system()!='Linux' or not arch: raise ValueError('Linux manager required')
        binary=pathlib.Path(__file__).resolve().parents[1]/'manager'/'bin'/('ironcurtain-manager-linux-'+arch)
        fd=self.open(binary,root_controlled=True)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or not info.st_mode&0o111: raise ValueError('untrusted manager')
            with subprocess.Popen(['/proc/self/fd/'+str(fd),'--readiness'],pass_fds=(fd,),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,cwd='/',env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},start_new_session=True) as child:
                with self.lock:
                    self.child=child
                    closed=self.closed
                if closed: self.kill(child);raise ValueError('agent stopping')
                timer=threading.Timer(20,lambda:self.kill(child));timer.daemon=True;timer.start()
                try:
                    output=child.stdout.read(16385)
                    if len(output)>16384: raise ValueError('readiness response too large')
                    if child.wait(timeout=3)!=0: raise ValueError('readiness failed')
                    return validate_native(json.loads(output))
                except BaseException:
                    self.kill(child);raise
                finally:
                    timer.cancel()
                    with self.lock: self.child=None
        finally: os.close(fd)
    def close(self):
        with self.lock: self.closed=True;child=self.child
        if child: self.kill(child)

class Bridge:
    def __init__(self,probe,antivirus,busy=lambda:False,clock=time.monotonic,dispatch_lock=None):
        self.dispatch_lock=dispatch_lock if dispatch_lock is not None else threading.Lock()
        self.probe=probe;self.antivirus=antivirus;self.busy=busy;self.clock=clock;self.lock=threading.Lock();self.running=False;self.closed=False;self.thread=None;self.last=None;self.finished=None
        self.value=self.empty('unavailable','尚未执行本机引擎检查')
    def empty(self,state,reason):
        return {'schema':SCHEMA,'state':state,'reason':reason,'ready_count':0,'engines':[{'id':i,'state':'unavailable','detail':reason} for i in IDS]}
    def status(self):
        with self.lock: due=not self.running and not self.closed and (self.finished is None or self.clock()-self.finished>=60)
        if due: self.trigger()
        with self.lock:
            if self.finished is not None and self.clock()-self.finished>=120 and not self.running:
                return self.empty('unavailable','引擎检查已过期；维护完成后重新核验')
            return copy.deepcopy(self.value)
    def trigger(self):
        with self.dispatch_lock, self.lock:
            if self.closed: return 503,self.empty('unavailable','本机检查代理正在停止')
            if self.running: return 409,copy.deepcopy(self.value)
            if self.busy(): return 409,self.empty('unavailable','程序或病毒库更新中；完成后再检查引擎')
            if self.last is not None and self.clock()-self.last<30: return 429,{**copy.deepcopy(self.value),'reason':'检查过于频繁，请稍后重试'}
            self.running=True;self.last=self.clock();self.value=self.empty('checking','正在核验本机固定引擎与数据来源')
            self.thread=threading.Thread(target=self.run,daemon=True)
            try: self.thread.start()
            except RuntimeError:
                self.running=False;self.finished=self.clock();self.value=self.empty('unavailable','检查线程无法启动');return 503,copy.deepcopy(self.value)
            return 202,copy.deepcopy(self.value)
    def run(self):
        value=self.empty('unavailable','检查未完成')
        try:
            rows=self.probe()
            # Validate the injected/native boundary before publishing any state.
            rows=validate_native({'schema':SCHEMA,'checked_at':stamp(),'engines':rows})
            rows=[clamav_row(self.antivirus()),*rows]
            value={'schema':SCHEMA,'state':'checked','checked_at':stamp(),'ready_count':sum(e['state']=='ready' for e in rows),'engines':rows,'reason':'就绪仅表示检测依赖可用，实际覆盖以扫描报告为准'}
        except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError): value=self.empty('unavailable','Go 检测主控或本机状态未就绪；请在 Linux 菜单核对')
        finally:
            with self.lock:
                self.value=value;self.finished=self.clock();self.running=False
    def close(self):
        with self.lock: self.closed=True;thread=self.thread
        if hasattr(self.probe,'close'): self.probe.close()
        if thread and thread is not threading.current_thread():
            try: thread.join(timeout=3)
            except RuntimeError: pass
