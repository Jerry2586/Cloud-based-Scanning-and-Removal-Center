#!/usr/bin/env python3
"""Bounded host scanner and fixed local release-job bridge. No arbitrary commands."""
import argparse, copy, importlib.util, datetime, hashlib, http.server, json, os, pathlib, re, shutil, socket, socketserver, sqlite3, stat, struct, subprocess, tempfile, threading, time, uuid, sys

# Installed release code stays immutable, including CLI and dynamic module loads.
sys.dont_write_bytecode = True

IDS = ['integrity.program','host.configuration','container.contract','container.approved-image','response.containment','host.os-release','host.systemd-state','ssh.effective','permissions.secret-inventory','permissions.installation','permissions.cron','network.listeners','network.udp-listeners','network.routes','host.kernel-security','network.firewall','malware.program','malware.business','database.sqlite','host.process-executables','host.failed-units','cloudflare.dns','cloudflare.workers','cloudflare.rules','cloudflare.settings']
LABELS = ['程序完整性','关键配置完整性','容器隔离配置','容器镜像身份','处置与隔离状态','Linux 系统版本','持续监测服务','SSH 有效配置','凭据文件权限','程序目录权限','定时任务权限','TCP 监听端口','UDP 监听端口','路由环境','内核安全配置','主机防火墙','程序病毒扫描','数据目录病毒扫描','SQLite 一致性','进程执行文件','异常系统服务','Cloudflare DNS','Cloudflare Workers','Cloudflare 规则','Cloudflare 设置']
CATEGORIES = ['container','host','container','container','host','host','host','ssh','permissions','permissions','permissions','network','network','network','host','network','malware','malware','host','host','host','network','network','network','network']
DIGEST = re.compile(r'^[a-f0-9]{64}$')
MAX_FILE = 64 * 1024 * 1024
_av_spec = importlib.util.spec_from_file_location('ironcurtain_antivirus', pathlib.Path(__file__).with_name('antivirus.py'))
antivirus = importlib.util.module_from_spec(_av_spec); _av_spec.loader.exec_module(antivirus)
_findings_spec = importlib.util.spec_from_file_location('ironcurtain_findings', pathlib.Path(__file__).with_name('findings.py'))
findings = importlib.util.module_from_spec(_findings_spec); _findings_spec.loader.exec_module(findings)
_rules_spec = importlib.util.spec_from_file_location('ironcurtain_rules', pathlib.Path(__file__).with_name('rules.py'))
rules = importlib.util.module_from_spec(_rules_spec); _rules_spec.loader.exec_module(rules)
_inventory_spec = importlib.util.spec_from_file_location('ironcurtain_inventory', pathlib.Path(__file__).with_name('inventory.py'))
inventory = importlib.util.module_from_spec(_inventory_spec); _inventory_spec.loader.exec_module(inventory)
_fullscan_spec = importlib.util.spec_from_file_location('ironcurtain_fullscan', pathlib.Path(__file__).with_name('fullscan.py'))
fullscan = importlib.util.module_from_spec(_fullscan_spec); _fullscan_spec.loader.exec_module(fullscan)

_update_spec = importlib.util.spec_from_file_location('ironcurtain_updates', pathlib.Path(__file__).with_name('updates.py'))
updates = importlib.util.module_from_spec(_update_spec); _update_spec.loader.exec_module(updates)

_multi_spec = importlib.util.spec_from_file_location('ironcurtain_multi_engine', pathlib.Path(__file__).with_name('multi_engine.py'))
multi_engine = importlib.util.module_from_spec(_multi_spec); _multi_spec.loader.exec_module(multi_engine)

_readiness_spec = importlib.util.spec_from_file_location('ironcurtain_engine_readiness', pathlib.Path(__file__).with_name('engine_readiness.py'))
engine_readiness = importlib.util.module_from_spec(_readiness_spec); _readiness_spec.loader.exec_module(engine_readiness)

def utc(): return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def atomic_json(file, value):
    file = pathlib.Path(file); file.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix='.ironcurtain-',dir=file.parent)
    try:
        with os.fdopen(fd,'wb') as handle:
            if os.name=='posix': os.fchmod(handle.fileno(),0o600)
            handle.write(canonical(value)); handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp,file)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def secure_fd(file,root_controlled=False):
    """Walk absolute POSIX components with openat; never follow parent or leaf links."""
    if os.name != 'posix':
        if pathlib.Path(file).is_symlink(): raise ValueError('symbolic link rejected')
        return os.open(file,os.O_RDONLY)
    path=pathlib.PurePosixPath(file)
    if not path.is_absolute() or '..' in path.parts: raise ValueError('unsafe file path')
    directory=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
            if root_controlled:
                info=os.fstat(next_fd)
                if info.st_uid!=0 or (info.st_mode&0o022 and not info.st_mode&stat.S_ISVTX):
                    os.close(next_fd); raise ValueError('trust directory must be root-controlled')
            os.close(directory); directory=next_fd
        return os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    finally: os.close(directory)

def private_bytes(file,maximum=2*1024*1024):
    fd=secure_fd(file,root_controlled=True)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>maximum: raise ValueError('trust file outside budget')
        if os.name=='posix' and (info.st_uid!=0 or info.st_mode&0o022): raise ValueError('trust file must be root-controlled')
        data=stream.read(maximum+1)
        if len(data)>maximum: raise ValueError('trust file outside budget')
        after=os.fstat(stream.fileno())
        if (info.st_ino,info.st_size,info.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns): raise ValueError('trust file changed during read')
        return data

def private_json(file, maximum=2*1024*1024):
    return json.loads(private_bytes(file,maximum))


def safe_root(value):
    if not isinstance(value,str) or not value.startswith('/') or re.search(r'[\x00-\x1f\x7f]',value): raise ValueError('protected paths must be absolute')
    path=pathlib.PurePosixPath(value)
    if str(path)!=value or '..' in path.parts or value in ['/', '/etc', '/proc', '/sys', '/dev', '/run']: raise ValueError('protected root too broad')
    return str(path)

def profile_validate(value):
    if not isinstance(value,dict): raise ValueError('profile must be an object')
    if value.get('schema')!='ironcurtain-profile/v1': raise ValueError('profile schema invalid')
    allowed={'schema','program_roots','business_roots','config_files','secret_files','sqlite_files','containers','approved_tcp_ports','approved_udp_ports','baseline','cloudflare'}
    if set(value)-allowed: raise ValueError('unknown profile field')
    result=copy.deepcopy(value)
    for key in ['program_roots','business_roots','config_files','secret_files','sqlite_files']:
        items=result.setdefault(key,[])
        if not isinstance(items,list) or len(items)>32: raise ValueError('too many protected paths')
        result[key]=[safe_root(item) for item in items]
    for key in ['approved_tcp_ports','approved_udp_ports']:
        ports=result.setdefault(key,[])
        if not isinstance(ports,list) or len(ports)>128 or any(type(p)!=int or not 1<=p<=65535 for p in ports): raise ValueError('invalid port allowlist')
    containers=result.setdefault('containers',[])
    if not isinstance(containers,list) or len(containers)>32: raise ValueError('too many containers')
    for item in containers:
        if not isinstance(item,dict) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}',item.get('name','')): raise ValueError('invalid container name')
        if set(item)-{'name','image_id'}: raise ValueError('unknown container field')
        if item.get('image_id') and not re.fullmatch(r'sha256:[a-f0-9]{64}',item['image_id']): raise ValueError('invalid image digest')
    baseline=result.get('baseline')
    if baseline is not None:
        if not isinstance(baseline,dict) or set(baseline)!={'path','signature','public_key'}: raise ValueError('invalid baseline configuration')
        for item in baseline.values(): safe_root(item)
    cloudflare=result.get('cloudflare')
    if cloudflare is not None and (not isinstance(cloudflare,dict) or set(cloudflare)!={'enabled'} or type(cloudflare['enabled'])!=bool): raise ValueError('invalid Cloudflare configuration')
    return result

class Runner:
    def __call__(self,args,seconds=12,maximum=262144,input_fd=None):
        if not shutil.which(args[0]): return None,'dependency unavailable'
        # A bounded temporary output file avoids unbounded PIPE/communicate allocation.
        with tempfile.TemporaryFile() as output:
            child=subprocess.Popen(args,stdin=input_fd if input_fd is not None else subprocess.DEVNULL,stdout=output,stderr=output,shell=False,start_new_session=os.name=='posix')
            deadline=time.monotonic()+seconds
            while child.poll() is None:
                if time.monotonic()>deadline or os.fstat(output.fileno()).st_size>maximum:
                    if os.name=='posix':
                        import signal
                        try: os.killpg(child.pid,signal.SIGKILL)
                        except ProcessLookupError: pass
                    else: child.kill()
                    child.wait(); return None,'time or output budget exceeded'
                time.sleep(0.03)
            output.seek(0); data=output.read(maximum+1)
            if len(data)>maximum: return None,'output budget exceeded'
            return child.returncode,data.decode('utf-8','replace')

def digest_file(file,budget=None):
    fd=secure_fd(file); digest=hashlib.sha256()
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size>MAX_FILE: raise ValueError('file type or size outside budget')
        consumed=0
        for block in iter(lambda:stream.read(65536),b''):
            consumed+=len(block)
            if budget is not None:
                budget['bytes']+=len(block)
                if budget['bytes']>budget['maximum'] or time.monotonic()>budget['deadline']: raise ValueError('aggregate hash budget exceeded')
            if consumed>MAX_FILE: raise ValueError('file grew beyond budget')
            digest.update(block)
        after=os.fstat(stream.fileno())
        if (before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns): raise ValueError('file changed during scan')
    return digest.hexdigest()

class Scanner:
    def __init__(self,profile,run=None,cloudflare_collect=None,response_state=None,rule_path=None): self.rule_path=rule_path; self.rule_hits=[]; self.rule_hit_count=0; self.rule_scan_complete=True; self.rules_loaded=False; self.rule_pack=None; self.response_state=response_state; self.cloudflare_collect=cloudflare_collect; self.cloudflare_cache=None; self.profile=profile_validate(profile); self.run=run or Runner(); self.baseline=None; self.baseline_error=None; self.container_cache=None; self.observed_files={}; self.files_complete=False; self.findings=[]; self.findings_complete=True; self.malware_count=0; self.file_ranges={}; self.hash_budget={'bytes':0,'maximum':1024*1024*1024,'deadline':time.monotonic()+30}
    def load_baseline(self):
        config=self.profile.get('baseline')
        if not config: self.baseline_error='未配置独立签名基线'; return
        try:
            content=private_bytes(config['path'])
            signature=private_bytes(config['signature'],8192)
            public_key=private_bytes(config['public_key'],8192)
            # Verify the exact frozen inputs; no TOCTOU reread of root trust files.
            with tempfile.TemporaryDirectory(prefix='ironcurtain-verify-') as temporary:
                directory=pathlib.Path(temporary)
                for name,data in [('baseline',content),('signature',signature),('public.pem',public_key)]:
                    (directory/name).write_bytes(data)
                code,_=self.run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(directory/'public.pem'),'-rawin','-in',str(directory/'baseline'),'-sigfile',str(directory/'signature')])
            if code!=0: raise ValueError('baseline signature rejected')
            value=json.loads(content)
            if value.get('schema')!='ironcurtain-baseline/v1' or value.get('roots')!=self.profile['program_roots'] or not isinstance(value.get('files'),dict) or len(value['files'])>10000: raise ValueError('baseline scope invalid')
            roots=[pathlib.PurePosixPath(p) for p in value['roots']]
            configs=set(self.profile['config_files'])
            for filename,digest in value['files'].items():
                safe_root(filename)
                if not DIGEST.fullmatch(str(digest)) or not (filename in configs or any(pathlib.PurePosixPath(filename).is_relative_to(p) for p in roots)): raise ValueError('baseline path outside profile')
            self.baseline=value
        except Exception: self.baseline_error='基线无效或签名验证失败，拒绝自动信任当前文件'
    def containers(self):
        if self.container_cache is None:
            names=[item['name'] for item in self.profile['containers']]
            if not names: raise ValueError('未配置受保护容器')
            code,text=self.run(['docker','inspect','--type','container','--',*names])
            if code!=0: raise ValueError('容器读取失败或 Docker 未安装')
            value=json.loads(text)
            if not isinstance(value,list) or len(value)!=len(names): raise ValueError('容器报告不完整')
            self.container_cache=value
        return self.container_cache
    def integrity(self,config=False):
        if self.baseline is None: return 'unavailable',self.baseline_error or '签名基线不可用',{}
        files=self.baseline['files']; roots=self.profile['program_roots']; configs=self.profile['config_files']; changed=0; visited=0; uncertain=0; added=0
        self.file_ranges[config]=False; self.files_complete=False
        selected={p:d for p,d in files.items() if (p in configs)==config}
        if not selected: return 'unavailable','该范围没有签名文件基线',{}
        for filename,expected in selected.items():
            self.observed_files.pop(filename,None)
            try:
                actual=digest_file(filename,self.hash_budget); self.observed_files[filename]=actual
                if actual!=expected: changed+=1
            except FileNotFoundError: changed+=1
            except (OSError,ValueError): uncertain+=1
            visited+=1
            if time.monotonic()>self.hash_budget['deadline'] or self.hash_budget['bytes']>self.hash_budget['maximum']:
                return 'unavailable','哈希总耗时或大小超出预算，报告不完整',{'files_checked':visited,'changed':changed}
        if not config:
            def walk_error(error): raise error
            try:
                for root in roots:
                    info=os.lstat(root)
                    if stat.S_ISLNK(info.st_mode): return 'finding','受保护目录被替换为符号链接，摘要不完整',{'files_checked':visited}
                    if not stat.S_ISDIR(info.st_mode): raise ValueError('protected root is not a directory')
                    for directory,dirs,names in os.walk(root,followlinks=False,onerror=walk_error):
                        if time.monotonic()>self.hash_budget['deadline']: raise ValueError('directory traversal budget exceeded')
                        for entry in dirs[:]:
                            if os.path.islink(os.path.join(directory,entry)): added+=1; uncertain+=1; dirs.remove(entry)
                        for name in names:
                            filename=os.path.join(directory,name)
                            if filename not in files:
                                added+=1
                                try: self.observed_files[filename]=digest_file(filename,self.hash_budget)
                                except (OSError,ValueError): uncertain+=1
                            if visited+added>10000: raise ValueError('file count budget exceeded')
                            if time.monotonic()>self.hash_budget['deadline'] or self.hash_budget['bytes']>self.hash_budget['maximum']: raise ValueError('aggregate hash budget exceeded')
            except (OSError,ValueError): uncertain+=1
        self.file_ranges[config]=uncertain==0
        needs_config=any(p in configs for p in files)
        self.files_complete=bool(files) and self.file_ranges.get(False,False) and (not needs_config or self.file_ranges.get(True,False))
        state='finding' if changed or added else 'unavailable' if uncertain else 'ok'
        return state,f'核对 {visited} 个基线文件；异常 {changed}，新增 {added}，未能完整核对 {uncertain}',{'files_checked':visited,'changed':changed,'added':added,'unreadable':uncertain}
    def permissions(self,paths):
        if not paths: return 'unavailable','未配置检查范围',{}
        unsafe=0; missing=0
        for file in paths:
            try:
                info=os.lstat(file)
                if stat.S_ISLNK(info.st_mode) or info.st_mode&0o022 or info.st_uid!=0: unsafe+=1
            except OSError: missing+=1
        return ('finding' if unsafe else 'warning' if missing else 'ok'),f'检查 {len(paths)} 项；不安全 {unsafe}，缺失 {missing}',{'checked':len(paths),'unsafe':unsafe,'missing':missing}
    def command(self,args,description):
        code,text=self.run(args)
        return ('ok',description,{'output_digest':hashlib.sha256(text.encode()).hexdigest()}) if code==0 else ('unavailable','依赖缺失、读取失败或超出扫描预算',{})
    def clamav(self,paths):
        if not paths: return 'unavailable','未配置扫描目录',{}
        if any(not os.path.isdir(p) or os.path.islink(p) for p in paths): return 'unavailable','目录不存在或链接状态不安全',{}
        database=antivirus.database_status()
        if database['state']!='configured': return 'unavailable',database['detail'],{}
        args=['clamscan','--database='+antivirus.DATABASE_DIR,'--official-db-only=yes','--infected','--follow-dir-symlinks=0','--follow-file-symlinks=0','--max-files=10000','--max-filesize=64M','--max-scansize=256M','--alert-exceeds-max=yes','--fail-if-cvd-older-than=7']
        code,text=self.run([*args,'--recursive','--',*paths],seconds=60)
        if code not in [0,1]: return 'unavailable','ClamAV/病毒库不可用，扫描失败或超出预算',{}
        if 'Heuristics.Limits.Exceeded' in text: return 'unavailable','ClamAV 文件/解包预算超限，不作为病毒命中或通过',{}
        match=re.search(r'Scanned files:\s*(\d+)',text); infected=re.search(r'Infected files:\s*(\d+)',text)
        if not match or not infected: return 'unavailable','病毒扫描统计缺失',{}
        if re.search(r'Errors:\s*[1-9]',text): return 'unavailable','部分文件扫描失败，不能判为通过',{}
        count=int(infected.group(1)); checked=int(match.group(1))
        if checked==0: return 'unavailable','扫描范围没有可检查的文件',{}
        if (code==1)!=(count>0): return 'unavailable','病毒引擎退出状态与统计不一致',{}
        self.malware_count+=count
        if count:
            captured,complete=findings.collect(text,paths,self.run,args,maximum=max(0,findings.MAX_FINDINGS-len(self.findings)))
            new=[item for item in captured if item['id'] not in {old['id'] for old in self.findings}]
            self.findings.extend(new)
            self.findings_complete=self.findings_complete and complete and len(new)==count
        return ('finding' if count else 'ok'),f'实际扫描 {checked} 个文件；特征命中 {count}',{'files_scanned':checked,'infected':count,'output_digest':hashlib.sha256(text.encode()).hexdigest()}
    def hash_threats(self,paths):
        if not self.rules_loaded:
            self.rules_loaded=True
            try: self.rule_pack=rules.load(self.rule_path)[0] if self.rule_path else None
            except Exception: self.rule_pack=None
        if not self.rule_pack: return 'disabled','签名哈希规则未启用',{}
        if not paths:
            self.rule_scan_complete=False
            return 'unavailable','未配置哈希规则扫描范围',{}
        indicators={item['sha256']:item for item in self.rule_pack['indicators']}
        if not indicators:
            self.rule_scan_complete=False
            return 'unavailable','已签名规则包没有哈希特征',{}
        budget={'bytes':0,'maximum':1024*1024*1024,'deadline':time.monotonic()+30};visited=0;missed=0;hits=0
        def failure(error): raise error
        try:
            for root in paths:
                info=os.lstat(root)
                if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode): raise ValueError('unsafe root')
                for directory,dirs,names in os.walk(root,followlinks=False,onerror=failure):
                    if time.monotonic()>budget['deadline']: raise ValueError('budget')
                    for entry in dirs[:]:
                        if os.path.islink(os.path.join(directory,entry)): missed+=1;dirs.remove(entry)
                    for name in names:
                        if visited>=10000 or time.monotonic()>budget['deadline']: raise ValueError('budget')
                        visited+=1;filename=os.path.join(directory,name)
                        try:
                            if len(filename)>1024 or any(ord(c)<32 or ord(c)==127 for c in filename): raise ValueError('unsafe filename')
                            digest=digest_file(filename,budget)
                        except (OSError,ValueError): missed+=1;continue
                        if digest in indicators:
                            hits+=1;item=indicators[digest]
                            identity=hashlib.sha256(canonical({'path':filename,'sha256':digest,'rule_id':item['id']})).hexdigest()
                            if len(self.rule_hits)<8 and identity not in {old['id'] for old in self.rule_hits}:
                                self.rule_hits.append({'id':identity,'path':filename,'sha256':digest,'rule_id':item['id'],'label':item['label'],'observed_at':utc(),'rule_sequence':self.rule_pack['sequence']})
        except (OSError,ValueError): missed+=1
        self.rule_hit_count+=hits;self.rule_scan_complete=self.rule_scan_complete and missed==0 and visited>0
        return ('finding' if hits else 'unavailable' if missed or not visited else 'ok'),f'哈希规则检查 {visited} 个文件；命中 {hits}，未完整检查 {missed}',{'files_scanned':visited,'matched':hits,'unreadable':missed,'rule_sequence':self.rule_pack['sequence']}
    def malware(self,paths):
        hash_state,hash_detail,hash_evidence=self.hash_threats(paths)
        av_state,av_detail,av_evidence=self.clamav(paths)
        state='finding' if 'finding' in [hash_state,av_state] else 'unavailable' if av_state=='unavailable' or hash_state=='unavailable' else av_state
        return state,av_detail+'；'+hash_detail,{**av_evidence,'clamav_state':av_state,'clamav':av_evidence,'hash_rules_state':hash_state,'hash_rules':hash_evidence}
    def check(self,id):
        p=self.profile
        if id=='integrity.program': return self.integrity()
        if id=='host.configuration': return self.integrity(True)
        if id.startswith('container.'):
            values=self.containers(); issues=0; unknown=0
            for item in values:
                if id=='container.contract':
                    host=item.get('HostConfig',{}); user=item.get('Config',{}).get('User','')
                    mounts=item.get('Mounts',[])
                    if host.get('Privileged') or not host.get('ReadonlyRootfs') or not user or user.split(':')[0] in ['root','0'] or 'ALL' not in host.get('CapDrop',[]) or 'no-new-privileges' not in ' '.join(host.get('SecurityOpt',[])) or any(m.get('Destination') in ['/var/run/docker.sock','/run/docker.sock'] for m in mounts): issues+=1
                else:
                    config=next((c for c in p['containers'] if c['name']==item.get('Name','').lstrip('/')),None)
                    if not config or not config.get('image_id'): unknown+=1
                    elif item.get('Image')!=config['image_id']: issues+=1
            return ('finding' if issues else 'unavailable' if unknown else 'ok'),f'容器 {len(values)}；异常 {issues}，未固定镜像 {unknown}',{'containers':len(values),'issues':issues,'unknown':unknown}
        if id=='response.containment':
            if not self.response_state: return 'unavailable','未接入本机隔离记录；扫描不删除业务文件',{}
            status=findings.quarantine_status(self.response_state)
            if status['state']=='unavailable': return 'unavailable','隔离记录不可读取或损坏，保留现场',{}
            return ('warning' if status['pending'] else 'ok'),f"本机隔离记录 {status['count']} 项；待人工核查 {status['pending']} 项；不代表进程已阻断",{'records':status['count'],'pending':status['pending']}
        if id=='host.os-release':
            value=pathlib.Path('/etc/os-release').read_text()[:8192]; return 'ok','已读取 Linux 发行版；补丁状态需单独核查',{'release_digest':hashlib.sha256(value.encode()).hexdigest()}
        if id=='host.systemd-state': return self.command(['systemctl','is-active','ironcurtain-agent.service'],'独立检测服务处于运行状态')
        if id=='ssh.effective':
            code,text=self.run(['sshd','-T'])
            if code!=0: return 'unavailable','无法读取 SSH 有效配置',{}
            config=dict(line.split(' ',1) for line in text.splitlines() if ' ' in line)
            risky=config.get('permitrootlogin')=='yes' or config.get('passwordauthentication')=='yes' or config.get('permitemptypasswords')!='no'
            return ('warning' if risky else 'ok'),'已核对 root 登录、密码登录与空密码策略',{'root_login':config.get('permitrootlogin'),'password_login':config.get('passwordauthentication'),'empty_passwords':config.get('permitemptypasswords')}
        if id=='permissions.secret-inventory':
            result=self.permissions(p['secret_files'])
            if result[0]=='ok' and any(os.lstat(f).st_mode&0o077 for f in p['secret_files']): return 'finding','凭据文件可被非 root 用户读取',{}
            return result
        if id=='permissions.installation': return self.permissions(p['program_roots'])
        if id=='permissions.cron': return self.permissions(['/etc/crontab','/etc/cron.d'])
        if id in ['network.listeners','network.udp-listeners']:
            udp=id=='network.udp-listeners'; code,text=self.run(['ss','-H','-l','-n','-u' if udp else '-t'])
            if code!=0: return 'unavailable','无法读取实际监听端口',{}
            allowed=p['approved_udp_ports' if udp else 'approved_tcp_ports']; ports=set()
            for line in text.splitlines():
                fields=line.split()
                if len(fields)<4: return 'unavailable','监听端口输出格式无法识别',{}
                match=re.search(r':(\d+)$',fields[4] if fields[0] in ['tcp','udp'] else fields[3])
                if not match: return 'unavailable','监听端口地址无法识别',{}
                ports.add(int(match.group(1)))
            extra=sorted(ports-set(allowed))
            if not allowed: return 'unavailable','已读取端口；尚未配置端口白名单',{'listeners_count':len(ports)}
            return ('warning' if extra else 'ok'),f'监听端口 {len(ports)} 个；白名单外 {len(extra)} 个',{'ports':sorted(ports),'unexpected_ports':extra}
        if id=='network.routes': return self.routes()
        if id=='host.kernel-security':
            values={name:pathlib.Path(file).read_text().strip() for name,file in [('aslr','/proc/sys/kernel/randomize_va_space'),('ptrace','/proc/sys/kernel/yama/ptrace_scope')]}
            return ('ok' if values['aslr']=='2' and values['ptrace']!='0' else 'warning'),'已核对 ASLR 与 ptrace 策略',values
        if id=='network.firewall':
            args=['nft','list','ruleset'] if shutil.which('nft') else ['iptables-save']; code,text=self.run(args)
            if code!=0: return 'unavailable','防火墙规则不可读取',{}
            meaningful=bool(re.search(r'(?im)^\s*(?:chain |-[AP] |table )',text))
            return ('warning' if meaningful else 'finding'),'已读取规则；需要按实际业务审查过滤策略' if meaningful else '未发现可核查的过滤规则',{'rules_digest':hashlib.sha256(text.encode()).hexdigest()}
        if id=='malware.program': return self.malware(p['program_roots'])
        if id=='malware.business': return self.malware(p['business_roots'])
        if id=='database.sqlite':
            if not p['sqlite_files']: return 'unavailable','未配置 SQLite 检查对象',{}
            for filename in p['sqlite_files']:
                if os.path.islink(filename) or not os.path.isfile(filename): return 'unavailable','数据库不存在或路径不安全',{}
                connection=sqlite3.connect(pathlib.Path(filename).as_uri()+'?mode=ro',uri=True,timeout=2)
                try:
                    deadline=time.monotonic()+8; connection.set_progress_handler(lambda: int(time.monotonic()>deadline),10000)
                    if connection.execute('PRAGMA quick_check').fetchall()!=[('ok',)]: return 'finding','SQLite 结构一致性检查发现问题',{}
                finally: connection.close()
            return 'ok',f'只读核对 {len(p["sqlite_files"])} 个数据库；不代表业务数据未被篡改',{'databases':len(p['sqlite_files'])}
        if id=='host.process-executables':
            deleted=0; checked=0; denied=0
            for process in list(pathlib.Path('/proc').iterdir())[:8192]:
                if not process.name.isdigit(): continue
                try:
                    target=os.readlink(process/'exe'); checked+=1
                    if target.endswith(' (deleted)'): deleted+=1
                except FileNotFoundError: pass
                except PermissionError: denied+=1
            return ('unavailable' if denied else 'warning' if deleted else 'ok'),f'核对 {checked} 个进程执行文件；已删除路径 {deleted}',{'checked':checked,'deleted':deleted,'denied':denied}
        if id=='host.failed-units':
            code,text=self.run(['systemctl','list-units','--failed','--no-legend','--no-pager'])
            if code!=0: return 'unavailable','异常服务不可读取',{}
            count=len([line for line in text.splitlines() if line.strip()]); return ('warning' if count else 'ok'),f'异常 systemd 服务 {count} 个',{'failed_units':count}
        if id.startswith('cloudflare.'):
            if not p.get('cloudflare',{}).get('enabled'): return 'unavailable','未启用 Cloudflare 单 Zone 只读配置监测',{}
            if self.cloudflare_cache is None:
                if self.cloudflare_collect is None:
                    spec=importlib.util.spec_from_file_location('ironcurtain_cloudflare',pathlib.Path(__file__).with_name('cloudflare.py'))
                    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); self.cloudflare_collect=module.collect_safe
                self.cloudflare_cache=self.cloudflare_collect()
            rows=self.cloudflare_cache.get('checks',[])
            if len(rows)!=4 or {row.get('id') for row in rows}!={name for name in IDS if name.startswith('cloudflare.')}: return 'unavailable','Cloudflare 返回范围不完整',{}
            row=next(row for row in rows if row['id']==id)
            if row.get('state') not in ['ok','finding','unavailable'] or not isinstance(row.get('detail'),str) or len(row['detail'])>1000: return 'unavailable','Cloudflare 报告无效',{}
            return row['state'],row['detail'],row.get('evidence')
        raise ValueError('unknown fixed check')
    def routes(self):
        code,text=self.run(['ip','-j','route','show'])
        return ('warning','已读取路由；缺少可信路由基线，需复核',{'routes_digest':hashlib.sha256(text.encode()).hexdigest()}) if code==0 else ('unavailable','无法读取主机路由',{})
    def run_checks(self,on_step=lambda *args:None):
        self.load_baseline(); results=[]
        for index,id in enumerate(IDS):
            on_step(copy.deepcopy(results),id)
            try: state,detail,evidence=self.check(id)
            except Exception: state,detail,evidence='unavailable','依赖缺失、读取失败或配置不完整',{}
            item={'id':id,'name':LABELS[index],'category':CATEGORIES[index],'state':state,'severity':'high' if state=='finding' else 'medium' if state=='warning' else 'unknown' if state=='unavailable' else 'info','checked_at':utc(),'scope':id,'detail':detail,'evidence_digest':hashlib.sha256(canonical(evidence)).hexdigest()}
            results.append(item)
        on_step(copy.deepcopy(results),None); return results

def valid_timestamp(value):
    if not isinstance(value,str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z',value): return False
    try: datetime.datetime.fromisoformat(value.replace('Z','+00:00')); return True
    except ValueError: return False

def valid_saved_check(item):
    return isinstance(item,dict) and item.get('id') in IDS and item.get('state') in ['ok','warning','finding','unavailable'] and isinstance(item.get('evidence_digest'),str) and bool(DIGEST.fullmatch(item['evidence_digest'])) and valid_timestamp(item.get('checked_at')) and item.get('category') in CATEGORIES and item.get('severity') in ['info','low','medium','high','critical','unknown'] and all(isinstance(item.get(k),str) and 0<len(item[k])<=limit for k,limit in [('name',160),('detail',1000),('scope',120)]) and item.get('previous_state') in [None,'ok','warning','finding','unavailable']

def valid_checkup(value,profile):
    if not isinstance(value,dict) or value.get('schema')!='ironcurtain-checkup/v1' or value.get('profile_digest')!=fullscan.profile_digest(profile): return False
    if 'task_id' in value and (not isinstance(value['task_id'],str) or not re.fullmatch(r'[a-f0-9]{32}',value['task_id'])): return False
    if value.get('state')=='idle': return True
    if (value.get('state') not in ('running','finished','partial','failed','paused') or value.get('stage') not in ('environment','files','complete')
        or not valid_timestamp(value.get('started_at')) or not valid_timestamp(value.get('updated_at')) or value['updated_at']<value['started_at']
        or not isinstance(value.get('reasons'),list) or len(value['reasons'])>8
        or not all(isinstance(x,str) and 0<len(x)<=240 and not re.search(r'[\x00-\x1f\x7f]',x) for x in value['reasons'])): return False
    env=value.get('environment_at')
    if env is not None and (not valid_timestamp(env) or not value['started_at']<=env<=value['updated_at']): return False
    if value['state'] in ('finished','partial') and (value['stage']!='complete' or not env): return False
    if value['state']=='finished' and value['reasons']: return False
    if value['stage']=='files' and not env: return False
    return True

class Agent:
    def __init__(self,profile,state_dir,interval=300,rule_path=None):
        self.rule_path=rule_path; self.rule_hits={'items':[],'total':0,'state':'unavailable'}
        self.profile=profile_validate(profile); self.state_dir=pathlib.Path(state_dir); self.interval=interval; self.lock=threading.Lock(); self.last=0; self.stop=threading.Event()
        self.engine_update_last=0
        self.previous={}; self.history=[]; self.history_available=True; self.outbound=None; self.findings_bundle={'schema':'ironcurtain-findings/v1','state':'unavailable','items':[], 'total':0}
        self.inventory={'state':'unavailable'}; self.full_result={'schema':'ironcurtain-full-scan/v1','state':'idle'}; self.full_running=False; self.findings_source='quick'; self.checkup={'schema':'ironcurtain-checkup/v1','state':'idle'}
        try:
            saved_inventory=private_json(self.state_dir/'last-inventory.json')
            if inventory.public_inventory(saved_inventory).get('state') != 'unavailable': self.inventory=saved_inventory
        except (OSError,ValueError): pass
        try:
            saved_full=private_json(self.state_dir/'full-scan-report.json',65536)
            if not fullscan.valid_report(saved_full) or saved_full['profile_digest'] != fullscan.profile_digest(self.profile): raise ValueError('invalid saved file scan')
            self.full_result=saved_full
            if self.full_result.get('state') in ('indexing','scanning'): self.full_result['state']='paused'
        except (OSError,ValueError): pass
        self.result={'state':'idle','checks':[],'history':[],'history_state':'ok'}
        try:
            saved=private_json(self.state_dir/'last-report.json',256*1024)
            if not isinstance(saved.get('profile_digest'),str) or not DIGEST.fullmatch(saved['profile_digest']) or saved.get('state')!='finished' or len(saved.get('checks',[]))!=len(IDS) or [item.get('id') for item in saved['checks']]!=IDS: raise ValueError('invalid previous report')
            if 'task_id' in saved and (not isinstance(saved['task_id'],str) or not re.fullmatch(r'[a-f0-9]{32}',saved['task_id'])): raise ValueError('invalid task identity')
            if not isinstance(saved.get('history'),list) or not valid_timestamp(saved.get('checked_at')): raise ValueError('invalid history metadata')
            for item in saved['checks']+saved['history']:
                if not valid_saved_check(item) or item['checked_at']>saved['checked_at']: raise ValueError('invalid history evidence')
            if saved.get('history_state') not in ['ok','truncated'] or len(saved.get('history',[]))>128: raise ValueError('invalid previous history')
            if saved['profile_digest'] != fullscan.profile_digest(self.profile):
                atomic_json(self.state_dir/'previous-profile-report.json',saved)
                self.history=saved['history']; self.result['history']=copy.deepcopy(self.history)
            else:
                self.previous={item['id']:item for item in saved['checks']}; self.history=saved['history']; self.result=saved
        except FileNotFoundError: pass
        except Exception:
            self.history_available=False; self.result['history_state']='unavailable'
        # Restore only evidence bound to the active profile and a validated scan report.
        try:
            saved_bundle=private_json(self.state_dir/'last-findings.json',256*1024)
            if (saved_bundle.get('schema') != 'ironcurtain-findings/v1' or saved_bundle.get('profile_digest') != fullscan.profile_digest(self.profile)
                or saved_bundle.get('state') not in ('complete','partial') or saved_bundle.get('checked_at') != self.result.get('checked_at')
                or self.result.get('state') != 'finished' or type(saved_bundle.get('total')) is not int or saved_bundle['total'] < 0
                or not isinstance(saved_bundle.get('items'),list) or len(saved_bundle['items']) > 32 or len(saved_bundle['items']) > saved_bundle['total']
                or not all(fullscan.valid_finding(x) for x in saved_bundle['items'])): raise ValueError('invalid saved findings')
            self.findings_bundle=saved_bundle
        except (OSError,ValueError,TypeError): pass
        if fullscan.valid_report(self.full_result) and self.full_result['updated_at'] >= self.findings_bundle.get('checked_at',''):
            self.findings_bundle={'schema':'ironcurtain-findings/v1','checked_at':self.full_result['updated_at'],'profile_digest':fullscan.profile_digest(self.profile),
                'items':self.full_result['findings'],'total':self.full_result['infected'],
                'state':'complete' if self.full_result['state']=='finished' and self.full_result['infected']==len(self.full_result['findings']) else 'partial'}
            self.findings_source='full'
        try:
            saved_checkup=private_json(self.state_dir/'checkup-report.json',8192)
            if not valid_checkup(saved_checkup,self.profile): raise ValueError('invalid checkup')
            if saved_checkup['state']=='finished':
                env=self.result; files=self.full_result
                if (env.get('task_id')!=saved_checkup.get('task_id') or files.get('task_id')!=saved_checkup.get('task_id')
                    or env.get('state')!='finished' or env.get('checked_at')!=saved_checkup.get('environment_at')
                    or any(x['checked_at']<saved_checkup['started_at'] for x in env['checks'])
                    or files.get('state')!='finished' or files.get('started_at','')<saved_checkup['environment_at']
                    or files.get('finished_at','')>saved_checkup['updated_at']): raise ValueError('unbound completed checkup')
            self.checkup=saved_checkup
            if self.checkup['state']=='running':
                self.checkup={**self.checkup,'state':'paused','updated_at':utc(),'reasons':['代理重启中断体检，请重新执行一键全面体检']}
        except (OSError,ValueError,TypeError): pass
    def status(self):
        engine=antivirus.engine_status()
        with self.lock:
            result=copy.deepcopy(self.result)
            result['profile_digest']=fullscan.profile_digest(self.profile)
            result['antivirus']=engine
            result['checkup']=copy.deepcopy(self.checkup)
            result['inventory']=inventory.public_inventory(self.inventory)
            result['protection']=inventory.protection(self.profile,self.inventory,result['antivirus'],result.get('checks',[]),result.get('checked_at') if result['state']=='finished' else None)
            result['full_scan']={k:copy.deepcopy(v) for k,v in self.full_result.items() if k != 'findings'}
            result['findings_source']=self.findings_source
            result['rules']=rules.summary(self.rule_path)
            result['rule_hits']=copy.deepcopy(self.rule_hits)
            result['quarantine']=findings.quarantine_status(self.state_dir)
            bundle=self.findings_bundle
            evidence_available=result['state']=='finished' or self.findings_source=='full'
            result['findings']=[{k:item[k] for k in ['id','path','signature','sha256','observed_at','size']} for item in bundle['items'][:8]] if evidence_available else []
            result['findings_state']=bundle['state'] if evidence_available else 'unavailable'
            result['findings_total']=bundle['total'] if evidence_available else 0
            if len(result.get('history',[]))>8:
                result['history']=result['history'][-8:]
                if result['history_state']=='ok': result['history_state']='truncated'
            return result
    def trigger_engine_update(self):
        with self.lock:
            if (getattr(self,'multi',None) and self.multi.running) or self.full_running or self.result['state']=='running' or antivirus.update_status()=='running':
                return 409,{'state':'unavailable','reason':'local task already active'}
            if self.engine_update_last and time.monotonic()-self.engine_update_last<300:
                return 429,{'state':'unavailable','reason':'updater cooldown'}
            try: antivirus.request_official_update()
            except (OSError,ValueError,subprocess.SubprocessError):
                return 503,{'state':'unavailable','reason':'official updater unavailable'}
            self.engine_update_last=time.monotonic()
        return 202,{'state':'running'}
    def clear_checkup(self):
        # A separate scan invalidates the combined record on disk as well as in memory.
        value={'schema':'ironcurtain-checkup/v1','state':'idle','profile_digest':fullscan.profile_digest(self.profile)}
        try: atomic_json(self.state_dir/'checkup-report.json',value)
        except (OSError,ValueError): return False
        self.checkup=value; return True
    def trigger(self):
        with self.lock:
            if (getattr(self,'multi',None) and self.multi.running) or self.full_running: return 409,{'state':'unavailable','reason':'file scan in progress'}
            if self.result['state']=='running': return 409,{**copy.deepcopy(self.result),'history':copy.deepcopy(self.history[-8:]),'history_state':'unavailable' if not self.history_available else 'truncated' if len(self.history)>8 else 'ok'}
            if self.last and time.monotonic()-self.last<60: return 429,{'state':'unavailable','reason':'scan cooldown'}
            if not self.clear_checkup(): return 503,{'state':'unavailable','reason':'task persistence unavailable'}
            self.last=time.monotonic(); self.result={'state':'running','task_id':uuid.uuid4().hex,'started_at':utc(),'checks':[],'progress':{'completed':0,'total':len(IDS),'current':IDS[0]},'history':copy.deepcopy(self.history),'history_state':'ok' if self.history_available else 'unavailable'}
            result={**copy.deepcopy(self.result),'history':copy.deepcopy(self.history[-8:]),'history_state':'unavailable' if not self.history_available else 'truncated' if len(self.history)>8 else 'ok'}
        try: threading.Thread(target=self.scan,daemon=True).start()
        except RuntimeError:
            with self.lock: self.result={'state':'failed','checks':[],'history':copy.deepcopy(self.history),'history_state':'unavailable'}
            return 503,{'state':'unavailable','reason':'task start unavailable'}
        return 202,result
    def scan(self):
        with self.lock: identity={k:self.result[k] for k in ('task_id','started_at') if k in self.result}
        def update(checks,current):
            with self.lock:
                self.result['checks']=checks; self.result['progress']={'completed':len(checks),'total':len(IDS),'current':current}
        try:
            observed=inventory.discover(Runner(),previous=self.inventory)
            atomic_json(self.state_dir/'last-inventory.json',observed)
            with self.lock: self.inventory=observed
            scanner=Scanner(self.profile,response_state=self.state_dir,rule_path=self.rule_path); checks=scanner.run_checks(update)
            events=copy.deepcopy(self.history)
            if self.history_available:
                for item in checks:
                    old=self.previous.get(item['id'])
                    if (old and (old['state']!=item['state'] or old['evidence_digest']!=item['evidence_digest'])) or (not old and item['state']!='ok'):
                        events.append({**item,'previous_state':old['state'] if old else None})
            report={**identity,'state':'finished','profile_digest':fullscan.profile_digest(self.profile),'checked_at':utc(),'checks':checks,'history':events[-128:],'history_state':'truncated' if len(events)>8 else 'ok','progress':{'completed':len(IDS),'total':len(IDS),'current':None}}
            if not self.history_available: report['history_state']='unavailable'
            bundle={'schema':'ironcurtain-findings/v1','checked_at':report['checked_at'],'profile_digest':hashlib.sha256(canonical(self.profile)).hexdigest(),
                    'items':scanner.findings,'total':scanner.malware_count,'state':'complete' if scanner.findings_complete and all(item['state'] in ['ok','finding'] for item in checks if item['category']=='malware') else 'partial'}
            rule_hits={'items':scanner.rule_hits,'total':scanner.rule_hit_count,'state':'complete' if scanner.rule_pack and scanner.rule_scan_complete else 'partial' if scanner.rule_pack else 'unavailable'}
            atomic_json(self.state_dir/'last-rule-hits.json',rule_hits)
            atomic_json(self.state_dir/'last-findings.json',bundle)
            with self.lock: self.findings_bundle=bundle; self.rule_hits=rule_hits; self.findings_source='quick'
            # Do not overwrite corrupt prior evidence or silently reset its history.
            if self.history_available:
                atomic_json(self.state_dir/'last-report.json',report)
                self.previous={item['id']:item for item in checks}; self.history=report['history']
            with self.lock:
                self.result=report
                digest_snapshot={'scan':{**report,'history':[]},'files':scanner.observed_files,'files_state':'complete' if scanner.files_complete else 'unavailable'}
                if len(canonical(digest_snapshot))>250000: digest_snapshot.update(files={},files_state='unavailable')
                self.outbound=digest_snapshot
        except Exception:
            with self.lock: self.result={**identity,'state':'failed','checked_at':utc(),'checks':[],'history':copy.deepcopy(self.history),'history_state':'unavailable'}
    def trigger_full(self):
        with self.lock:
            if (getattr(self,'multi',None) and self.multi.running) or self.full_running or self.result['state']=='running': return 409,{'state':'unavailable','reason':'scan already active'}
            engine=antivirus.engine_status()
            if engine.get('update_state')=='running': return 409,{'state':'unavailable','reason':'database update in progress'}
            if not (self.profile['program_roots'] or self.profile['business_roots']) or not engine.get('installed') or engine.get('state')!='configured':
                return 503,{'state':'unavailable','reason':'scan scope or engine unavailable'}
            if self.last and time.monotonic()-self.last<60: return 429,{'state':'unavailable','reason':'scan cooldown'}
            if not self.clear_checkup(): return 503,{'state':'unavailable','reason':'task persistence unavailable'}
            self.last=time.monotonic(); self.full_running=True
            self.full_result={'schema':'ironcurtain-full-scan/v1','state':'indexing','started_at':utc(),'task_id':uuid.uuid4().hex}
        try: threading.Thread(target=self.scan_full,args=(engine,),daemon=True).start()
        except RuntimeError:
            with self.lock: self.full_running=False; self.full_result={'schema':'ironcurtain-full-scan/v1','state':'idle'}
            return 503,{'state':'unavailable','reason':'task start unavailable'}
        return 202,{'state':'running','task_id':self.full_result['task_id']}
    def scan_full(self,engine,release=True):
        def publish(value):
            atomic_json(self.state_dir/'full-scan-report.json',value)
            bundle=None
            if 'indexed' in value:
                bundle={'schema':'ironcurtain-findings/v1','checked_at':value['updated_at'],'profile_digest':hashlib.sha256(canonical(self.profile)).hexdigest(),
                        'items':value.get('findings',[]),'total':value['infected'],'state':'complete' if value['state']=='finished' and value['infected']<=len(value.get('findings',[])) else 'partial'}
                atomic_json(self.state_dir/'last-findings.json',bundle)
            with self.lock:
                self.full_result=copy.deepcopy(value)
                if bundle: self.findings_bundle=bundle; self.findings_source='full'
        try:
            with self.lock: identity={k:self.full_result[k] for k in ('task_id','started_at') if k in self.full_result}
            task=fullscan.FullScan(self.profile,self.state_dir,Runner(),secure_fd,engine,antivirus.DATABASE_DIR,publish,self.stop,database_status=antivirus.database_status,**identity)
            task.run()
        except Exception:
            with self.lock:
                prior=self.full_result
                self.full_result={'schema':'ironcurtain-full-scan/v1','state':'failed','task_id':prior.get('task_id',uuid.uuid4().hex),'started_at':prior.get('started_at',utc()),'updated_at':utc(),'finished_at':utc(),
                                  **{k:prior.get(k,0) for k in ('indexed','processed','clean','infected','skipped','errors','bytes_scanned')},
                                  'profile_digest':fullscan.profile_digest(self.profile),'findings':prior.get('findings',[]),'index_complete':False,'scope':'enrolled-directories-only','reasons':['扫描任务持久化失败，请核对代理日志与受保护状态目录']}
        finally:
            with self.lock:
                if release: self.full_running=False
    def trigger_checkup(self):
        with self.lock:
            if (getattr(self,'multi',None) and self.multi.running) or self.full_running or self.result['state']=='running' or antivirus.update_status()=='running': return 409,{'state':'unavailable','reason':'scan already active'}
            if self.last and time.monotonic()-self.last<60: return 429,{'state':'unavailable','reason':'scan cooldown'}
            started=utc(); task_id=uuid.uuid4().hex
            task={'schema':'ironcurtain-checkup/v1','state':'running','task_id':task_id,'stage':'environment','profile_digest':fullscan.profile_digest(self.profile),'started_at':started,'updated_at':started,'reasons':[]}
            try: atomic_json(self.state_dir/'checkup-report.json',task)
            except (OSError,ValueError): return 503,{'state':'unavailable','reason':'task persistence unavailable'}
            self.last=time.monotonic(); self.full_running=True; self.checkup=task
            self.full_result={'schema':'ironcurtain-full-scan/v1','state':'idle'}
            self.result={'state':'running','task_id':task_id,'started_at':started,'checks':[],'progress':{'completed':0,'total':len(IDS),'current':IDS[0]},'history':copy.deepcopy(self.history),'history_state':'ok' if self.history_available else 'unavailable'}
        try: threading.Thread(target=self.scan_checkup,daemon=True).start()
        except RuntimeError:
            self.fail_checkup('体检任务无法启动，请检查代理日志')
            with self.lock:
                self.full_running=False; self.result={'state':'failed','checks':[],'history':copy.deepcopy(self.history),'history_state':'unavailable'}
            return 503,{'state':'unavailable','reason':'task start unavailable'}
        return 202,{'state':'running','task_id':task_id}
    def fail_checkup(self,reason):
        with self.lock: value={**self.checkup,'state':'failed','updated_at':utc(),'reasons':[reason]}
        try: atomic_json(self.state_dir/'checkup-report.json',value)
        except (OSError,ValueError): pass
        with self.lock: self.checkup=value
    def scan_checkup(self):
        def publish(state,stage,reasons,environment_at=None):
            with self.lock: value={**self.checkup,'state':state,'stage':stage,'updated_at':utc(),'reasons':reasons[:8]}
            if environment_at: value['environment_at']=environment_at
            atomic_json(self.state_dir/'checkup-report.json',value)
            with self.lock: self.checkup=value
        try:
            self.scan()
            with self.lock: report=copy.deepcopy(self.result); observed=copy.deepcopy(self.inventory)
            if report['state']!='finished':
                publish('failed','environment',['环境检查失败，请检查主机代理日志']); return
            reasons=[]
            if any(x['state']=='unavailable' and not x['id'].startswith('cloudflare.') for x in report['checks']): reasons.append('部分环境检查不可用，请查看逐项报告')
            if any(observed.get(k)!='complete' for k in ('container_state','listener_state','directory_state')) or any(observed.get('environment',{}).get(k)!='complete' for k in ('system_state','package_state','service_state')): reasons.append('主机资产发现存在覆盖缺口，请查看环境清单')
            engine=antivirus.engine_status()
            if not (self.profile['program_roots'] or self.profile['business_roots']): reasons.append('尚未纳管文件目录，未执行文件查杀；请在 Linux 菜单配置保护范围')
            if engine.get('update_state')=='running': reasons.append('病毒库正在更新，未执行文件查杀，请稍后重试')
            if not engine.get('installed') or engine.get('state')!='configured': reasons.append('病毒引擎或病毒库未就绪，未执行文件查杀')
            if not (self.profile['program_roots'] or self.profile['business_roots']) or not engine.get('installed') or engine.get('state')!='configured' or engine.get('update_state')=='running':
                publish('partial','complete',reasons,report['checked_at']); return
            publish('running','files',reasons,report['checked_at'])
            with self.lock: self.full_result={'schema':'ironcurtain-full-scan/v1','state':'indexing','started_at':utc(),'task_id':self.checkup['task_id']}
            self.scan_full(engine,release=False)
            with self.lock: files=copy.deepcopy(self.full_result)
            if files['state']!='finished': reasons.append('文件查杀未完整完成，请查看跳过、错误与中断原因')
            publish('partial' if reasons else 'finished','complete',reasons,report['checked_at'])
        except Exception:
            self.fail_checkup('体检状态保存失败，请检查受保护状态目录与代理日志')
        finally:
            with self.lock: self.full_running=False
    def schedule(self):
        self.trigger()
        while not self.stop.wait(self.interval): self.trigger()

class UnixServer(socketserver.ThreadingMixIn,getattr(socketserver,'UnixStreamServer',socketserver.TCPServer)):
    # TCP fallback permits portable unit imports only; serve() is Linux-only.
    daemon_threads=True
    request_queue_size=8
    def __init__(self,*args,**kwargs):
        self.slots=threading.BoundedSemaphore(8)
        super().__init__(*args,**kwargs)
    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False): self.shutdown_request(request); return
        try: super().process_request(request,address)
        except BaseException: self.slots.release(); raise
    def process_request_thread(self,request,address):
        try: super().process_request_thread(request,address)
        finally: self.slots.release()

def prepare_socket_parent(socket_path):
    location=pathlib.Path(socket_path)
    if not location.is_absolute() or '..' in location.parts: raise ValueError('unsafe socket path')
    location.parent.mkdir(parents=True,exist_ok=True,mode=0o750)
    for current in [location.parent,*location.parent.parents]:
        info=current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0: raise ValueError('socket parent must be root owned without links')
        if info.st_mode & 0o022 and (current==location.parent or not info.st_mode & stat.S_ISVTX): raise ValueError('socket parent cannot be writable by other users')
    if location.exists() or location.is_symlink():
        info=location.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0: raise ValueError('untrusted socket entry')
    return location

def serve(profile_file,state_dir,socket_path,allowed_uid,group):
    if os.name!='posix' or not hasattr(socketserver,'UnixStreamServer'): raise SystemExit('Linux Unix socket required')
    if os.geteuid()!=0: raise SystemExit('host agent must be started by root')
    agent=Agent(private_json(profile_file),state_dir,rule_path=pathlib.Path(profile_file).parent/'rules.json')
    update_bridge=updates.Bridge(private_bytes,atomic_json)
    agent.multi=multi_engine.Bridge(agent,profile_file,{'open':secure_fd,'read':private_json,'write':atomic_json,'digest':fullscan.profile_digest,'updating':antivirus.update_status,'discover':inventory.discover,'runner':Runner})
    engine_bridge=engine_readiness.Bridge(engine_readiness.NativeProbe(secure_fd),antivirus.engine_status,
        busy=lambda:update_bridge.status().get('state')=='running' or antivirus.update_status()=='running')
    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(5)
            super().setup()
        def log_message(self,*args): pass
        def reply(self,code,value):
            data=canonical(value)
            if len(data)>(262144 if self.path=='/report' else 65536): code=503; data=b'{"state":"unavailable"}'
            self.send_response(code); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
        def authorized(self):
            try: _,uid,_=struct.unpack('3i',self.connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)); return uid in [0,allowed_uid]
            except OSError: return False
        def do_GET(self):
            if not self.authorized(): return self.reply(403,{'state':'unavailable'})
            if self.path=='/engines': return self.reply(200,engine_bridge.status())
            if self.path=='/multi-engine': return self.reply(200,agent.multi.status())
            if self.path=='/update-status': return self.reply(200,update_bridge.status())
            if self.path=='/status': return self.reply(200,agent.status())
            if self.path=='/report':
                with agent.lock: value=copy.deepcopy(agent.outbound)
                return self.reply(200,value or {'state':'unavailable'})
            return self.reply(404,{'state':'unavailable'})
        def do_POST(self):
            if not self.authorized(): return self.reply(403,{'state':'unavailable'})
            if self.path not in ['/scan','/full-scan','/checkup','/engine-update','/update-check','/update','/multi-engine','/engines'] or self.headers.get('Content-Length')!='0' or self.headers.get('Transfer-Encoding'): return self.reply(400,{'state':'unavailable'})
            if self.path=='/engines': return self.reply(*engine_bridge.trigger())
            if self.path=='/multi-engine': return self.reply(*agent.multi.trigger())
            if self.path=='/engine-update': return self.reply(*agent.trigger_engine_update())
            if self.path in ['/update-check','/update']: return self.reply(*update_bridge.trigger('check' if self.path=='/update-check' else 'update'))
            self.reply(*(agent.trigger_checkup() if self.path=='/checkup' else agent.trigger_full() if self.path=='/full-scan' else agent.trigger()))
    location=prepare_socket_parent(socket_path)
    if location.exists() or location.is_symlink():
        if not stat.S_ISSOCK(os.lstat(location).st_mode): raise SystemExit('refusing to replace non-socket')
        probe=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); probe.settimeout(1)
        try:
            probe.connect(str(location))
        except ConnectionRefusedError: location.unlink()
        else: raise SystemExit('host agent already running')
        finally: probe.close()
    server=UnixServer(str(location),Handler); os.chown(location,0,group); os.chmod(location,0o660)
    threading.Thread(target=agent.schedule,daemon=True).start()
    try: server.serve_forever()
    finally: agent.stop.set(); engine_bridge.close(); agent.multi.close(); server.server_close(); location.unlink(missing_ok=True)

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--profile',default='/etc/ironcurtain/profile.json'); parser.add_argument('--state',default='/var/lib/ironcurtain'); parser.add_argument('--socket',default='/run/ironcurtain/scan.sock'); parser.add_argument('--allowed-uid',type=int,default=10001); parser.add_argument('--group',type=int,default=10001); parser.add_argument('--validate-profile',action='store_true'); parser.add_argument('--once',action='store_true'); args=parser.parse_args()
    if args.validate_profile:
        profile_validate(private_json(args.profile)); print('保护配置格式有效'); return
    if args.once:
        report={'state':'finished','checked_at':utc(),'checks':Scanner(private_json(args.profile),rule_path=pathlib.Path(args.profile).parent/'rules.json').run_checks(),'history':[],'history_state':'unavailable'}; report['checked_at']=utc(); print(json.dumps(report,ensure_ascii=False))
    else: serve(args.profile,args.state,args.socket,args.allowed_uid,args.group)
if __name__=='__main__': main()
