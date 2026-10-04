import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
const python=process.env.APPGOG_TEST_PYTHON || 'python3';
const enabled={skip:spawnSync(python,['--version']).status!==0};
const agent=JSON.stringify(resolve('scripts/host-security-agent.py'));
function run(script) {
 const result=spawnSync(python,['-c',`import importlib.util, socketserver
if not hasattr(socketserver,'UnixStreamServer'): socketserver.UnixStreamServer=socketserver.TCPServer
s=importlib.util.spec_from_file_location('agent',${agent})
a=importlib.util.module_from_spec(s); s.loader.exec_module(a)
${script}`], {encoding:'utf8',timeout:10000,env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'}});
 assert.equal(result.status,0,result.stderr || result.error?.message);
}
const fixture="import json, os, pathlib, tempfile, types, subprocess\n\ndef fixture(tmp):\n p=pathlib.Path(tmp); a.ROOT=p\n a.STATE_DIR=p/'state'; a.STATE_DIR.mkdir(mode=0o700)\n a.BASELINE=a.STATE_DIR/'baseline.json'; a.HOST_BASELINE=a.STATE_DIR/'host-baseline.json'; a.HISTORY_FILE=a.STATE_DIR/'events.json'\n a.EVENTS=[]; a.PREVIOUS={}; a.HISTORY_VALID=True\n (p/'current').mkdir()\n for name in a.PROGRAM_ROOT_FILES:\n  (p/'current'/name).write_text(json.dumps({'version':'1.2.68'}) if name=='package.json' else 'trusted')\n for name in a.PROGRAM_DIRS:\n  (p/'current'/name).mkdir(); (p/'current'/name/'one.txt').write_text('trusted')\n return p\n";

test('legacy baselines require explicit approval and incomplete or oversized inventories remain unknown',enabled,()=>run(fixture+`
with tempfile.TemporaryDirectory() as tmp:
 p=fixture(tmp); a.FILES=('compose.yaml',)
 a.atomic_json(a.BASELINE,{'compose.yaml':a.file_digest(p/'current/compose.yaml')})
 assert a.integrity_check()['state']=='warning'
 (p/'current/compose.yaml').write_text('changed'); assert a.integrity_check()['state']=='finding'
 a.write_baseline(); assert a.integrity_check()['state']=='ok'
 a.MAX_INVENTORY_FILES=2; assert a.integrity_check()['state']=='unavailable'
 a.MAX_INVENTORY_FILES=4096; a.MAX_INVENTORY_BYTES=1; assert a.integrity_check()['state']=='unavailable'
`));

test('host configuration detects account, service, application-setting and mode changes without exposing secrets',enabled,()=>run(fixture+`
with tempfile.TemporaryDirectory() as tmp:
 p=fixture(tmp); host=p/'host'; host.mkdir(); (host/'sshd.conf').write_text('known')
 cron=host/'cron.d'; cron.mkdir(); (cron/'job').write_text('approved')
 a.HOST_FILES=(str(host/'sshd.conf'),str(host/'missing.conf')); a.HOST_DIRS=(str(cron),); a.LOCAL_PASSWD=host/'passwd'; a.LOCAL_PASSWD.write_text('service:x:100:100::/nonexistent:/usr/sbin/nologin')
 (p/'shared').mkdir(); env=p/'shared/.env'; env.write_text('TOKEN=secret-value')
 a.write_host_baseline(); original=a.HOST_BASELINE.read_bytes(); assert a.host_configuration_check()['state']=='ok'
 env.write_text('TOKEN=new-secret'); report=a.host_configuration_check(); assert report['state']=='finding'
 assert 'new-secret' not in json.dumps(report) and 'secret-value' not in json.dumps(report)
 env.write_text('TOKEN=secret-value'); assert a.host_configuration_check()['state']=='ok'
 (cron/'new-job').write_text('persistence'); assert a.host_configuration_check()['state']=='finding'
 (cron/'new-job').unlink(); (host/'missing.conf').write_text('new'); assert a.host_configuration_check()['state']=='finding'
 assert a.HOST_BASELINE.read_bytes()==original
 a.atomic_json(a.HOST_BASELINE,{'schema':1,'files':{'bad':{'digest':'junk'}}}); assert a.host_configuration_check()['state']=='unavailable'
`));

test('history records transitions, survives restart, remains bounded and preserves corrupt evidence',enabled,()=>run(fixture+`
with tempfile.TemporaryDirectory() as tmp:
 p=fixture(tmp)
 item=a.check('program','ok','clean',check_id='integrity.program')
 assert a.save_history([item])==[]
 finding=a.check('program','finding','changed',check_id='integrity.program')
 history=a.save_history([finding]); assert len(history)==1 and history[0]['previous_state']=='ok'
 assert a.save_history([finding])==history
 a.EVENTS=[]; a.PREVIOUS={}; assert a.load_history(); assert len(a.EVENTS)==1
 history=a.save_history([item]); assert history[-1]['state']=='ok' and history[-1]['previous_state']=='finding'
 for i in range(90): a.save_history([a.check('program','finding','changed '+str(i),check_id='integrity.program')])
 assert len(a.EVENTS)==64 and len(a.save_history([item]))==8
 a.HISTORY_FILE.write_text('corrupt'); a.HISTORY_VALID=a.load_history(); assert not a.HISTORY_VALID
 a.scan=lambda:[item if key==item['id'] else a.check(key,'ok','clean',check_id=key) for key in sorted(a.HOST_SCAN_IDS)]; a.run_scan(); assert a.STATE['history_state']=='unavailable'
 assert a.STATE['checks'][-1]['id']=='host.history'; assert a.HISTORY_FILE.read_text()=='corrupt'
`));

test('root state rejects symlinks and insecure permissions; program scans reject links', {skip:process.platform!=='linux'},()=>run(fixture+`
with tempfile.TemporaryDirectory() as tmp:
 p=fixture(tmp); a.write_baseline(); a.BASELINE.chmod(0o666); assert a.integrity_check()['state']=='unavailable'
 a.BASELINE.chmod(0o600); assert a.integrity_check()['state']=='ok'
 (p/'current/apps/one.txt').unlink(); (p/'current/apps/one.txt').symlink_to('/etc/passwd'); assert a.integrity_check()['state']=='unavailable'
 a.HISTORY_FILE.symlink_to(a.BASELINE)
 try: a.atomic_json(a.HISTORY_FILE,{}); assert False
 except OSError: pass
`));

test('HTTP reports enforce UTF-8 byte limits, discard old history first and fail closed for oversized checks',enabled,()=>run(`
import io
class Response:
 reply=a.Handler.reply
 def __init__(self): self.wfile=io.BytesIO(); self.headers={}
 def send_response(self,code): self.code=code
 def send_header(self,key,value): self.headers[key]=value
 def end_headers(self): pass
response=Response(); response.reply(200,{'state':'finished','checks':[],'history':[{'detail':'中'*10000},{'detail':'new'}],'history_state':'ok'})
assert response.code==200 and len(response.wfile.getvalue())<=32768
# Force actual byte overflow, not merely character count.
response=Response(); response.reply(200,{'state':'finished','checks':['中'*12000]})
assert response.code==503 and json.loads(response.wfile.getvalue())['state']=='unavailable'
`.replace('import io','import io, json')));


test('HTTP fixed actions reject query paths, methods, bodies and ambiguous framing',enabled,()=>run(`
import socket, threading, socketserver, unittest.mock
with socketserver.TCPServer(('127.0.0.1',0), a.Handler) as server:
 worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
 def call(method,path,headers=''):
  with socket.create_connection(server.server_address,timeout=3) as connection:
   message=method+' '+path+' HTTP/1.0\\r\\nHost: local\\r\\n'+headers+'\\r\\n'
   connection.sendall(message.encode()); response=b''
   while True:
    chunk=connection.recv(65536)
    if not chunk: break
    response+=chunk
   return int(response.split(b' ')[1])
 with unittest.mock.patch.object(a,'start_scan',return_value=202) as start:
  assert call('GET','/status')==200
  assert call('POST','/scan','Content-Length: 0\\r\\n')==202
  assert start.call_count==1
  assert call('GET','/scan')==404
  assert call('POST','/status')==400
  assert call('GET','/status?path=/etc/passwd')==404
  assert call('POST','/scan?command=id')==400
  for method in ('PUT','DELETE'): assert call(method,'/scan')==501
  for headers in ('Content-Length: 1\\r\\n','Transfer-Encoding: chunked\\r\\n','Content-Length: 0\\r\\nContent-Length: 1\\r\\n','Content-Length: -1\\r\\n'):
   assert call('POST','/scan',headers)==400
   assert call('GET','/status',headers)==400
  assert start.call_count==1
 server.shutdown(); worker.join(3)
`));


test('ZIP coverage limits and encrypted members cannot be accepted as clean',enabled,()=>run(fixture+`
import zipfile
with tempfile.TemporaryDirectory() as tmp:
 p=fixture(tmp); target=p/'current/apps/input.zip'
 with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED) as z:
  z.writestr('oversized',b'Z'*(9*1024*1024))
 try: a.validate_zip_budget(target); raise AssertionError('oversized archive accepted')
 except OSError: pass
 with zipfile.ZipFile(target,'w') as z: z.writestr('small','ok')
 a.validate_zip_budget(target)
 # Set both on-disk ZIP encryption flags; validator must reject rather than return clean.
 import struct
 encrypted=bytearray(target.read_bytes())
 central=encrypted.index(b'PK\\x01\\x02')
 for offset in (6,central+8): struct.pack_into('<H',encrypted,offset,struct.unpack_from('<H',encrypted,offset)[0]|1)
 target.write_bytes(encrypted)
 try: a.validate_zip_budget(target); raise AssertionError('encrypted member accepted')
 except OSError: pass
 with zipfile.ZipFile(target,'w') as z:
  for i in range(101): z.writestr(str(i),'ok')
 try: a.validate_zip_budget(target); raise AssertionError('entry budget accepted')
 except OSError: pass
 target.write_bytes(b'PK\\x03\\x04broken')
 try: a.validate_zip_budget(target); raise AssertionError('broken ZIP accepted')
 except OSError: pass
`));


test('business malware history survives initial unknown, finding, recovery and service restart',enabled,()=>run(fixture+`
with tempfile.TemporaryDirectory() as tmp:
 p=fixture(tmp)
 for state in ['unavailable', 'finding', 'ok']:
  item=a.check('business scan', state, 'bounded result', check_id='malware.business', category='malware')
  a.scan=lambda:[item if key==item['id'] else a.check(key,'ok','clean',check_id=key) for key in sorted(a.HOST_SCAN_IDS)]; a.run_scan()
  assert a.STATE['state']=='finished' and a.STATE['history_state']=='ok', a.STATE
  assert a.STATE['history'][-1]['state']==state and a.STATE['history'][-1]['category']=='malware'
  a.EVENTS=[]; a.PREVIOUS={}; assert a.load_history()
 assert [item['state'] for item in a.EVENTS]==['unavailable','finding','ok']
 assert a.EVENTS[-1]['previous_state']=='finding'
`));
