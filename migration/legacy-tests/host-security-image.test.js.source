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
const fixture=`
import json, pathlib, tempfile, types, copy
from unittest.mock import patch
with tempfile.TemporaryDirectory() as tmp:
 p=pathlib.Path(tmp).resolve(); a.ROOT=p; a.STATE_DIR=p/'state'; a.STATE_DIR.mkdir(mode=0o700)
 a.BASELINE=a.STATE_DIR/'baseline.json'; a.HOST_BASELINE=a.STATE_DIR/'host-baseline.json'
 a.HOST_FILES=(); a.HOST_DIRS=()
 a.LOCAL_PASSWD=p/'local-passwd'; a.LOCAL_PASSWD.write_text('service:x:100:100::/nonexistent:/usr/sbin/nologin\\n')
 for dirname in a.PROGRAM_DIRS: (p/dirname).mkdir()
 for name in a.PROGRAM_ROOT_FILES:
  (p/name).write_text(json.dumps({'version':'1.2.68'}) if name=='package.json' else 'trusted')
 a.atomic_json(a.BASELINE,{'schema':2,'version':'1.2.68','files':a.program_snapshot()})
 a.atomic_json(a.HOST_BASELINE,{'schema':1,'files':a.host_snapshot()})
 cid='a'*64; image='sha256:'+'b'*64; pinfile=a.STATE_DIR/'approved-image.json'
 pin={'schema':1,'root':str(p),'version':'1.2.68','image_id':image,
      'program_baseline':a.approved_baseline_pin(a.BASELINE),'host_baseline':a.approved_baseline_pin(a.HOST_BASELINE)}
 payload={'Id':cid,'Image':image,'Config':{'Labels':{'com.docker.compose.project':'appgog',
   'com.docker.compose.service':'appgog','com.docker.compose.project.working_dir':str(p),
   'com.docker.compose.project.config_files':str(p/'compose.yaml')},'Env':['SECRET=never-persist']}}
 calls=[]
 def fake(args,**kw):
  calls.append(args)
  if args[:2]==['/usr/bin/docker','ps']: return types.SimpleNamespace(returncode=0,stdout=cid)
  if args[:2]==['/usr/bin/docker','inspect']: return types.SimpleNamespace(returncode=0,stdout=json.dumps([payload]))
  raise AssertionError(args)
 def check():
  with patch.object(a.subprocess,'run',side_effect=fake): return a.approved_image_check()
`;

test('approved full image identity is explicit, detects same-tag replacement and never overwrites approval',enabled,()=>run(fixture+`
 assert check()['state']=='warning' and not pinfile.exists()
 a.atomic_json(pinfile,pin); original=pinfile.read_bytes(); assert check()['state']=='ok'
 payload['Image']='sha256:'+'c'*64; report=check(); assert report['state']=='finding'
 assert 'image-id-changed' in report['detail'] and 'SECRET' not in json.dumps(report)
 assert pinfile.read_bytes()==original
 assert all(command[1] in ('ps','inspect') for command in calls)
 payload['Image']=image; assert check()['state']=='ok'
`));

test('image approval detects changed versions and semantic baselines while ignoring approval timestamps',enabled,()=>run(fixture+`
 a.atomic_json(pinfile,pin); baseline=json.loads(a.BASELINE.read_text()); baseline['approved_at']='later'
 a.atomic_json(a.BASELINE,baseline); assert check()['state']=='ok'
 original_digest=baseline['files']['compose.yaml']; baseline['files']['compose.yaml']='c'*64; a.atomic_json(a.BASELINE,baseline); report=check()
 assert report['state']=='finding' and 'program-baseline-changed' in report['detail']
 baseline['files']['compose.yaml']=original_digest; a.atomic_json(a.BASELINE,baseline)
 (p/'package.json').write_text(json.dumps({'version':'1.2.69'})); assert 'version-changed' in check()['detail']
 (p/'package.json').write_text(json.dumps({'version':'1.2.68'}))
 host=json.loads(a.HOST_BASELINE.read_text()); host['files']['new']={'digest':'b'*64,'mode':384,'uid':0,'gid':0,'link':False}; a.atomic_json(a.HOST_BASELINE,host)
 assert 'host-baseline-changed' in check()['detail']
`));

test('untrusted approval and ambiguous or foreign container identity remain unknown',enabled,()=>run(fixture+`
 for bad in ({},dict(pin,root='/foreign'),dict(pin,image_id='latest'),dict(pin,program_baseline=None)):
  a.atomic_json(pinfile,bad); assert check()['state']=='unavailable'
 a.atomic_json(pinfile,pin)
 payload['Id']='d'*64; assert check()['state']=='unavailable'; payload['Id']=cid
 payload['Config']['Labels']['com.docker.compose.project']='foreign'; assert check()['state']=='unavailable'
 payload['Config']['Labels']['com.docker.compose.project']='appgog'
 payload['Config']['Labels']['com.docker.compose.project.working_dir']=str(p.parent); assert check()['state']=='unavailable'
 pinfile.write_text('broken'); assert check()['state']=='unavailable'
 a.atomic_json(pinfile,pin); a.BASELINE.write_text('broken'); assert check()['state']=='unavailable'
`));

test('image approval rejects linked and publicly writable records on Linux',{skip:process.platform!=='linux'},()=>run(fixture+`
 a.atomic_json(pinfile,pin); pinfile.chmod(0o666); assert check()['state']=='unavailable'
 pinfile.chmod(0o600); assert check()['state']=='ok'
 other=p/'pin.json'; pinfile.rename(other); pinfile.symlink_to(other); assert check()['state']=='unavailable'
`));

test('matching approval cannot bless invalid, incomplete or changed program and host inventories',enabled,()=>run(fixture+`
 a.atomic_json(pinfile,pin)
 baseline=json.loads(a.BASELINE.read_text())
 for invalid in ({'files':{'package.json':'a'*64}},dict(baseline,files={}),dict(baseline,version=None),
                 dict(baseline,files={'package.json':'invalid'}),dict(baseline,files={'../outside':'a'*64})):
  a.atomic_json(a.BASELINE,invalid); assert check()['state']=='unavailable'
 a.atomic_json(a.BASELINE,dict(baseline,files={'package.json':baseline['files']['package.json']}))
 pin['program_baseline']=a.approved_baseline_pin(a.BASELINE); a.atomic_json(pinfile,pin)
 assert check()['state']=='finding'
 a.atomic_json(a.BASELINE,baseline); pin['program_baseline']=a.approved_baseline_pin(a.BASELINE); a.atomic_json(pinfile,pin)
 (p/'compose.yaml').write_text('changed'); assert 'program-files-changed' in check()['detail']
 (p/'compose.yaml').write_text('trusted')
 (p/'.env').write_text('NEW=changed'); assert 'host-files-changed' in check()['detail']
 (p/'.env').unlink(); assert check()['state']=='ok'
 a.atomic_json(a.HOST_BASELINE,{'schema':1,'files':{'x':{'digest':'a'*64}}}); assert check()['state']=='unavailable'
`));
