import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
const python=process.env.APPGOG_TEST_PYTHON||'python3';
const available=spawnSync(python,['--version']).status===0;
function run(script) {
 const bootstrap='import importlib.util,socketserver,json,pathlib,tempfile,os,types,unittest.mock as mock\nif not hasattr(socketserver,"UnixStreamServer"): socketserver.UnixStreamServer=socketserver.TCPServer\ns=importlib.util.spec_from_file_location("a",'+JSON.stringify(resolve('scripts/host-security-agent.py'))+')\na=importlib.util.module_from_spec(s); s.loader.exec_module(a)\n';
 const result=spawnSync(python,['-c',bootstrap+script],{encoding:'utf8',timeout:10000,env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'}});
 assert.equal(result.status,0,result.stderr||result.error?.message);
}
test('UDP checks distinguish connected clients, loopback, IPv4-mapped binds and incomplete snapshots',{skip:!available},()=>run(
 'header="sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\\n"\n'+
 'loop=header+"0: 0100007F:0035 00000000:0000 07 0 0 0 0 0 0\\n"\n'+
 'bound=header+"0: 00000000:0035 00000000:0000 07 0 0 0 0 0 0\\n"\n'+
 'client=header+"0: 00000000:2328 08080808:0035 01 0 0 0 0 0 0\\n"\n'+
 'mapped=header+"0: 0000000000000000FFFF00000100007F:0035 00000000000000000000000000000000:0000 07 0 0 0 0 0 0\\n"\n'+
 'assert a.udp_posture_from_text(loop,header)["state"]=="ok"\n'+
 'assert a.udp_posture_from_text(loop,header.replace("rem_address","remote_address"))["state"]=="ok"\n'+
 'assert a.udp_posture_from_text(bound,header)["state"]=="warning"\n'+
 'assert a.udp_posture_from_text(client,header)["state"]=="ok"\n'+
 'assert a.udp_posture_from_text(bound.replace(" 07 "," ZZ "),header)["state"]=="unavailable"\n'+
 'assert a.udp_posture_from_text(header,mapped)["state"]=="ok"\n'+
 'assert a.udp_posture_from_text(bound+"bad\\n",header)["state"]=="unavailable"\n'+
 'with mock.patch.object(a,"fixed_proc_text",side_effect=OSError("partial")):\n assert a.udp_posture_check()["state"]=="unavailable"\n'
));
test('route baseline requires exact approval, ignores counters, detects gateway changes and preserves prior approval',{skip:!available},()=>run(
 'header="Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\\n"\n'+
 'row="eth0 00000000 0100000A 0003 0 0 100 00000000 0 0 0\\n"\n'+
 'v6="00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000002 00200200 lo\\n"\n'+
 'current=a.route_snapshot_from_text(header+row,v6)\n'+
 'assert current==a.route_snapshot_from_text(header+row.replace("0003 0 0", "0003 9 5"),v6.replace("00000001 00000002","00000004 00000008"))\n'+
 'assert current!=a.route_snapshot_from_text(header+row.replace("0100000A","0200000A"),v6)\n'+
 'for bad4,bad6 in [(header+row*257,v6),(header+row,v6.replace(" 00 "," ff ",1)),("bad",v6),(header+row.replace("eth0","bad/interface"),v6)]:\n try: a.route_snapshot_from_text(bad4,bad6); raise AssertionError("bad routes accepted")\n except ValueError: pass\n'+
 'with tempfile.TemporaryDirectory() as tmp:\n a.NETWORK_BASELINE=pathlib.Path(tmp)/"network.json"\n with mock.patch.object(a,"route_snapshot",return_value=current):\n  assert a.route_configuration_check()["state"]=="unavailable"\n  try: a.approve_network_baseline("0"*64); raise AssertionError("wrong digest approved")\n  except ValueError: pass\n  assert not a.NETWORK_BASELINE.exists()\n  a.approve_network_baseline(current["digest"])\n  assert a.route_configuration_check()["state"]=="ok"\n original=a.NETWORK_BASELINE.read_bytes()\n with mock.patch.object(a,"route_snapshot",return_value={**current,"digest":"0"*64}):\n  assert a.route_configuration_check()["state"]=="finding"\n assert a.NETWORK_BASELINE.read_bytes()==original\n invalid=json.loads(original); invalid["root"]="/foreign"; a.atomic_json(a.NETWORK_BASELINE,invalid)\n with mock.patch.object(a,"route_snapshot",return_value=current): assert a.route_configuration_check()["state"]=="unavailable"\n'
));
test('route observation and kernel checks fail closed for races and partial output; no automatic kernel changes',{skip:!available},()=>run(
 'header="Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\\n"\n'+
 'row="eth0 00000000 0100000A 0003 0 0 100 00000000 0 0 0\\n"\n'+
 'with mock.patch.object(a,"fixed_proc_text",side_effect=[header+row,"",header+row.replace("0100000A","0200000A"),""]):\n try: a.route_snapshot(); raise AssertionError("racing route approved")\n except ValueError: pass\n'+
 'values={path:str(min(policy)) for path,policy in a.KERNEL_POLICY.items()}\n'+
 'with mock.patch.object(a,"fixed_proc_text",side_effect=lambda p:values[p]): assert a.kernel_security_check()["state"]=="ok"\n'+
 'values["/proc/sys/kernel/randomize_va_space"]="0"\n'+
 'with mock.patch.object(a,"fixed_proc_text",side_effect=lambda p:values[p]): assert a.kernel_security_check()["state"]=="warning"\n'+
 'with mock.patch.object(a,"fixed_proc_text",side_effect=OSError("missing")): assert a.kernel_security_check()["state"]=="unavailable"\n'
));

test('fixed proc readers reject arbitrary paths and bypass only known kernel net aliases',{skip:!available},()=>run(
 'with mock.patch.object(a,"read_regular",return_value=b"safe") as reader:\n assert a.fixed_proc_text("/proc/net/udp")=="safe"\n assert reader.call_args.args[0]==pathlib.Path("/proc")/str(os.getpid())/"net"/"udp"\n assert reader.call_args.kwargs=={"proc_lookup":True}\n assert a.fixed_proc_text("/proc/sys/kernel/kptr_restrict")=="safe"\n assert reader.call_args.args[0]==pathlib.Path("/proc/sys/kernel/kptr_restrict")\n for path in ["/etc/shadow","/proc/net/tcp","/proc/self/net/udp"]:\n  try: a.fixed_proc_text(path); raise AssertionError("arbitrary proc path accepted")\n  except ValueError: pass\n'
));

test('all network and runtime check markers survive restart within the current bounded check contract',{skip:!available},()=>run(
 'with tempfile.TemporaryDirectory() as tmp:\n a.HISTORY_FILE=pathlib.Path(tmp)/"events.json"\n a.EVENTS=[]; a.PREVIOUS={}; a.HISTORY_VALID=True\n checks=[a.check("item", "unavailable", "bounded",check_id="host.item-"+str(i)) for i in range(a.MAX_CHECKS)]\n a.save_history(checks)\n a.EVENTS=[]; a.PREVIOUS={}\n assert a.load_history() is True\n assert len(a.PREVIOUS)==a.MAX_CHECKS\n payload=json.loads(a.HISTORY_FILE.read_bytes())\n for i in range(a.MAX_CHECKS,a.MAX_CHECKS+1): payload["previous"]["host.item-"+str(i)]={"state":"ok","digest":"0"*64}\n a.atomic_json(a.HISTORY_FILE,payload)\n original=a.HISTORY_FILE.read_bytes()\n assert a.load_history() is False\n assert a.HISTORY_FILE.read_bytes()==original\n'
));

test('fixed proc lookup timestamps may refresh while descriptor and named-entry replacements remain rejected',{skip:!available},()=>run(
 'with tempfile.TemporaryDirectory() as tmp:\n path=pathlib.Path(tmp)/"entry"; path.write_bytes(b"safe")\n base=path.stat()\n keys=("st_dev","st_ino","st_mode","st_uid","st_gid","st_size","st_mtime_ns","st_ctime_ns")\n values={key:getattr(base,key) for key in keys}\n named=types.SimpleNamespace(**{**values,"st_mtime_ns":values["st_mtime_ns"]+1000000000,"st_ctime_ns":values["st_ctime_ns"]+1000000000})\n'+
 ' def get_stat(target,*args,**kwargs):\n  if str(target) in ("entry",str(path)): return named\n  return base\n'+
 ' with mock.patch.object(a.os,"fstat",return_value=base), mock.patch.object(a.os,"stat",side_effect=get_stat):\n  assert a.read_regular(path,4,proc_lookup=True)==b"safe"\n  try: a.read_regular(path,4); raise AssertionError("regular file timestamp change accepted")\n  except OSError: pass\n'+
 ' for key in ("st_dev","st_ino","st_mode","st_uid","st_gid","st_size"):\n  named=types.SimpleNamespace(**{**values,key:values[key]+1})\n  with mock.patch.object(a.os,"fstat",return_value=base), mock.patch.object(a.os,"stat",side_effect=get_stat):\n   try: a.read_regular(path,4,proc_lookup=True); raise AssertionError("changed proc identity accepted: "+key)\n   except OSError: pass\n'+
 ' named=types.SimpleNamespace(**values)\n changed=types.SimpleNamespace(**{**values,"st_mtime_ns":values["st_mtime_ns"]+1})\n with mock.patch.object(a.os,"fstat",side_effect=[base,changed]), mock.patch.object(a.os,"stat",side_effect=get_stat):\n  try: a.read_regular(path,4,proc_lookup=True); raise AssertionError("open proc descriptor changed")\n  except OSError: pass\n'+
 ' try: a.read_regular(path,3,proc_lookup=True); raise AssertionError("proc size limit bypassed")\n except OSError: pass\n'
));
