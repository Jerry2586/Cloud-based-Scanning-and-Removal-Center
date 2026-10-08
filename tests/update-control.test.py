import http.client
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

spec=importlib.util.spec_from_file_location('update_control',Path(__file__).parents[1]/'src/host/update_control.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)

class FixtureBridge:
    def status(self):
        return {'schema':'ironcurtain-update-status/v1','installed_version':'0.6.6','check':{'state':'idle'},'job':{'state':'idle'}}
    def trigger(self,action):
        return (202,{'state':'running'}) if action in ('check','update') else (400,{'state':'unavailable'})

@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'Linux root Unix credentials')
class ControlBoundary(unittest.TestCase):
    def test_real_unix_peer_identity_and_no_arbitrary_operation(self):
        with tempfile.TemporaryDirectory(dir='/run',prefix='ironcurtain-update-test-') as directory:
            root=Path(directory);root.chmod(0o755);address=str(root/'control.sock')
            def serve():
                with c.Server(address,c.handler(FixtureBridge())) as server:
                    os.chmod(address,0o666);server.serve_forever()
            proc=multiprocessing.Process(target=serve);proc.start()
            def call(method,path,body=None,headers=None):
                conn=http.client.HTTPConnection('localhost',timeout=3);conn.sock=socket.socket(socket.AF_UNIX);conn.sock.connect(address)
                conn.request(method,path,body,headers or {});response=conn.getresponse();value=(response.status,json.loads(response.read()));conn.close();return value
            try:
                for _ in range(50):
                    if Path(address).exists():break
                    time.sleep(.02)
                self.assertEqual(call('GET','/update-status')[1]['installed_version'],'0.6.6')
                self.assertEqual(call('POST','/update',b'')[0],202)
                self.assertEqual(call('POST','/update-check',b'')[0],202)
                self.assertEqual(call('POST','/update',b'{"command":"sh"}')[0],400)
                self.assertEqual(call('POST','/update',b'',{'Transfer-Encoding':'chunked'})[0],400)
                self.assertEqual(call('POST','/shell',b'')[0],404)
                self.assertEqual(call('GET','/update-status?path=/etc/shadow')[0],404)
                code='import socket,http.client;c=http.client.HTTPConnection("localhost");c.sock=socket.socket(socket.AF_UNIX);c.sock.connect('+repr(address)+');c.request("GET","/update-status");print(c.getresponse().status)'
                def peer(uid,gid):return subprocess.check_output(['setpriv','--reuid='+str(uid),'--regid='+str(gid),'--clear-groups',sys.executable,'-c',code],text=True).strip()
                self.assertEqual(peer(10001,10001),'200')
                self.assertEqual(peer(10001,65534),'403')
                self.assertEqual(peer(65534,10001),'403')
            finally:
                proc.terminate();proc.join(5);self.assertFalse(proc.is_alive())

if __name__=='__main__':unittest.main(verbosity=2)
