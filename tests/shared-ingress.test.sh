#!/usr/bin/env bash
# Disposable Linux only: actual Caddy, TLS trust and rollback, not ACME issuance.
set -euo pipefail
[[ $EUID == 0 && ${GITHUB_ACTIONS:-} == true && $(uname -s) == Linux ]] || { echo 'Disposable root Linux runner required' >&2; exit 1; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[[ ! -e /opt/appgog && ! -L /opt/appgog ]] || { echo 'Existing APPGOG refused' >&2; exit 1; }
[[ -d /opt && ! -L /opt ]] || exit 1
chown root:root /opt
chmod 755 /opt
WORK=$(mktemp -d /opt/ic-ingress-test.XXXXXXXX)
CONTAINER=ic-ingress-fixture
! docker inspect "$CONTAINER" >/dev/null 2>&1 || exit 1
PID=
cleanup() {
  result=$?
  if ((result)); then docker logs "$CONTAINER" >&2 || true; fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  [[ -z $PID ]] || kill "$PID" 2>/dev/null || true
  [[ $(realpath /opt/appgog) == /opt/appgog ]] && rm -rf -- /opt/appgog
  [[ $WORK == /opt/ic-ingress-test.* && $(realpath "$WORK") == "$WORK" ]] && rm -rf -- "$WORK"
  exit "$result"
}
trap cleanup EXIT
install -d -m 755 /opt/appgog/shared/ingress "$WORK/runtime/domain-certificates"
chmod 755 "$WORK"
GEN=$(printf a%.0s {1..64})
install -d -m 755 "$WORK/runtime/domain-certificates/$GEN"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$WORK/runtime/panel.key" -out "$WORK/runtime/panel.crt" -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$WORK/runtime/domain-certificates/$GEN/key.pem" -out "$WORK/runtime/domain-certificates/$GEN/cert.pem" -subj '/CN=guard.example.test' -addext 'subjectAltName=DNS:guard.example.test,DNS:cloud.example.test' >/dev/null 2>&1
cat > "$WORK/fixture.mjs" <<'JS'
import {createServer} from 'node:https';
import {readFileSync} from 'node:fs';
const runtime=process.argv[2];
for(const [port,service] of [[8790,'ironcurtain-local'],[8791,'xuanwu-admin']]) {
 createServer({cert:readFileSync(runtime+'/panel.crt'),key:readFileSync(runtime+'/panel.key')},(req,res)=>{
  res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({service,ready:true,host:req.headers.host}));
 }).listen(port,'0.0.0.0');
}
JS
node "$WORK/fixture.mjs" "$WORK/runtime" &
PID=$!
cat > "$WORK/Caddyfile" <<'CADDY'
{
  admin off
  http_port 8080
  https_port 8443
  auto_https off
}
http://127.0.0.1:8081 {
  bind 127.0.0.1
  respond /health "ok" 200
}
import /app/runtime/ingress/*.caddy
CADDY
chmod 644 "$WORK/Caddyfile"
docker run -d --name "$CONTAINER" --label com.appgog.shared-ingress=v1 --user 1000:1000 -p 80:8080 -p 443:8443 --add-host host.docker.internal:host-gateway -v /opt/appgog/shared/ingress:/app/runtime/ingress:ro -v "$WORK/Caddyfile:/app/Caddyfile:ro" --health-cmd 'wget -q -O - http://127.0.0.1:8081/health' --health-interval 1s --health-retries 20 caddy:2.10.2 caddy run --config /app/Caddyfile --adapter caddyfile
PYTHONPATH="$ROOT/scripts" python3 - "$WORK" "$GEN" <<'PY'
import json, subprocess, sys, time
from pathlib import Path
from shared_ingress import SharedIngress, ingress_lock, publish
work,generation=Path(sys.argv[1]),sys.argv[2]
def curl(domain,route,https=False):
 args=['curl','--noproxy','*','--fail','--silent','--show-error','--max-time','10','--resolve',domain+':'+('443' if https else '80')+':127.0.0.1']
 if https: args+=['--cacert',str(work/'runtime/domain-certificates'/generation/'cert.pem')]
 return subprocess.check_output(args+[('https' if https else 'http')+'://'+domain+route])
for _ in range(40):
 try: adapter=SharedIngress.discover('local','guard.example.test'); break
 except RuntimeError: time.sleep(0.25)
else: raise RuntimeError('Caddy fixture failed discovery')
with ingress_lock():
 before=adapter.snapshot()
 adapter.prepare('guard.example.test',before)
 token=adapter.webroot/'.well-known/acme-challenge/fixture-token'
 token.parent.mkdir(parents=True,mode=0o755,exist_ok=True)
 token.write_text('real-http-challenge')
 assert curl('guard.example.test','/.well-known/acme-challenge/fixture-token')==b'real-http-challenge'
 adapter.activate('guard.example.test',generation,work/'runtime','127.0.0.1')
 result=json.loads(curl('guard.example.test','/healthz',True))
 assert result=={'service':'ironcurtain-local','ready':True,'host':'guard.example.test'},result
 ready=adapter.snapshot()
 publish(adapter.site,b'https://guard.example.test {\n  unknown_directive\n}\n')
 try: adapter.reload()
 except RuntimeError: pass
 else: raise AssertionError('invalid Caddyfile admitted')
 adapter.restore(ready)
 assert json.loads(curl('guard.example.test','/healthz',True))['service']=='ironcurtain-local'
 text=ready['content'].replace('tls_server_name 127.0.0.1','tls_server_name attacker.example.test')
 publish(adapter.site,text.encode())
 adapter.reload()
 try: curl('guard.example.test','/healthz',True)
 except subprocess.CalledProcessError: pass
 else: raise AssertionError('wrong upstream identity was trusted')
 adapter.restore(ready)
 assert json.loads(curl('guard.example.test','/healthz',True))['ready'] is True
 cloud=SharedIngress.discover('cloud','cloud.example.test')
 cloud_before=cloud.snapshot()
 cloud.prepare('cloud.example.test',cloud_before)
 cloud.activate('cloud.example.test',generation,work/'runtime','127.0.0.1')
 assert json.loads(curl('cloud.example.test','/healthz',True))['service']=='xuanwu-admin'
 cloud.restore(cloud_before)
 assert json.loads(curl('guard.example.test','/healthz',True))['service']=='ironcurtain-local'
 adapter.restore(before)
 assert not adapter.site.exists()
print('Real Caddy challenge, TLS, fixed roles, trust failure and rollback passed')
PY
