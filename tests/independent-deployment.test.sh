#!/usr/bin/env bash
# Runs REAL installation and Docker/systemd services only on a disposable CI VM.
set -euo pipefail
umask 077
[[ $EUID == 0 && $(uname -s) == Linux && ${IRONCURTAIN_ACCEPT_DISPOSABLE_RUNNER:-} == 1 ]] || { echo 'Requires an explicitly disposable Linux root runner.' >&2; exit 1; }
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
for path in /opt/ironcurtain /etc/ironcurtain /var/lib/ironcurtain /etc/systemd/system/ironcurtain-agent.service /usr/local/bin/ironcurtain /usr/local/bin/xuanwu; do
  [[ ! -e $path && ! -L $path ]] || { echo 'Independent installation already exists; test refuses to replace it.' >&2; exit 1; }
done
# Docker is a CI prerequisite; empty-host dependency provisioning is a separate matrix.
command -v docker >/dev/null || { echo 'Disposable runner prerequisite missing: Docker.' >&2; exit 1; }
systemctl start docker
docker info >/dev/null || { echo 'Disposable runner Docker daemon unavailable.' >&2; exit 1; }
docker compose version >/dev/null
docker buildx version >/dev/null
for container in ironcurtain-local ironcurtain-cloud; do
  ! docker inspect "$container" >/dev/null 2>&1 || { echo 'Test container already exists.' >&2; exit 1; }
done
# GitHub hosted runners keep /opt group-writable for tool caches. This test's
# explicit disposable-runner gate allows preparing the production trust boundary.
[[ -d /opt && ! -L /opt && $(realpath /opt) == /opt ]] || { echo 'Unsafe runner /opt path.' >&2; exit 1; }
chown root:root /opt
chmod 755 /opt
WORK=$(mktemp -d /opt/ironcurtain-deployment-test.XXXXXXXX)
# Keep installed files on this ephemeral runner for diagnostics. Runner teardown removes them.
install -d -m 750 "$WORK/source"
tar -C "$ROOT" --exclude=.git --exclude=.codex --exclude=dist --exclude='__pycache__' -cf - . | tar -C "$WORK/source" -xf -
SOURCE=$WORK/source
CLOUD_HOST=$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')
[[ $CLOUD_HOST =~ ^[0-9.]+$ ]] || { echo 'Docker bridge gateway unavailable' >&2; exit 1; }
bash "$SOURCE/scripts/install-independent.sh" --role cloud --host "$CLOUD_HOST" --bind "$CLOUD_HOST"
bash "$SOURCE/scripts/install-independent.sh" --role local --host 127.0.0.1 --bind 127.0.0.1
source "$SOURCE/scripts/lib/independent.sh"
ic_role cloud; ic_load
install -d -m 700 "$WORK/pair"
PAIR=$WORK/pair
ic_certificate "$PAIR" client node-ci clientAuth
install -m 600 "$CONF/ca.crt" "$PAIR/ca.crt"
openssl rand -hex 32 > "$PAIR/token"
jq -n --arg endpoint "https://$CLOUD_HOST:9443/" '{schema:"ironcurtain-cloud/v1",node_id:"node-ci",endpoint:$endpoint}' > "$PAIR/cloud.json"
cp "$CONF/runtime/config.json" "$PAIR/config.json"
IRONCURTAIN_CONTROL_WORK=$PAIR node "$SOURCE/scripts/control.js" register-node
install -m 640 -o root -g 10001 "$PAIR/config.next.json" "$CONF/runtime/config.json"
ic_compose restart; ic_wait
# Use real pairing pack seal/unseal and independent CA fingerprint, no printed secrets.
openssl rand -hex 24 > "$PAIR/password"
IRONCURTAIN_CONTROL_WORK=$PAIR node "$SOURCE/scripts/control.js" seal < "$PAIR/password"
node -e 'const fs=require("fs"),crypto=require("crypto");const p=process.argv[1];process.stdout.write(JSON.stringify({password:fs.readFileSync(p+"/password","utf8").trim(),fingerprint:new crypto.X509Certificate(fs.readFileSync(p+"/ca.crt")).fingerprint256}));' "$PAIR" |
  IRONCURTAIN_CONTROL_WORK=$PAIR node "$SOURCE/scripts/control.js" unseal
# Default Docker bridge nodes reach the cloud through the host bridge gateway.
# The certificate SAN and pairing endpoint match that address; TLS stays verified.
ic_role local; ic_load
mv "$PAIR/identity" "$CONF/runtime/cloud"
chown root:10001 "$CONF/runtime/cloud" "$CONF/runtime/cloud/"*; chmod 750 "$CONF/runtime/cloud"; chmod 640 "$CONF/runtime/cloud/"*
node "$SOURCE/tests/helpers/independent-deployment-probe.js"
bash "$SOURCE/scripts/install-independent.sh" --role local
bash "$SOURCE/scripts/install-independent.sh" --role cloud
before=$(sha256sum /etc/ironcurtain/local/runtime/panel-auth.json /etc/ironcurtain/cloud/ca.key)
node -e 'const fs=require("fs"),p=process.argv[1],v=JSON.parse(fs.readFileSync(p));v.version=v.version.split(".").map((n,i)=>i===2?String(Number(n)+1):n).join(".");fs.writeFileSync(p,JSON.stringify(v,null,2)+"\n");' "$SOURCE/package.json"
bash "$SOURCE/scripts/install-independent.sh" --role local
bash "$SOURCE/scripts/install-independent.sh" --role cloud
after=$(sha256sum /etc/ironcurtain/local/runtime/panel-auth.json /etc/ironcurtain/cloud/ca.key)
[[ $before == "$after" ]] || { echo 'Upgrade replaced existing identity.' >&2; exit 1; }
/usr/local/bin/ironcurtain doctor
/usr/local/bin/xuanwu doctor
node "$SOURCE/tests/helpers/independent-deployment-probe.js"
echo 'Real local/cloud Docker first installation, rerun and upgrade passed; identities preserved.'
