#!/usr/bin/env bash
# Runs REAL installation and Docker/systemd services only on a disposable CI VM.
set -euo pipefail
umask 077
[[ $EUID == 0 && $(uname -s) == Linux && ${IRONCURTAIN_ACCEPT_DISPOSABLE_RUNNER:-} == 1 ]] || { echo 'Requires an explicitly disposable Linux root runner.' >&2; exit 1; }
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
for path in /opt/ironcurtain /etc/ironcurtain /var/lib/ironcurtain /etc/systemd/system/ironcurtain-agent.service /etc/systemd/system/ironcurtain-rules-sync.service /etc/systemd/system/ironcurtain-rules-sync.timer /usr/local/bin/ironcurtain /usr/local/bin/xuanwu; do
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
for directory in /opt /usr /usr/local /usr/local/bin; do
  [[ -d $directory && ! -L $directory && $(realpath "$directory") == "$directory" ]] || { echo 'Unsafe runner installation ancestor.' >&2; exit 1; }
  chown root:root "$directory"
  chmod 755 "$directory"
done
WORK=$(mktemp -d /opt/ironcurtain-deployment-test.XXXXXXXX)
# Keep installed files on this ephemeral runner for diagnostics. Runner teardown removes them.
install -d -m 750 "$WORK/source"
tar -C "$ROOT" --exclude=.git --exclude=.codex --exclude=dist --exclude='__pycache__' -cf - . | tar -C "$WORK/source" -xf -
SOURCE=$WORK/source
node "$SOURCE/tests/helpers/rule-deployment-fixture.js" "$SOURCE" "$WORK"
CLOUD_HOST=$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')
[[ $CLOUD_HOST =~ ^[0-9.]+$ ]] || { echo 'Docker bridge gateway unavailable' >&2; exit 1; }
bash "$SOURCE/scripts/install-independent.sh" --role cloud --host "$CLOUD_HOST" --bind "$CLOUD_HOST"
bash "$SOURCE/scripts/install-independent.sh" --role local --antivirus skip --host 127.0.0.1 --bind 127.0.0.1
systemctl is-enabled --quiet ironcurtain-rules-sync.timer
systemctl is-active --quiet ironcurtain-rules-sync.timer
[[ $(systemctl show ironcurtain-rules-sync.service -p CapabilityBoundingSet --value) == '' ]]
[[ $(systemctl show ironcurtain-rules-sync.service -p PrivateDevices --value) == yes ]]
systemctl start ironcurtain-rules-sync.service
# Unpaired service must succeed without inventing installed rules.
[[ ! -e /etc/ironcurtain/local/rules.json ]]
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
# Exercise real cloud publication, authenticated native pull and real file-byte hits.
python3 /opt/ironcurtain/cloud/current/scripts/rules-client.py cloud import "$WORK/signed-rules-1.json"
# An installation lock must postpone the fixed service without activating rules.
(
  exec 9>/run/lock/ironcurtain-local.lock
  flock -n 9
  systemctl start ironcurtain-rules-sync.service
  [[ ! -e /etc/ironcurtain/local/rules.json ]]
)
# Unresolved transaction fails closed; no rule file is written.
printf '{}\n' > /opt/ironcurtain/local/admin-transaction.json
if systemctl start ironcurtain-rules-sync.service; then echo 'Unresolved transaction accepted' >&2; exit 1; fi
[[ ! -e /etc/ironcurtain/local/rules.json ]]
rm -f /opt/ironcurtain/local/admin-transaction.json
systemctl reset-failed ironcurtain-rules-sync.service
systemctl start ironcurtain-rules-sync.service
python3 /opt/ironcurtain/local/current/scripts/rules-client.py local status | jq -e '.state == "ready" and .sequence == 1' >/dev/null
jq '.business_roots=["/srv/ironcurtain-rule-ci"]' "$CONF/profile.json" > "$WORK/profile-rules.json"
install -m 600 "$WORK/profile-rules.json" "$CONF/profile.json"
systemctl restart ironcurtain-agent.service
ic_scan_wait
IRONCURTAIN_EXPECT_RULE_SEQUENCE=1 node "$SOURCE/tests/helpers/independent-deployment-probe.js"
# Agent restarts must preserve the directory inode bound into the web container.
[[ $(stat -c '%a:%u:%g' /run/ironcurtain) == 750:0:10001 ]]
runtime_inode=$(stat -c '%d:%i' /run/ironcurtain)
systemctl stop ironcurtain-agent.service
[[ $(stat -c '%d:%i' /run/ironcurtain) == "$runtime_inode" ]]
systemctl start ironcurtain-agent.service
ic_scan_wait
[[ $(stat -c '%d:%i' /run/ironcurtain) == "$runtime_inode" ]]
node "$SOURCE/tests/helpers/independent-deployment-probe.js"
bash "$SOURCE/scripts/install-independent.sh" --role local --antivirus skip
bash "$SOURCE/scripts/install-independent.sh" --role cloud
systemctl disable --now ironcurtain-rules-sync.timer
before=$(sha256sum /etc/ironcurtain/local/runtime/panel-auth.json /etc/ironcurtain/cloud/ca.key)
node -e 'const fs=require("fs"),p=process.argv[1],v=JSON.parse(fs.readFileSync(p));v.version=v.version.split(".").map((n,i)=>i===2?String(Number(n)+1):n).join(".");fs.writeFileSync(p,JSON.stringify(v,null,2)+"\n");' "$SOURCE/package.json"
bash "$SOURCE/scripts/install-independent.sh" --role local --antivirus skip
bash "$SOURCE/scripts/install-independent.sh" --role cloud
after=$(sha256sum /etc/ironcurtain/local/runtime/panel-auth.json /etc/ironcurtain/cloud/ca.key)
[[ $before == "$after" ]] || { echo 'Upgrade replaced existing identity.' >&2; exit 1; }
! systemctl is-enabled --quiet ironcurtain-rules-sync.timer
! systemctl is-active --quiet ironcurtain-rules-sync.timer
systemctl enable --now ironcurtain-rules-sync.timer
/usr/local/bin/ironcurtain doctor
/usr/local/bin/xuanwu doctor
node "$SOURCE/tests/helpers/independent-deployment-probe.js"
# Authenticated same-host recovery uses the REAL role containers and root agent.
# Other website files and credentials are never touched by the backup mechanism.
for recovery_role in local cloud; do
  ic_role "$recovery_role"; ic_load
  printf before-recovery > "$DATA/runtime/recovery-fixture"; chmod 600 "$DATA/runtime/recovery-fixture"
  identity_before=$(sha256sum "$CONF/runtime/"*.crt)
  bash "$SOURCE/scripts/independent-backup.sh" "$ROLE" backup > "$WORK/$ROLE-recovery.log"
  package=$(find "$BASE/backups" -name '*.icbackup' -type f | sort | tail -n 1)
  [[ -n $package ]]
  bash "$SOURCE/scripts/independent-backup.sh" "$ROLE" verify-backup "$package"
  printf after-backup > "$DATA/runtime/recovery-fixture"
  # Snapshot sequence 1, then activate 2: ordinary recovery must preserve the live
  # signed rule and independent high-water mark, including cloud distribution.
  if [[ $ROLE == local ]]; then
    python3 /opt/ironcurtain/cloud/current/scripts/rules-client.py cloud import "$WORK/signed-rules-2.json"
    systemctl start ironcurtain-rules-sync.service
    live_rules="$CONF"
  else
    live_rules="$CONF/runtime"
  fi
  rules_before=$(sha256sum "$live_rules/rules.json" "$live_rules/rules.highwater.json")
  if [[ $ROLE == cloud ]]; then
    # Revoke AFTER snapshot. Restoring the old archive must not restore this identity.
    jq 'del(.nodes["node-ci"])' "$CONF/runtime/config.json" > "$WORK/config-revoked.json"
    install -m 640 -o root -g 10001 "$WORK/config-revoked.json" "$CONF/runtime/config.json"
  fi
  bash "$SOURCE/scripts/independent-backup.sh" "$ROLE" restore-backup "$package" SAME-HOST-RESTORE
  [[ $(cat "$DATA/runtime/recovery-fixture") == before-recovery ]]
  [[ $(sha256sum "$CONF/runtime/"*.crt) == "$identity_before" ]]
  [[ $(sha256sum "$live_rules/rules.json" "$live_rules/rules.highwater.json") == "$rules_before" ]]
  python3 "$BASE/current/scripts/rules-client.py" "$ROLE" status | jq -e '.state == "ready" and .sequence == 2' >/dev/null
  ic_healthy
  if [[ $ROLE == local ]]; then
    systemctl is-enabled --quiet ironcurtain-rules-sync.timer
    systemctl is-active --quiet ironcurtain-rules-sync.timer
    ic_scan_wait
    IRONCURTAIN_EXPECT_RULE_SEQUENCE=2 node "$SOURCE/tests/helpers/independent-deployment-probe.js"
  fi
  if [[ $ROLE == cloud ]]; then jq -e '.nodes | has("node-ci") | not' "$CONF/runtime/config.json" >/dev/null; fi
  cp "$package" "$WORK/$ROLE-corrupt.icbackup"
  printf corrupt >> "$WORK/$ROLE-corrupt.icbackup"; chmod 600 "$WORK/$ROLE-corrupt.icbackup"
  if bash "$SOURCE/scripts/independent-backup.sh" "$ROLE" restore-backup "$WORK/$ROLE-corrupt.icbackup" SAME-HOST-RESTORE; then
    echo 'Corrupt archive was accepted' >&2; exit 1
  fi
  [[ $(cat "$DATA/runtime/recovery-fixture") == before-recovery ]]; ic_healthy
  [[ ! -e $BASE/transaction.json ]]
done
/usr/local/bin/ironcurtain doctor
/usr/local/bin/xuanwu doctor
echo 'Real encrypted local/cloud recovery passed; current identity and revocation state retained.'
echo 'Real local/cloud Docker first installation, rerun and upgrade passed; identities preserved.'
