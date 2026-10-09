#!/usr/bin/env bash
# Runs REAL installation and Docker/systemd services only on a disposable CI VM.
set -euo pipefail
# Report only the failing line, never trace requests, tokens or identity files.
trap 'status=$?; if [[ $- == *e* ]]; then printf "Deployment gate failed at line %s (status %s)\n" "$LINENO" "$status" >&2; fi' ERR
umask 077
[[ $EUID == 0 && $(uname -s) == Linux && ${IRONCURTAIN_ACCEPT_DISPOSABLE_RUNNER:-} == 1 ]] || { echo 'Requires an explicitly disposable Linux root runner.' >&2; exit 1; }
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
for path in /opt/ironcurtain /etc/ironcurtain /var/lib/ironcurtain /etc/systemd/system/ironcurtain-agent.service /etc/systemd/system/ironcurtain-rules-sync.service /etc/systemd/system/ironcurtain-rules-sync.timer /usr/local/bin/ironcurtain /usr/local/bin/tiemu /usr/local/bin/xuanwu; do
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
# A source checkout may contain local bytecode; installation must omit it.
install -d -m 777 "$SOURCE/src/host/__pycache__"
printf 'not a release input\n' > "$SOURCE/src/host/__pycache__/fixture.pyc"
node "$SOURCE/tests/helpers/rule-deployment-fixture.js" "$SOURCE" "$WORK"
# First-install acceptance must run the exact signed payload, not the richer checkout.
# A checkout-only gate previously missed a Python entry omitted by the packager.
install -d -m 700 "$WORK/first-install-assets" "$WORK/first-install-source"
bash "$SOURCE/scripts/package-release.sh" --source-dir "$SOURCE" --output-dir "$WORK/first-install-assets" --signing-key "$WORK/rules-publisher.key"
node "$SOURCE/scripts/verify-release.js" --dir "$WORK/first-install-assets" --public-key "$SOURCE/release-public.pem"
version=$(jq -er .version "$SOURCE/package.json")
tar -xzf "$WORK/first-install-assets/APPGOG-Cloud-Security-Center-$version.tar.gz" -C "$WORK/first-install-source"
INSTALL_SOURCE=$WORK/first-install-source
CLOUD_HOST=$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')
[[ $CLOUD_HOST =~ ^[0-9.]+$ ]] || { echo 'Docker bridge gateway unavailable' >&2; exit 1; }
bash "$INSTALL_SOURCE/scripts/install-independent.sh" --role cloud --host "$CLOUD_HOST" --bind "$CLOUD_HOST"
bash "$INSTALL_SOURCE/scripts/install-independent.sh" --role local --antivirus skip --host 127.0.0.1 --bind 127.0.0.1
python3 "$SOURCE/tests/helpers/operations-deployment-probe.py" policy
python3 "$SOURCE/tests/helpers/operations-deployment-probe.py" scope
# Real non-root cloud container storage must survive a container restart.
node "$SOURCE/tests/helpers/cloud-deployment-probe.js" seed "$CLOUD_HOST" "$WORK/cloud-control-fixture.json"
[[ $(stat -c '%u:%g:%a' /var/lib/ironcurtain/cloud/runtime/control.sqlite) == 10001:10001:600 ]]
docker restart ironcurtain-cloud >/dev/null
cloud_ready=0
for attempt in $(seq 1 60); do
  if curl --noproxy '*' --fail --silent --max-time 5 --cacert /etc/ironcurtain/cloud/runtime/panel.crt "https://$CLOUD_HOST:8791/healthz" >/dev/null; then cloud_ready=1; break; fi
  sleep 1
done
[[ $cloud_ready == 1 ]] || { echo 'Cloud admin did not recover after restart.' >&2; exit 1; }
node "$SOURCE/tests/helpers/cloud-deployment-probe.js" verify "$CLOUD_HOST" "$WORK/cloud-control-fixture.json"
# Copied runner-owned source must become root-controlled before trust calibration.
for role in local cloud; do
  release=$(readlink -f "/opt/ironcurtain/$role/current")
  unsafe=$(find "$release" \( ! -user root -o ! -group root -o -perm /022 \) -print -quit)
  [[ -z $unsafe ]] || { stat -c 'Untrusted installed code: %u:%g:%a type=%F path=%n target=%N' "$unsafe" >&2; exit 1; }
done
# Source cache must stay absent across root agent startup and fixed release checks.
release=$(readlink -f /opt/ironcurtain/local/current)
[[ -z $(find "$release/src/host" -name __pycache__ -print -quit) ]]
for action in check update; do
  [[ $(systemctl show "ironcurtain-panel-$action.service" -p ExecStart --value) == *"python3 -B "* ]]
done
[[ $(systemctl show ironcurtain-agent.service -p ExecStart --value) == *"python3 -B "* ]]
python3 "$SOURCE/tests/helpers/engine-maintenance-deployment-probe.py" "$release"
# Cloud has its own bounded update bridge and signed worker; no scan socket or Docker API.
systemctl is-active --quiet ironcurtain-update-cloud-control.service
[[ $(systemctl show ironcurtain-update-cloud-control.service -p ProtectSystem --value) == strict ]]
for action in check update; do
  [[ $(systemctl show "ironcurtain-panel-cloud-$action.service" -p ExecStart --value) == *"updates.py $action --role cloud"* ]]
done
setpriv --reuid=10001 --regid=10001 --clear-groups curl -q --noproxy '*' --fail --silent --unix-socket /run/ironcurtain-update-cloud/control.sock http://localhost/update-status | jq -e --arg version "$version" ' .installed_version == $version' >/dev/null
# Signed manager executables survive root-owned install normalization and are runnable.
manager_dir=$(readlink -f /opt/ironcurtain/local/current)/src/manager/bin
for arch in amd64 arm64; do
  mode=$(stat -c '%u:%g:%a' "$manager_dir/ironcurtain-manager-linux-$arch")
  [[ $mode == 0:0:755 ]] || { printf 'Manager mode mismatch for %s: %s\n' "$arch" "$mode" >&2; exit 1; }
done
case "$(uname -m)" in x86_64) manager_arch=amd64 ;; aarch64) manager_arch=arm64 ;; *) exit 1 ;; esac
set +e
printf '{}\n' | "$manager_dir/ironcurtain-manager-linux-$manager_arch" > "$WORK/manager-stdout" 2> "$WORK/manager-stderr"
manager_status=$?
set -e
[[ $manager_status == 2 && ! -s $WORK/manager-stdout ]]
grep -qx 'invalid managed request' "$WORK/manager-stderr"
[[ $(systemctl show ironcurtain-agent.service -p KillMode --value) == control-group ]]
# Actual fixed root services exist, but a fresh IP installation must not claim 443.
for role in local cloud; do
  systemctl is-active --quiet "ironcurtain-domain-$role-control.service"
  systemctl is-active --quiet "ironcurtain-domain-$role-renew.timer"
  ! systemctl is-active --quiet "ironcurtain-domain-$role-gateway.socket"
  [[ $(systemctl show "ironcurtain-domain-$role-apply.service" -p ProtectSystem --value) == strict ]]
  [[ $(systemctl show "ironcurtain-domain-$role-renew.service" -p ProtectSystem --value) == strict ]]
  systemctl is-active --quiet "ironcurtain-account-$role-control.service"
  [[ $(systemctl show "ironcurtain-account-$role-control.service" -p ProtectSystem --value) == strict ]]
  setpriv --reuid=10001 --regid=10001 --clear-groups curl -q --noproxy '*' --fail --silent --unix-socket "/run/ironcurtain-account-$role/control.sock" http://localhost/account | jq -e ' .ready == true' >/dev/null
  command -v certbot
  # Drive the real Unix controller as the exact non-root panel identity.
  setpriv --reuid=10001 --regid=10001 --clear-groups python3 - "$role" <<'PY'
import http.client, json, socket, sys, time
address = '/run/ironcurtain-domain-' + sys.argv[1] + '/control.sock'
for _ in range(40):
    try:
        client = socket.socket(socket.AF_UNIX)
        client.settimeout(5)
        client.connect(address)
        break
    except (FileNotFoundError, ConnectionRefusedError):
        client.close()
        time.sleep(0.25)
else:
    raise RuntimeError('domain controller socket unavailable')
connection = http.client.HTTPConnection('localhost', timeout=5)
connection.sock = client
connection.request('GET', '/domain')
response = connection.getresponse()
assert response.status == 200, response.status
reply = json.loads(response.read())
assert reply['state'] == 'idle', reply
connection.close()
PY
  # Real systemd socket passthrough; trust only the fixture's existing IP cert.
  systemctl start "ironcurtain-domain-$role-gateway.socket"
  host=127.0.0.1; port=8790; service=ironcurtain-local
  if [[ $role == cloud ]]; then host=$CLOUD_HOST; port=8791; service=xuanwu-admin; fi
  curl --noproxy '*' --fail --silent --show-error --max-time 15 --cacert "/etc/ironcurtain/$role/runtime/panel.crt" --resolve "$host:443:127.0.0.1" -H "Host: $host:$port" "https://$host:443/healthz" | jq -e --arg service "$service" '.service == $service and .ready == true'
  systemctl stop "ironcurtain-domain-$role-gateway.socket" "ironcurtain-domain-$role-gateway.service"
done
# Verify both real workers reject unrelated port owners without modifying them.
python3 "$SOURCE/tests/domain-entry-conflicts.test.py"
# Conflict probes must leave both real services healthy, independently of menu rendering.
for role in local cloud; do
  source "$SOURCE/scripts/lib/independent.sh"
  ic_role "$role"; ic_load
  ic_wait || {
    docker inspect --format '{{json .State.Health}}' "$CONTAINER" >&2
    echo "$role: container failed to recover after conflict probes" >&2; exit 1
  }
done
# Both role menus must open in a real terminal; the legacy entry still works.
for entry in tiemu ironcurtain xuanwu; do
  [[ -f /usr/local/bin/$entry && ! -L /usr/local/bin/$entry && $(stat -c '%a:%u:%h' /usr/local/bin/$entry) == 755:0:1 ]]
done
/usr/local/bin/ironcurtain status > "$WORK/legacy-status.log"
/usr/local/bin/tiemu status > "$WORK/tiemu-status.log"
[[ $(cat "$WORK/legacy-status.log") == "$(cat "$WORK/tiemu-status.log")" ]]
for entry in tiemu xuanwu; do
  printf '0\n' | TERM=xterm timeout 60 script -q -e -c "/usr/local/bin/$entry" "$WORK/$entry-menu.log"
  grep -q 'Linux 管理菜单' "$WORK/$entry-menu.log"
  grep -q "打开菜单：sudo $entry" "$WORK/$entry-menu.log"
  grep -q "更新程序：sudo $entry update" "$WORK/$entry-menu.log"
  grep -q '请输入菜单编号（0 退出）' "$WORK/$entry-menu.log"
  printf '0\n' | NO_COLOR=1 TERM=xterm timeout 60 script -q -e -c "/usr/local/bin/$entry" "$WORK/$entry-plain-menu.log" >/dev/null
  python3 "$SOURCE/tests/helpers/menu-transcript.py" "$WORK/$entry-menu.log" "$entry"
done
# A layout comparison never substitutes for convergence of both real health probes.
for role in local cloud; do
  ic_role "$role"; ic_load
  ic_wait || {
    docker inspect --format '{{json .State.Health}}' "$CONTAINER" >&2
    echo "$role: container failed the post-menu health gate" >&2; exit 1
  }
done
# Do not send acknowledgement until the real PTY proves results stay on screen.
python3 "$SOURCE/tests/helpers/menu-result-input.py"
systemctl is-enabled --quiet ironcurtain-rules-sync.timer
systemctl is-active --quiet ironcurtain-rules-sync.timer
[[ $(systemctl show ironcurtain-rules-sync.service -p CapabilityBoundingSet --value) == '' ]]
[[ $(systemctl show ironcurtain-rules-sync.service -p PrivateDevices --value) == yes ]]
systemctl start ironcurtain-rules-sync.service
# Unpaired service must succeed without inventing installed rules.
[[ ! -e /etc/ironcurtain/local/rules.json ]]
IRONCURTAIN_EXPECT_UNPAIRED=1 node "$SOURCE/tests/helpers/independent-deployment-probe.js"
source "$SOURCE/scripts/lib/independent.sh"
ic_role cloud; ic_load
# Register through the real cloud menu without choosing a password, then import
# the generated encrypted pack through the real local menu and verify live mTLS.
python3 "$SOURCE/tests/helpers/pairing-auto-password.py"
ic_role local; ic_load
systemctl is-enabled --quiet ironcurtain-panel-check.timer
systemctl is-active --quiet ironcurtain-panel-check.timer
[[ $(systemctl show ironcurtain-panel-update.service -p KillMode --value) == control-group ]]
[[ $(systemctl show ironcurtain-panel-update.service -p TimeoutStartUSec --value) == 32min ]]
IRONCURTAIN_CHECK_PANEL_UPDATE=1 node "$SOURCE/tests/helpers/independent-deployment-probe.js"
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
bash "$INSTALL_SOURCE/scripts/install-independent.sh" --role local --antivirus skip
bash "$INSTALL_SOURCE/scripts/install-independent.sh" --role cloud
systemctl disable --now ironcurtain-rules-sync.timer
systemctl disable --now ironcurtain-panel-check.timer
before=$(sha256sum /etc/ironcurtain/local/runtime/panel-auth.json /etc/ironcurtain/cloud/ca.key)
node -e 'const fs=require("fs"),p=process.argv[1],v=JSON.parse(fs.readFileSync(p));v.version=v.version.split(".").map((n,i)=>i===2?String(Number(n)+1):n).join(".");fs.writeFileSync(p,JSON.stringify(v,null,2)+"\n");' "$SOURCE/package.json"
# Build the actual six-asset signed package with the isolated CI publisher.
# The cloud imports through its real root menu; the local host pulls over mTLS.
install -d -m 700 "$WORK/program-assets"
bash "$SOURCE/scripts/package-release.sh" --source-dir "$SOURCE" --output-dir "$WORK/program-assets" --signing-key "$WORK/rules-publisher.key"
version=$(jq -er .version "$SOURCE/package.json")
install -d -m 700 "$WORK/upgrade-source"
node "$SOURCE/scripts/verify-release.js" --dir "$WORK/program-assets" --public-key "$SOURCE/release-public.pem"
tar -xzf "$WORK/program-assets/APPGOG-Cloud-Security-Center-$version.tar.gz" -C "$WORK/upgrade-source"
UPGRADE_SOURCE=$WORK/upgrade-source
# Report bounded public attachment metadata when the real importer rejects it.
stat -c 'Release attachment %n: uid=%u gid=%g mode=%a links=%h bytes=%s' "$WORK/program-assets/"*
python3 "$SOURCE/tests/helpers/release-menu-input.py" "$WORK/program-assets"
/usr/local/bin/xuanwu release-status | jq -e --arg version "$version" '.state == "ready" and .version == $version' >/dev/null
# Cache is read-only in the live non-root cloud container.
[[ $(docker inspect ironcurtain-cloud --format '{{.Config.User}}') == 10001:10001 ]]
[[ $(docker inspect ironcurtain-cloud --format '{{range .Mounts}}{{if eq .Destination "/var/lib/xuanwu-releases"}}{{.RW}}{{end}}{{end}}') == false ]]
profile_before=$(sha256sum /etc/ironcurtain/local/profile.json)
cloud_identity_before=$(sha256sum /etc/ironcurtain/local/runtime/cloud/*)
rules_before=$(sha256sum /etc/ironcurtain/local/rules.json /etc/ironcurtain/local/rules.highwater.json)
# Refuse a damaged downloaded RUN while retaining installed identity and version.
active_run="/var/lib/ironcurtain/cloud/releases/$version/APPGOG-Cloud-Security-Center-$version.run"
cp "$active_run" "$WORK/program-valid.run"
printf damage >> "$active_run"
installed_before=$(sha256sum /opt/ironcurtain/local/install.json)
if /usr/local/bin/tiemu release-update; then echo 'Damaged cloud program accepted' >&2; exit 1; fi
[[ $(sha256sum /opt/ironcurtain/local/install.json) == "$installed_before" ]]
install -m 640 -o root -g 10001 "$WORK/program-valid.run" "$active_run"
# Exercise preservation of an already activated gateway across a real signed upgrade.
systemctl enable --now ironcurtain-domain-local-gateway.socket
# Upgrading must recover an inactive required controller, while preserving timer preferences.
systemctl stop ironcurtain-account-local-control.service
systemctl stop ironcurtain-domain-local-control.service
systemctl stop ironcurtain-operations-local-control.service
systemctl disable --now ironcurtain-domain-local-renew.timer
/usr/local/bin/tiemu release-update
python3 "$SOURCE/tests/helpers/engine-maintenance-deployment-probe.py" /opt/ironcurtain/local/current ready
systemctl is-active --quiet ironcurtain-domain-local-control.service
systemctl is-active --quiet ironcurtain-account-local-control.service
python3 "$SOURCE/tests/helpers/operations-deployment-probe.py" ready
! systemctl is-active --quiet ironcurtain-domain-local-renew.timer
! systemctl is-enabled --quiet ironcurtain-domain-local-renew.timer
systemctl enable --now ironcurtain-domain-local-renew.timer
systemctl is-enabled --quiet ironcurtain-domain-local-gateway.socket
systemctl is-active --quiet ironcurtain-domain-local-gateway.socket
curl --noproxy '*' --fail --silent --show-error --max-time 15 --cacert /etc/ironcurtain/local/runtime/panel.crt -H 'Host: 127.0.0.1:8790' https://127.0.0.1:443/healthz | jq -e '.service == "ironcurtain-local" and .ready == true'
systemctl disable --now ironcurtain-domain-local-gateway.socket
systemctl stop ironcurtain-domain-local-gateway.service
[[ $(jq -er .version /opt/ironcurtain/local/install.json) == "$version" ]]
[[ $(jq -er .antivirus /opt/ironcurtain/local/install.json) == skip ]]
[[ $(sha256sum /etc/ironcurtain/local/profile.json) == "$profile_before" ]]
[[ $(sha256sum /etc/ironcurtain/local/runtime/cloud/*) == "$cloud_identity_before" ]]
[[ $(sha256sum /etc/ironcurtain/local/rules.json /etc/ironcurtain/local/rules.highwater.json) == "$rules_before" ]]
IRONCURTAIN_EXPECT_RULE_SEQUENCE=1 IRONCURTAIN_EXPECT_RELEASE_VERSION="$version" node "$SOURCE/tests/helpers/independent-deployment-probe.js"
# Same signed cloud program can be re-downloaded and safely reused.
/usr/local/bin/tiemu release-update
systemctl stop ironcurtain-account-cloud-control.service
systemctl stop ironcurtain-domain-cloud-control.service
bash "$UPGRADE_SOURCE/scripts/install-independent.sh" --role cloud
systemctl is-active --quiet ironcurtain-domain-cloud-control.service
systemctl is-active --quiet ironcurtain-account-cloud-control.service
after=$(sha256sum /etc/ironcurtain/local/runtime/panel-auth.json /etc/ironcurtain/cloud/ca.key)
[[ $before == "$after" ]] || { echo 'Upgrade replaced existing identity.' >&2; exit 1; }
! systemctl is-enabled --quiet ironcurtain-rules-sync.timer
! systemctl is-active --quiet ironcurtain-rules-sync.timer
! systemctl is-enabled --quiet ironcurtain-panel-check.timer
! systemctl is-active --quiet ironcurtain-panel-check.timer
systemctl enable --now ironcurtain-rules-sync.timer
systemctl enable --now ironcurtain-panel-check.timer
/usr/local/bin/tiemu doctor
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
    systemctl is-enabled --quiet ironcurtain-panel-check.timer
    systemctl is-active --quiet ironcurtain-panel-check.timer
    ic_scan_wait
    python3 "$SOURCE/tests/helpers/engine-maintenance-deployment-probe.py" /opt/ironcurtain/local/current ready
    python3 "$SOURCE/tests/helpers/operations-deployment-probe.py" ready
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
/usr/local/bin/tiemu doctor
/usr/local/bin/xuanwu doctor
for role in local cloud; do
  systemctl is-active --quiet "ironcurtain-account-$role-control.service"
  systemctl is-active --quiet "ironcurtain-domain-$role-control.service"
  setpriv --reuid=10001 --regid=10001 --clear-groups curl -q --noproxy '*' --fail --silent --unix-socket "/run/ironcurtain-account-$role/control.sock" http://localhost/account | jq -e ' .ready == true' >/dev/null
done
echo 'Real encrypted local/cloud recovery passed; current identity and revocation state retained.'
for role in local cloud; do
  release=$(readlink -f "/opt/ironcurtain/$role/current")
  [[ -z $(find "$release/src/host" -name __pycache__ -print -quit) ]]
  unsafe=$(find "$release" \( ! -user root -o ! -group root -o -perm /022 \) -print -quit)
  [[ -z $unsafe ]] || { stat -c 'Untrusted installed code: %u:%g:%a type=%F path=%n target=%N' "$unsafe" >&2; exit 1; }
done
python3 "$SOURCE/tests/helpers/account-password.py" "$CLOUD_HOST"
echo 'Real local/cloud Docker first installation, rerun and upgrade passed; identities preserved.'
