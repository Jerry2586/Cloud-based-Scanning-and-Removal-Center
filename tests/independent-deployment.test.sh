#!/usr/bin/env bash
# Runs REAL installation and Docker/systemd services only on a disposable CI VM.
set -euo pipefail
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
node "$SOURCE/tests/helpers/rule-deployment-fixture.js" "$SOURCE" "$WORK"
CLOUD_HOST=$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')
[[ $CLOUD_HOST =~ ^[0-9.]+$ ]] || { echo 'Docker bridge gateway unavailable' >&2; exit 1; }
bash "$SOURCE/scripts/install-independent.sh" --role cloud --host "$CLOUD_HOST" --bind "$CLOUD_HOST"
bash "$SOURCE/scripts/install-independent.sh" --role local --antivirus skip --host 127.0.0.1 --bind 127.0.0.1
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
  python3 - "$WORK/$entry-menu.log" "$entry" <<'PY'
import re, sys, unicodedata
with open(sys.argv[1], encoding='utf-8') as source:
    raw = source.read()
    assert '\x1b[1;34m' in raw
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', raw)
with open(sys.argv[1].replace('-menu.log', '-plain-menu.log'), encoding='utf-8') as source:
    plain = source.read()
assert '\x1b[' not in plain
assert text[text.index('╔'):text.index('请输入菜单编号（0 退出）')] == plain[plain.index('╔'):plain.index('请输入菜单编号（0 退出）')]
lines = text.splitlines()
items = [line for line in lines if re.match(r'^ *\d+\. ', line)]
expected = list(range(1, 28)) + [29, 31, 32, 33, 34, 0] if sys.argv[2] == 'tiemu' else list(range(1, 12)) + list(range(22, 31)) + [0]
assert [int(re.match(r'^ *(\d+)\.', line)[1]) for line in items] == expected
assert all(len(re.findall(r'\d+\. ', line)) == 1 for line in items)
assert '╔' in text and '╠' in text and '╚' in text
assert '安装目录：' in text
assert not re.search(r'"(?:engine|installed|updater|state)"\s*:', text)
for line in lines:
    if line.startswith('║'):
        width = sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1 for c in line)
        assert width == 60, (width, line)
if sys.argv[2] == 'tiemu':
    assert '病毒引擎：未就绪' in text
    assert '玄武连接：尚未配对' in text
else:
    assert '登记节点：0 个' in text
PY
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
source "$SOURCE/scripts/lib/independent.sh"
ic_role cloud; ic_load
# Register through the real cloud menu without choosing a password, then import
# the generated encrypted pack through the real local menu and verify live mTLS.
python3 "$SOURCE/tests/helpers/pairing-auto-password.py"
ic_role local; ic_load
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
# Build the actual six-asset signed package with the isolated CI publisher.
# The cloud imports through its real root menu; the local host pulls over mTLS.
install -d -m 700 "$WORK/program-assets"
bash "$SOURCE/scripts/package-release.sh" --source-dir "$SOURCE" --output-dir "$WORK/program-assets" --signing-key "$WORK/rules-publisher.key"
version=$(jq -er .version "$SOURCE/package.json")
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
/usr/local/bin/tiemu release-update
[[ $(jq -er .version /opt/ironcurtain/local/install.json) == "$version" ]]
[[ $(jq -er .antivirus /opt/ironcurtain/local/install.json) == skip ]]
[[ $(sha256sum /etc/ironcurtain/local/profile.json) == "$profile_before" ]]
[[ $(sha256sum /etc/ironcurtain/local/runtime/cloud/*) == "$cloud_identity_before" ]]
[[ $(sha256sum /etc/ironcurtain/local/rules.json /etc/ironcurtain/local/rules.highwater.json) == "$rules_before" ]]
IRONCURTAIN_EXPECT_RULE_SEQUENCE=1 IRONCURTAIN_EXPECT_RELEASE_VERSION="$version" node "$SOURCE/tests/helpers/independent-deployment-probe.js"
# Same signed cloud program can be re-downloaded and safely reused.
/usr/local/bin/tiemu release-update
bash "$SOURCE/scripts/install-independent.sh" --role cloud
after=$(sha256sum /etc/ironcurtain/local/runtime/panel-auth.json /etc/ironcurtain/cloud/ca.key)
[[ $before == "$after" ]] || { echo 'Upgrade replaced existing identity.' >&2; exit 1; }
! systemctl is-enabled --quiet ironcurtain-rules-sync.timer
! systemctl is-active --quiet ironcurtain-rules-sync.timer
systemctl enable --now ironcurtain-rules-sync.timer
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
/usr/local/bin/tiemu doctor
/usr/local/bin/xuanwu doctor
echo 'Real encrypted local/cloud recovery passed; current identity and revocation state retained.'
echo 'Real local/cloud Docker first installation, rerun and upgrade passed; identities preserved.'
