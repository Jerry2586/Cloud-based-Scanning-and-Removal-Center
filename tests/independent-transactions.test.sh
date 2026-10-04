#!/usr/bin/env bash
# Real Linux filesystem recovery tests; Docker/systemd are explicitly simulated.
set -euo pipefail
umask 077
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[[ $EUID == 0 && $(uname -s) == Linux ]] || { echo 'Requires Linux root; service operations are simulated.' >&2; exit 1; }
for tool in jq tar realpath; do command -v "$tool" >/dev/null; done
WORK=$(mktemp -d /root/ironcurtain-transaction-test.XXXXXXXX)
cleanup() {
  [[ $WORK == /root/ironcurtain-transaction-test.* && $(dirname "$WORK") == /root && -d $WORK && ! -L $WORK ]] || return 1
  rm -rf -- "$WORK"
}
trap cleanup EXIT
source "$ROOT/scripts/lib/independent.sh"
source "$ROOT/scripts/lib/install-transaction.sh"
source "$ROOT/scripts/lib/management-transaction.sh"
# No actual service, container or production path is changed by these doubles.
docker() { [[ $1 == inspect ]] || return 1; echo "$CONTAINER_RUNNING"; }
systemctl() {
  case "$1" in
    is-active) [[ $AGENT_RUNNING == true ]] ;;
    is-enabled) [[ $AGENT_ENABLED == true ]] ;;
    stop) AGENT_RUNNING=false ;;
    start) AGENT_RUNNING=true ;;
    enable) AGENT_ENABLED=true ;;
    disable) [[ -f $AGENT_UNIT ]] || return 1; AGENT_ENABLED=false ;;
    daemon-reload) return 0 ;;
    *) return 1 ;;
  esac
}
ic_compose() {
  case "$1" in
    down) [[ $FAIL_DOWN == false ]] || return 1; CONTAINER_RUNNING=false ;;
    stop) CONTAINER_RUNNING=false ;;
    up) CONTAINER_RUNNING=true ;;
    *) return 1 ;;
  esac
}
ic_load() { IMAGE=fixture; }
ic_wait() { [[ $FAIL_HEALTH == false ]]; }
ic_agent_wait() { [[ $AGENT_RUNNING == true && $FAIL_HEALTH == false ]]; }
ic_scan_wait() { [[ $AGENT_RUNNING == true && $CONTAINER_RUNNING == true && $FAIL_SCAN == false ]]; }
number=0
fixture() {
  number=$((number+1)); ROLE=local
  BASE=$WORK/case-$number/base; CONF=$WORK/case-$number/config; DATA=$WORK/case-$number/data
  MENU=$WORK/case-$number/menu; AGENT_UNIT=$WORK/case-$number/agent.service
  CONTAINER=fixture; CONTAINER_RUNNING=true; AGENT_RUNNING=true; AGENT_ENABLED=true
  FAIL_DOWN=false; FAIL_HEALTH=false; FAIL_SCAN=false; IC_ADMIN_TX=''; IC_TX=''
  install -d -m 750 "$BASE/releases/1.0.0" "$CONF" "$DATA"
  printf '{"schema":1}\n' > "$BASE/install.json"; chmod 600 "$BASE/install.json"
  ln -s "$BASE/releases/1.0.0" "$BASE/current"
  printf old-config > "$CONF/value"; printf old-data > "$DATA/value"
  printf old-menu > "$MENU"; printf old-agent > "$AGENT_UNIT"
}
assert_old() { [[ $(cat "$CONF/value") == old-config ]]; }
pass() { echo "PASS $1"; }
fixture
install -d -m 700 "$CONF/exports" "$CONF/.admin.fixture"
printf encrypted-evidence > "$CONF/exports/node.icpair.pending"
ic_admin_begin profile
printf changed > "$CONF/value"
ic_admin_recover
assert_old
[[ $CONTAINER_RUNNING == true && $AGENT_RUNNING == true && ! -e $BASE/admin-transaction.json ]]
[[ -f $CONF/exports/node.icpair.pending && ! -e $CONF/.admin.fixture ]]
pass 'management restores config, services and evidence; ignores staging'
fixture
CONTAINER_RUNNING=false; AGENT_RUNNING=false
ic_admin_begin profile; printf changed > "$CONF/value"; ic_admin_recover
assert_old; [[ $CONTAINER_RUNNING == false && $AGENT_RUNNING == false ]]
pass 'management preserves stopped service state'
fixture
ic_admin_begin profile; printf changed > "$CONF/value"; FAIL_DOWN=true
if ic_admin_recover; then echo 'Expected compose down failure' >&2; exit 1; fi
[[ $(cat "$CONF/value") == changed && -f $BASE/admin-transaction.json ]]
FAIL_DOWN=false; ic_admin_recover; assert_old
pass 'failed disconnect leaves configuration untouched and supports retry'
fixture
ic_admin_begin profile; printf changed > "$CONF/value"; FAIL_HEALTH=true
if ic_admin_recover; then echo 'Expected health failure' >&2; exit 1; fi
[[ -f $BASE/admin-transaction.json ]]; assert_old
FAIL_HEALTH=false; ic_admin_recover; assert_old
pass 'management recovery keeps checkpoint until health succeeds'
fixture
ic_admin_begin profile; printf changed > "$CONF/value"
printf broken > "$IC_ADMIN_TX/config.tar"
if ic_admin_recover 2>/dev/null; then echo 'Expected corrupt archive rejection' >&2; exit 1; fi
[[ $(cat "$CONF/value") == changed && $CONTAINER_RUNNING == true && -f $BASE/admin-transaction.json ]]
pass 'corrupt archive never replaces live config'
fixture
ic_admin_begin profile; printf changed > "$CONF/value"; touch "$IC_ADMIN_TX/committed"
ic_admin_recover
[[ $(cat "$CONF/value") == changed && ! -e $BASE/admin-transaction.json ]]
pass 'committed operation survives interrupted checkpoint cleanup'
fixture
ic_tx_begin; ic_tx_mutating
printf changed > "$CONF/value"; printf changed > "$DATA/value"
printf changed > "$MENU"; printf changed > "$AGENT_UNIT"
ic_tx_recover
assert_old
[[ $(cat "$DATA/value") == old-data && $(cat "$MENU") == old-menu && $(cat "$AGENT_UNIT") == old-agent ]]
[[ $CONTAINER_RUNNING == true && $AGENT_RUNNING == true && $AGENT_ENABLED == true ]]
pass 'installation restores configuration, data, menu and agent'
fixture
ic_tx_begin; ic_tx_mutating; printf changed > "$CONF/value"
FAIL_SCAN=true
if ic_tx_recover; then echo 'Expected scanner channel failure' >&2; exit 1; fi
[[ -f $BASE/transaction.json ]]; assert_old
FAIL_SCAN=false; ic_tx_recover; assert_old
[[ ! -e $BASE/transaction.json ]]
pass 'installation recovery waits for restored scanner channel and supports retry'
fixture
CONTAINER_RUNNING=false; AGENT_RUNNING=false; AGENT_ENABLED=false
ic_tx_begin; ic_tx_mutating; printf changed > "$CONF/value"; ic_tx_recover
assert_old; [[ $CONTAINER_RUNNING == false && $AGENT_RUNNING == false && $AGENT_ENABLED == false ]]
pass 'installation preserves stopped and disabled state'
fixture
ic_tx_begin; ic_tx_mutating; printf changed > "$CONF/value"; FAIL_DOWN=true
if ic_tx_recover; then echo 'Expected install disconnect failure' >&2; exit 1; fi
[[ $(cat "$CONF/value") == changed && -f $BASE/transaction.json ]]
FAIL_DOWN=false; ic_tx_recover; assert_old
pass 'installation failed stop is retryable without file mutation'
fixture
ic_tx_begin; ic_tx_mutating; printf changed > "$CONF/value"; FAIL_HEALTH=true
if ic_tx_recover; then echo 'Expected install health failure' >&2; exit 1; fi
[[ -f $BASE/transaction.json ]]; FAIL_HEALTH=false; ic_tx_recover; assert_old
pass 'installation recovery remains pending on failed health'
fixture
# First install has no previous installation, menu or agent.
rm -f -- "$BASE/current" "$BASE/install.json" "$MENU" "$AGENT_UNIT"
CONTAINER_RUNNING=false; AGENT_RUNNING=false; AGENT_ENABLED=false
ic_tx_begin; ic_tx_mutating
printf changed > "$CONF/value"; printf changed > "$DATA/value"
printf candidate > "$BASE/install.json"; ln -s "$BASE/releases/1.0.0" "$BASE/current"
printf candidate > "$MENU"; printf candidate > "$AGENT_UNIT"
AGENT_ENABLED=true; AGENT_RUNNING=true; CONTAINER_RUNNING=true
ic_tx_recover; assert_old
[[ ! -e $BASE/install.json && ! -L $BASE/current && ! -e $MENU && ! -e $AGENT_UNIT && $AGENT_ENABLED == false && $AGENT_RUNNING == false ]]
pass 'failed first installation restores pre-install state'
fixture
ic_tx_begin
# Simulate crash after stopping old services, before mutation begins.
ic_tx_recover
assert_old; [[ $CONTAINER_RUNNING == true && $AGENT_RUNNING == true ]]
pass 'pre-mutation interruption restarts original services'
fixture
ic_tx_begin; ic_tx_mutating; printf changed > "$CONF/value"; touch "$IC_TX/committed"
ic_tx_recover
[[ $(cat "$CONF/value") == changed && ! -e $BASE/transaction.json ]]
pass 'committed installation is not rolled back'
fixture
jq -n --arg snapshot "$WORK" '{schema:1,role:"local",snapshot:$snapshot}' > "$BASE/admin-transaction.json"
chmod 600 "$BASE/admin-transaction.json"
if (ic_admin_recover) 2>/dev/null; then echo 'Expected escaped checkpoint rejection' >&2; exit 1; fi
assert_old
pass 'recovery rejects snapshot outside its role backup directory'
echo '14 Linux filesystem transaction checks passed; no real Docker/systemd acceptance claimed.'
