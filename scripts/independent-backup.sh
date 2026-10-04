#!/usr/bin/env bash
# Independent, same-host/same-version recovery. Only root's Linux menu can invoke it.
set -euo pipefail
umask 077
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/scripts/lib/independent.sh"
source "$ROOT/scripts/lib/install-transaction.sh"
source "$ROOT/scripts/lib/management-transaction.sh"
[[ $EUID == 0 ]] || ic_fail '请用 sudo 运行'
ROLE=${1:?角色缺失}; ACTION=${2:?动作缺失}; INPUT=${3:-}; CONFIRM=${4:-}
ic_role "$ROLE"
MENU=/usr/local/bin/ironcurtain
[[ $ROLE != cloud ]] || MENU=/usr/local/bin/xuanwu
AGENT_UNIT=/etc/systemd/system/ironcurtain-agent.service
exec 9>"/run/lock/ironcurtain-$ROLE.lock"
flock -n 9 || ic_fail '安装或管理操作正在运行'
ic_tx_recover
ic_load
ic_admin_recover
KEY=$BASE/recovery.key
STAGE='' IC_TX=''
cleanup() {
  local result=$?
  trap - EXIT INT TERM
  if [[ -e $BASE/transaction.json || -L $BASE/transaction.json ]]; then
    ic_tx_recover || { echo '恢复未完成，请重复安装命令恢复；保留事务记录。' >&2; result=1; }
  fi
  # Private work directories are retained for diagnostics; never erase a displaced tree.
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ $ACTION == backup && ! -e $KEY && ! -L $KEY ]]; then
  ic_check_dir "$BASE"
  KEY_PENDING=$(mktemp "$BASE/.recovery-key.XXXXXXXX")
  openssl rand 64 > "$KEY_PENDING"
  chmod 600 "$KEY_PENDING"
  mv -n -- "$KEY_PENDING" "$KEY"
fi
ic_private_file "$KEY"
args=(--key "$KEY" --install "$BASE/install.json" --role "$ROLE" --machine /etc/machine-id)
archive() { python3 "$ROOT/scripts/recovery-archive.py" "$@" "${args[@]}"; }
case "$ACTION" in
  backup)
    [[ -z $INPUT ]] || ic_fail '备份动作不接受额外参数'
    ic_tx_begin  # records original running state and quiesces both writers
    ic_trusted_dir "$BASE/backups"
    STAGE=$(mktemp -d "$BASE/backups/recovery.XXXXXXXX"); chmod 700 "$STAGE"
    OUTPUT=$STAGE/$ROLE-$(date -u +%Y%m%dT%H%M%SZ).icbackup
    archive create --snapshot "$IC_TX" --output "$OUTPUT"
    archive verify --backup "$OUTPUT"
    ic_tx_recover  # no mutation marker: restart exactly the original services
    printf '加密恢复包：%s\n独立恢复密钥：%s\n' "$OUTPUT" "$KEY"
    echo '请通过可信通道分别保存包和密钥到异地；只放在本机不具备异地容灾能力。'
    ;;
  verify-backup|restore-backup)
    [[ $INPUT == /* && $(realpath -m -- "$INPUT") == "$INPUT" ]] || ic_fail '恢复包必须为规范绝对路径'
    ic_check_dir "$(dirname -- "$INPUT")"
    ic_private_file "$INPUT"
    if [[ $ACTION == verify-backup ]]; then archive verify --backup "$INPUT"; exit; fi
    [[ $CONFIRM == SAME-HOST-RESTORE ]] || ic_fail '恢复需明确传入 SAME-HOST-RESTORE 确认'
    ic_trusted_dir "$BASE/backups"
    STAGE=$(mktemp -d "$BASE/backups/restore.XXXXXXXX"); chmod 700 "$STAGE"
    archive extract --backup "$INPUT" --directory "$STAGE"
    # Identity and revocation state remain live. A data rollback must never undo a
    # password change, node revocation or unpairing. Archives retain old identity
    # material for future fenced rebuild, but this command never activates it.
    for name in runtime credentials; do
      [[ -d $CONF/$name && ! -L $CONF/$name ]] || ic_fail '当前身份目录缺失，停止普通恢复'
      [[ ! -e $STAGE/previous-$name ]] || ic_fail '暂存路径冲突'
      if [[ -e $STAGE/conf/$name ]]; then mv -- "$STAGE/conf/$name" "$STAGE/previous-$name"; fi
      cp -a -- "$CONF/$name" "$STAGE/conf/$name"
    done
    if [[ $ROLE == cloud ]]; then
      for name in ca.crt ca.key ca.srl; do
        [[ -f $CONF/$name && ! -L $CONF/$name ]] || ic_fail '当前云端 CA 缺失，停止普通恢复'
        cp -p -- "$CONF/$name" "$STAGE/conf/$name"
      done
      ic_helper "$STAGE/conf/runtime" validate-cloud
    else
      python3 "$ROOT/src/host/agent.py" --validate-profile --profile "$STAGE/conf/profile.json"
      # Historical scan evidence may not authorize a fresh quarantine after rollback.
      rm -f -- "$STAGE/data/agent/last-findings.json" "$STAGE/data/agent/last-rule-hits.json"
      # Never roll back a currently activated publisher rule or its high-water mark.
      for name in rules.json rules.highwater.json; do
        if [[ -e $CONF/$name || -L $CONF/$name ]]; then
          ic_private_file "$CONF/$name"
          cp -p -- "$CONF/$name" "$STAGE/conf/$name"
        else
          rm -f -- "$STAGE/conf/$name"
        fi
      done
    fi
    ic_tx_begin
    ic_tx_mutating
    # Recreate Docker: restart would retain bind mounts to displaced directory inodes.
    ic_compose down
    mv -- "$CONF" "$STAGE/displaced-conf"
    mv -- "$DATA" "$STAGE/displaced-data"
    mv -- "$STAGE/conf" "$CONF"
    mv -- "$STAGE/data" "$DATA"
    if [[ $ROLE == local && -f $IC_TX/agent-active ]]; then systemctl start ironcurtain-agent.service; ic_agent_wait; fi
    if [[ -f $IC_TX/container-running ]]; then
      ic_compose up -d; ic_wait
      [[ $ROLE != local || ! -f $IC_TX/agent-active ]] || ic_scan_wait
    fi
    ic_tx_finish
    echo '同机恢复完成；当前密码、证书、节点允许名单与解绑状态保留。被替换状态保留在 root 私有目录。'
    ;;
  *) ic_fail '动作须为 backup / verify-backup / restore-backup' ;;
esac
