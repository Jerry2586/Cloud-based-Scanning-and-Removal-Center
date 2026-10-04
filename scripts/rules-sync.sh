#!/usr/bin/env bash
# Fixed root-only scheduled pull. Never accepts commands, paths or cloud policies.
set -euo pipefail
umask 077
[[ $# == 0 && $EUID == 0 && $(uname -s) == Linux ]] || exit 1
SOURCE=/opt/ironcurtain/local/current
source "$SOURCE/scripts/lib/independent.sh"
ic_role local
exec 9>/run/lock/ironcurtain-local.lock
if ! flock -n 9; then echo '规则同步延后：安装或管理操作正在运行。'; exit 0; fi
ic_check_dir "$CONF"; ic_check_dir "$BASE"
for checkpoint in transaction.json admin-transaction.json; do
  [[ ! -e $BASE/$checkpoint && ! -L $BASE/$checkpoint ]] || { echo '规则同步暂停：存在未完成的安装或管理事务。' >&2; exit 1; }
done
ic_load
if [[ ! -d $CONF/runtime/cloud ]]; then echo '尚未配对玄武；本地扫描继续运行。'; exit 0; fi
python3 "$SOURCE/scripts/rules-client.py" local update
