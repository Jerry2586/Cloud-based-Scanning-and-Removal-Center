#!/usr/bin/env bash
set -euo pipefail
umask 077
SOURCE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$SOURCE/scripts/lib/independent.sh"
[[ $EUID == 0 && $# -ge 1 && $# -le 2 ]] || ic_fail "需要 root 和固定角色"
ic_role "$1"
action=${2:-apply}
[[ $action == apply || $action == renew ]] || ic_fail "无效域名动作"
[[ ! -L /run/lock/ironcurtain-$ROLE.lock ]] || ic_fail "安装锁无效"
exec 9>"/run/lock/ironcurtain-$ROLE.lock"
if [[ $action == renew ]]; then
  flock -n 9 || exit 0
elif ! flock -w 15 9; then
  python3 -c 'import sys;sys.path.insert(0,sys.argv[1]);from domain_control import Controller;c=Controller(sys.argv[2]);c.status_write("failed",c.status().get("requested_domain",""),"安装或管理任务正在运行，请稍后重试")' "$SOURCE/scripts" "$ROLE"
  exit 1
fi
report_failure() {
  local status=$?
  if ((status != 0)); then
    python3 -c 'import sys;sys.path.insert(0,sys.argv[1]);from domain_control import Controller;c=Controller(sys.argv[2]);s=c.status();c.status_write("failed",s.get("requested_domain",""),"安装配置尚未就绪，请在 Linux 菜单检查恢复事务") if s.get("state")=="running" else None' "$SOURCE/scripts" "$ROLE" || true
  fi
  exit "$status"
}
trap report_failure EXIT
ic_load
[[ ! -e $BASE/transaction.json && ! -e $BASE/admin-transaction.json ]] || ic_fail "有未完成的安装或管理恢复事务"
python3 "$BASE/current/scripts/domain_control.py" --role "$ROLE" --action "$action"
