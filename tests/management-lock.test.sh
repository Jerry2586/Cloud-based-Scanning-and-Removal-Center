#!/usr/bin/env bash
# Mocked wait/error decisions; never touches host locks or services.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ ${1:-} == --case ]]; then
  scenario=$2 work=$3
  source "$ROOT/scripts/lib/independent.sh"
  ROLE=$4
  calls=0
  flock() {
    calls=$((calls+1))
    printf '%s\n' "$*" >> "$work/calls"
    if (( calls == 1 )); then
      [[ $1 == -n && $2 == 9 ]] || return 99
      case "$scenario" in immediate) return 0 ;; error) return 74 ;; *) return 1 ;; esac
    fi
    [[ $1 == -w && $2 == 15 && $3 == 9 ]] || return 99
    case "$scenario" in released) return 0 ;; wait-error) return 74 ;; *) return 1 ;; esac
  }
  exec 9<>"$work/lock"
  ic_wait_management_lock 9 "$work/lock"
  printf 'entered\n' > "$work/entered"
  exit 0
fi
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT
for role in local cloud; do
  for scenario in immediate released timeout error wait-error; do
    work=$WORK/$role-$scenario
    mkdir "$work"
    printf 'original-lock-content\n' > "$work/lock"
    result=0
    bash "$0" --case "$scenario" "$work" "$role" > "$work/output" 2>&1 || result=$?
    [[ $(cat "$work/lock") == original-lock-content ]]
    case "$scenario" in
      immediate) [[ $result == 0 && -e $work/entered && $(wc -l < "$work/calls") == 1 ]]; ! grep -q '等待' "$work/output" ;;
      released) [[ $result == 0 && -e $work/entered && $(wc -l < "$work/calls") == 2 ]]; grep -q '管理锁已释放' "$work/output" ;;
      timeout) [[ $result != 0 && ! -e $work/entered ]]; grep -q 'sudo lslocks' "$work/output"; grep -q "ironcurtain-domain-$role-apply.service" "$work/output"; grep -q '不要删除锁文件' "$work/output" ;;
      error) [[ $result != 0 && ! -e $work/entered && $(wc -l < "$work/calls") == 1 ]]; grep -q '退出码 74' "$work/output" ;;
      wait-error) [[ $result != 0 && ! -e $work/entered && $(wc -l < "$work/calls") == 2 ]]; grep -q '退出码 74' "$work/output"; ! grep -q '仍被占用' "$work/output" ;;
    esac
    printf 'PASS %s/%s\n' "$role" "$scenario"
  done
done
