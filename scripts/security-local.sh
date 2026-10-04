#!/usr/bin/env sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
SOCKET=${APPGOG_HOST_SCAN_SOCKET:-/run/appgog-security/scan.sock}
[ "$(id -u)" -eq 0 ] || { echo 'Run as root to inspect the host agent' >&2; exit 1; }
ROOT=${APPGOG_INSTALL_ROOT:-/opt/appgog}
AGENT=/usr/local/lib/appgog-security/host-security-agent.py
trusted_root_path() {
  trusted_path=$1
  while :; do
    [ ! -L "$trusted_path" ] && [ -d "$trusted_path" ] && [ "$(stat -c %u "$trusted_path")" = 0 ] || return 1
    trusted_mode=$(stat -c %a "$trusted_path") || return 1
    [ $((trusted_mode % 100 / 10 / 2 % 2)) -eq 0 ] && [ $((trusted_mode % 10 / 2 % 2)) -eq 0 ] || return 1
    [ "$trusted_path" != / ] || break
    trusted_path=$(dirname -- "$trusted_path")
  done
}
trusted_root_file() {
  [ ! -L "$1" ] && [ -f "$1" ] && [ "$(stat -c %u "$1")" = 0 ] || return 1
  trusted_mode=$(stat -c %a "$1") || return 1
  [ $((trusted_mode % 100 / 10 / 2 % 2)) -eq 0 ] && [ $((trusted_mode % 10 / 2 % 2)) -eq 0 ] || return 1
  trusted_root_path "$(dirname -- "$1")"
}
ROOT=$(CDPATH= cd -- "$ROOT" && pwd -P) || exit 1
trusted_root_path "$ROOT" || { echo "安装目录或父目录不可信" >&2; exit 1; }
case "${1:-}" in
  firewall)
    shift
    collector=/usr/local/lib/appgog-security/host-security-firewall.py
    trusted_root_file "$collector" && trusted_root_file "$AGENT" || { echo '防火墙采集器或依赖不可信' >&2; exit 1; }
    exec /usr/bin/python3 -I "$collector" "$@" ;;
  cloudflare)
    shift
    collector=/usr/local/lib/appgog-security/host-security-cloudflare.py
    trusted_root_file "$collector" || { echo 'CF 只读采集器缺失或归属不可信' >&2; exit 1; }
    exec /usr/bin/python3 -I "$collector" "$@" ;;
  response)
    shift
    controller=/usr/local/sbin/appgog-security-response
    trusted_root_file "$controller" || { echo "独立事故控制器缺失或不可信" >&2; exit 1; }
    exec "$controller" "$@" ;;
  engine)
    [ "$#" -eq 1 ] || exit 2
    case "$ROOT" in /*) ;; *) exit 2 ;; esac
    source_dir=$ROOT/current
    [ -d "$source_dir" ] || source_dir=$ROOT
    source_dir=$(CDPATH= cd -- "$source_dir" && pwd -P) || exit 1
    case "$source_dir" in "$ROOT"|"$ROOT"/releases/*) ;; *) echo "当前版本目录超出安装范围" >&2; exit 1 ;; esac
    trusted_root_file "$source_dir/scripts/install-host-security.sh" || { echo "安装器归属或权限异常" >&2; exit 1; }
    APPGOG_INSTALL_ROOT="$ROOT" sh "$source_dir/scripts/install-host-security.sh" engine
    exit $? ;;
  network-fingerprint|approve-network)
    trusted_root_file "$AGENT" && [ "$(stat -c %a "$AGENT")" = 700 ] || { echo '代理文件或父目录不可信' >&2; exit 1; }
    if [ "$1" = network-fingerprint ]; then
      [ "$#" -eq 1 ] || exit 2
      APPGOG_INSTALL_ROOT="$ROOT" /usr/bin/python3 -I "$AGENT" --network-fingerprint
    else
      [ "$#" -eq 2 ] || { echo '批准路由需要完整 SHA-256 指纹' >&2; exit 2; }
      APPGOG_INSTALL_ROOT="$ROOT" /usr/bin/python3 -I "$AGENT" --approve-network-baseline "$2"
      systemctl restart appgog-host-security.service
    fi
    exit $? ;;
  approve-program|approve-host)
    [ "$#" -eq 2 ] || { echo '批准程序需精确版本；批准主机需 APPROVE-HOST' >&2; exit 2; }
    [ -f "$AGENT" ] && [ ! -L "$AGENT" ] && [ "$(stat -c %u "$AGENT")" = 0 ] && [ "$(stat -c %a "$AGENT")" = 700 ] || { echo '代理文件归属不可信' >&2; exit 1; }
    trusted_root_file "$AGENT" || { echo '代理父目录不可信' >&2; exit 1; }
    echo '只在独立核验可信发布包或合法主机变更后批准；批准会接受当前内容。'
    if [ "$1" = approve-program ]; then
      APPGOG_INSTALL_ROOT="$ROOT" python3 -I "$AGENT" --approve-baseline "$2"
    else
      [ "$2" = APPROVE-HOST ] || exit 2
      APPGOG_INSTALL_ROOT="$ROOT" python3 -I "$AGENT" --approve-host-baseline "$2"
    fi
    systemctl restart appgog-host-security.service
    exit $? ;;
esac
[ -S "$SOCKET" ] || { echo 'Host security agent unavailable: socket missing' >&2; exit 1; }
command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 || {
  echo 'curl and jq are required; rerun the Linux installer to repair dependencies' >&2; exit 1;
}
case "${1:-}" in
  status|history) ;;
  scan)
    [ "$#" -eq 1 ] || exit 2
    code=$(curl --silent --show-error --unix-socket "$SOCKET" --max-time 5 -o /dev/null -w '%{http_code}' -X POST 'http://localhost/scan') || exit 1
    case "$code" in
      202) echo 'Host scan started; run appgog security-local status for results'; exit 0 ;;
      409) echo 'Host scan already running'; exit 0 ;;
      429) echo 'Host scan cooldown active (60 seconds)' >&2; exit 1 ;;
      *) echo "Host scan rejected: HTTP $code" >&2; exit 1 ;;
    esac ;;
  *) echo 'Usage: appgog security-local status|scan|history|engine|approve-program VERSION|approve-host APPROVE-HOST|network-fingerprint|approve-network SHA256|firewall menu|cloudflare menu|response ACTION' >&2; exit 2 ;;
esac
[ "$#" -eq 1 ] || exit 2
result=$(curl --silent --show-error --fail --unix-socket "$SOCKET" --max-time 5 'http://localhost/status') || exit 1
if [ "$1" = history ]; then
  printf '%s\n' "$result" | jq -r '"History: \(.history_state // "unavailable")", (.history[]? | "  [\(.checked_at)] \(.name): \(.previous_state // "first") -> \(.state) · \(.detail)")'
  printf '%s\n' "$result" | jq -e '.history_state == "ok" or .history_state == "truncated"' >/dev/null
  exit $?
fi
printf '%s\n' "$result" | jq -r '"Scan: \(.state) (\(.checked_at // "never"))", (.checks[]? | "  [\(.state)] \(.name): \(.detail)")'
# Missing and unfinished reports are not healthy; incomplete checks never become a clean status.
printf '%s\n' "$result" | jq -e '.state == "finished" and (.checked_at | type == "string") and (.checks | type == "array" and length > 0) and all(.checks[]; .state == "ok")' >/dev/null || {
  echo 'Host scan has findings, is incomplete, or cannot establish a clean result' >&2; exit 1;
}
checked_at=$(printf '%s\n' "$result" | jq -er '.checked_at | select(type == "string")') || exit 1
checked_epoch=$(date -u -d "$checked_at" +%s 2>/dev/null) || { echo 'Host scan timestamp invalid' >&2; exit 1; }
now_epoch=$(date -u +%s)
[ "$checked_epoch" -le "$((now_epoch + 120))" ] && [ "$checked_epoch" -ge "$((now_epoch - 900))" ] || {
  echo 'Host scan is stale or timestamp is in the future' >&2; exit 1;
}