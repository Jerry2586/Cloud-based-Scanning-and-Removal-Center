#!/usr/bin/env bash
set -euo pipefail

BASE=${SECURITY_INSTALL_DIR:-/opt/appgog-security}
CONF=${SECURITY_CONFIG_DIR:-/etc/appgog-security}
DATA=${SECURITY_DATA_DIR:-/var/lib/appgog-security}
SYSTEMCTL=${SECURITY_SYSTEMCTL:-systemctl}
SERVICE=${SECURITY_SERVICE_NAME:-appgog-security.service}
SYSTEMD_DIR=${SECURITY_SYSTEMD_DIR:-/etc/systemd/system}
BIN_DIR=${SECURITY_BIN_DIR:-/usr/local/bin}
validate_path() {
  local path=$1 kind=$2 normalized
  [[ $path == /* ]] || return 1
  case "/$path/" in */./*|*/../*) return 1 ;; esac
  normalized=$(realpath -m -- "$path") || return 1
  [[ $normalized == "$path" ]] || return 1
  if [[ $kind == managed ]]; then
    case "$path" in /|/opt|/etc|/var|/usr|/usr/local|/usr/local/bin) return 1 ;; esac
  else
    case "$path" in /|/opt|/etc|/var|/usr|/usr/local) return 1 ;; esac
  fi
}
for path in "$BASE" "$CONF" "$DATA"; do
  validate_path "$path" managed || { echo "Unsafe management path: $path" >&2; exit 1; }
done
for path in "$SYSTEMD_DIR" "$BIN_DIR"; do
  validate_path "$path" container || { echo "Unsafe management path: $path" >&2; exit 1; }
done

need_root() { [[ $EUID -eq 0 ]] || { echo '请使用 root 运行。' >&2; exit 1; }; }
version() { jq -r '.version // "未知"' "$BASE/current/package.json" 2>/dev/null || echo '未知'; }
service_state() { "$SYSTEMCTL" is-active "$SERVICE" 2>/dev/null || echo inactive; }
latest_backup() { find "$DATA/backups" -maxdepth 1 -type f -name 'appgog-security-*.tar.gz.enc' -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' 2>/dev/null | sort -r | head -n 1; }

status() {
  echo "版本：$(version)"
  echo "服务：$(service_state)"
  echo "地址：https://$(sed -n 's/^SECURITY_PUBLIC_HOST=//p' "$CONF/install.env" 2>/dev/null | head -n 1):9443/dashboard"
  echo "最近备份：$(latest_backup || true)"
}
doctor() {
  failures=0
  for file in "$CONF/config.json" "$CONF/ca.crt" "$CONF/server.crt" "$CONF/server.key" "$CONF/service.env" "$CONF/install.env"; do
    if [[ -s $file ]]; then echo "[OK] $file"; else echo "[失败] 缺少 $file"; failures=$((failures + 1)); fi
  done
  jq -e 'type == "object"' "$CONF/config.json" >/dev/null 2>&1 || { echo '[失败] config.json 无效'; failures=$((failures + 1)); }
  openssl verify -CAfile "$CONF/ca.crt" "$CONF/server.crt" >/dev/null 2>&1 || { echo '[失败] 服务证书不能由本机 CA 验证'; failures=$((failures + 1)); }
  [[ $(stat -c '%U:%G %a' "$CONF/server.key" 2>/dev/null) == root:appgog-security\ 640 ]] \
    || { echo '[失败] server.key 必须为 root:appgog-security 640'; failures=$((failures + 1)); }
  [[ $(service_state) == active ]] || { echo '[失败] 服务未运行'; failures=$((failures + 1)); }
  ((failures == 0)) && echo '诊断通过。'
  ((failures == 0))
}
update() { need_root; [[ -s $BASE/install.sh ]] || { echo '缺少签名更新引导器' >&2; exit 1; }; sh "$BASE/install.sh"; }
backup() { need_root; bash "$BASE/current/scripts/backup.sh"; }
restore() { need_root; [[ -n ${1:-} ]] || { echo 'Usage: appgog-security restore BACKUP_FILE' >&2; exit 2; }; bash "$BASE/current/scripts/restore.sh" --backup "$1"; }
uninstall_program() {
  need_root
  [[ ${1:-} == --yes ]] || { read -r -p '确认卸载程序并保留配置、身份、状态和备份？输入 YES：' answer; [[ $answer == YES ]] || return 0; }
  [[ -f $BASE/current/release-contract.json ]] \
    && [[ $(jq -r '.product // empty' "$BASE/current/release-contract.json") == appgog-cloud-security-center ]] \
    || { echo '安装目录缺少有效产品标识，拒绝删除。' >&2; exit 1; }
  "$SYSTEMCTL" disable --now "$SERVICE" 2>/dev/null || true
  rm -f "$SYSTEMD_DIR/$SERVICE" "$BIN_DIR/appgog-security"
  "$SYSTEMCTL" daemon-reload 2>/dev/null || true
  rm -rf -- "$BASE/releases" "$BASE/runtime" "$BASE/current" "$BASE/install.sh"
  echo "程序已卸载；$CONF 与 $DATA 已保留。"
}
logs() { "$SYSTEMCTL" status "$SERVICE" --no-pager || true; journalctl -u "$SERVICE" -n "${1:-100}" --no-pager; }

menu() {
  while true; do
    clear 2>/dev/null || true
    cat <<EOF
╔══════════════════════════════════════════════════════╗
║       APPGOG 云端安全查杀中心 管理中心              ║
╠══════════════════════════════════════════════════════╣
║  版本：$(version)      状态：$(service_state)
╚══════════════════════════════════════════════════════╝
  1. 查看系统状态
  2. 启动服务
  3. 停止服务
  4. 重启服务
  5. 查看服务日志
  6. 系统诊断
  7. 安全更新最新签名版本
  8. 创建完整加密备份
  9. 从完整备份恢复
 10. 卸载程序（保留配置与数据）
  0. 退出
EOF
    read -r -p '请选择：' choice
    case "$choice" in
      1) status ;; 2) need_root; "$SYSTEMCTL" start "$SERVICE" ;; 3) need_root; "$SYSTEMCTL" stop "$SERVICE" ;;
      4) need_root; "$SYSTEMCTL" restart "$SERVICE" ;; 5) logs ;; 6) doctor || true ;; 7) update ;; 8) backup ;;
      9) read -r -p '备份文件绝对路径：' file; restore "$file" ;; 10) uninstall_program ;; 0) return ;;
      *) echo '无效选择' ;;
    esac
    read -r -p '按回车继续...' _
  done
}

case "${1:-menu}" in
  menu) menu ;; status) status ;; start|stop|restart) need_root; "$SYSTEMCTL" "$1" "$SERVICE" ;;
  logs) logs "${2:-100}" ;; doctor) doctor ;; update) update ;; backup) backup ;; restore) restore "${2:-}" ;;
  uninstall) uninstall_program "${2:-}" ;;
  *) echo 'Usage: appgog-security [status|start|stop|restart|logs|doctor|update|backup|restore FILE|uninstall]' >&2; exit 2 ;;
esac
