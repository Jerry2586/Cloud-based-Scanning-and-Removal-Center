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
  service_group=$(sed -n 's/^Group=//p' "$SYSTEMD_DIR/$SERVICE" 2>/dev/null | head -n 1)
  for file in "$CONF/config.json" "$CONF/ca.crt" "$CONF/server.crt" "$CONF/server.key" "$CONF/service.env" "$CONF/install.env"; do
    if [[ -s $file ]]; then echo "[OK] $file"; else echo "[失败] 缺少 $file"; failures=$((failures + 1)); fi
  done
  jq -e 'type == "object"' "$CONF/config.json" >/dev/null 2>&1 || { echo '[失败] config.json 无效'; failures=$((failures + 1)); }
  openssl verify -CAfile "$CONF/ca.crt" "$CONF/server.crt" >/dev/null 2>&1 || { echo '[失败] 服务证书不能由本机 CA 验证'; failures=$((failures + 1)); }
  if [[ -z $service_group ]]; then
    echo '[失败] systemd 服务组无法确定'; failures=$((failures + 1))
  elif [[ $(stat -c '%U:%G %a' "$CONF/server.key" 2>/dev/null) != "root:$service_group 640" ]]; then
    echo "[失败] server.key 必须为 root:$service_group 640"; failures=$((failures + 1))
  fi
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

nodes() {
  need_root
  local host token curl_config response
  host=$(sed -n 's/^SECURITY_PUBLIC_HOST=//p' "$CONF/install.env" 2>/dev/null | head -n 1)
  [[ -n $host && -s $CONF/credentials/reader.crt && -s $CONF/credentials/reader.key \
    && -s $CONF/credentials/reader.token && -s $CONF/ca.crt ]] \
    || { echo '只读管理身份或公网主机配置不完整。' >&2; exit 1; }
  token=$(<"$CONF/credentials/reader.token")
  curl_config=$(mktemp "$CONF/nodes.curl.XXXXXX")
  chmod 600 "$curl_config"
  printf '%s\n' \
    'silent' 'show-error' 'fail' \
    "cacert = \"$CONF/ca.crt\"" \
    "cert = \"$CONF/credentials/reader.crt\"" \
    "key = \"$CONF/credentials/reader.key\"" \
    "header = \"Authorization: Bearer $token\"" \
    "resolve = \"$host:9443:127.0.0.1\"" \
    "url = \"https://$host:9443/v1/status\"" > "$curl_config"
  if ! response=$(curl --config "$curl_config"); then
    rm -f -- "$curl_config"
    echo '无法读取本机安全状态 API。' >&2
    return 1
  fi
  rm -f -- "$curl_config"
  jq -r '
    "部署状态：\(.deployment.state)｜已注册 \(.deployment.configured_roles | length)/\(.deployment.required_roles | length)｜已认证连接 \(.deployment.connected_roles | length)",
    (.nodes | to_entries[] |
      "- \(if .key == "license-center" then "授权中心" else "打包中心" end)：注册=\(.value.configured)｜配对=\(.value.pairing_state)｜探测=\(.value.probe.state)｜完整性=\(.value.integrity.state)｜证书=\(.value.certificate_state)｜建议=\(.value.recommended_action)")
  ' <<<"$response"
}

enroll_node() {
  need_root
  local role=${1:-} url=${2:-} baseline=${3:-}
  [[ $role =~ ^(license-center|build-center)$ && -n $url && -n $baseline ]] \
    || { echo 'Usage: appgog-security enroll license-center|build-center HTTPS_URL ABSOLUTE_BASELINE' >&2; exit 2; }
  bash "$BASE/current/scripts/enroll-node.sh" "$role" "$url" "$baseline"
}

export_bundle() {
  need_root
  local profile=${1:-} destination=${2:-}
  [[ $profile =~ ^(all|license|build)$ && -n $destination ]] \
    || { echo 'Usage: appgog-security export all|license|build NEW_ABSOLUTE_DIRECTORY' >&2; exit 2; }
  bash "$BASE/current/scripts/export-business-bundle.sh" "$profile" "$destination"
}

rotate_identity() {
  need_root
  local action=${1:-} role=${2:-}
  [[ $action =~ ^(stage|commit)$ && $role =~ ^(reader|license-center|build-center)$ ]] \
    || { echo 'Usage: appgog-security rotate stage|commit reader|license-center|build-center' >&2; exit 2; }
  bash "$BASE/current/scripts/rotate-identity.sh" "$action" "$role"
}

pairing_menu() {
  local choice role url baseline destination action
  while true; do
    cat <<'EOF'

节点对接管理
  1. 查看注册、连接、证书与报告状态
  2. 注册授权中心
  3. 注册打包中心
  4. 导出同机业务身份包（授权 + 打包）
  5. 导出独立授权服务器身份包
  6. 导出独立打包服务器身份包
  7. 身份轮换
  0. 返回
EOF
    read -r -p '请选择：' choice
    case "$choice" in
      1) nodes || true ;;
      2|3)
        [[ $choice == 2 ]] && role=license-center || role=build-center
        read -r -p '公网 HTTPS 健康地址：' url
        read -r -p '可信基线 JSON 绝对路径：' baseline
        enroll_node "$role" "$url" "$baseline"
        ;;
      4|5|6)
        case "$choice" in 4) role=all ;; 5) role=license ;; 6) role=build ;; esac
        read -r -p '新建身份包目录绝对路径：' destination
        export_bundle "$role" "$destination"
        ;;
      7)
        read -r -p '动作（stage/commit）：' action
        read -r -p '角色（reader/license-center/build-center）：' role
        rotate_identity "$action" "$role"
        ;;
      0) return ;;
      *) echo '无效选择' ;;
    esac
  done
}

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
 11. 节点对接管理（单双机拓扑）
 12. 注册授权中心
 13. 注册打包中心
 14. 导出授权/打包同机身份包
 15. 导出独立授权服务器身份包
 16. 导出独立打包服务器身份包
 17. 查看节点连接与证书状态
 18. 身份轮换管理
  0. 退出
EOF
    read -r -p '请选择：' choice
    case "$choice" in
      1) status ;; 2) need_root; "$SYSTEMCTL" start "$SERVICE" ;; 3) need_root; "$SYSTEMCTL" stop "$SERVICE" ;;
      4) need_root; "$SYSTEMCTL" restart "$SERVICE" ;; 5) logs ;; 6) doctor || true ;; 7) update ;; 8) backup ;;
      9) read -r -p '备份文件绝对路径：' file; restore "$file" ;; 10) uninstall_program ;;
      11) pairing_menu ;;
      12|13)
        [[ $choice == 12 ]] && role=license-center || role=build-center
        read -r -p '公网 HTTPS 健康地址：' url
        read -r -p '可信基线 JSON 绝对路径：' baseline
        enroll_node "$role" "$url" "$baseline"
        ;;
      14|15|16)
        case "$choice" in 14) profile=all ;; 15) profile=license ;; 16) profile=build ;; esac
        read -r -p '新建身份包目录绝对路径：' destination
        export_bundle "$profile" "$destination"
        ;;
      17) nodes || true ;;
      18)
        read -r -p '动作（stage/commit）：' action
        read -r -p '角色（reader/license-center/build-center）：' role
        rotate_identity "$action" "$role"
        ;;
      0) return ;;
      *) echo '无效选择' ;;
    esac
    read -r -p '按回车继续...' _
  done
}

case "${1:-menu}" in
  menu) menu ;; status) status ;; start|stop|restart) need_root; "$SYSTEMCTL" "$1" "$SERVICE" ;;
  logs) logs "${2:-100}" ;; doctor) doctor ;; update) update ;; backup) backup ;; restore) restore "${2:-}" ;;
  nodes) nodes ;; enroll) enroll_node "${2:-}" "${3:-}" "${4:-}" ;;
  export) export_bundle "${2:-}" "${3:-}" ;; rotate) rotate_identity "${2:-}" "${3:-}" ;;
  uninstall) uninstall_program "${2:-}" ;;
  *) echo 'Usage: appgog-security [status|start|stop|restart|logs|doctor|update|backup|restore FILE|nodes|enroll ROLE URL BASELINE|export PROFILE DEST|rotate ACTION ROLE|uninstall]' >&2; exit 2 ;;
esac
