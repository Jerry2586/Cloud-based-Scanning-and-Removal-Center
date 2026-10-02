#!/usr/bin/env bash
set -euo pipefail

BASE=${SECURITY_INSTALL_DIR:-/opt/appgog-security}
CONF=${SECURITY_CONFIG_DIR:-/etc/appgog-security}
DATA=${SECURITY_DATA_DIR:-/var/lib/appgog-security}
SYSTEMCTL=${SECURITY_SYSTEMCTL:-systemctl}
SERVICE=${SECURITY_SERVICE_NAME:-appgog-security.service}
SYSTEMD_DIR=${SECURITY_SYSTEMD_DIR:-/etc/systemd/system}
BIN_DIR=${SECURITY_BIN_DIR:-/usr/local/bin}
ENROLL_SCRIPT=${SECURITY_ENROLL_SCRIPT:-$BASE/current/scripts/enroll-node.sh}
EXPORT_SCRIPT=${SECURITY_EXPORT_SCRIPT:-$BASE/current/scripts/export-business-bundle.sh}
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
  bash "$ENROLL_SCRIPT" "$role" "$url" "$baseline"
}

export_bundle() {
  need_root
  local profile=${1:-} destination=${2:-}
  [[ $profile =~ ^(all|license|build)$ && -n $destination ]] \
    || { echo 'Usage: appgog-security export all|license|build NEW_ABSOLUTE_DIRECTORY' >&2; exit 2; }
  bash "$EXPORT_SCRIPT" "$profile" "$destination"
}

rotate_identity() {
  need_root
  local action=${1:-} role=${2:-}
  [[ $action =~ ^(stage|commit)$ && $role =~ ^(reader|license-center|build-center)$ ]] \
    || { echo 'Usage: appgog-security rotate stage|commit reader|license-center|build-center' >&2; exit 2; }
  bash "$BASE/current/scripts/rotate-identity.sh" "$action" "$role"
}

validate_export_root() {
  local destination=$1 normalized parent
  [[ $destination == /* && ! -e $destination ]] || return 1
  case "$destination" in *'/./'*|*'/../'*|*'//'*) return 1 ;; esac
  normalized=$(realpath -m -- "$destination") || return 1
  [[ $normalized == "$destination" ]] || return 1
  case "$destination" in /|/root|/etc|/opt|/var|/usr|/usr/local) return 1 ;; esac
  parent=$(dirname -- "$destination")
  [[ -d $parent ]]
}

rollback_setup() {
  local config_backup=$1 export_root=$2
  cp -p -- "$config_backup" "$CONF/config.json"
  rm -f -- "$CONF/credentials/license-center.key" "$CONF/credentials/license-center.csr" \
    "$CONF/credentials/license-center.crt" "$CONF/credentials/license-center.token" \
    "$CONF/credentials/build-center.key" "$CONF/credentials/build-center.csr" \
    "$CONF/credentials/build-center.crt" "$CONF/credentials/build-center.token"
  if [[ -e $export_root ]]; then rm -rf -- "$export_root"; fi
  "$SYSTEMCTL" restart "$SERVICE" >/dev/null 2>&1 || true
}

setup_business_nodes() {
  need_root
  local mode=${1:-} license_url=${2:-} license_baseline=${3:-}
  local build_url=${4:-} build_baseline=${5:-} export_root=${6:-}
  local config_backup role suffix
  [[ $mode =~ ^(shared|separate)$ && -n $license_url && -n $license_baseline \
    && -n $build_url && -n $build_baseline && -n $export_root ]] \
    || { echo '用法：appgog-security setup shared|separate 授权健康地址 授权基线 打包健康地址 打包基线 身份包目录' >&2; return 2; }
  jq -e 'type == "object" and (.nodes | type == "object")' "$CONF/config.json" >/dev/null 2>&1 \
    || { echo '安全中心配置无效，请先运行系统诊断。' >&2; return 1; }
  if jq -e '(.nodes["license-center"]? != null) or (.nodes["build-center"]? != null)' "$CONF/config.json" >/dev/null; then
    echo '已存在授权中心或打包中心身份。为避免覆盖，请进入“高级管理 → 节点对接管理”。' >&2
    return 1
  fi
  for role in license-center build-center; do
    for suffix in key csr crt token; do
      [[ ! -e $CONF/credentials/$role.$suffix ]] \
        || { echo "发现已有身份文件：$role.$suffix，请先人工核查。" >&2; return 1; }
    done
  done
  validate_export_root "$export_root" \
    || { echo '身份包目录必须是尚不存在的安全绝对路径，并且父目录必须已存在。' >&2; return 2; }

  config_backup=$(mktemp "$CONF/setup-config.XXXXXX")
  cp -p -- "$CONF/config.json" "$config_backup"
  echo '[1/4] 正在注册授权中心专属身份……'
  if ! enroll_node license-center "$license_url" "$license_baseline"; then
    rm -f -- "$config_backup"
    echo '授权中心注册失败，未改变原配置。' >&2
    return 1
  fi
  echo '[2/4] 正在注册打包中心专属身份……'
  if ! enroll_node build-center "$build_url" "$build_baseline"; then
    rollback_setup "$config_backup" "$export_root"
    rm -f -- "$config_backup"
    echo '打包中心注册失败，本次向导产生的授权身份已全部回滚。' >&2
    return 1
  fi

  echo '[3/4] 正在生成业务服务器身份包……'
  if [[ $mode == shared ]]; then
    if ! export_bundle all "$export_root"; then
      rollback_setup "$config_backup" "$export_root"
      rm -f -- "$config_backup"
      echo '身份包生成失败，本次注册已全部回滚。' >&2
      return 1
    fi
  else
    install -d -m 700 "$export_root"
    if ! export_bundle license "$export_root/license-center" \
      || ! export_bundle build "$export_root/build-center"; then
      rollback_setup "$config_backup" "$export_root"
      rm -f -- "$config_backup"
      echo '身份包生成失败，本次注册已全部回滚。' >&2
      return 1
    fi
  fi
  rm -f -- "$config_backup"
  echo '[4/4] 首次配置完成。'
  echo "身份包目录：$export_root"
  if [[ $mode == shared ]]; then
    echo '下一步：把整个身份包目录安全传到授权与打包同机的业务服务器，并在业务端导入。'
  else
    echo '下一步：分别把 license-center 和 build-center 子目录安全传到对应业务服务器，并在业务端导入。'
  fi
  echo '身份包含私钥和令牌：不要发到聊天、网页、Git 或公开网盘；导入成功后删除中转副本。'
}

setup_wizard() {
  need_root
  local topology mode license_url license_baseline build_url build_baseline export_root answer
  cat <<'EOF'

首次配置向导
  1. 双机总架构：授权中心和打包中心在同一台业务服务器
  2. 三机总架构：授权中心、打包中心分别在两台业务服务器

准备内容：两个 HTTPS 健康地址、两个可信基线 JSON 文件。
本向导只创建独立身份和监测配置，不会登录或控制业务服务器。
EOF
  read -r -p '请选择部署方式 [1/2]：' topology
  case "$topology" in 1) mode=shared ;; 2) mode=separate ;; *) echo '选择无效，已退出。'; return 2 ;; esac
  read -r -p '授权中心 HTTPS 健康地址：' license_url
  read -r -p '授权中心可信基线 JSON 绝对路径：' license_baseline
  read -r -p '打包中心 HTTPS 健康地址：' build_url
  read -r -p '打包中心可信基线 JSON 绝对路径：' build_baseline
  export_root="/root/appgog-business-pairing-$(date -u +%Y%m%dT%H%M%SZ)"
  read -r -p "身份包保存目录 [默认 $export_root]：" answer
  [[ -z $answer ]] || export_root=$answer
  echo
  echo "部署方式：$([[ $mode == shared ]] && echo '双机总架构' || echo '三机总架构')"
  echo "授权地址：$license_url"
  echo "打包地址：$build_url"
  echo "身份包目录：$export_root"
  read -r -p '确认无误请输入 YES：' answer
  [[ $answer == YES ]] || { echo '已取消，未修改任何配置。'; return 0; }
  setup_business_nodes "$mode" "$license_url" "$license_baseline" "$build_url" "$build_baseline" "$export_root"
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

dashboard_info() {
  local host
  host=$(sed -n 's/^SECURITY_PUBLIC_HOST=//p' "$CONF/install.env" 2>/dev/null | head -n 1)
  [[ -n $host ]] || { echo '尚未找到公网主机配置，请运行系统诊断。' >&2; return 1; }
  echo "网页面板：https://$host:9443/dashboard"
  echo '登录用户名：reader'
  echo "登录令牌位置：$CONF/credentials/reader.token（仅限 root 本机读取）"
  echo '浏览器还必须安装 reader 客户端证书；页面保持只读，不能远程执行命令。'
}

backup_restore_menu() {
  local choice file
  cat <<'EOF'

备份与恢复
  1. 创建完整加密备份
  2. 从完整备份恢复
  0. 返回
EOF
  read -r -p '请选择：' choice
  case "$choice" in
    1) backup ;;
    2) read -r -p '备份文件绝对路径：' file; restore "$file" ;;
    0) return ;;
    *) echo '无效选择' ;;
  esac
}

advanced_menu() {
  local choice
  while true; do
    cat <<'EOF'

高级管理
  1. 启动服务
  2. 停止服务
  3. 重启服务
  4. 查看服务日志
  5. 系统诊断
  6. 节点对接与身份轮换
  7. 卸载程序（保留配置与数据）
  0. 返回
EOF
    read -r -p '请选择：' choice
    case "$choice" in
      1) need_root; "$SYSTEMCTL" start "$SERVICE" ;;
      2) need_root; "$SYSTEMCTL" stop "$SERVICE" ;;
      3) need_root; "$SYSTEMCTL" restart "$SERVICE" ;;
      4) logs ;;
      5) doctor || true ;;
      6) pairing_menu ;;
      7) uninstall_program ;;
      0) return ;;
      *) echo '无效选择' ;;
    esac
    read -r -p '按回车继续...' _
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
  1. 首次配置向导（推荐）
  2. 查看安全状态
  3. 查看网页面板地址
  4. 检查并更新
  5. 备份与恢复
  6. 高级管理
  0. 退出
EOF
    read -r -p '请选择：' choice
    case "$choice" in
      1) setup_wizard ;;
      2) status; echo; nodes || true ;;
      3) dashboard_info ;;
      4) update ;;
      5) backup_restore_menu ;;
      6) advanced_menu ;;
      0) return ;;
      *) echo '无效选择' ;;
    esac
    read -r -p '按回车继续...' _
  done
}

case "${1:-menu}" in
  menu) menu ;; status) status ;; start|stop|restart) need_root; "$SYSTEMCTL" "$1" "$SERVICE" ;;
  logs) logs "${2:-100}" ;; doctor) doctor ;; update) update ;; backup) backup ;; restore) restore "${2:-}" ;;
  setup)
    if (($# == 1)); then setup_wizard; else setup_business_nodes "${2:-}" "${3:-}" "${4:-}" "${5:-}" "${6:-}" "${7:-}"; fi
    ;;
  nodes) nodes ;; enroll) enroll_node "${2:-}" "${3:-}" "${4:-}" ;;
  export) export_bundle "${2:-}" "${3:-}" ;; rotate) rotate_identity "${2:-}" "${3:-}" ;;
  uninstall) uninstall_program "${2:-}" ;;
  *) echo 'Usage: appgog-security [setup [shared|separate LICENSE_URL LICENSE_BASELINE BUILD_URL BUILD_BASELINE EXPORT_ROOT]|status|start|stop|restart|logs|doctor|update|backup|restore FILE|nodes|enroll ROLE URL BASELINE|export PROFILE DEST|rotate ACTION ROLE|uninstall]' >&2; exit 2 ;;
esac
