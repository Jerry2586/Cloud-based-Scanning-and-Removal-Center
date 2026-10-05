#!/usr/bin/env bash
set -euo pipefail
umask 077
SOURCE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$SOURCE/scripts/lib/independent.sh"
source "$SOURCE/scripts/lib/install-transaction.sh"
source "$SOURCE/scripts/lib/management-transaction.sh"
source "$SOURCE/scripts/lib/install-environment.sh"
source "$SOURCE/scripts/lib/install-host.sh"
source "$SOURCE/scripts/lib/install-image.sh"
ROLE='' HOST='' BIND='' ENGINE_MODE=auto ENGINE_REQUESTED=false
while (($#)); do
  case "$1" in
    --role) ROLE=${2:?missing role}; shift 2 ;;
    --host) HOST=${2:?missing host}; shift 2 ;;
    --bind) BIND=${2:?missing bind}; shift 2 ;;
    --antivirus) ENGINE_MODE=${2:?missing antivirus mode}; ENGINE_REQUESTED=true; shift 2 ;;
    *) ic_fail '用法：--role local|cloud [--host 域名或IPv4] [--bind IPv4]' ;;
  esac
done
[[ $ENGINE_MODE == auto || $ENGINE_MODE == skip ]] || ic_fail '病毒引擎模式仅支持 auto 或 skip'
[[ $EUID == 0 && $(uname -s) == Linux && -d /run/systemd/system ]] || ic_fail '需要带 systemd 的 Linux root 环境'
ic_role "$ROLE"
MENU=/usr/local/bin/ironcurtain
[[ $ROLE != cloud ]] || MENU=/usr/local/bin/xuanwu
# Keep MENU fixed for recovery of pre-tiemu transactions and signed bootstrap contracts.
MENU_EXTRA=
[[ $ROLE != local ]] || MENU_EXTRA=/usr/local/bin/tiemu
AGENT_UNIT=/etc/systemd/system/ironcurtain-agent.service
RULES_SERVICE=/etc/systemd/system/ironcurtain-rules-sync.service
RULES_TIMER=/etc/systemd/system/ironcurtain-rules-sync.timer
engine_setup() {
  [[ $ROLE == local && $ENGINE_MODE == auto ]] || return 0
  local engine_action=install
  if command -v clamscan >/dev/null && [[ -f /etc/systemd/system/ironcurtain-antivirus-update.timer ]]; then engine_action=policy; fi
  install -d -m 700 "$DATA/logs"
  if ! bash "$BASE/current/scripts/antivirus-engine.sh" "$engine_action" > "$DATA/logs/antivirus-install.log" 2>&1; then
    echo "病毒引擎尚未就绪；安装记录：$DATA/logs/antivirus-install.log。请运行 tiemu engine-install 重试。" >&2
  fi
}

REQUESTED_HOST=$HOST REQUESTED_BIND=$BIND
ic_env_prepare
# /run/lock is normally present, but minimal supported images may omit it.
[[ -d /run/lock ]] || install -d -m 755 /run/lock
[[ ! -L /run/lock/ironcurtain-$ROLE.lock ]] || ic_fail '安装锁文件是符号链接'
exec 9>"/run/lock/ironcurtain-$ROLE.lock"
flock -n 9 || ic_fail '另一安装或管理操作正在运行'
for directory in /opt/ironcurtain /etc/ironcurtain /var/lib/ironcurtain "$BASE" "$CONF" "$DATA"; do ic_trusted_dir "$directory"; done
ic_env_docker_prepare
if [[ -e $BASE/transaction.json || -L $BASE/transaction.json ]]; then
  ic_tx_recover || ic_fail '上次安装恢复未完成，请保留恢复目录并检查服务'
fi
HOST=$REQUESTED_HOST BIND=$REQUESTED_BIND
if [[ -e $BASE/install.json || -L $BASE/install.json ]]; then
  ic_load
  ic_admin_recover || ic_fail '上次管理操作尚未恢复，请先运行菜单诊断'
  if ! $ENGINE_REQUESTED; then ENGINE_MODE=$(jq -er '.antivirus // "auto"' "$BASE/install.json"); fi
  [[ $ENGINE_MODE == auto || $ENGINE_MODE == skip ]] || ic_fail '已保存的病毒引擎模式无效'
  old_host=$(jq -er '.host' "$BASE/install.json"); old_bind=$(jq -er '.bind' "$BASE/install.json")
  HOST=${REQUESTED_HOST:-$old_host}; BIND=${REQUESTED_BIND:-$old_bind}
  [[ $HOST == "$old_host" && $BIND == "$old_bind" ]] || ic_fail '更新保留原访问地址；变更地址需另行重签证书'
fi
if [[ -z $HOST ]]; then
  HOST=$(ic_host_select "" "") || exit 1
  printf '自动识别公网 IPv4：%s\n' "$HOST"
fi
[[ ${#HOST} -le 253 && $HOST =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]] || ic_fail '域名或 IPv4 格式错误'
if [[ $HOST =~ ^[0-9.]+$ ]]; then
  python3 -c 'import ipaddress,sys;ipaddress.IPv4Address(sys.argv[1])' "$HOST" || ic_fail 'IPv4 无效'
  SAN=IP:$HOST
else
  [[ $HOST != *..* && $HOST != *.-* && $HOST != *-.* ]] || ic_fail '域名无效'
  SAN=DNS:$HOST
fi
BIND=${BIND:-0.0.0.0}
python3 -c 'import ipaddress,sys;ipaddress.IPv4Address(sys.argv[1])' "$BIND" || ic_fail '监听 IPv4 无效'
if [[ -s $BASE/install.json ]]; then ic_load; fi
VERSION=$(jq -er '.version' "$SOURCE/package.json")
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || ic_fail '版本格式错误'
payload_digest() { (cd "$1"; find src docker scripts -type f ! -path '*/__pycache__/*' -print0; printf 'package.json\0release-contract.json\0release-public.pem\0.dockerignore\0install.sh\0') | sort -z | while IFS= read -r -d '' file; do (cd "$1"; sha256sum "$file"); done | sha256sum | cut -d' ' -f1; }
[[ -z $(find "$SOURCE/src" "$SOURCE/docker" "$SOURCE/scripts" -type l -print -quit) ]] || ic_fail '安装载荷含符号链接，拒绝接受'
DIGEST=$(payload_digest "$SOURCE")
OLD_VERSION=''
if [[ -f $BASE/current/package.json ]]; then
  OLD_VERSION=$(jq -er .version "$BASE/current/package.json")
  [[ $(printf '%s\n' "$OLD_VERSION" "$VERSION" | sort -V | tail -n1) == "$VERSION" ]] || ic_fail '拒绝自动降级'
  if [[ $OLD_VERSION == "$VERSION" ]]; then
    [[ $DIGEST == "$(cat "$BASE/current/.payload-sha256")" && $(payload_digest "$BASE/current") == "$DIGEST" ]] || ic_fail '相同版本源码内容不同，需发布新版本'
    ic_load
    ic_healthy || ic_fail '当前版本服务不健康，请从菜单诊断，避免自动覆盖'
    [[ $ROLE != local ]] || ic_scan_wait || ic_fail '本地扫描代理不可用，请运行 tiemu doctor'
    engine_setup
    echo "$PRODUCT_NAME v$VERSION 已安装且健康。打开 Linux 管理菜单：sudo $MENU_COMMAND"; exit 0
  fi
fi
if docker inspect "$CONTAINER" >/dev/null 2>&1; then
  [[ -n $OLD_VERSION ]] || ic_fail '同名容器缺少可信安装记录，拒绝接管'
  [[ $(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$CONTAINER") == "$PROJECT" ]] || ic_fail '同名容器不属于本项目，拒绝接管'
else
  if ss -ltnH | awk '{print $4}' | grep -Eq ":$PORT$"; then ic_fail "端口 $PORT 已被占用"; fi
fi
ic_trusted_dir "$BASE/releases"
RELEASE=$BASE/releases/$VERSION
if [[ -e $RELEASE ]]; then
  [[ -f $RELEASE/.payload-sha256 && $(cat "$RELEASE/.payload-sha256") == "$DIGEST" && $(payload_digest "$RELEASE") == "$DIGEST" ]] || ic_fail '残留候选版本内容不一致，拒绝覆盖'
else
  install -d -m 750 "$RELEASE"
  cp -a "$SOURCE/src" "$SOURCE/scripts" "$SOURCE/docker" "$RELEASE/"
  cp "$SOURCE/package.json" "$SOURCE/release-contract.json" "$SOURCE/release-public.pem" "$SOURCE/.dockerignore" "$SOURCE/install.sh" "$RELEASE/"
  printf '%s\n' "$DIGEST" > "$RELEASE/.payload-sha256"
  find "$RELEASE" -type d -exec chmod 755 {} +
  find "$RELEASE" -type f -exec chmod 644 {} +
fi
IMAGE=ironcurtain-security:$VERSION-$ROLE-$DIGEST
# Build before active configuration/service changes.
ic_image_build "$RELEASE" "$IMAGE" "$DATA/logs"
ic_env
SUCCESS=false
rollback() {
  local result=$?
  trap - EXIT INT TERM
  if ! $SUCCESS; then
    ic_tx_recover || echo '自动恢复未完成；恢复记录已保留，请再次运行同一安装命令。' >&2
  fi
  exit "$result"
}
trap rollback EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ic_tx_begin
ic_tx_mutating
IMAGE=ironcurtain-security:$VERSION-$ROLE-$DIGEST
ic_env
install -d -m 750 -o root -g 10001 "$CONF/runtime"
install -d -m 700 "$CONF/credentials"
install -d -m 700 -o 10001 -g 10001 "$DATA/runtime"
if [[ $ROLE == cloud ]]; then
  ic_trusted_dir "$DATA/releases"
  chown root:10001 "$DATA/releases"
  chmod 750 "$DATA/releases"
fi
ic_trusted_dir "$DATA/virus-db"
chown root:10001 "$DATA/virus-db"
chmod 750 "$DATA/virus-db"
if [[ $ROLE == local ]]; then
  if [[ ! -f $CONF/runtime/panel-auth.json ]]; then
    [[ -f $CONF/credentials/panel-auth.json ]] || ic_helper "$CONF/credentials" init-local
    install -m 600 -o 10001 -g 10001 "$CONF/credentials/panel-auth.json" "$CONF/runtime/panel-auth.json"
  fi
  if [[ ! -f $CONF/runtime/panel.key ]]; then
    openssl req -x509 -newkey rsa:3072 -nodes -days 365 -subj "/CN=$HOST" -addext "subjectAltName=$SAN" -addext 'extendedKeyUsage=serverAuth' -keyout "$CONF/runtime/panel.key" -out "$CONF/runtime/panel.crt" >/dev/null 2>&1
    chown root:10001 "$CONF/runtime/panel.key" "$CONF/runtime/panel.crt"; chmod 640 "$CONF/runtime/panel.key" "$CONF/runtime/panel.crt"
  fi
  if [[ ! -f $CONF/profile.json ]]; then printf '{"schema":"ironcurtain-profile/v1"}\n' > "$CONF/profile.json"; fi
  # systemd resolves Group through NSS even when a numeric ID is configured.
  # Container GID 10001 therefore needs a real host group; do not add members.
  if ! getent group 10001 >/dev/null; then
    ! getent group ironcurtain-web >/dev/null || ic_fail 'ironcurtain-web 用户组编号冲突'
    groupadd --system --gid 10001 ironcurtain-web
  fi
  install -d -m 750 -o root -g 10001 /run/ironcurtain
  cat > /etc/systemd/system/ironcurtain-agent.service <<EOF
[Unit]
Description=IronCurtain bounded read-only host scanner
After=network-online.target docker.service
[Service]
Type=simple
User=root
Group=10001
ExecStart=/usr/bin/python3 $BASE/current/src/host/agent.py --profile $CONF/profile.json --state $DATA/agent --socket /run/ironcurtain/scan.sock --allowed-uid 10001 --group 10001
Restart=on-failure
RestartSec=5
UMask=0077
RuntimeDirectory=ironcurtain
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=$DATA /run/ironcurtain
[Install]
WantedBy=multi-user.target
EOF
  cat > "$RULES_SERVICE" <<EOF
[Unit]
Description=IronCurtain authenticated signed rule pull
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=root
ExecStart=/bin/bash $BASE/current/scripts/rules-sync.sh
TimeoutStartSec=30
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
PrivateDevices=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=$CONF /run/lock
ReadOnlyPaths=$CONF/runtime
MemoryMax=128M
TasksMax=16
EOF
  cat > "$RULES_TIMER" <<EOF
[Unit]
Description=IronCurtain periodic signed rule synchronization
[Timer]
OnBootSec=2min
OnUnitInactiveSec=15min
RandomizedDelaySec=60
Unit=ironcurtain-rules-sync.service
[Install]
WantedBy=timers.target
EOF
  chmod 644 "$RULES_SERVICE" "$RULES_TIMER"
else
  if [[ ! -f $CONF/ca.key ]]; then
    openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj '/CN=Xuanwu Independent CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -keyout "$CONF/ca.key" -out "$CONF/ca.crt" >/dev/null 2>&1
  fi
  if [[ ! -f $CONF/runtime/server.key ]]; then ic_certificate "$CONF/runtime" server "$HOST" serverAuth "$SAN"; fi
  if [[ ! -f $CONF/runtime/health.key ]]; then ic_certificate "$CONF/runtime" health xuanwu-health clientAuth; fi
  if [[ ! -f $CONF/credentials/client.key ]]; then
    ic_certificate "$CONF/credentials" client xuanwu-reader clientAuth
    openssl rand -hex 32 > "$CONF/credentials/token"
    ic_helper "$CONF/credentials" identity
    openssl pkcs12 -export -out "$CONF/credentials/reader.p12" -inkey "$CONF/credentials/client.key" -in "$CONF/credentials/client.crt" -certfile "$CONF/ca.crt" -passout file:"$CONF/credentials/token" >/dev/null 2>&1
  fi
  if [[ ! -f $CONF/runtime/config.json ]]; then
    jq -n --slurpfile identity "$CONF/credentials/identity.json" '{nodes:{},readers:[{role:"reader",identities:$identity}],policy:{version:"1",rules:{require_signed_updates:true,allow_remote_commands:false,allow_cloud_push:false}}}' > "$CONF/runtime/config.json"
  fi
  ic_helper "$CONF/runtime" validate-cloud
  install -m 640 -o root -g 10001 "$CONF/ca.crt" "$CONF/runtime/ca.crt"
  chown root:10001 "$CONF/runtime/"*; chmod 640 "$CONF/runtime/"*
  chmod 600 "$CONF/ca.key"
fi
jq -n --arg role "$ROLE" --arg host "$HOST" --arg bind "$BIND" --arg image "$IMAGE" --arg version "$VERSION" --arg antivirus "$ENGINE_MODE" '{schema:1,role:$role,host:$host,bind:$bind,image:$image,version:$version,antivirus:$antivirus}' > "$BASE/install.json.new"
chmod 600 "$BASE/install.json.new"; mv -f "$BASE/install.json.new" "$BASE/install.json"
ln -sfn "$RELEASE" "$BASE/current.next"; mv -Tf "$BASE/current.next" "$BASE/current"
ic_check_dir /usr/local/bin
ic_menu_write "$MENU"
[[ -z $MENU_EXTRA ]] || ic_menu_write "$MENU_EXTRA"
if [[ $ROLE == local ]]; then
  systemctl daemon-reload
  systemctl enable --now ironcurtain-agent.service
  systemctl restart ironcurtain-agent.service
  if [[ ! -f $IC_TX/$(basename "$RULES_TIMER") ]]; then
    systemctl enable --now ironcurtain-rules-sync.timer
  else
    if [[ -f $IC_TX/rules-timer-enabled ]]; then systemctl enable ironcurtain-rules-sync.timer;
    else systemctl disable ironcurtain-rules-sync.timer; fi
    if [[ -f $IC_TX/rules-timer-active ]]; then systemctl start ironcurtain-rules-sync.timer; fi
  fi
fi
ic_compose config --quiet
ic_compose up -d --wait --wait-timeout 90
ic_wait || ic_fail '容器 HTTPS 身份健康检查未通过'
if [[ $ROLE == local ]]; then
  ic_scan_wait || ic_fail '宿主扫描器或容器扫描通道不可用'
fi
ic_tx_finish
SUCCESS=true
engine_setup
echo "$PRODUCT_NAME v$VERSION 安装完成"
echo "网页面板：https://$HOST:$PORT"
echo "打开 Linux 管理菜单：sudo $MENU_COMMAND"
echo "检查并更新程序：sudo $MENU_COMMAND update"
echo '请在防火墙限制管理来源，确认服务器证书指纹后导入信任；脚本不会关闭 TLS 校验。'
[[ $ROLE != local ]] || echo '输入 tiemu 打开管理菜单并配置受保护项目和玄武连接；旧命令 ironcurtain 继续可用。'
[[ $ROLE != cloud ]] || { echo '输入 xuanwu 打开管理菜单，登记铁幕节点并导出加密身份包。'; ic_fingerprint; }
