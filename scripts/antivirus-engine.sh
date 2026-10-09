#!/usr/bin/env bash
# Local root menu only. Uses an isolated database and updater; no cloud command execution.
set -euo pipefail
umask 077
ACTION=${1:-status}
SOURCE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$SOURCE/scripts/lib/independent.sh"
source "$SOURCE/scripts/lib/antivirus-apparmor.sh"
source "$SOURCE/scripts/lib/install-environment.sh"
[[ $EUID == 0 && $(uname -s) == Linux ]] || ic_fail '病毒引擎管理需要 Linux root'
case "$ACTION" in status|install|update|policy) ;; *) ic_fail '仅支持 status、install、update、policy' ;; esac
if [[ $ACTION == status ]]; then python3 "$SOURCE/src/host/antivirus.py"; exit; fi
[[ -d /run/lock ]] || install -d -m 755 /run/lock
[[ ! -L /run/lock/ironcurtain-antivirus.lock ]] || ic_fail '病毒引擎锁文件是符号链接'
exec 8>/run/lock/ironcurtain-antivirus.lock
flock -n 8 || ic_fail '病毒引擎安装或更新正在运行'
CONF=/etc/ironcurtain-antivirus
DATA=/var/lib/ironcurtain-antivirus
UNIT=/etc/systemd/system/ironcurtain-antivirus-update.service
TIMER=/etc/systemd/system/ironcurtain-antivirus-update.timer
ic_trusted_dir "$CONF"
ic_trusted_dir "$DATA"
# These dedicated directories contain no keys and must be traversable by the updater user.
chmod 755 "$CONF" "$DATA"
if [[ -e $DATA/activation.json || -L $DATA/activation.json ]]; then
  systemctl disable --now ironcurtain-antivirus-update.timer
  ic_fail '病毒库切换事务待恢复，请运行 tiemu virus-db-update；保持官方更新器停用'
fi
install_packages() {
  . /etc/os-release
  ic_env_select
  if [[ $MANAGER == apt-get ]]; then
    apt-get update || ic_fail '病毒引擎软件源更新失败；检查网络与 apt 源'
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-remove clamav clamav-freshclam || ic_fail '文件查杀引擎安装失败；请检查受信任软件源'
  else
    "$MANAGER" install -y clamav clamav-update || ic_fail '受信任软件源未提供文件查杀引擎；请检查发行版软件源'
  fi
  command -v clamscan >/dev/null && command -v freshclam >/dev/null || ic_fail '文件查杀引擎尚未就绪'
}
if [[ -e $DATA/source.json || -L $DATA/source.json ]]; then
  python3 - "$SOURCE" <<'PY'
import importlib.util,pathlib,sys
spec=importlib.util.spec_from_file_location('db_cache',pathlib.Path(sys.argv[1])/'scripts/virus-db-cache.py');cache=importlib.util.module_from_spec(spec);spec.loader.exec_module(cache)
v=cache.bytes_json(pathlib.Path('/var/lib/ironcurtain-antivirus/source.json'))
assert isinstance(v,dict) and set(v)=={'schema','source','snapshot'} and v['schema']=='ironcurtain-virus-db-source/v1' and v['source']=='xuanwu-signed' and cache.re.fullmatch('[a-f0-9]{64}',v['snapshot']), 'DB_SOURCE'
PY
  if [[ $ACTION == policy || $ACTION == install ]]; then
    if [[ -e $TIMER ]]; then systemctl disable --now ironcurtain-antivirus-update.timer; fi
    if [[ -e $UNIT ]]; then systemctl stop ironcurtain-antivirus-update.service; fi
    if [[ $ACTION == install ]]; then
      install_packages
      python3 "$SOURCE/src/host/antivirus.py"
      echo '文件引擎依赖维护完成；保留玄武签名病毒库与更新来源。'
    fi
    exit
  fi
  ic_fail '当前使用玄武签名病毒库，请使用 tiemu virus-db-update；禁止混用更新源'
fi
# Missing source metadata must never turn a signed database into an official writer.
for evidence in "$DATA/cloud-highwater.json" "$DATA/database/manifest.json" "$DATA/database/manifest.json.sig"; do
  if [[ -e $evidence || -L $evidence ]]; then
    [[ ! -e $TIMER ]] || systemctl disable --now ironcurtain-antivirus-update.timer
    [[ ! -e $UNIT ]] || systemctl stop ironcurtain-antivirus-update.service
    ic_fail '玄武病毒库来源标记缺失；停止维护，请恢复签名来源后重试，禁止自动改用其他来源'
  fi
done
if [[ $ACTION == install ]]; then
  # Quiesce the existing official writer before package/configuration repair.
  [[ ! -e $TIMER ]] || systemctl stop ironcurtain-antivirus-update.timer
  [[ ! -e $UNIT ]] || systemctl stop ironcurtain-antivirus-update.service
  install_packages
  if ! getent passwd ironcurtain-av >/dev/null; then
    useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin ironcurtain-av
  fi
  [[ $(id -u ironcurtain-av) != 0 && $(getent passwd ironcurtain-av | cut -d: -f7) =~ ^/(usr/)?sbin/nologin$ ]] || ic_fail '病毒引擎账户冲突'
  if [[ -e $DATA/database || -L $DATA/database ]]; then
    [[ -d $DATA/database && ! -L $DATA/database && $(stat -c %u "$DATA/database") == "$(id -u ironcurtain-av)" && $(stat -c %a "$DATA/database") == 755 ]] || ic_fail '病毒库目录已有异常权限，停止覆盖'
  else install -d -m 755 -o ironcurtain-av -g ironcurtain-av "$DATA/database"; fi
  cat > "$CONF/freshclam.conf.new" <<EOF
DatabaseDirectory $DATA/database
DatabaseOwner ironcurtain-av
DatabaseMirror database.clamav.net
ScriptedUpdates yes
TestDatabases yes
ConnectTimeout 15
ReceiveTimeout 30
MaxAttempts 2
EOF
  chmod 644 "$CONF/freshclam.conf.new"; mv -f "$CONF/freshclam.conf.new" "$CONF/freshclam.conf"
  FRESHCLAM=$(command -v freshclam)
  cat > "$UNIT.new" <<EOF
[Unit]
Description=IronCurtain official antivirus database update
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=ironcurtain-av
Group=ironcurtain-av
ExecStart=$FRESHCLAM --config-file=$CONF/freshclam.conf --stdout
TimeoutStartSec=240
UMask=0022
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=$DATA/database
EOF
  chmod 644 "$UNIT.new"; mv -f "$UNIT.new" "$UNIT"
  cat > "$TIMER.new" <<'EOF'
[Unit]
Description=IronCurtain antivirus database refresh schedule
[Timer]
OnBootSec=5min
OnUnitActiveSec=6h
RandomizedDelaySec=15min
Persistent=true
[Install]
WantedBy=timers.target
EOF
  chmod 644 "$TIMER.new"; mv -f "$TIMER.new" "$TIMER"
  systemctl daemon-reload
  systemctl enable --now ironcurtain-antivirus-update.timer
fi
[[ -f $UNIT && ! -L $UNIT && -f $CONF/freshclam.conf && ! -L $CONF/freshclam.conf ]] || ic_fail '请先运行 tiemu engine-install'
ic_av_apparmor
[[ $ACTION != policy ]] || exit 0
if ! systemctl start ironcurtain-antivirus-update.service; then
  echo '病毒库更新失败；保留现有库，尚未就绪请核对网络及更新日志。' >&2
  python3 "$SOURCE/src/host/antivirus.py"
  exit 1
fi
python3 "$SOURCE/src/host/antivirus.py"
echo '病毒库加载与查杀结果请运行本地扫描核实；元数据检查不代表扫描通过。'
