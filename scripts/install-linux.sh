#!/usr/bin/env bash
set -euo pipefail
umask 077

SOURCE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$SOURCE/scripts/lib/identity-config.sh"
BASE=${SECURITY_INSTALL_DIR:-/opt/appgog-security}
CONF=${SECURITY_CONFIG_DIR:-/etc/appgog-security}
DATA=${SECURITY_DATA_DIR:-/var/lib/appgog-security}
SYSTEMD_DIR=${SECURITY_SYSTEMD_DIR:-/etc/systemd/system}
BIN_DIR=${SECURITY_BIN_DIR:-/usr/local/bin}
SYSTEMCTL=${SECURITY_SYSTEMCTL:-systemctl}
SERVICE=${SECURITY_SERVICE_NAME:-appgog-security.service}
TEST_MODE=${SECURITY_TEST_MODE:-false}
HOST=${APPGOG_SECURITY_HOST:-}

while (($#)); do
  case "$1" in
    --host) HOST=${2:?missing host}; shift 2 ;;
    *) echo 'Usage: install-linux.sh [--host DNS-name-or-public-IPv4]' >&2; exit 2 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
if [[ $TEST_MODE == true ]]; then
  [[ ${APPGOG_SECURITY_ALLOW_TEST_MODE:-false} == true ]] || { echo 'Test mode requires explicit test authorization' >&2; exit 1; }
else
  [[ $(uname -s) == Linux && -d /run/systemd/system ]] || { echo 'Linux with systemd required' >&2; exit 1; }
fi
validate_path_lexical() {
  local path=$1 kind=$2
  [[ $path == /* ]] || return 1
  [[ $path != */ && $path != *//* ]] || return 1
  case "/$path/" in */./*|*/../*) return 1 ;; esac
  if [[ $kind == managed ]]; then
    case "$path" in /|/opt|/etc|/var|/usr|/usr/local|/usr/local/bin) return 1 ;; esac
  else
    case "$path" in /|/opt|/etc|/var|/usr|/usr/local) return 1 ;; esac
  fi
}
for path in "$BASE" "$CONF" "$DATA"; do
  validate_path_lexical "$path" managed || { echo "Unsafe installation path: $path" >&2; exit 1; }
done
for path in "$SYSTEMD_DIR" "$BIN_DIR"; do
  validate_path_lexical "$path" container || { echo "Unsafe installation path: $path" >&2; exit 1; }
done

if [[ -z $HOST && -s $CONF/install.env ]]; then HOST=$(sed -n 's/^SECURITY_PUBLIC_HOST=//p' "$CONF/install.env" | head -n 1); fi
[[ -n $HOST ]] || { echo 'First installation requires --host DNS-name-or-public-IPv4' >&2; exit 2; }
if [[ $HOST =~ ^((0|[1-9][0-9]{0,2})\.){3}(0|[1-9][0-9]{0,2})$ ]]; then
  IFS=. read -r o1 o2 o3 o4 <<< "$HOST"
  for octet in "$o1" "$o2" "$o3" "$o4"; do ((10#$octet <= 255)) || { echo 'Invalid IPv4 address' >&2; exit 1; }; done
  SERVER_SAN="IP:$HOST"
elif [[ $HOST =~ ^[0-9.]+$ ]]; then
  echo 'Invalid IPv4 address' >&2; exit 1
elif [[ ${#HOST} -le 253 && $HOST =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]]; then
  SERVER_SAN="DNS:$HOST"
else
  echo 'Valid DNS hostname or IPv4 address required' >&2; exit 1
fi

ARCH=$(uname -m)
case "$ARCH" in x86_64) ARCH=x64 ;; aarch64) ARCH=arm64 ;; *) echo 'Only x86_64 and aarch64 are supported' >&2; exit 1 ;; esac
NODE_VERSION=$(sed -n 's/^[[:space:]]*"node_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$SOURCE/release-contract.json" | head -n 1)
VERSION=$(sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$SOURCE/package.json" | head -n 1)
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid package version' >&2; exit 1; }
CURRENT_VERSION=''
[[ ! -f $BASE/current/package.json ]] || CURRENT_VERSION=$(sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$BASE/current/package.json" | head -n 1)
if [[ -n $CURRENT_VERSION && $CURRENT_VERSION != "$VERSION" ]]; then
  newest=$(printf '%s\n%s\n' "$CURRENT_VERSION" "$VERSION" | sort -V | tail -n 1)
  [[ $newest == "$VERSION" ]] || { echo "Refusing downgrade from v$CURRENT_VERSION to v$VERSION" >&2; exit 1; }
fi

if [[ $TEST_MODE != true ]]; then
  if command -v apt-get >/dev/null; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl xz-utils tar openssl jq coreutils
  elif command -v dnf >/dev/null; then
    dnf install -y ca-certificates curl xz tar openssl jq coreutils
  elif command -v yum >/dev/null; then
    yum install -y ca-certificates curl xz tar openssl jq coreutils
  else
    echo 'Supported package managers: apt, dnf, yum' >&2; exit 1
  fi
fi

validate_path_canonical() {
  local path=$1 normalized
  normalized=$(realpath -m -- "$path") || return 1
  [[ $normalized == "$path" ]]
}
for path in "$BASE" "$CONF" "$DATA" "$SYSTEMD_DIR" "$BIN_DIR"; do
  validate_path_canonical "$path" || { echo "Unsafe installation path: $path" >&2; exit 1; }
done

WORK=$(mktemp -d)
TRANSACTION_ACTIVE=true
ROLLBACK_RUNNING=false
BASE_EXISTED=false
CONF_EXISTED=false
DATA_EXISTED=false
RUNTIME_EXISTED=false
RELEASE_EXISTED=false
SERVICE_WAS_ACTIVE=false
SERVICE_WAS_ENABLED=false
SERVICE_USER_CREATED=false
[[ -e $BASE ]] && BASE_EXISTED=true
[[ -e $CONF ]] && CONF_EXISTED=true
[[ -e $DATA ]] && DATA_EXISTED=true
[[ -e $BASE/runtime ]] && RUNTIME_EXISTED=true
[[ -e $BASE/releases/$VERSION ]] && RELEASE_EXISTED=true
OLD_CURRENT=$(readlink "$BASE/current" 2>/dev/null || true)
"$SYSTEMCTL" is-active "$SERVICE" >/dev/null 2>&1 && SERVICE_WAS_ACTIVE=true
"$SYSTEMCTL" is-enabled "$SERVICE" >/dev/null 2>&1 && SERVICE_WAS_ENABLED=true
[[ ! -f $SYSTEMD_DIR/$SERVICE ]] || cp -a "$SYSTEMD_DIR/$SERVICE" "$WORK/old.service"
[[ ! -f $BIN_DIR/appgog-security ]] || cp -a "$BIN_DIR/appgog-security" "$WORK/old.command"
[[ ! -f $BASE/install.sh ]] || cp -a "$BASE/install.sh" "$WORK/old.installer"

rollback() {
  [[ $ROLLBACK_RUNNING == false ]] || return 0
  ROLLBACK_RUNNING=true
  set +e
  echo 'Installation transaction failed; restoring the previous state.' >&2
  if [[ -n ${AUTO_BACKUP:-} && -f ${AUTO_BACKUP:-} ]]; then
    SECURITY_SYSTEMCTL="$SYSTEMCTL" bash "$SOURCE/scripts/restore.sh" --backup "$AUTO_BACKUP" --no-service
  elif [[ -n $OLD_CURRENT ]]; then
    ln -sfn "$OLD_CURRENT" "$BASE/current.rollback"
    mv -Tf "$BASE/current.rollback" "$BASE/current"
  else
    rm -f -- "$BASE/current"
  fi
  if [[ -f $WORK/old.service ]]; then cp -a "$WORK/old.service" "$SYSTEMD_DIR/$SERVICE"; else rm -f -- "$SYSTEMD_DIR/$SERVICE"; fi
  if [[ -f $WORK/old.command ]]; then cp -a "$WORK/old.command" "$BIN_DIR/appgog-security"; else rm -f -- "$BIN_DIR/appgog-security"; fi
  if [[ -f $WORK/old.installer ]]; then cp -a "$WORK/old.installer" "$BASE/install.sh"; else rm -f -- "$BASE/install.sh"; fi
  [[ $RELEASE_EXISTED == true ]] || rm -rf -- "$BASE/releases/$VERSION"
  [[ $RUNTIME_EXISTED == true ]] || rm -rf -- "$BASE/runtime"
  "$SYSTEMCTL" daemon-reload
  if [[ $SERVICE_WAS_ENABLED == true ]]; then "$SYSTEMCTL" enable "$SERVICE"; else "$SYSTEMCTL" disable "$SERVICE"; fi
  if [[ $SERVICE_WAS_ACTIVE == true ]]; then "$SYSTEMCTL" restart "$SERVICE"; else "$SYSTEMCTL" stop "$SERVICE"; fi
  [[ $BASE_EXISTED == true ]] || rm -rf -- "$BASE"
  [[ $CONF_EXISTED == true ]] || rm -rf -- "$CONF"
  [[ $DATA_EXISTED == true ]] || rm -rf -- "$DATA"
  if [[ $SERVICE_USER_CREATED == true ]]; then userdel appgog-security; fi
  set -e
}

transaction_exit() {
  status=$?
  trap - EXIT
  if [[ $TRANSACTION_ACTIVE == true && $status -ne 0 ]]; then rollback; fi
  rm -rf -- "$WORK"
  exit "$status"
}
trap transaction_exit EXIT

mkdir -p "$BASE/runtime/bin" "$BASE/releases" "$CONF/credentials" "$DATA/runtime" "$DATA/backups" "$SYSTEMD_DIR" "$BIN_DIR"
chmod 700 "$CONF" "$CONF/credentials"
if [[ ! -x $BASE/runtime/bin/node ]]; then
  if [[ $TEST_MODE == true ]]; then
    ln -s "$(command -v node)" "$BASE/runtime/bin/node"
  else
    TARBALL="node-v${NODE_VERSION}-linux-${ARCH}.tar.xz"
    TEMP_NODE=$(mktemp -d)
    curl --proto =https -fsS --retry 3 "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt" -o "$TEMP_NODE/SHASUMS256.txt"
    curl --proto =https -fsS --retry 3 "https://nodejs.org/dist/v${NODE_VERSION}/${TARBALL}" -o "$TEMP_NODE/$TARBALL"
    (cd "$TEMP_NODE"; grep -E "^[a-f0-9]{64}  ${TARBALL}$" SHASUMS256.txt | sha256sum -c -)
    tar -xJf "$TEMP_NODE/$TARBALL" -C "$BASE/runtime" --strip-components=1
    rm -rf "$TEMP_NODE"
  fi
fi
"$BASE/runtime/bin/node" -e "if (+process.versions.node.split('.')[0] !== 24) process.exit(1)"

SERVICE_USER=appgog-security
if [[ $TEST_MODE == true ]]; then
  SERVICE_USER=${SECURITY_TEST_SERVICE_USER:-root}
elif ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home "$DATA" --shell /usr/sbin/nologin "$SERVICE_USER"
  SERVICE_USER_CREATED=true
fi
SERVICE_GROUP=$(id -gn "$SERVICE_USER")

health_check() {
  if [[ -n ${SECURITY_HEALTHCHECK_CMD:-} ]]; then "$SECURITY_HEALTHCHECK_CMD"; return; fi
  "$SYSTEMCTL" is-active "$SERVICE" >/dev/null 2>&1 || return 1
  token=$(cat "$CONF/credentials/reader.token")
  curl -fsS --max-time 4 --resolve "$HOST:9443:127.0.0.1" --cacert "$CONF/ca.crt" \
    --cert "$CONF/credentials/reader.crt" --key "$CONF/credentials/reader.key" \
    -H "Authorization: Bearer $token" "https://$HOST:9443/v1/status" >/dev/null
}

RELEASE="$BASE/releases/$VERSION"
if [[ -e $RELEASE ]]; then
  cmp -s "$SOURCE/package.json" "$RELEASE/package.json" \
    && cmp -s "$SOURCE/release-contract.json" "$RELEASE/release-contract.json" \
    && cmp -s "$SOURCE/release-public.pem" "$RELEASE/release-public.pem" \
    && diff -qr "$SOURCE/src" "$RELEASE/src" >/dev/null \
    && diff -qr "$SOURCE/scripts" "$RELEASE/scripts" >/dev/null || {
    echo "Release $VERSION exists with different source; increase the version" >&2; exit 1;
  }
fi
if [[ $CURRENT_VERSION == "$VERSION" && -L $BASE/current ]] && health_check; then
  install -m 700 "$SOURCE/install.sh" "$BASE/install.sh"
  install -m 755 "$SOURCE/scripts/appgog-security.sh" "$BIN_DIR/appgog-security"
  TRANSACTION_ACTIVE=false
  echo "APPGOG cloud security center v$VERSION is already healthy."
  exit 0
fi

AUTO_BACKUP=''
if [[ -n $CURRENT_VERSION && -d $BASE/current ]]; then
  AUTO_BACKUP=$(bash "$SOURCE/scripts/backup.sh" --print-path)
  echo "Pre-update encrypted backup: $AUTO_BACKUP"
fi

if [[ ! -e $RELEASE ]]; then
  mkdir "$RELEASE"
  cp -R "$SOURCE/src" "$SOURCE/scripts" "$SOURCE/package.json" "$SOURCE/release-contract.json" "$SOURCE/release-public.pem" "$RELEASE/"
fi
chown -R root:root "$RELEASE"
chgrp "$SERVICE_GROUP" "$CONF"
chmod 750 "$CONF"
if [[ ! -f $CONF/ca.key ]]; then
  openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 -subj '/CN=APPGOG Security Private CA' \
    -keyout "$CONF/ca.key" -out "$CONF/ca.crt" >/dev/null 2>&1
  chmod 600 "$CONF/ca.key"
fi
server_cert_valid=false
if [[ -f $CONF/server.key && -f $CONF/server.crt ]] && openssl x509 -in "$CONF/server.crt" -checkend 2592000 -noout >/dev/null 2>&1; then
  if [[ $SERVER_SAN == IP:* ]]; then openssl x509 -in "$CONF/server.crt" -checkip "$HOST" -noout >/dev/null 2>&1 && server_cert_valid=true
  else openssl x509 -in "$CONF/server.crt" -checkhost "$HOST" -noout >/dev/null 2>&1 && server_cert_valid=true; fi
fi
if [[ $server_cert_valid != true ]]; then
  if [[ ! -f $CONF/server.key ]]; then
    openssl req -newkey rsa:3072 -nodes -subj "/CN=$HOST" -keyout "$CONF/server.key" -out "$CONF/server.csr" >/dev/null 2>&1
  else
    openssl req -new -key "$CONF/server.key" -subj "/CN=$HOST" -out "$CONF/server.csr" >/dev/null 2>&1
  fi
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$SERVER_SAN" > "$CONF/server.ext"
  openssl x509 -req -in "$CONF/server.csr" -CA "$CONF/ca.crt" -CAkey "$CONF/ca.key" -CAcreateserial \
    -out "$CONF/server.crt" -days 365 -sha256 -extfile "$CONF/server.ext" >/dev/null 2>&1
fi
if [[ ! -f $CONF/credentials/reader.key ]]; then
  openssl req -newkey rsa:3072 -nodes -subj '/CN=authorization-dashboard' -keyout "$CONF/credentials/reader.key" \
    -out "$CONF/credentials/reader.csr" >/dev/null 2>&1
  openssl x509 -req -in "$CONF/credentials/reader.csr" -CA "$CONF/ca.crt" -CAkey "$CONF/ca.key" -CAcreateserial \
    -out "$CONF/credentials/reader.crt" -days 365 -sha256 >/dev/null 2>&1
  openssl rand -hex 32 > "$CONF/credentials/reader.token"
fi
[[ -s $CONF/backup.key ]] || openssl rand -out "$CONF/backup.key" 48
[[ -f $CONF/config.json ]] || printf '{}\n' > "$CONF/config.json"
TMP_CONFIG=$(mktemp "$CONF/config.XXXXXX")
if appgog_normalize_reader_config "$CONF/config.json" "$CONF/credentials/reader.crt" "$CONF/credentials/reader.token" > "$TMP_CONFIG"; then
  chown "$SERVICE_USER:$SERVICE_GROUP" "$TMP_CONFIG"; chmod 600 "$TMP_CONFIG"; mv "$TMP_CONFIG" "$CONF/config.json"
else
  result=$?; rm -f "$TMP_CONFIG"; exit "$result"
fi
chmod 640 "$CONF/config.json" "$CONF/server.key" "$CONF/server.crt" "$CONF/ca.crt"
chmod 600 "$CONF/ca.key" "$CONF/backup.key" "$CONF/credentials/"*.key "$CONF/credentials/"*.token
chown "root:$SERVICE_GROUP" "$CONF/server.key" "$CONF/server.crt" "$CONF/ca.crt" "$CONF/config.json"
if [[ -f $DATA/state.json && ! -e $DATA/runtime/state.json ]]; then
  mv "$DATA/state.json" "$DATA/runtime/state.json"
fi
chown "root:$SERVICE_GROUP" "$DATA"
chown root:root "$DATA/backups"
chmod 750 "$DATA"
chmod 700 "$DATA/backups"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA/runtime"
chmod 700 "$DATA/runtime"

cat > "$CONF/install.env" <<EOF
SECURITY_PUBLIC_HOST=$HOST
EOF
cat > "$CONF/service.env" <<EOF
SECURITY_TLS_KEY=$CONF/server.key
SECURITY_TLS_CERT=$CONF/server.crt
SECURITY_CLIENT_CA=$CONF/ca.crt
SECURITY_CONFIG=$CONF/config.json
SECURITY_STATE_FILE=$DATA/runtime/state.json
SECURITY_PORT=9443
EOF
chmod 600 "$CONF/install.env" "$CONF/service.env"
cat > "$SYSTEMD_DIR/$SERVICE" <<EOF
[Unit]
Description=APPGOG independent cloud security monitor
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$BASE/current
EnvironmentFile=$CONF/service.env
ExecStart=$BASE/runtime/bin/node $BASE/current/src/server.js
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=$DATA
[Install]
WantedBy=multi-user.target
EOF
install -m 700 "$SOURCE/install.sh" "$BASE/install.sh"
install -m 755 "$SOURCE/scripts/appgog-security.sh" "$BIN_DIR/appgog-security"
ln -sfn "$RELEASE" "$BASE/current.next"
mv -Tf "$BASE/current.next" "$BASE/current"

"$SYSTEMCTL" daemon-reload
"$SYSTEMCTL" enable "$SERVICE"
"$SYSTEMCTL" restart "$SERVICE"
healthy=false
for _ in $(seq 1 15); do if health_check; then healthy=true; break; fi; sleep 2; done
[[ $healthy == true ]] || { echo 'Installed service did not pass its authenticated health check.' >&2; exit 1; }

TRANSACTION_ACTIVE=false

echo "Cloud security center v$VERSION ready at https://$HOST:9443"
echo 'CA fingerprint (verify through an independent administrator channel):'
openssl x509 -in "$CONF/ca.crt" -noout -fingerprint -sha256
echo
echo '下一步只需两步：'
echo '  1. 输入：sudo appgog-security'
echo '  2. 选择：1. 首次配置向导（推荐）'
echo '向导会按中文提示完成授权中心、打包中心注册并生成业务身份包。'
echo '以后更新：重新执行首次安装的同一条命令，系统会自动识别并安全更新；也可在管理菜单选择 4。'
