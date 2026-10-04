#!/usr/bin/env bash
set -euo pipefail
umask 077

for argument in "$@"; do
  if [[ $argument == --role ]]; then exec bash "$(dirname "${BASH_SOURCE[0]}")/install-independent.sh" "$@"; fi
done

SOURCE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$SOURCE/scripts/lib/identity-config.sh"
BASE=${SECURITY_INSTALL_DIR:-/opt/appgog-security}
CONF=${SECURITY_CONFIG_DIR:-/etc/appgog-security}
DATA=${SECURITY_DATA_DIR:-/var/lib/appgog-security}
SYSTEMD_DIR=${SECURITY_SYSTEMD_DIR:-/etc/systemd/system}
BIN_DIR=${SECURITY_BIN_DIR:-/usr/local/bin}
SYSTEMCTL=${SECURITY_SYSTEMCTL:-systemctl}
SERVICE=${SECURITY_SERVICE_NAME:-appgog-security.service}
LOCK_FILE=${SECURITY_LOCK_FILE:-/run/lock/appgog-security.lock}
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
if [[ $TEST_MODE != true ]]; then
  if command -v apt-get >/dev/null; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl xz-utils tar openssl jq coreutils util-linux
  elif command -v dnf >/dev/null; then
    dnf install -y ca-certificates curl xz tar openssl jq coreutils util-linux
  elif command -v yum >/dev/null; then
    yum install -y ca-certificates curl xz tar openssl jq coreutils util-linux
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
for tool in flock openssl tar jq realpath runuser; do
  command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done
if [[ $TEST_MODE == true ]]; then
  SERVICE_USER=${SECURITY_TEST_SERVICE_USER:?Test mode requires SECURITY_TEST_SERVICE_USER}
else
  SERVICE_USER=appgog-security
fi
[[ $SERVICE_USER =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] \
  || { echo "Invalid service user: $SERVICE_USER" >&2; exit 1; }
if [[ $TEST_MODE == true ]]; then
  id "$SERVICE_USER" >/dev/null 2>&1 \
    || { echo "Test service user does not exist: $SERVICE_USER" >&2; exit 1; }
fi
[[ $LOCK_FILE == /* && $(realpath -m -- "$LOCK_FILE") == "$LOCK_FILE" ]] \
  || { echo "Unsafe maintenance lock path: $LOCK_FILE" >&2; exit 1; }
LOCK_DIR=$(dirname "$LOCK_FILE")
[[ ! -L $LOCK_DIR ]] || { echo "Maintenance lock directory must not be a symbolic link: $LOCK_DIR" >&2; exit 1; }
mkdir -p -- "$LOCK_DIR"
[[ -d $LOCK_DIR && ! -L $LOCK_DIR ]] \
  || { echo "Unsafe maintenance lock directory: $LOCK_DIR" >&2; exit 1; }
if [[ -e $LOCK_FILE || -L $LOCK_FILE ]]; then
  [[ -f $LOCK_FILE && ! -L $LOCK_FILE ]] \
    || { echo "Maintenance lock must be a regular file: $LOCK_FILE" >&2; exit 1; }
fi
exec {MAINTENANCE_LOCK_FD}<>"$LOCK_FILE"
LOCK_FD_PATH="/proc/$$/fd/$MAINTENANCE_LOCK_FD"
[[ -f $LOCK_FILE && ! -L $LOCK_FILE && -e $LOCK_FD_PATH && "$LOCK_FD_PATH" -ef "$LOCK_FILE" ]] \
  || { echo 'Maintenance lock path changed while opening it' >&2; exit 1; }
flock -n "$MAINTENANCE_LOCK_FD" \
  || { echo 'Another APPGOG maintenance transaction is running' >&2; exit 1; }
[[ -f $LOCK_FILE && ! -L $LOCK_FILE && -e $LOCK_FD_PATH && "$LOCK_FD_PATH" -ef "$LOCK_FILE" ]] \
  || { echo 'Maintenance lock path changed after acquisition' >&2; exit 1; }

CURRENT_VERSION=''
[[ ! -f $BASE/current/package.json ]] || CURRENT_VERSION=$(sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$BASE/current/package.json" | head -n 1)
if [[ -n $CURRENT_VERSION && $CURRENT_VERSION != "$VERSION" ]]; then
  newest=$(printf '%s\n%s\n' "$CURRENT_VERSION" "$VERSION" | sort -V | tail -n 1)
  [[ $newest == "$VERSION" ]] || { echo "Refusing downgrade from v$CURRENT_VERSION to v$VERSION" >&2; exit 1; }
fi

WORK=$(mktemp -d)
TRANSACTION_ACTIVE=true
ROLLBACK_RUNNING=false
PRESERVE_WORK=false
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
  local rollback_failed=false
  set +e
  echo 'Installation transaction failed; restoring the previous state.' >&2
  "$SYSTEMCTL" stop "$SERVICE" >/dev/null 2>&1 || rollback_failed=true
  if "$SYSTEMCTL" is-active "$SERVICE" >/dev/null 2>&1; then
    echo 'Failed to stop the service before rollback.' >&2
    rollback_failed=true
  fi
  if [[ -n ${AUTO_BACKUP:-} && -f ${AUTO_BACKUP:-} ]]; then
    if ! SECURITY_SYSTEMCTL="$SYSTEMCTL" SECURITY_SERVICE_USER="$SERVICE_USER" \
      SECURITY_MAINTENANCE_LOCK_FD="$MAINTENANCE_LOCK_FD" \
      bash "$SOURCE/scripts/restore.sh" --backup "$AUTO_BACKUP" --no-service; then
      echo 'Authenticated backup restore failed during installation rollback.' >&2
      rollback_failed=true
    fi
  elif [[ -n $OLD_CURRENT ]]; then
    ln -sfn "$OLD_CURRENT" "$BASE/current.rollback" || rollback_failed=true
    mv -Tf "$BASE/current.rollback" "$BASE/current" || rollback_failed=true
  else
    rm -f -- "$BASE/current" || rollback_failed=true
  fi
  if [[ -f $WORK/old.service ]]; then cp -a "$WORK/old.service" "$SYSTEMD_DIR/$SERVICE" || rollback_failed=true; else rm -f -- "$SYSTEMD_DIR/$SERVICE" || rollback_failed=true; fi
  if [[ -f $WORK/old.command ]]; then cp -a "$WORK/old.command" "$BIN_DIR/appgog-security" || rollback_failed=true; else rm -f -- "$BIN_DIR/appgog-security" || rollback_failed=true; fi
  if [[ -f $WORK/old.installer ]]; then cp -a "$WORK/old.installer" "$BASE/install.sh" || rollback_failed=true; else rm -f -- "$BASE/install.sh" || rollback_failed=true; fi
  [[ $RELEASE_EXISTED == true ]] || rm -rf -- "$BASE/releases/$VERSION" || rollback_failed=true
  [[ $RUNTIME_EXISTED == true ]] || rm -rf -- "$BASE/runtime" || rollback_failed=true
  [[ $BASE_EXISTED == true ]] || rm -rf -- "$BASE" || rollback_failed=true
  [[ $CONF_EXISTED == true ]] || rm -rf -- "$CONF" || rollback_failed=true
  [[ $DATA_EXISTED == true ]] || rm -rf -- "$DATA" || rollback_failed=true
  if [[ $SERVICE_USER_CREATED == true ]]; then userdel "$SERVICE_USER" || rollback_failed=true; fi
  "$SYSTEMCTL" daemon-reload || rollback_failed=true
  if [[ $rollback_failed == false ]]; then
    if [[ $SERVICE_WAS_ENABLED == true ]]; then "$SYSTEMCTL" enable "$SERVICE" || rollback_failed=true; else "$SYSTEMCTL" disable "$SERVICE" || rollback_failed=true; fi
  fi
  if [[ $rollback_failed == false ]]; then
    if [[ $SERVICE_WAS_ACTIVE == true ]]; then "$SYSTEMCTL" restart "$SERVICE" || rollback_failed=true; else "$SYSTEMCTL" stop "$SERVICE" || rollback_failed=true; fi
  fi
  if [[ $rollback_failed == true ]]; then
    "$SYSTEMCTL" stop "$SERVICE" >/dev/null 2>&1 || true
    PRESERVE_WORK=true
    echo "Rollback did not complete. Service remains stopped; recovery evidence is preserved at $WORK" >&2
    set -e
    return 1
  fi
  set -e
}

transaction_exit() {
  status=$?
  trap - EXIT
  if [[ $TRANSACTION_ACTIVE == true && $status -ne 0 ]]; then
    if ! rollback; then status=1; fi
  fi
  if [[ $PRESERVE_WORK == true ]]; then
    echo "Installation recovery directory preserved: $WORK" >&2
  else
    rm -rf -- "$WORK"
  fi
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

if [[ $TEST_MODE != true ]] && ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home "$DATA" --shell /usr/sbin/nologin "$SERVICE_USER"
  SERVICE_USER_CREATED=true
fi
SERVICE_GROUP=$(id -gn "$SERVICE_USER")

write_install_env() {
  local target="$CONF/install.env" temporary
  if [[ -e $target || -L $target ]]; then
    [[ -f $target && ! -L $target ]] \
      || { echo "install.env must be a regular file: $target" >&2; return 1; }
  fi
  temporary=$(mktemp "$CONF/install.env.XXXXXX")
  if {
    if [[ -f $target ]]; then
      awk '!/^[[:space:]]*(SECURITY_PUBLIC_HOST|SECURITY_SERVICE_USER)=/' "$target"
    fi
    printf 'SECURITY_PUBLIC_HOST=%s\n' "$HOST"
    printf 'SECURITY_SERVICE_USER=%s\n' "$SERVICE_USER"
  } > "$temporary"; then
    chown root:root "$temporary"
    chmod 600 "$temporary"
    mv -Tf "$temporary" "$target"
  else
    rm -f -- "$temporary"
    return 1
  fi
}

ensure_backup_key() {
  local target=$1 directory temporary size
  directory=$(dirname -- "$target")
  [[ -d $directory && ! -L $directory ]] \
    || { echo "Backup key directory must be a real directory: $directory" >&2; return 1; }
  if [[ -e $target || -L $target ]]; then
    [[ -f $target && ! -L $target ]] \
      || { echo "Backup key must be a regular file: $target" >&2; return 1; }
    size=$(wc -c < "$target")
    ((size >= 32)) \
      || { echo "Backup key is too short: $target" >&2; return 1; }
    chown root:root "$target"
    chmod 600 "$target"
    return 0
  fi
  temporary=$(mktemp "$directory/.appgog-backup-key.XXXXXX")
  if openssl rand -hex 48 > "$temporary"; then
    chown root:root "$temporary"
    chmod 600 "$temporary"
    if ! ln -- "$temporary" "$target"; then
      rm -f -- "$temporary"
      echo "Backup key path appeared during creation: $target" >&2
      return 1
    fi
    rm -f -- "$temporary"
  else
    rm -f -- "$temporary"
    return 1
  fi
}

health_check() (
  local token curl_config=''
  trap '[[ -z $curl_config ]] || rm -f -- "$curl_config"' EXIT
  if [[ -n ${SECURITY_HEALTHCHECK_CMD:-} ]]; then "$SECURITY_HEALTHCHECK_CMD"; return; fi
  "$SYSTEMCTL" is-active "$SERVICE" >/dev/null 2>&1 || return 1
  token=$(<"$CONF/credentials/reader.token")
  curl_config=$(mktemp "$CONF/health.curl.XXXXXX")
  chmod 600 "$curl_config"
  printf '%s\n' \
    'silent' 'show-error' 'fail' 'max-time = 4' \
    "resolve = \"$HOST:9443:127.0.0.1\"" \
    "cacert = \"$CONF/ca.crt\"" \
    "cert = \"$CONF/credentials/reader.crt\"" \
    "key = \"$CONF/credentials/reader.key\"" \
    "header = \"Authorization: Bearer $token\"" \
    "url = \"https://$HOST:9443/v1/status\"" > "$curl_config"
  curl --config "$curl_config" >/dev/null
)

repair_install_permissions() {
  local path
  [[ -d $RELEASE && -x $BASE/runtime/bin/node && -d $CONF && -d $DATA ]] || return 1
  ensure_backup_key "$CONF/backup.key" || return 1
  ensure_backup_key "$CONF/backup.mac.key" || return 1

  chown "root:$SERVICE_GROUP" "$BASE" "$BASE/runtime" "$BASE/runtime/bin" "$BASE/releases"
  chmod 750 "$BASE" "$BASE/runtime" "$BASE/runtime/bin" "$BASE/releases"
  chown -R "root:$SERVICE_GROUP" "$RELEASE"
  find "$RELEASE" -type d -exec chmod 750 {} +
  find "$RELEASE" -type f -exec chmod 640 {} +
  chown -R "root:$SERVICE_GROUP" "$BASE/runtime"
  find "$BASE/runtime" -type d -exec chmod 750 {} +
  find "$BASE/runtime" -type f -perm /111 -exec chmod 750 {} +
  find "$BASE/runtime" -type f ! -perm /111 -exec chmod 640 {} +

  chown "root:$SERVICE_GROUP" "$CONF"
  chmod 750 "$CONF"
  if [[ -d $CONF/credentials ]]; then
    chown -R root:root "$CONF/credentials"
    find "$CONF/credentials" -type d -exec chmod 700 {} +
    find "$CONF/credentials" -type f -exec chmod 600 {} +
    find "$CONF/credentials" -type f -name '*.crt' -exec chmod 640 {} +
  fi
  for path in "$CONF/server.key" "$CONF/server.crt" "$CONF/ca.crt" "$CONF/config.json"; do
    [[ ! -e $path ]] || { chown "root:$SERVICE_GROUP" "$path"; chmod 640 "$path"; }
  done
  for path in "$CONF/ca.key" "$CONF/install.env" "$CONF/service.env" "$CONF/backup.key" "$CONF/backup.mac.key"; do
    [[ ! -e $path ]] || { chown root:root "$path"; chmod 600 "$path"; }
  done

  mkdir -p "$DATA/runtime" "$DATA/backups"
  chown "root:$SERVICE_GROUP" "$DATA"
  chmod 750 "$DATA"
  chown root:root "$DATA/backups"
  chmod 700 "$DATA/backups"
  chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA/runtime"
  chmod 700 "$DATA/runtime"

  runuser -u "$SERVICE_USER" -- "$BASE/runtime/bin/node" -e '
    const fs=require("node:fs");
    for (const path of process.argv.slice(1, 5)) fs.accessSync(path, fs.constants.R_OK);
    fs.accessSync(process.argv[5], fs.constants.R_OK | fs.constants.W_OK);
  ' "$RELEASE/src/server.js" "$CONF/config.json" "$CONF/server.key" "$CONF/ca.crt" "$DATA/runtime"
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
if [[ $CURRENT_VERSION == "$VERSION" && -L $BASE/current ]]; then
  if repair_install_permissions; then
    install -m 700 "$SOURCE/install.sh" "$BASE/install.sh"
    install -m 755 "$SOURCE/scripts/appgog-security.sh" "$BIN_DIR/appgog-security"
    if health_check; then
      write_install_env
      TRANSACTION_ACTIVE=false
      echo "APPGOG cloud security center v$VERSION is already healthy."
      exit 0
    fi
  fi
fi
AUTO_BACKUP=''
if [[ -n $CURRENT_VERSION && -d $BASE/current ]]; then
  if [[ $SERVICE_WAS_ACTIVE == true ]]; then
    "$SYSTEMCTL" stop "$SERVICE"
    ! "$SYSTEMCTL" is-active "$SERVICE" >/dev/null 2>&1 \
      || { echo 'Service did not stop; refusing to create an inconsistent update snapshot.' >&2; exit 1; }
  fi
  AUTO_BACKUP=$(SECURITY_MAINTENANCE_LOCK_FD="$MAINTENANCE_LOCK_FD" bash "$SOURCE/scripts/backup.sh" --print-path)
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
ensure_backup_key "$CONF/backup.key"
ensure_backup_key "$CONF/backup.mac.key"
[[ -f $CONF/config.json ]] || printf '{}\n' > "$CONF/config.json"
TMP_CONFIG=$(mktemp "$CONF/config.XXXXXX")
if appgog_normalize_reader_config "$CONF/config.json" "$CONF/credentials/reader.crt" "$CONF/credentials/reader.token" > "$TMP_CONFIG"; then
  chown "$SERVICE_USER:$SERVICE_GROUP" "$TMP_CONFIG"; chmod 600 "$TMP_CONFIG"; mv "$TMP_CONFIG" "$CONF/config.json"
else
  result=$?; rm -f "$TMP_CONFIG"; exit "$result"
fi
chmod 640 "$CONF/config.json" "$CONF/server.key" "$CONF/server.crt" "$CONF/ca.crt"
chmod 600 "$CONF/ca.key" "$CONF/backup.key" "$CONF/backup.mac.key" "$CONF/credentials/"*.key "$CONF/credentials/"*.token
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

write_install_env
cat > "$CONF/service.env" <<EOF
SECURITY_TLS_KEY=$CONF/server.key
SECURITY_TLS_CERT=$CONF/server.crt
SECURITY_CLIENT_CA=$CONF/ca.crt
SECURITY_CONFIG=$CONF/config.json
SECURITY_STATE_FILE=$DATA/runtime/state.json
SECURITY_PORT=9443
EOF
chmod 600 "$CONF/install.env" "$CONF/service.env"
repair_install_permissions
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
