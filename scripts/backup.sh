#!/usr/bin/env bash
set -euo pipefail
umask 077

BASE=${SECURITY_INSTALL_DIR:-/opt/appgog-security}
CONF=${SECURITY_CONFIG_DIR:-/etc/appgog-security}
DATA=${SECURITY_DATA_DIR:-/var/lib/appgog-security}
OUTPUT=${SECURITY_BACKUP_DIR:-$DATA/backups}
LOCK_FILE=${SECURITY_LOCK_FILE:-/run/lock/appgog-security.lock}
NODE=${SECURITY_NODE_BIN:-$BASE/runtime/bin/node}
PRINT_PATH=false
while (($#)); do
  case "$1" in
    --output-dir) OUTPUT=${2:?missing output directory}; shift 2 ;;
    --print-path) PRINT_PATH=true; shift ;;
    *) echo "Usage: backup.sh [--output-dir directory] [--print-path]" >&2; exit 2 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
for path in "$BASE" "$CONF" "$DATA" "$OUTPUT"; do
  [[ $path == /* ]] || { echo "Unsafe path: $path" >&2; exit 1; }
  case "/$path/" in */./*|*/../*) echo "Unsafe path: $path" >&2; exit 1 ;; esac
  [[ $(realpath -m -- "$path") == "$path" ]] || { echo "Unsafe path: $path" >&2; exit 1; }
  case "$path" in /|/opt|/etc|/var|/usr|/usr/local|/usr/local/bin) echo "Unsafe path: $path" >&2; exit 1 ;; esac
done
[[ -d $BASE/current && -d $CONF && -d $DATA ]] || { echo 'Installed program, configuration, and data are required' >&2; exit 1; }
for required in config.json ca.crt ca.key server.crt server.key install.env service.env; do
  [[ -f $CONF/$required ]] || { echo "Installed configuration is incomplete: $required" >&2; exit 1; }
done
[[ -d $CONF/credentials && -f $BASE/current/src/server.js && -f $BASE/current/package.json ]] \
  || { echo 'Installed runtime payload is incomplete' >&2; exit 1; }
for tool in openssl tar jq flock wc; do command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }; done
[[ -x $NODE ]] || { echo "Private Node runtime is missing: $NODE" >&2; exit 1; }
LOCK_DIR=$(dirname -- "$LOCK_FILE")
[[ $LOCK_FILE == /* && $(realpath -m -- "$LOCK_FILE") == "$LOCK_FILE" \
  && -d $LOCK_DIR && ! -L $LOCK_DIR && ! -L $LOCK_FILE ]] \
  || { echo "Unsafe maintenance lock path: $LOCK_FILE" >&2; exit 1; }
if [[ -e $LOCK_FILE || -L $LOCK_FILE ]]; then
  [[ -f $LOCK_FILE && ! -L $LOCK_FILE ]] \
    || { echo "Maintenance lock must be a regular file: $LOCK_FILE" >&2; exit 1; }
fi
if [[ -n ${SECURITY_MAINTENANCE_LOCK_FD:-} ]]; then
  MAINTENANCE_LOCK_FD=$SECURITY_MAINTENANCE_LOCK_FD
  [[ $MAINTENANCE_LOCK_FD =~ ^[0-9]+$ && $MAINTENANCE_LOCK_FD -ge 10 \
    && -f $LOCK_FILE && ! -L $LOCK_FILE \
    && -e /proc/$$/fd/$MAINTENANCE_LOCK_FD \
    && /proc/$$/fd/$MAINTENANCE_LOCK_FD -ef "$LOCK_FILE" ]] \
    || { echo 'Inherited maintenance lock descriptor is invalid' >&2; exit 1; }
else
  exec {MAINTENANCE_LOCK_FD}<>"$LOCK_FILE"
  [[ -f $LOCK_FILE && ! -L $LOCK_FILE && -e /proc/$$/fd/$MAINTENANCE_LOCK_FD \
    && /proc/$$/fd/$MAINTENANCE_LOCK_FD -ef "$LOCK_FILE" ]] \
    || { echo 'Maintenance lock path changed while opening it' >&2; exit 1; }
fi
flock -n "$MAINTENANCE_LOCK_FD" \
  || { echo 'Another APPGOG maintenance transaction is running' >&2; exit 1; }
[[ -f $LOCK_FILE && ! -L $LOCK_FILE && -e /proc/$$/fd/$MAINTENANCE_LOCK_FD \
  && /proc/$$/fd/$MAINTENANCE_LOCK_FD -ef "$LOCK_FILE" ]] \
  || { echo 'Maintenance lock path changed after it was locked' >&2; exit 1; }
if [[ -n ${SECURITY_TEST_OPERATION_LOG_FILE:-} ]]; then
  [[ ${SECURITY_TEST_MODE:-false} == true && ${APPGOG_SECURITY_ALLOW_TEST_MODE:-false} == true ]] \
    || { echo 'Operation logging is restricted to authorized test mode' >&2; exit 1; }
  printf 'backup-start\n' >> "$SECURITY_TEST_OPERATION_LOG_FILE"
fi

mkdir -p "$OUTPUT"
chmod 700 "$OUTPUT"
KEY=${SECURITY_BACKUP_KEY_FILE:-$CONF/backup.key}
MAC_KEY=${SECURITY_BACKUP_MAC_KEY_FILE:-$CONF/backup.mac.key}
for key_path in "$KEY" "$MAC_KEY"; do
  [[ $key_path == /* && $(realpath -m -- "$key_path") == "$key_path" && ! -L $key_path ]] \
    || { echo "Unsafe backup key path: $key_path" >&2; exit 1; }
  case "$key_path" in "$BASE"|"$BASE"/*) echo "Backup keys may not be stored under $BASE" >&2; exit 1 ;; esac
done
[[ $KEY != "$MAC_KEY" ]] || { echo 'Encryption and authentication keys must be separate files' >&2; exit 1; }
ensure_backup_key() {
  local key_path=$1 key_dir temp
  key_dir=$(dirname -- "$key_path")
  [[ -d $key_dir && ! -L $key_dir ]] \
    || { echo "Backup key directory must be a real directory: $key_dir" >&2; return 1; }
  if [[ -e $key_path || -L $key_path ]]; then
    [[ -f $key_path && ! -L $key_path ]] \
      || { echo "Backup key must be a regular file: $key_path" >&2; return 1; }
  else
    temp=$(mktemp "$key_dir/.appgog-backup-key.XXXXXX")
    if ! openssl rand -hex 48 > "$temp"; then
      rm -f -- "$temp"
      return 1
    fi
    chown root:root "$temp"
    chmod 600 "$temp"
    if ! ln -- "$temp" "$key_path"; then
      rm -f -- "$temp"
      echo "Backup key path appeared during creation: $key_path" >&2
      return 1
    fi
    rm -f -- "$temp"
  fi
  [[ -r $key_path && $(wc -c < "$key_path") -ge 32 ]] \
    || { echo "Backup key must be readable and contain at least 32 bytes: $key_path" >&2; return 1; }
  chown root:root "$key_path"
  chmod 600 "$key_path"
}
ensure_backup_key "$KEY"
ensure_backup_key "$MAC_KEY"

WORK=$(mktemp -d)
TEMP_DEST=''
cleanup() {
  rm -rf -- "$WORK"
  [[ -z $TEMP_DEST ]] || rm -f -- "$TEMP_DEST"
}
trap cleanup EXIT
mkdir -p "$WORK/payload/config" "$WORK/payload/data" "$WORK/payload/release"
CONF_EXCLUDES=(--exclude='./github-release.token')
DATA_EXCLUDES=(--exclude='./backups')
for key_path in "$KEY" "$MAC_KEY"; do
  case "$key_path" in
    "$CONF"/*) CONF_EXCLUDES+=(--exclude="./${key_path#"$CONF"/}") ;;
    "$DATA"/*) DATA_EXCLUDES+=(--exclude="./${key_path#"$DATA"/}") ;;
  esac
done
tar -C "$CONF" "${CONF_EXCLUDES[@]}" -cf - . | tar -C "$WORK/payload/config" -xf -
tar -C "$DATA" "${DATA_EXCLUDES[@]}" -cf - . | tar -C "$WORK/payload/data" -xf -
tar -C "$BASE/current" -cf - . | tar -C "$WORK/payload/release" -xf -
VERSION=$(jq -er '.version' "$BASE/current/package.json")
HOST=$(sed -n 's/^SECURITY_PUBLIC_HOST=//p' "$CONF/install.env" 2>/dev/null | head -n 1)
CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
jq -n --arg product appgog-cloud-security-center --arg version "$VERSION" --arg created "$CREATED" --arg host "$HOST" \
  '{schema:1,product:$product,version:$version,created_at:$created,public_host:$host}' > "$WORK/payload/backup-manifest.json"
STAMP="$(date -u +%Y%m%dT%H%M%S%NZ)-$(openssl rand -hex 4)"
DEST="$OUTPUT/appgog-security-$VERSION-$STAMP.tar.gz.enc"
FORMAT=APPGOG-BACKUP-V3
tar -C "$WORK/payload" -czf "$WORK/archive.tar.gz" .
{ printf '%s\n' "$FORMAT"; cat "$WORK/archive.tar.gz"; } > "$WORK/plaintext"
"$NODE" "$(dirname "$0")/backup-auth.js" derive "$KEY" \
  | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 -pass stdin -in "$WORK/plaintext" -out "$WORK/ciphertext"
TEMP_DEST=$(mktemp "$OUTPUT/.appgog-security-backup.XXXXXX")
rm -f -- "$TEMP_DEST"
"$NODE" "$(dirname "$0")/backup-auth.js" pack "$MAC_KEY" "$WORK/ciphertext" "$TEMP_DEST"
chmod 600 "$TEMP_DEST"
mv -f -- "$TEMP_DEST" "$DEST"
TEMP_DEST=''
if [[ $PRINT_PATH == true ]]; then printf '%s\n' "$DEST"; else echo "Encrypted backup created: $DEST"; fi
