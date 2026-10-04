#!/usr/bin/env bash
set -euo pipefail
umask 077

BASE=${SECURITY_INSTALL_DIR:-/opt/appgog-security}
CONF=${SECURITY_CONFIG_DIR:-/etc/appgog-security}
DATA=${SECURITY_DATA_DIR:-/var/lib/appgog-security}
SYSTEMCTL=${SECURITY_SYSTEMCTL:-systemctl}
SERVICE=${SECURITY_SERVICE_NAME:-appgog-security.service}
LOCK_FILE=${SECURITY_LOCK_FILE:-/run/lock/appgog-security.lock}
NODE=${SECURITY_NODE_BIN:-$BASE/runtime/bin/node}
SERVICE_USER=${SECURITY_SERVICE_USER:-}
BACKUP=''
NO_SERVICE=false
ALLOW_LEGACY=false
test_checkpoint() {
  [[ ${SECURITY_TEST_FAIL_RESTORE_STEP:-} != "$1" ]] || {
    [[ ${SECURITY_TEST_MODE:-false} == true && ${APPGOG_SECURITY_ALLOW_TEST_MODE:-false} == true ]] || return 1
    echo "Injected restore failure at $1" >&2
    return 97
  }
}
while (($#)); do
  case "$1" in
    --backup) BACKUP=${2:?missing backup file}; shift 2 ;;
    --no-service) NO_SERVICE=true; shift ;;
    --allow-legacy) ALLOW_LEGACY=true; shift ;;
    *) echo 'Usage: restore.sh --backup encrypted-backup [--no-service] [--allow-legacy]' >&2; exit 2 ;;
  esac
done
[[ $EUID -eq 0 && -f $BACKUP ]] || { echo 'Root and an existing backup file are required' >&2; exit 1; }
for path in "$BASE" "$CONF" "$DATA"; do
  [[ $path == /* ]] || { echo "Unsafe path: $path" >&2; exit 1; }
  case "/$path/" in */./*|*/../*) echo "Unsafe path: $path" >&2; exit 1 ;; esac
  [[ $(realpath -m -- "$path") == "$path" ]] || { echo "Unsafe path: $path" >&2; exit 1; }
  case "$path" in /|/opt|/etc|/var|/usr|/usr/local|/usr/local/bin) echo "Unsafe path: $path" >&2; exit 1 ;; esac
done
for tool in openssl tar jq sha256sum flock runuser wc awk; do
  command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done
[[ -x $NODE ]] || { echo "Private Node runtime is missing: $NODE" >&2; exit 1; }
if [[ -z $SERVICE_USER && -s $CONF/install.env ]]; then
  SERVICE_USER=$(sed -n 's/^SECURITY_SERVICE_USER=//p' "$CONF/install.env" | head -n 1)
fi
SERVICE_USER=${SERVICE_USER:-appgog-security}
[[ ${#SERVICE_USER} -le 32 && $SERVICE_USER =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] \
  || { echo "Invalid service user: $SERVICE_USER" >&2; exit 1; }
id "$SERVICE_USER" >/dev/null 2>&1 || { echo "Service user is missing: $SERVICE_USER" >&2; exit 1; }
SERVICE_GROUP=$(id -gn "$SERVICE_USER")

write_target_install_env() {
  local target=$CONF/install.env temp target_identity public_host
  [[ -e $target || -L $target ]] \
    || { echo 'Restored install.env is missing' >&2; return 1; }
  [[ -f $target && ! -L $target ]] \
    || { echo 'Restored install.env must be a regular file' >&2; return 1; }
  target_identity=$(stat -c '%d:%i' "$target")
  public_host=$(sed -n 's/^SECURITY_PUBLIC_HOST=//p' "$target" | head -n 1)
  [[ -n $public_host ]] || { echo 'Restored install.env is missing SECURITY_PUBLIC_HOST' >&2; return 1; }
  temp=$(mktemp "$CONF/install.env.XXXXXX")
  awk '!/^SECURITY_PUBLIC_HOST=/ && !/^SECURITY_SERVICE_USER=/' "$target" > "$temp"
  printf 'SECURITY_PUBLIC_HOST=%s\n' "$public_host" >> "$temp"
  printf 'SECURITY_SERVICE_USER=%s\n' "$SERVICE_USER" >> "$temp"
  chown root:root "$temp"
  chmod 600 "$temp"
  [[ -f $target && ! -L $target && $(stat -c '%d:%i' "$target") == "$target_identity" ]] \
    || { rm -f -- "$temp"; echo 'Restored install.env changed during validation' >&2; return 1; }
  mv -Tf "$temp" "$target"
}

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

KEY=${SECURITY_BACKUP_KEY_FILE:-$CONF/backup.key}
MAC_KEY=${SECURITY_BACKUP_MAC_KEY_FILE:-$CONF/backup.mac.key}
for key_path in "$KEY" "$MAC_KEY"; do
  [[ $key_path == /* && $(realpath -m -- "$key_path") == "$key_path" && ! -L $key_path ]] \
    || { echo "Unsafe backup key path: $key_path" >&2; exit 1; }
  case "$key_path" in "$BASE"|"$BASE"/*) echo "Backup keys may not be stored under $BASE" >&2; exit 1 ;; esac
done
[[ $KEY != "$MAC_KEY" ]] || { echo 'Encryption and authentication keys must be separate files' >&2; exit 1; }
[[ -r $KEY ]] || { echo 'Backup encryption key is missing; restore cannot continue' >&2; exit 1; }
[[ $(wc -c < "$KEY") -ge 32 ]] \
  || { echo 'Backup encryption key must contain at least 32 bytes' >&2; exit 1; }

WORK=$(mktemp -d)
TRANSACTION_ACTIVE=false
ROLLBACK_RUNNING=false
SNAPSHOT_READY=false
SERVICE_WAS_ACTIVE=false
RELEASE_CREATED=false
PRESERVE_WORK=false
cleanup() {
  if [[ $PRESERVE_WORK == true ]]; then
    echo "Recovery snapshot preserved at: $WORK/original" >&2
  else
    rm -rf -- "$WORK"
  fi
}
trap cleanup EXIT

FORMAT_V3=APPGOG-BACKUP-V3
FORMAT_V2=APPGOG-BACKUP-V2
BACKUP_FORMAT=''
BACKUP_SECOND_LINE=''
{
  IFS= read -r BACKUP_FORMAT || true
  IFS= read -r BACKUP_SECOND_LINE || true
} < "$BACKUP"
BACKUP_FORMAT=${BACKUP_FORMAT%$'\r'}
BACKUP_SECOND_LINE=${BACKUP_SECOND_LINE%$'\r'}
case "$BACKUP_FORMAT" in
  "$FORMAT_V3")
    [[ -r $MAC_KEY ]] || { echo 'V3 backup authentication key is missing' >&2; exit 1; }
    [[ $(wc -c < "$MAC_KEY") -ge 32 ]] \
      || { echo 'V3 backup authentication key must contain at least 32 bytes' >&2; exit 1; }
    if ! "$NODE" "$(dirname "$0")/backup-auth.js" verify-extract "$MAC_KEY" "$BACKUP" "$WORK/ciphertext"; then
      echo 'V3 backup authentication failed; no restore data was applied' >&2
      exit 1
    fi
    if ! "$NODE" "$(dirname "$0")/backup-auth.js" derive "$KEY" \
      | openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass stdin \
        -in "$WORK/ciphertext" -out "$WORK/plaintext"; then
      echo 'V3 backup decryption failed; verify the encryption key' >&2
      exit 1
    fi
    INNER_FORMAT=''
    IFS= read -r INNER_FORMAT < "$WORK/plaintext" || true
    [[ $INNER_FORMAT == "$FORMAT_V3" ]] || { echo 'V3 backup inner format is invalid' >&2; exit 1; }
    tail -c +18 "$WORK/plaintext" > "$WORK/archive.tar.gz"
    ;;
  "$FORMAT_V2")
    [[ $ALLOW_LEGACY == true ]] || { echo 'V2 backup refused; retry with --allow-legacy after independent verification' >&2; exit 1; }
    [[ -r $MAC_KEY && -f $BACKUP.hmac ]] || { echo 'V2 backup requires its authentication key and HMAC sidecar' >&2; exit 1; }
    [[ $(wc -c < "$MAC_KEY") -ge 32 ]] \
      || { echo 'V2 backup authentication key must contain at least 32 bytes' >&2; exit 1; }
    "$NODE" "$(dirname "$0")/backup-auth.js" verify "$MAC_KEY" "$BACKUP" "$BACKUP.hmac"
    tail -c +18 "$BACKUP" > "$WORK/ciphertext"
    if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass file:"$KEY" \
      -in "$WORK/ciphertext" -out "$WORK/plaintext"; then
      echo 'V2 backup decryption failed; verify the encryption key' >&2
      exit 1
    fi
    INNER_FORMAT=''
    IFS= read -r INNER_FORMAT < "$WORK/plaintext" || true
    [[ $INNER_FORMAT == "$FORMAT_V2" ]] || { echo 'V2 backup inner format is invalid' >&2; exit 1; }
    tail -c +18 "$WORK/plaintext" > "$WORK/archive.tar.gz"
    ;;
  *)
    [[ ! $BACKUP_SECOND_LINE =~ ^[0-9a-f]{64}$ ]] \
      || { echo 'Authenticated backup header is invalid' >&2; exit 1; }
    [[ ! -e $BACKUP.hmac ]] || { echo 'Backup HMAC exists but its authenticated format marker is missing' >&2; exit 1; }
    [[ $ALLOW_LEGACY == true ]] || { echo 'Legacy backup refused; retry with --allow-legacy after independent verification' >&2; exit 1; }
    [[ -f $BACKUP.sha256 ]] || { echo 'Legacy backup requires its SHA-256 sidecar' >&2; exit 1; }
    (cd "$(dirname "$BACKUP")"; sha256sum -c "$(basename "$BACKUP").sha256" >/dev/null)
    if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass file:"$KEY" \
      -in "$BACKUP" -out "$WORK/archive.tar.gz"; then
      echo 'Legacy backup decryption failed; verify the encryption key' >&2
      exit 1
    fi
    ;;
esac
while IFS= read -r entry; do
  case "$entry" in /*|../*|*/../*|*/..) echo "Unsafe archive entry: $entry" >&2; exit 1 ;; esac
done < <(tar -tzf "$WORK/archive.tar.gz")
mkdir "$WORK/payload"
tar -xzf "$WORK/archive.tar.gz" -C "$WORK/payload"
[[ -f $WORK/payload/backup-manifest.json && -d $WORK/payload/config && -d $WORK/payload/data && -d $WORK/payload/release ]] || {
  echo 'Backup payload is incomplete' >&2; exit 1;
}
find "$WORK/payload" -type l -print -quit | grep -q . && { echo 'Backup payload may not contain symbolic links' >&2; exit 1; }
find "$WORK/payload" -type f -links +1 -print -quit | grep -q . && { echo 'Backup payload may not contain hard links' >&2; exit 1; }
PRODUCT=$(jq -er '.product' "$WORK/payload/backup-manifest.json")
VERSION=$(jq -er '.version' "$WORK/payload/backup-manifest.json")
[[ $PRODUCT == appgog-cloud-security-center && $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Backup identity is invalid' >&2; exit 1; }
[[ $(jq -er '.version' "$WORK/payload/release/package.json") == "$VERSION" ]] || { echo 'Backup release version mismatch' >&2; exit 1; }
for required in config.json ca.crt ca.key server.crt server.key install.env service.env; do
  [[ -f $WORK/payload/config/$required ]] || { echo "Backup configuration is missing: $required" >&2; exit 1; }
done
[[ -d $WORK/payload/config/credentials && -f $WORK/payload/release/src/server.js ]] \
  || { echo 'Backup runtime payload is incomplete' >&2; exit 1; }

RELEASE="$BASE/releases/$VERSION"
if [[ -e $RELEASE ]]; then
  diff -qr "$WORK/payload/release" "$RELEASE" >/dev/null \
    || { echo 'Installed release differs from backup release' >&2; exit 1; }
else
  RELEASE_CREATED=true
fi
[[ -d $CONF && -d $DATA ]] || { echo 'Installed configuration and data directories are required' >&2; exit 1; }
OLD_CURRENT=$(readlink "$BASE/current" 2>/dev/null || true)
if "$SYSTEMCTL" is-active "$SERVICE" >/dev/null 2>&1; then
  SERVICE_WAS_ACTIVE=true
fi
if [[ $NO_SERVICE == true && $SERVICE_WAS_ACTIVE == true ]]; then
  echo 'Refusing --no-service restore while the service is active' >&2
  exit 1
fi

mkdir -p "$WORK/preserved-keys"
KEY_PRESERVED=false
MAC_KEY_PRESERVED=false
case "$KEY" in
  "$CONF"/*|"$DATA"/*) cp -a -- "$KEY" "$WORK/preserved-keys/encryption.key"; KEY_PRESERVED=true ;;
esac
if [[ -r $MAC_KEY ]]; then
  case "$MAC_KEY" in
    "$CONF"/*|"$DATA"/*) cp -a -- "$MAC_KEY" "$WORK/preserved-keys/authentication.key"; MAC_KEY_PRESERVED=true ;;
  esac
fi

restore_original() {
  [[ $ROLLBACK_RUNNING == false ]] || return 0
  ROLLBACK_RUNNING=true
  local rollback_failed=false mode uid gid
  set +e
  echo 'Restore transaction failed; returning the original state.' >&2

  if [[ ${SECURITY_TEST_FAIL_ROLLBACK_STEP:-} == before-original-restore ]]; then
    if [[ ${SECURITY_TEST_MODE:-false} == true && ${APPGOG_SECURITY_ALLOW_TEST_MODE:-false} == true ]]; then
      echo 'Injected rollback failure before original restore' >&2
    fi
    rollback_failed=true
  fi

  if [[ $SNAPSHOT_READY == true && $rollback_failed == false ]]; then
    mkdir -p "$CONF" "$DATA" || rollback_failed=true
    if [[ $rollback_failed == false ]]; then
      find "$CONF" -mindepth 1 -maxdepth 1 ! -name backup.key ! -name backup.mac.key ! -name github-release.token -exec rm -rf -- {} + \
        || rollback_failed=true
    fi
    [[ $rollback_failed == true ]] || cp -a "$WORK/original/config/." "$CONF/" || rollback_failed=true
    if [[ $rollback_failed == false ]]; then
      find "$DATA" -mindepth 1 -maxdepth 1 ! -name backups -exec rm -rf -- {} + || rollback_failed=true
    fi
    [[ $rollback_failed == true ]] || cp -a "$WORK/original/data/." "$DATA/" || rollback_failed=true
    if [[ $rollback_failed == false ]]; then
      read -r mode uid gid <<< "$CONF_META"
      chmod "$mode" "$CONF" && chown "$uid:$gid" "$CONF" || rollback_failed=true
      read -r mode uid gid <<< "$DATA_META"
      chmod "$mode" "$DATA" && chown "$uid:$gid" "$DATA" || rollback_failed=true
    fi
    if [[ $rollback_failed == false ]]; then
      if [[ -n $OLD_CURRENT ]]; then
        ln -sfn "$OLD_CURRENT" "$BASE/current.rollback" && mv -Tf "$BASE/current.rollback" "$BASE/current" \
          || rollback_failed=true
      else
        rm -f -- "$BASE/current" || rollback_failed=true
      fi
    fi
    if [[ $rollback_failed == false && $RELEASE_CREATED == true ]]; then
      rm -rf -- "$RELEASE" || rollback_failed=true
    fi
  fi

  if [[ $rollback_failed == false && $NO_SERVICE != true ]]; then
    "$SYSTEMCTL" daemon-reload || rollback_failed=true
    if [[ $rollback_failed == false ]]; then
      if [[ $SERVICE_WAS_ACTIVE == true ]]; then
        "$SYSTEMCTL" restart "$SERVICE" || rollback_failed=true
      else
        "$SYSTEMCTL" stop "$SERVICE" || rollback_failed=true
      fi
    fi
  fi

  if [[ $rollback_failed == true ]]; then
    PRESERVE_WORK=true
    echo 'Automatic rollback did not complete; the service remains stopped for manual recovery.' >&2
    return 1
  fi
  set -e
  return 0
}

transaction_exit() {
  local status=$?
  trap - EXIT
  if [[ $TRANSACTION_ACTIVE == true && $status -ne 0 ]]; then
    restore_original || status=1
  fi
  cleanup
  exit "$status"
}
trap transaction_exit EXIT

TRANSACTION_ACTIVE=true
if [[ $NO_SERVICE != true ]]; then
  "$SYSTEMCTL" stop "$SERVICE"
  if "$SYSTEMCTL" is-active "$SERVICE" >/dev/null 2>&1; then
    echo 'Service did not stop; restore aborted before snapshot creation' >&2
    exit 1
  fi
fi

mkdir -p "$WORK/original/config" "$WORK/original/data"
tar -C "$CONF" -cf - . | tar -C "$WORK/original/config" -xf -
tar -C "$DATA" --exclude='./backups' -cf - . | tar -C "$WORK/original/data" -xf -
CONF_META=$(stat -c '%a %u %g' "$CONF")
DATA_META=$(stat -c '%a %u %g' "$DATA")
SNAPSHOT_READY=true

mkdir -p "$BASE/releases" "$CONF" "$DATA"
find "$CONF" -mindepth 1 -maxdepth 1 ! -name backup.key ! -name backup.mac.key ! -name github-release.token -exec rm -rf -- {} +
test_checkpoint after-config-clear
cp -a "$WORK/payload/config/." "$CONF/"
find "$DATA" -mindepth 1 -maxdepth 1 ! -name backups -exec rm -rf -- {} +
test_checkpoint after-data-clear
cp -a "$WORK/payload/data/." "$DATA/"
if [[ $KEY_PRESERVED == true ]]; then
  mkdir -p -- "$(dirname "$KEY")"
  install -m 600 "$WORK/preserved-keys/encryption.key" "$KEY"
fi
if [[ $MAC_KEY_PRESERVED == true ]]; then
  mkdir -p -- "$(dirname "$MAC_KEY")"
  install -m 600 "$WORK/preserved-keys/authentication.key" "$MAC_KEY"
fi
write_target_install_env
test_checkpoint after-install-env
if [[ ! -e $RELEASE ]]; then
  mkdir "$RELEASE"
  cp -a "$WORK/payload/release/." "$RELEASE/"
fi
ln -sfn "$RELEASE" "$BASE/current.restore"
mv -Tf "$BASE/current.restore" "$BASE/current"
test_checkpoint after-current-switch
if ! jq -e 'type == "object"' "$CONF/config.json" >/dev/null \
  || ! openssl verify -CAfile "$CONF/ca.crt" "$CONF/server.crt" >/dev/null 2>&1; then
  echo 'Restored configuration validation failed' >&2
  exit 1
fi
chown "root:$SERVICE_GROUP" "$BASE" "$BASE/runtime" "$BASE/runtime/bin" "$BASE/releases"
chmod 750 "$BASE" "$BASE/runtime" "$BASE/runtime/bin" "$BASE/releases"
chown -R "root:$SERVICE_GROUP" "$RELEASE"
find "$RELEASE" -type d -exec chmod 750 {} +
find "$RELEASE" -type f -exec chmod 640 {} +
chown "root:$SERVICE_GROUP" "$CONF"
chmod 750 "$CONF"
chown -R root:root "$CONF/credentials"
find "$CONF/credentials" -type d -exec chmod 700 {} +
find "$CONF/credentials" -type f -exec chmod 600 {} +
find "$CONF/credentials" -type f -name '*.crt' -exec chmod 640 {} +
chown "root:$SERVICE_GROUP" "$CONF/server.key" "$CONF/server.crt" "$CONF/ca.crt" "$CONF/config.json"
chmod 640 "$CONF/server.key" "$CONF/server.crt" "$CONF/ca.crt" "$CONF/config.json"
chown root:root "$CONF/ca.key" "$CONF/install.env" "$CONF/service.env" "$KEY"
chmod 600 "$CONF/ca.key" "$CONF/install.env" "$CONF/service.env" "$KEY"
if [[ -r $MAC_KEY ]]; then
  chown root:root "$MAC_KEY"
  chmod 600 "$MAC_KEY"
fi
mkdir -p "$DATA/runtime" "$DATA/backups"
if [[ -f $DATA/state.json && ! -e $DATA/runtime/state.json ]]; then
  mv "$DATA/state.json" "$DATA/runtime/state.json"
fi
chown "root:$SERVICE_GROUP" "$DATA"
chown root:root "$DATA/backups"
chmod 750 "$DATA"
chmod 700 "$DATA/backups"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA/runtime"
chmod 700 "$DATA/runtime"
runuser -u "$SERVICE_USER" -- "$NODE" -e '
  const fs=require("node:fs");
  for (const path of process.argv.slice(1, 5)) fs.accessSync(path, fs.constants.R_OK);
  fs.accessSync(process.argv[5], fs.constants.R_OK | fs.constants.W_OK);
' "$RELEASE/src/server.js" "$CONF/config.json" "$CONF/server.key" "$CONF/ca.crt" "$DATA/runtime"
if [[ $NO_SERVICE != true ]]; then
  "$SYSTEMCTL" daemon-reload
  if [[ $SERVICE_WAS_ACTIVE == true ]]; then
    "$SYSTEMCTL" restart "$SERVICE"
  else
    "$SYSTEMCTL" stop "$SERVICE"
  fi
fi
TRANSACTION_ACTIVE=false
echo "Backup restored: v$VERSION"
