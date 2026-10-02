#!/usr/bin/env bash
set -euo pipefail
umask 077

BASE=${SECURITY_INSTALL_DIR:-/opt/appgog-security}
CONF=${SECURITY_CONFIG_DIR:-/etc/appgog-security}
DATA=${SECURITY_DATA_DIR:-/var/lib/appgog-security}
SYSTEMCTL=${SECURITY_SYSTEMCTL:-systemctl}
SERVICE=${SECURITY_SERVICE_NAME:-appgog-security.service}
BACKUP=''
NO_SERVICE=false
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
    *) echo 'Usage: restore.sh --backup encrypted-backup [--no-service]' >&2; exit 2 ;;
  esac
done
[[ $EUID -eq 0 && -f $BACKUP ]] || { echo 'Root and an existing backup file are required' >&2; exit 1; }
for path in "$BASE" "$CONF" "$DATA"; do
  [[ $path == /* ]] || { echo "Unsafe path: $path" >&2; exit 1; }
  case "/$path/" in */./*|*/../*) echo "Unsafe path: $path" >&2; exit 1 ;; esac
  [[ $(realpath -m -- "$path") == "$path" ]] || { echo "Unsafe path: $path" >&2; exit 1; }
  case "$path" in /|/opt|/etc|/var|/usr|/usr/local|/usr/local/bin) echo "Unsafe path: $path" >&2; exit 1 ;; esac
done
KEY=${SECURITY_BACKUP_KEY_FILE:-$CONF/backup.key}
[[ -r $KEY ]] || { echo 'Backup key is missing; restore cannot continue' >&2; exit 1; }
if [[ -f $BACKUP.sha256 ]]; then (cd "$(dirname "$BACKUP")"; sha256sum -c "$(basename "$BACKUP").sha256" >/dev/null); fi

WORK=$(mktemp -d)
TRANSACTION_ACTIVE=false
ROLLBACK_RUNNING=false
SERVICE_WAS_ACTIVE=false
RELEASE_CREATED=false
cleanup() { rm -rf -- "$WORK"; }
transaction_exit() {
  status=$?
  trap - EXIT
  if [[ $TRANSACTION_ACTIVE == true && $status -ne 0 ]]; then restore_original; fi
  cleanup
  exit "$status"
}
trap transaction_exit EXIT
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass file:"$KEY" -in "$BACKUP" -out "$WORK/archive.tar.gz"
while IFS= read -r entry; do
  case "$entry" in /*|../*|*/../*|*/..) echo "Unsafe archive entry: $entry" >&2; exit 1 ;; esac
done < <(tar -tzf "$WORK/archive.tar.gz")
mkdir "$WORK/payload"
tar -xzf "$WORK/archive.tar.gz" -C "$WORK/payload"
[[ -f $WORK/payload/backup-manifest.json && -d $WORK/payload/config && -d $WORK/payload/data && -d $WORK/payload/release ]] || {
  echo 'Backup payload is incomplete' >&2; exit 1;
}
find "$WORK/payload" -type l -print -quit | grep -q . && { echo 'Backup payload may not contain symbolic links' >&2; exit 1; }
PRODUCT=$(jq -er '.product' "$WORK/payload/backup-manifest.json")
VERSION=$(jq -er '.version' "$WORK/payload/backup-manifest.json")
[[ $PRODUCT == appgog-cloud-security-center && $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Backup identity is invalid' >&2; exit 1; }
[[ $(jq -er '.version' "$WORK/payload/release/package.json") == "$VERSION" ]] || { echo 'Backup release version mismatch' >&2; exit 1; }

mkdir -p "$WORK/original/config" "$WORK/original/data"
if [[ -d $CONF ]]; then tar -C "$CONF" -cf - . | tar -C "$WORK/original/config" -xf -; fi
if [[ -d $DATA ]]; then tar -C "$DATA" --exclude='./backups' -cf - . | tar -C "$WORK/original/data" -xf -; fi
CONF_META=$(stat -c '%a %u %g' "$CONF")
DATA_META=$(stat -c '%a %u %g' "$DATA")
OLD_CURRENT=$(readlink "$BASE/current" 2>/dev/null || true)
RELEASE="$BASE/releases/$VERSION"
[[ -e $RELEASE ]] || RELEASE_CREATED=true
if [[ $NO_SERVICE != true ]] && "$SYSTEMCTL" is-active "$SERVICE" >/dev/null 2>&1; then SERVICE_WAS_ACTIVE=true; fi
restore_original() {
  [[ $ROLLBACK_RUNNING == false ]] || return 0
  ROLLBACK_RUNNING=true
  set +e
  echo 'Restore transaction failed; returning the original state.' >&2
  mkdir -p "$CONF" "$DATA"
  find "$CONF" -mindepth 1 -maxdepth 1 ! -name backup.key ! -name github-release.token -exec rm -rf -- {} +
  cp -a "$WORK/original/config/." "$CONF/"
  find "$DATA" -mindepth 1 -maxdepth 1 ! -name backups -exec rm -rf -- {} +
  cp -a "$WORK/original/data/." "$DATA/"
  read -r mode uid gid <<< "$CONF_META"; chmod "$mode" "$CONF"; chown "$uid:$gid" "$CONF"
  read -r mode uid gid <<< "$DATA_META"; chmod "$mode" "$DATA"; chown "$uid:$gid" "$DATA"
  if [[ -n $OLD_CURRENT ]]; then
    ln -sfn "$OLD_CURRENT" "$BASE/current.rollback"
    mv -Tf "$BASE/current.rollback" "$BASE/current"
  else
    rm -f -- "$BASE/current"
  fi
  [[ $RELEASE_CREATED == false ]] || rm -rf -- "$RELEASE"
  if [[ $NO_SERVICE != true ]]; then
    "$SYSTEMCTL" daemon-reload
    if [[ $SERVICE_WAS_ACTIVE == true ]]; then "$SYSTEMCTL" restart "$SERVICE"; else "$SYSTEMCTL" stop "$SERVICE"; fi
  fi
  set -e
}

TRANSACTION_ACTIVE=true
[[ $NO_SERVICE == true ]] || "$SYSTEMCTL" stop "$SERVICE"
mkdir -p "$BASE/releases" "$CONF" "$DATA"
find "$CONF" -mindepth 1 -maxdepth 1 ! -name backup.key ! -name github-release.token -exec rm -rf -- {} +
test_checkpoint after-config-clear
cp -a "$WORK/payload/config/." "$CONF/"
find "$DATA" -mindepth 1 -maxdepth 1 ! -name backups -exec rm -rf -- {} +
test_checkpoint after-data-clear
cp -a "$WORK/payload/data/." "$DATA/"
if [[ -e $RELEASE ]]; then
  diff -qr "$WORK/payload/release" "$RELEASE" >/dev/null || { echo 'Installed release differs from backup release' >&2; exit 1; }
else
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
chown -R root:root "$RELEASE"
if id appgog-security >/dev/null 2>&1; then
  chown root:appgog-security "$CONF/server.key" "$CONF/server.crt" "$CONF/ca.crt" "$CONF/config.json"
  chmod 640 "$CONF/server.key" "$CONF/server.crt" "$CONF/ca.crt" "$CONF/config.json"
  chmod 600 "$CONF/ca.key" "$CONF/backup.key" "$CONF/credentials/"*.key "$CONF/credentials/"*.token
  mkdir -p "$DATA/runtime" "$DATA/backups"
  if [[ -f $DATA/state.json && ! -e $DATA/runtime/state.json ]]; then
    mv "$DATA/state.json" "$DATA/runtime/state.json"
  fi
  chown root:appgog-security "$DATA"
  chown root:root "$DATA/backups"
  chmod 750 "$DATA"
  chmod 700 "$DATA/backups"
  chown -R appgog-security:appgog-security "$DATA/runtime"
  chmod 700 "$DATA/runtime"
fi
[[ $NO_SERVICE == true ]] || { "$SYSTEMCTL" daemon-reload; "$SYSTEMCTL" restart "$SERVICE"; }
TRANSACTION_ACTIVE=false
echo "Backup restored: v$VERSION"
