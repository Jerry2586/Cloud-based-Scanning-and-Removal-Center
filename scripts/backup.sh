#!/usr/bin/env bash
set -euo pipefail
umask 077

BASE=${SECURITY_INSTALL_DIR:-/opt/appgog-security}
CONF=${SECURITY_CONFIG_DIR:-/etc/appgog-security}
DATA=${SECURITY_DATA_DIR:-/var/lib/appgog-security}
OUTPUT=${SECURITY_BACKUP_DIR:-$DATA/backups}
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
for tool in openssl tar jq sha256sum; do command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }; done

mkdir -p "$OUTPUT"
chmod 700 "$OUTPUT"
KEY=${SECURITY_BACKUP_KEY_FILE:-$CONF/backup.key}
if [[ ! -s $KEY ]]; then openssl rand -out "$KEY" 48; chmod 600 "$KEY"; fi
[[ -r $KEY ]] || { echo 'Backup key is not readable' >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/payload/config" "$WORK/payload/data" "$WORK/payload/release"
tar -C "$CONF" --exclude='./backup.key' --exclude='./github-release.token' -cf - . | tar -C "$WORK/payload/config" -xf -
tar -C "$DATA" --exclude='./backups' -cf - . | tar -C "$WORK/payload/data" -xf -
tar -C "$BASE/current" -cf - . | tar -C "$WORK/payload/release" -xf -
VERSION=$(jq -er '.version' "$BASE/current/package.json")
HOST=$(sed -n 's/^SECURITY_PUBLIC_HOST=//p' "$CONF/install.env" 2>/dev/null | head -n 1)
CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
jq -n --arg product appgog-cloud-security-center --arg version "$VERSION" --arg created "$CREATED" --arg host "$HOST" \
  '{schema:1,product:$product,version:$version,created_at:$created,public_host:$host}' > "$WORK/payload/backup-manifest.json"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DEST="$OUTPUT/appgog-security-$VERSION-$STAMP.tar.gz.enc"
tar -C "$WORK/payload" -czf - . | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 -pass file:"$KEY" -out "$DEST"
chmod 600 "$DEST"
sha256sum "$DEST" > "$DEST.sha256"
chmod 600 "$DEST.sha256"
if [[ $PRINT_PATH == true ]]; then printf '%s\n' "$DEST"; else echo "Encrypted backup created: $DEST"; fi
