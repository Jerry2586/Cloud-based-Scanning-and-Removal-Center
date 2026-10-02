#!/usr/bin/env bash
set -euo pipefail
umask 077
ACTION=${1:-}
ROLE=${2:-}
CONF=${SECURITY_CONFIG_DIR:-/etc/appgog-security}
[[ $EUID -eq 0 && $ACTION =~ ^(stage|commit)$ && $ROLE =~ ^(reader|license-center|build-center)$ ]] || {
  echo 'Usage: sudo rotate-identity.sh stage|commit reader|license-center|build-center' >&2; exit 2;
}
[[ -f $CONF/config.json && -f $CONF/ca.key ]] || { echo 'Cloud security center not initialized' >&2; exit 1; }
BASE="$CONF/credentials/$ROLE"
[[ -f $BASE.key && -f $BASE.crt && -f $BASE.token ]] || { echo 'Existing identity missing' >&2; exit 1; }

cleanup_next() {
  rm -f "$BASE.next.key" "$BASE.next.csr" "$BASE.next.crt" "$BASE.next.token"
}

validate_single_active() {
  jq -e --arg role "$ROLE" '
    (if $role == "reader" then .readers[0] else .nodes[$role] end) as $subject |
    ($subject | type == "object") and
    ($subject.identities | type == "array") and
    ($subject.identities | length == 1) and
    ([$subject.identities[] | select((.status // "active") == "active")] | length == 1) and
    ([$subject.identities[] | select(.status == "staged")] | length == 0)
  ' "$CONF/config.json" >/dev/null
}

install_config() {
  local candidate=$1 backup=$2
  chown appgog-security:appgog-security "$candidate"
  chmod 600 "$candidate"
  cp -p "$CONF/config.json" "$backup"
  mv "$candidate" "$CONF/config.json"
  if ! systemctl restart appgog-security.service; then
    mv "$backup" "$CONF/config.json"
    systemctl restart appgog-security.service >/dev/null 2>&1 || true
    return 1
  fi
  rm -f "$backup"
}

if [[ $ACTION == stage ]]; then
  for pending in "$BASE.next.key" "$BASE.next.csr" "$BASE.next.crt" "$BASE.next.token"; do
    [[ ! -e $pending ]] || { echo 'Rotation already staged or incomplete artifacts exist' >&2; exit 1; }
  done
  validate_single_active || { echo 'Identity is not in a clean single-active state' >&2; exit 1; }
  STAGE_COMPLETE=0
  TMP=''
  BACKUP=''
  stage_cleanup() {
    local status=$?
    trap - EXIT
    rm -f "${TMP:-}" "${BACKUP:-}"
    (( STAGE_COMPLETE == 1 )) || cleanup_next
    exit "$status"
  }
  trap stage_cleanup EXIT
  openssl req -newkey rsa:3072 -nodes -subj "/CN=$ROLE" -keyout "$BASE.next.key" -out "$BASE.next.csr" >/dev/null 2>&1
  openssl x509 -req -in "$BASE.next.csr" -CA "$CONF/ca.crt" -CAkey "$CONF/ca.key" -CAcreateserial -out "$BASE.next.crt" -days 365 -sha256 >/dev/null 2>&1
  openssl rand -hex 32 > "$BASE.next.token"
  chmod 600 "$BASE.next.key" "$BASE.next.token"
  FP=$(openssl x509 -in "$BASE.next.crt" -noout -fingerprint -sha256 | cut -d= -f2)
  TOKEN=$(cat "$BASE.next.token")
  ISSUED_AT=$(date -u -d "$(openssl x509 -in "$BASE.next.crt" -noout -startdate | cut -d= -f2-)" +%Y-%m-%dT%H:%M:%SZ)
  NOT_AFTER=$(date -u -d "$(openssl x509 -in "$BASE.next.crt" -noout -enddate | cut -d= -f2-)" +%Y-%m-%dT%H:%M:%SZ)
  TMP=$(mktemp "$CONF/config.XXXXXX")
  BACKUP=$(mktemp "$CONF/config.backup.XXXXXX")
  jq --arg role "$ROLE" --arg fp "$FP" --arg token "$TOKEN" --arg issued "$ISSUED_AT" --arg expires "$NOT_AFTER" '
    if $role == "reader" then
      .readers[0].identities += [{fingerprint256:$fp,token:$token,status:"staged",issued_at:$issued,cert_not_after:$expires}]
    else
      .nodes[$role].identities += [{fingerprint256:$fp,token:$token,status:"staged",issued_at:$issued,cert_not_after:$expires}]
    end
  ' "$CONF/config.json" > "$TMP"
  jq -e --arg role "$ROLE" --arg fp "$FP" --arg token "$TOKEN" '
    (if $role == "reader" then .readers[0].identities else .nodes[$role].identities end) as $ids |
    ($ids | length == 2) and
    ([$ids[] | select((.status // "active") == "active")] | length == 1) and
    ([$ids[] | select(.status == "staged" and .fingerprint256 == $fp and .token == $token)] | length == 1)
  ' "$TMP" >/dev/null
  install_config "$TMP" "$BACKUP" || { echo 'Service rejected staged identity; previous configuration restored' >&2; exit 1; }
  TMP=''
  BACKUP=''
  STAGE_COMPLETE=1
  echo "New identity staged. Transfer $BASE.next.crt, .next.key and .next.token through a secure channel; then commit after both ends pass a live check."
else
  [[ -f $BASE.next.key && -f $BASE.next.csr && -f $BASE.next.crt && -f $BASE.next.token ]] || { echo 'No complete staged rotation' >&2; exit 1; }
  FP=$(openssl x509 -in "$BASE.next.crt" -noout -fingerprint -sha256 | cut -d= -f2)
  TOKEN=$(cat "$BASE.next.token")
  jq -e --arg role "$ROLE" --arg fp "$FP" --arg token "$TOKEN" '
    (if $role == "reader" then .readers[0].identities else .nodes[$role].identities end) as $ids |
    ($ids | type == "array") and ($ids | length == 2) and
    ([$ids[] | select((.status // "active") == "active")] | length == 1) and
    ([$ids[] | select(.status == "staged")] | length == 1) and
    ([$ids[] | select(.status == "staged" and .fingerprint256 == $fp and .token == $token)] | length == 1)
  ' "$CONF/config.json" >/dev/null || { echo 'Staged configuration does not match staged credentials' >&2; exit 1; }
  TMP=$(mktemp "$CONF/config.XXXXXX")
  BACKUP=$(mktemp "$CONF/config.backup.XXXXXX")
  trap 'rm -f "${TMP:-}" "${BACKUP:-}"' EXIT
  jq --arg role "$ROLE" --arg fp "$FP" --arg token "$TOKEN" '
    if $role == "reader" then
      .readers[0].identities |= map(select(.status == "staged" and .fingerprint256 == $fp and .token == $token) | .status = "active")
    else
      .nodes[$role].identities |= map(select(.status == "staged" and .fingerprint256 == $fp and .token == $token) | .status = "active")
    end
  ' "$CONF/config.json" > "$TMP"
  jq -e --arg role "$ROLE" --arg fp "$FP" --arg token "$TOKEN" '
    (if $role == "reader" then .readers[0].identities else .nodes[$role].identities end) as $ids |
    ($ids | length == 1) and $ids[0].status == "active" and
    $ids[0].fingerprint256 == $fp and $ids[0].token == $token
  ' "$TMP" >/dev/null
  install_config "$TMP" "$BACKUP" || { echo 'Service rejected committed identity; previous configuration restored' >&2; exit 1; }
  TMP=''
  BACKUP=''
  mv "$BASE.next.key" "$BASE.key"
  mv "$BASE.next.crt" "$BASE.crt"
  mv "$BASE.next.token" "$BASE.token"
  rm -f "$BASE.next.csr"
  echo "Old identity revoked: $ROLE"
fi
