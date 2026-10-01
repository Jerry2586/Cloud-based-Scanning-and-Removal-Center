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
case "$ROLE" in reader) TARGET='.readers[0]' ;; *) TARGET=".nodes[\"$ROLE\"]" ;; esac
[[ -f $BASE.key && -f $BASE.crt && -f $BASE.token ]] || { echo 'Existing identity missing' >&2; exit 1; }
if [[ $ACTION == stage ]]; then
  [[ ! -e $BASE.next.key && ! -e $BASE.next.token ]] || { echo 'Rotation already staged' >&2; exit 1; }
  openssl req -newkey rsa:3072 -nodes -subj "/CN=$ROLE" -keyout "$BASE.next.key" -out "$BASE.next.csr" >/dev/null 2>&1
  openssl x509 -req -in "$BASE.next.csr" -CA "$CONF/ca.crt" -CAkey "$CONF/ca.key" -CAcreateserial -out "$BASE.next.crt" -days 365 -sha256 >/dev/null 2>&1
  openssl rand -hex 32 > "$BASE.next.token"
  FP=$(openssl x509 -in "$BASE.next.crt" -noout -fingerprint -sha256 | cut -d= -f2)
  TOKEN=$(cat "$BASE.next.token")
  TMP=$(mktemp "$CONF/config.XXXXXX")
  trap 'rm -f "$TMP"' EXIT
  jq --arg role "$ROLE" --arg fp "$FP" --arg token "$TOKEN" '
    if $role == "reader" then
      .readers[0].identities = ((.readers[0].identities // [{fingerprint256:.readers[0].fingerprint256,token:.readers[0].token}]) + [{fingerprint256:$fp,token:$token}])
    else
      .nodes[$role].identities = ((.nodes[$role].identities // [{fingerprint256:.nodes[$role].fingerprint256,token:.nodes[$role].token}]) + [{fingerprint256:$fp,token:$token}])
    end
  ' "$CONF/config.json" > "$TMP"
  jq -e --arg role "$ROLE" 'if $role == "reader" then .readers[0].identities|length == 2 else .nodes[$role].identities|length == 2 end' "$TMP" >/dev/null
  chown appgog-security:appgog-security "$TMP"
  chmod 600 "$TMP"
  mv "$TMP" "$CONF/config.json"
  systemctl restart appgog-security.service
  echo "New identity staged. Transfer $BASE.next.crt, .next.key and .next.token through a secure channel; then commit after both ends pass a live check."
else
  [[ -f $BASE.next.key && -f $BASE.next.crt && -f $BASE.next.token ]] || { echo 'No staged rotation' >&2; exit 1; }
  FP=$(openssl x509 -in "$BASE.next.crt" -noout -fingerprint -sha256 | cut -d= -f2)
  TMP=$(mktemp "$CONF/config.XXXXXX")
  trap 'rm -f "$TMP"' EXIT
  jq --arg role "$ROLE" --arg fp "$FP" '
    if $role == "reader" then
      .readers[0].identities |= map(select(.fingerprint256 == $fp))
    else
      .nodes[$role].identities |= map(select(.fingerprint256 == $fp))
    end
  ' "$CONF/config.json" > "$TMP"
  jq -e --arg role "$ROLE" 'if $role == "reader" then .readers[0].identities|length == 1 else .nodes[$role].identities|length == 1 end' "$TMP" >/dev/null
  chown appgog-security:appgog-security "$TMP"
  chmod 600 "$TMP"
  mv "$TMP" "$CONF/config.json"
  systemctl restart appgog-security.service
  mv "$BASE.next.key" "$BASE.key"
  mv "$BASE.next.crt" "$BASE.crt"
  mv "$BASE.next.token" "$BASE.token"
  rm -f "$BASE.next.csr"
  echo "Old identity revoked: $ROLE"
fi
