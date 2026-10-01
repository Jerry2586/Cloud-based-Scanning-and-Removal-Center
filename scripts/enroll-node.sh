#!/usr/bin/env bash
set -euo pipefail
ROLE=${1:-}
HEALTH_URL=${2:-}
BASELINE_FILE=${3:-}
CONF=${SECURITY_CONFIG_DIR:-/etc/appgog-security}
[[ $EUID -eq 0 && $ROLE =~ ^(license-center|build-center)$ && $HEALTH_URL == https://* && -f $BASELINE_FILE ]] || {
  echo 'Usage: sudo enroll-node.sh license-center|build-center https://host/health baseline.json' >&2; exit 2;
}
# Baseline must come from a verified source release, never from the monitored host after a breach.
jq -e 'type == "object" and all(.[]; type == "string" and test("^[0-9a-f]{64}$"))' "$BASELINE_FILE" >/dev/null
[[ ! -e $CONF/credentials/$ROLE.key ]] || { echo 'Identity already exists; use a planned rotation, do not overwrite it' >&2; exit 1; }
openssl req -newkey rsa:3072 -nodes -subj "/CN=$ROLE" -keyout "$CONF/credentials/$ROLE.key" -out "$CONF/credentials/$ROLE.csr" >/dev/null 2>&1
openssl x509 -req -in "$CONF/credentials/$ROLE.csr" -CA "$CONF/ca.crt" -CAkey "$CONF/ca.key" -CAcreateserial -out "$CONF/credentials/$ROLE.crt" -days 365 -sha256 >/dev/null 2>&1
openssl rand -hex 32 > "$CONF/credentials/$ROLE.token"
FP=$(openssl x509 -in "$CONF/credentials/$ROLE.crt" -noout -fingerprint -sha256 | cut -d= -f2)
TOKEN=$(cat "$CONF/credentials/$ROLE.token")
TMP=$(mktemp "$CONF/config.XXXXXX")
jq --arg role "$ROLE" --arg url "$HEALTH_URL" --arg fp "$FP" --arg token "$TOKEN" --slurpfile baseline "$BASELINE_FILE" \
  '.nodes[$role] = {health_url:$url,fingerprint256:$fp,token:$token,baseline:$baseline[0]}' "$CONF/config.json" > "$TMP"
chmod 600 "$TMP"
chown appgog-security:appgog-security "$TMP"
mv "$TMP" "$CONF/config.json"
chmod 600 "$CONF/credentials/$ROLE.key" "$CONF/credentials/$ROLE.token"
systemctl restart appgog-security.service
echo "Node $ROLE enrolled. Transfer ca.crt, $ROLE.crt, $ROLE.key, and $ROLE.token via a secure channel to its server."
