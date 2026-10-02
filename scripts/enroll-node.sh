#!/usr/bin/env bash
set -euo pipefail
umask 077

ROLE=${1:-}
HEALTH_URL=${2:-}
BASELINE_FILE=${3:-}
CONF=${SECURITY_CONFIG_DIR:-/etc/appgog-security}
SYSTEMCTL=${SECURITY_SYSTEMCTL:-systemctl}
SERVICE=${SECURITY_SERVICE_NAME:-appgog-security.service}

usage() {
  echo 'Usage: sudo enroll-node.sh license-center|build-center https://host/health /absolute/trusted-baseline.json' >&2
  exit 2
}

[[ $EUID -eq 0 ]] || usage
[[ $ROLE =~ ^(license-center|build-center)$ ]] || usage
[[ $HEALTH_URL == https://* && $HEALTH_URL != *'@'* && $HEALTH_URL != *[[:space:]]* ]] || usage
[[ $BASELINE_FILE == /* && -f $BASELINE_FILE && ! -L $BASELINE_FILE ]] || usage
[[ $(realpath -m -- "$BASELINE_FILE") == "$BASELINE_FILE" ]] || usage
[[ -s $CONF/config.json && -s $CONF/ca.crt && -s $CONF/ca.key && -d $CONF/credentials ]] \
  || { echo 'Security center configuration or CA is incomplete' >&2; exit 1; }

# Baselines are accepted only as canonical, non-empty SHA-256 maps from a trusted release.
jq -e 'type == "object" and length > 0 and all(.[]; type == "string" and test("^[0-9a-f]{64}$"))' \
  "$BASELINE_FILE" >/dev/null || { echo 'Baseline must be a non-empty object of lowercase SHA-256 digests' >&2; exit 1; }

for suffix in key csr crt token; do
  [[ ! -e $CONF/credentials/$ROLE.$suffix ]] \
    || { echo 'Identity already exists; use a planned rotation, do not overwrite it' >&2; exit 1; }
done

CONFIG_OWNER=$(stat -c '%U' "$CONF/config.json")
CONFIG_GROUP=$(stat -c '%G' "$CONF/config.json")
WORK=$(mktemp -d "$CONF/enroll.$ROLE.XXXXXX")
CANDIDATE=$(mktemp "$CONF/config.XXXXXX")
BACKUP=$(mktemp "$CONF/config.backup.XXXXXX")
CONFIG_REPLACED=0
CREDENTIALS_INSTALLED=0

cleanup() {
  local status=$?
  trap - EXIT
  if ((status != 0)); then
    if ((CONFIG_REPLACED == 1)) && [[ -s $BACKUP ]]; then
      mv -f -- "$BACKUP" "$CONF/config.json"
    fi
    if ((CREDENTIALS_INSTALLED == 1)); then
      rm -f -- "$CONF/credentials/$ROLE.key" "$CONF/credentials/$ROLE.csr" \
        "$CONF/credentials/$ROLE.crt" "$CONF/credentials/$ROLE.token"
    fi
    "$SYSTEMCTL" restart "$SERVICE" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$WORK"
  rm -f -- "$CANDIDATE" "$BACKUP"
  exit "$status"
}
trap cleanup EXIT

openssl req -newkey rsa:3072 -nodes -subj "/CN=$ROLE" \
  -keyout "$WORK/$ROLE.key" -out "$WORK/$ROLE.csr" >/dev/null 2>&1
openssl x509 -req -in "$WORK/$ROLE.csr" -CA "$CONF/ca.crt" -CAkey "$CONF/ca.key" \
  -CAcreateserial -out "$WORK/$ROLE.crt" -days 365 -sha256 >/dev/null 2>&1
openssl rand -hex 32 > "$WORK/$ROLE.token"

FP=$(openssl x509 -in "$WORK/$ROLE.crt" -noout -fingerprint -sha256 | cut -d= -f2)
TOKEN=$(<"$WORK/$ROLE.token")
ISSUED_AT=$(date -u -d "$(openssl x509 -in "$WORK/$ROLE.crt" -noout -startdate | cut -d= -f2-)" +%Y-%m-%dT%H:%M:%SZ)
NOT_AFTER=$(date -u -d "$(openssl x509 -in "$WORK/$ROLE.crt" -noout -enddate | cut -d= -f2-)" +%Y-%m-%dT%H:%M:%SZ)

jq --arg role "$ROLE" --arg url "$HEALTH_URL" --arg fp "$FP" --arg token "$TOKEN" \
  --arg issued "$ISSUED_AT" --arg expires "$NOT_AFTER" --slurpfile baseline "$BASELINE_FILE" \
  '.nodes[$role] = {role:$role,health_url:$url,identities:[{fingerprint256:$fp,token:$token,status:"active",issued_at:$issued,cert_not_after:$expires}],baseline:$baseline[0]}' \
  "$CONF/config.json" > "$CANDIDATE"
jq -e --arg role "$ROLE" '.nodes[$role].role == $role and (.nodes[$role].identities | length) == 1' \
  "$CANDIDATE" >/dev/null
chown "$CONFIG_OWNER:$CONFIG_GROUP" "$CANDIDATE"
chmod 600 "$CANDIDATE"
cp -p -- "$CONF/config.json" "$BACKUP"

CREDENTIALS_INSTALLED=1
install -m 600 "$WORK/$ROLE.key" "$CONF/credentials/$ROLE.key"
install -m 600 "$WORK/$ROLE.token" "$CONF/credentials/$ROLE.token"
install -m 640 "$WORK/$ROLE.crt" "$CONF/credentials/$ROLE.crt"
install -m 600 "$WORK/$ROLE.csr" "$CONF/credentials/$ROLE.csr"
mv -f -- "$CANDIDATE" "$CONF/config.json"
CONFIG_REPLACED=1

if ! "$SYSTEMCTL" restart "$SERVICE"; then
  echo 'Service rejected the new node; previous configuration restored and new credentials removed' >&2
  exit 1
fi

CONFIG_REPLACED=0
CREDENTIALS_INSTALLED=0
rm -f -- "$BACKUP"
echo "Node $ROLE enrolled. Export its business identity from the root management menu; no token or private key was printed."
