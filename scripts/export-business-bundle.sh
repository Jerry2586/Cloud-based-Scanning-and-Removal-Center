#!/usr/bin/env bash
set -euo pipefail
umask 077
ROLE=${1:-}
DEST=${2:-}
CONF=${SECURITY_CONFIG_DIR:-/etc/appgog-security}
case "$ROLE" in all) identities=(license-center:license build-center:build) ;; license) identities=(license-center:license) ;; build) identities=(build-center:build) ;; *) echo 'Usage: sudo export-business-bundle.sh all|license|build /root/new-private-bundle-directory' >&2; exit 2 ;; esac
[[ $EUID -eq 0 && $DEST == /* && ! -e $DEST && -s $CONF/ca.crt ]] || { echo 'Root, a new absolute destination, and an installed CA are required' >&2; exit 2; }
case "$DEST" in *'/./'*|*'/../'*|*'//'*) echo 'Unsafe export destination' >&2; exit 2 ;; esac
[[ $(realpath -m -- "$DEST") == "$DEST" && $DEST != / && $DEST != /root && $DEST != /etc && $DEST != /opt && $DEST != /var ]] \
  || { echo 'Unsafe export destination' >&2; exit 2; }
for entry in "${identities[@]}"; do
  source_role=${entry%%:*}
  for suffix in crt key token; do
    [[ -s $CONF/credentials/$source_role.$suffix ]] || { echo "Missing identity: $source_role.$suffix" >&2; exit 1; }
  done
done
WORK=$(mktemp -d "${DEST}.tmp.XXXXXX")
cleanup() {
  local status=$?
  trap - EXIT
  [[ -z ${WORK:-} ]] || rm -rf -- "$WORK"
  exit "$status"
}
trap cleanup EXIT

chmod 700 "$WORK"
cp -- "$CONF/ca.crt" "$WORK/ca.crt"
for entry in "${identities[@]}"; do
  source_role=${entry%%:*}; target_role=${entry#*:}
  for suffix in crt key token; do
    cp -- "$CONF/credentials/$source_role.$suffix" "$WORK/$target_role.$suffix"
    cmp -s -- "$CONF/credentials/$source_role.$suffix" "$WORK/$target_role.$suffix" \
      || { echo "Export verification failed: $source_role.$suffix" >&2; exit 1; }
  done
  openssl verify -CAfile "$WORK/ca.crt" "$WORK/$target_role.crt" >/dev/null \
    || { echo "Certificate verification failed: $source_role" >&2; exit 1; }
  EXPORTED_FP=$(openssl x509 -in "$WORK/$target_role.crt" -noout -fingerprint -sha256 | cut -d= -f2)
  EXPORTED_DIGEST=$(tr -d '\r\n' < "$WORK/$target_role.token" | sha256sum | awk '{print $1}')
  jq -e --arg role "$source_role" --arg fp "$EXPORTED_FP" --arg digest "$EXPORTED_DIGEST" '
    .nodes[$role].identities as $ids |
    ($ids | type == "array") and
    ([$ids[] | select((.status // "active") == "active" and .fingerprint256 == $fp and .token_sha256 == $digest)] | length == 1)
  ' "$CONF/config.json" >/dev/null \
    || { echo "Exported identity does not match active configuration: $source_role" >&2; exit 1; }
done
chmod 600 "$WORK"/*
CA_FP=$(openssl x509 -in "$CONF/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)
jq -n --arg profile "$ROLE" --arg ca_fingerprint "$CA_FP" --arg created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson roles "$(printf '%s\n' "${identities[@]#*:}" | jq -R . | jq -s .)" \
  '{schema:1,profile:$profile,roles:$roles,ca_sha256_fingerprint:$ca_fingerprint,created_at:$created_at,one_time_export:true}' > "$WORK/bundle.json"
chmod 600 "$WORK/bundle.json"
jq -e --arg profile "$ROLE" '.schema == 1 and .profile == $profile and .one_time_export == true and (.roles | length) > 0' \
  "$WORK/bundle.json" >/dev/null

mv -- "$WORK" "$DEST"
WORK=''
for entry in "${identities[@]}"; do
  source_role=${entry%%:*}
  rm -f -- "$CONF/credentials/$source_role.key" "$CONF/credentials/$source_role.csr" \
    "$CONF/credentials/$source_role.crt" "$CONF/credentials/$source_role.token"
  for suffix in key csr crt token; do
    [[ ! -e $CONF/credentials/$source_role.$suffix ]] \
      || { echo "Failed to remove exported cloud credential: $source_role.$suffix" >&2; exit 1; }
  done
done
echo "Bundle for $ROLE exported once to $DEST. Cloud copies of the selected business private keys and tokens were removed; keep the bundle offline until pairing is complete."
