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
install -d -m 700 "$DEST"
cp "$CONF/ca.crt" "$DEST/ca.crt"
for entry in "${identities[@]}"; do
  source_role=${entry%%:*}; target_role=${entry#*:}
  for suffix in crt key token; do cp "$CONF/credentials/$source_role.$suffix" "$DEST/$target_role.$suffix"; done
done
chmod 600 "$DEST"/*
CA_FP=$(openssl x509 -in "$CONF/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)
jq -n --arg profile "$ROLE" --arg ca_fingerprint "$CA_FP" --arg created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson roles "$(printf '%s\n' "${identities[@]#*:}" | jq -R . | jq -s .)" \
  '{schema:1,profile:$profile,roles:$roles,ca_sha256_fingerprint:$ca_fingerprint,created_at:$created_at}' > "$DEST/bundle.json"
chmod 600 "$DEST/bundle.json"
echo "Bundle for $ROLE exported to $DEST. It contains business identities only; transfer privately and erase staging copies after pairing. Never include ca.key or reader credentials."
