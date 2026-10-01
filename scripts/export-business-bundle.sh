#!/usr/bin/env bash
set -euo pipefail
umask 077
ROLE=${1:-}
DEST=${2:-}
CONF=${SECURITY_CONFIG_DIR:-/etc/appgog-security}
case "$ROLE" in all) identities=(reader:reader license-center:license build-center:build) ;; license) identities=(reader:reader license-center:license) ;; build) identities=(build-center:build) ;; *) echo 'Usage: sudo export-business-bundle.sh all|license|build /root/new-private-bundle-directory' >&2; exit 2 ;; esac
[[ $EUID -eq 0 && -n $DEST && ! -e $DEST && -s $CONF/ca.crt ]] || { echo 'Root, a new destination, and an installed CA are required' >&2; exit 2; }
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
echo "Bundle for $ROLE exported to $DEST. Transfer privately and erase staging copies after pairing. Never include ca.key."
