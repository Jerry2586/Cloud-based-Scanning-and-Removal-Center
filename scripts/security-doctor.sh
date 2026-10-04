#!/usr/bin/env sh
set -eu
umask 077
INSTALL_DIR=${APPGOG_INSTALL_DIR:-/opt/appgog}
[ "$(id -u)" -eq 0 ] || { echo 'Root required to read private credentials' >&2; exit 1; }
[ "$#" -eq 0 ] || { echo 'Usage: sudo sh scripts/security-doctor.sh (set APPGOG_INSTALL_DIR for a custom install)' >&2; exit 2; }
SHARED="$INSTALL_DIR/shared"
ENV_FILE="$SHARED/.env"
SECURITY="$SHARED/security"
ROOT_DIR="$INSTALL_DIR/current"
ROLE_LIBRARY="$ROOT_DIR/scripts/lib/deployment-role.sh"
[ -s "$ENV_FILE" ] && [ -s "$SECURITY/ca.crt" ] && [ -f "$ROLE_LIBRARY" ] || { echo 'Cloud pairing is not installed' >&2; exit 1; }
. "$ROLE_LIBRARY"
ROLE=$(appgog_deployment_role "$ENV_FILE") || exit 1
COMPOSE_FILE=$(appgog_compose_file "$ROOT_DIR" "$ENV_FILE") || exit 1
compose() { docker compose -p "${APPGOG_PROJECT:-appgog}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"; }
case "$ROLE" in all) ROLES='reader license build' ;; license) ROLES='reader license' ;; build) ROLES='reader build' ;; esac
field() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1; }
CLOUD_URL=$(field SECURITY_CLOUD_URL)
case "$CLOUD_URL" in https://*/*|https://*@*|https://*\?*|https://*\#*|'') echo 'Cloud origin is invalid' >&2; exit 1 ;; https://*) ;; *) echo 'Cloud HTTPS is required' >&2; exit 1 ;; esac
printf '%s' "$CLOUD_URL" | LC_ALL=C grep -Eq '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$' || { echo 'Invalid cloud hostname or port' >&2; exit 1; }
PROBE=$(mktemp)
trap 'rm -f "$PROBE"' EXIT HUP INT TERM
for role in $ROLES; do
  case "$role" in reader) expected=reader ;; license) expected=license-center ;; build) expected=build-center ;; esac
  token=$(field "SECURITY_CLOUD_$(printf '%s' "$role" | tr '[:lower:]' '[:upper:]')_TOKEN")
  printf '%s\n' "$token" | LC_ALL=C grep -Eq '^[a-f0-9]{64}$' && [ -s "$SECURITY/$role.crt" ] && [ -s "$SECURITY/$role.key" ] || {
    echo "Missing cloud identity: $role" >&2; exit 1;
  }
  printf 'header = "Authorization: Bearer %s"\n' "$token" > "$PROBE"
  result=$(curl --silent --show-error --fail --max-time 10 --cacert "$SECURITY/ca.crt" \
    --cert "$SECURITY/$role.crt" --key "$SECURITY/$role.key" --config "$PROBE" \
    "$CLOUD_URL/v1/connectivity") || { echo "TLS or cloud authentication failed: $role" >&2; exit 1; }
  printf '%s' "$result" | jq -e --arg expected "$expected" '.identity == $expected' >/dev/null || {
    echo "Cloud identity mismatch: $role" >&2; exit 1;
  }
  echo "Cloud identity accepted: $role"
done
if [ "$ROLE" = build ]; then
  cd "$ROOT_DIR"
  compose exec -T appgog node --input-type=module - <<'NODE'
const { sendReport } = await import('./scripts/security-agent.js');
const result = await sendReport({
  SECURITY_CLOUD_URL: process.env.SECURITY_CLOUD_URL,
  SECURITY_CLOUD_CA: '/app/runtime/security/ca.crt',
  SECURITY_CLOUD_CLIENT_CERT: '/app/runtime/security/build.crt',
  SECURITY_CLOUD_CLIENT_KEY: '/app/runtime/security/build.key',
  SECURITY_CLOUD_TOKEN: process.env.SECURITY_CLOUD_BUILD_TOKEN,
  SECURITY_SCAN_ROOT: '/app',
});
if (result.state !== 'matched') throw new Error(`Build node integrity report: ${result.state}`);
NODE
  echo 'Build identity and integrity report accepted; aggregate status is checked on the license server.'
  exit 0
fi
reader_token=$(field SECURITY_CLOUD_READER_TOKEN)
printf 'header = "Authorization: Bearer %s"\n' "$reader_token" > "$PROBE"
result=$(curl --silent --show-error --fail --max-time 10 --cacert "$SECURITY/ca.crt" \
  --cert "$SECURITY/reader.crt" --key "$SECURITY/reader.key" --config "$PROBE" \
  "$CLOUD_URL/v1/status") || { echo 'Cloud status is unavailable' >&2; exit 1; }
printf '%s' "$result" | jq -e '
  (.nodes | type == "object") and
  (. as $status | all(["license-center", "build-center"][]; . as $role |
    $status.nodes[$role].report_fresh == true and $status.nodes[$role].integrity.state == "matched" and $status.nodes[$role].probe.state == "healthy"))
' >/dev/null || {
  echo 'One or more nodes have stale reports, altered files, or failed external probes' >&2; exit 1;
}
echo 'Both nodes: fresh reports, matching baselines, external HTTPS probes healthy'
