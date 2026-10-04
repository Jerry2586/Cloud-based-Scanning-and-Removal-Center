#!/usr/bin/env sh
set -eu
umask 077
CLOUD_URL=''
BUNDLE=''
CA_PIN=''
INSTALL_DIR=${APPGOG_INSTALL_DIR:-/opt/appgog}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --cloud-url) CLOUD_URL=${2:?missing URL}; shift 2 ;;
    --bundle-dir) BUNDLE=${2:?missing bundle}; shift 2 ;;
    --ca-sha256) CA_PIN=${2:?missing CA fingerprint}; shift 2 ;;
    --install-dir) INSTALL_DIR=${2:?missing directory}; shift 2 ;;
    *) echo 'Usage: sudo sh scripts/security-connect.sh --cloud-url https://security.example.com:9443 --bundle-dir /root/security-bundle --ca-sha256 FINGERPRINT [--install-dir /opt/appgog]' >&2; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo 'Root required' >&2; exit 1; }
for utility in openssl curl jq docker; do
  if ! command -v "$utility" >/dev/null 2>&1; then
    case "$utility" in
      docker) echo 'Docker is required; run the platform installer first' >&2; exit 1 ;;
      *) if command -v apt-get >/dev/null 2>&1; then
           apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y "$utility"
         elif command -v dnf >/dev/null 2>&1; then dnf install -y "$utility"
         else echo "Install missing dependency: $utility" >&2; exit 1; fi ;;
    esac
  fi
done
docker compose version >/dev/null 2>&1 || { echo 'Docker Compose v2 is required' >&2; exit 1; }
case "$CLOUD_URL" in https://*/*|https://*@*|https://*\?*|https://*\#*|'') echo 'Use an HTTPS origin without path, userinfo or query' >&2; exit 2 ;; https://*) ;; *) echo 'HTTPS required' >&2; exit 2 ;; esac
printf '%s' "$CLOUD_URL" | LC_ALL=C grep -Eq '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$' || { echo 'Invalid cloud hostname or port' >&2; exit 2; }
ROOT_DIR="$INSTALL_DIR/current"
ENV_FILE="$INSTALL_DIR/shared/.env"
ROLE_LIBRARY="$ROOT_DIR/scripts/lib/deployment-role.sh"
[ -d "$BUNDLE" ] && [ -s "$BUNDLE/ca.crt" ] && [ -f "$ENV_FILE" ] && [ -f "$ROLE_LIBRARY" ] || { echo 'Install the platform and provide the cloud credential bundle first' >&2; exit 1; }
. "$ROLE_LIBRARY"
ROLE=$(appgog_deployment_role "$ENV_FILE") || exit 1
COMPOSE_FILE=$(appgog_compose_file "$ROOT_DIR" "$ENV_FILE") || exit 1
compose() { docker compose -p "${APPGOG_PROJECT:-appgog}" --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"; }
# First trust is pinned through an independent channel; routine re-pairing cannot replace the CA.
new_ca=$(openssl x509 -in "$BUNDLE/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]')
printf '%s' "$new_ca" | LC_ALL=C grep -Eq '^[a-f0-9]{64}$' || { echo 'Invalid cloud CA certificate' >&2; exit 1; }
if [ -s "$INSTALL_DIR/shared/security/ca.crt" ]; then
  old_ca=$(openssl x509 -in "$INSTALL_DIR/shared/security/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]')
  [ "$new_ca" = "$old_ca" ] || { echo 'Cloud CA changed. Stop pairing; use an audited offline CA recovery procedure' >&2; exit 1; }
else
  [ -n "$CA_PIN" ] || { echo 'First pairing requires --ca-sha256 from the independent cloud console' >&2; exit 1; }
fi
if [ -n "$CA_PIN" ]; then
  pin=$(printf '%s' "$CA_PIN" | tr -d ':' | tr '[:upper:]' '[:lower:]')
  [ "$pin" = "$new_ca" ] || { echo 'Cloud CA fingerprint mismatch; existing deployment unchanged' >&2; exit 1; }
fi
case "$ROLE" in all) ROLES='reader license build' ;; license) ROLES='reader license' ;; build) ROLES='reader build' ;; esac
for role in $ROLES; do
  for suffix in crt key token; do
    [ -s "$BUNDLE/$role.$suffix" ] || { echo "Missing $role.$suffix" >&2; exit 1; }
  done
  openssl verify -CAfile "$BUNDLE/ca.crt" "$BUNDLE/$role.crt" >/dev/null
  openssl x509 -in "$BUNDLE/$role.crt" -checkend 604800 -noout >/dev/null
  cert_pub=$(openssl x509 -in "$BUNDLE/$role.crt" -pubkey -noout | openssl sha256)
  key_pub=$(openssl pkey -in "$BUNDLE/$role.key" -pubout | openssl sha256)
  [ "$cert_pub" = "$key_pub" ] || { echo "Key mismatch: $role" >&2; exit 1; }
  LC_ALL=C grep -Eq '^[a-f0-9]{64}$' "$BUNDLE/$role.token" || { echo "Invalid token: $role" >&2; exit 1; }
done
# Probe the actual hostname and reader identity before touching a running installation.
PROBE=$(mktemp)
STAGE=''
ENV_STAGE=''
cleanup() {
  rm -f "$PROBE"
  [ -z "$STAGE" ] || rm -rf "$STAGE"
  [ -z "$ENV_STAGE" ] || rm -f "$ENV_STAGE"
}
trap cleanup EXIT HUP INT TERM
# Verify every future credential against the running cloud before changing the installation.
# This read-only endpoint also verifies that a credential is assigned to its intended role.
for role in $ROLES; do
  case "$role" in reader) expected=reader ;; license) expected=license-center ;; build) expected=build-center ;; esac
  printf 'header = "Authorization: Bearer %s"\n' "$(cat "$BUNDLE/$role.token")" > "$PROBE"
  response=$(curl --silent --show-error --fail --max-time 10 --cacert "$BUNDLE/ca.crt" \
    --cert "$BUNDLE/$role.crt" --key "$BUNDLE/$role.key" --config "$PROBE" \
    "$CLOUD_URL/v1/connectivity") || {
      echo "Cloud TLS and authorization check failed for $role; existing deployment unchanged" >&2; exit 1;
    }
  printf '%s' "$response" | jq -e --arg expected "$expected" '.identity == $expected' >/dev/null || {
    echo "Cloud identity mismatch for $role; existing deployment unchanged" >&2; exit 1;
  }
done
# Use cloud time for the post-restart freshness gate; business and cloud clocks may differ.
CUTOFF=''
if [ "$ROLE" != build ]; then
  printf 'header = "Authorization: Bearer %s"\n' "$(cat "$BUNDLE/reader.token")" > "$PROBE"
  before=$(curl --silent --show-error --fail --max-time 10 --cacert "$BUNDLE/ca.crt" \
    --cert "$BUNDLE/reader.crt" --key "$BUNDLE/reader.key" --config "$PROBE" \
    "$CLOUD_URL/v1/status") || { echo 'Cloud status check failed; existing deployment unchanged' >&2; exit 1; }
  CUTOFF=$(printf '%s' "$before" | jq -er '.generated_at | select(type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T"))') || {
    echo 'Cloud status timestamp invalid; existing deployment unchanged' >&2; exit 1;
  }
fi
SHARED="$INSTALL_DIR/shared"
STAGE=$(mktemp -d "$SHARED/.security-stage.XXXXXX")
cp "$BUNDLE/ca.crt" "$STAGE/ca.crt"
for role in $ROLES; do for suffix in crt key; do cp "$BUNDLE/$role.$suffix" "$STAGE/$role.$suffix"; done; done
chown -R 1000:1000 "$STAGE"
chmod 700 "$STAGE"
chmod 600 "$STAGE"/*
ENV_STAGE=$(mktemp "$SHARED/.env.security.XXXXXX")
awk '!/^SECURITY_CLOUD_(URL|LICENSE_TOKEN|BUILD_TOKEN|READER_TOKEN)=/' "$SHARED/.env" > "$ENV_STAGE"
printf 'SECURITY_CLOUD_URL=%s\n' "$CLOUD_URL" >> "$ENV_STAGE"
for role in $ROLES; do
  label=$(printf '%s' "$role" | tr '[:lower:]' '[:upper:]')
  printf 'SECURITY_CLOUD_%s_TOKEN=%s\n' "$label" "$(cat "$BUNDLE/$role.token")" >> "$ENV_STAGE"
done
chmod 600 "$ENV_STAGE"
BACKUP=$(mktemp -d "$SHARED/.security-rollback.XXXXXX")
cp -p "$SHARED/.env" "$BACKUP/env"
if [ -d "$SHARED/security" ]; then mv "$SHARED/security" "$BACKUP/security"; fi
mv "$STAGE" "$SHARED/security"
STAGE=''
mv "$ENV_STAGE" "$SHARED/.env"
ENV_STAGE=''
cd "$INSTALL_DIR/current"
cutoff=$CUTOFF
verify_reports() {
  if [ "$ROLE" = build ]; then
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
    return
  fi
  printf 'header = "Authorization: Bearer %s"\n' "$(cat "$BUNDLE/reader.token")" > "$PROBE"
  attempt=0
  while [ "$attempt" -lt 24 ]; do
    attempt=$((attempt + 1))
    result=$(curl --silent --show-error --fail --max-time 10 --cacert "$BUNDLE/ca.crt" \
      --cert "$BUNDLE/reader.crt" --key "$BUNDLE/reader.key" --config "$PROBE" \
      "$CLOUD_URL/v1/status") || return 1
    targets='["license-center"]'
    [ "$ROLE" = all ] && targets='["license-center", "build-center"]'
    if printf '%s' "$result" | jq -e --arg cutoff "$cutoff" --argjson targets "$targets" '
      (.nodes | type == "object") and
      (. as $status | all($targets[]; . as $role |
        $status.nodes[$role].report_fresh == true and
        $status.nodes[$role].integrity.state == "matched" and
        ($status.nodes[$role].last_report_at | type == "string") and
        ($status.nodes[$role].last_report_at > $cutoff)))
    ' >/dev/null; then return 0; fi
    sleep 5
  done
  return 1
}
if compose up -d --no-build --pull never --force-recreate --wait --wait-timeout 360 appgog && verify_reports; then
  rm -rf "$BACKUP"
  echo "Cloud pairing active for role $ROLE; run security-doctor.sh to verify both nodes."
else
  mv "$SHARED/security" "$BACKUP/failed-security"
  if [ -d "$BACKUP/security" ]; then mv "$BACKUP/security" "$SHARED/security"; fi
  cp -p "$BACKUP/env" "$SHARED/.env"
  compose up -d --no-build --pull never --force-recreate --wait --wait-timeout 360 appgog || true
  echo "Pairing or fresh report verification failed. Previous configuration restored; diagnostic credentials remain in $BACKUP" >&2
  exit 1
fi
