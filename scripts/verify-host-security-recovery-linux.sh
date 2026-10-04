#!/usr/bin/env sh
# Official-feed acceptance on a disposable runner, separate from synthetic lifecycle tests.
set -eu
[ "${GITHUB_ACTIONS:-}" = true ] || { echo 'Only isolated GitHub Actions runners are supported' >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo 'Requires root on the isolated runner' >&2; exit 1; }
SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
TEST_ROOT=/appgog-host-security-ci
STATE=/var/lib/appgog-security
for target in "$TEST_ROOT" "$STATE" /etc/systemd/system/appgog-host-security.service /usr/local/lib/appgog-security; do
  [ ! -e "$target" ] && [ ! -L "$target" ] || { echo 'Existing security installation; refusing fixture' >&2; exit 1; }
done
systemctl stop clamav-freshclam.service
# A failed download is a failed acceptance, never a synthetic or stale clean verdict.
timeout 360 freshclam --stdout
clamscan --version
install -d -o root -g root -m 0700 "$TEST_ROOT/releases/candidate" "$TEST_ROOT/shared"
RELEASE=$TEST_ROOT/releases/candidate
cp -R "$SOURCE/apps" "$SOURCE/packages" "$SOURCE/scripts" "$RELEASE/"
for name in package.json pnpm-lock.yaml release-contract.json Dockerfile compose.yaml compose.license.yaml compose.build.yaml Caddyfile Caddyfile.license Caddyfile.build .env.example .env.docker.example .dockerignore install-docker.sh; do cp "$SOURCE/$name" "$RELEASE/$name"; done
chown -R root:root "$TEST_ROOT"
ln -s releases/candidate "$TEST_ROOT/current"
printf 'AUTH_DOMAIN=license.appgog.test
BUILD_DOMAIN=build.appgog.test
' > "$TEST_ROOT/shared/.env"
openssl rand -hex 32 > "$TEST_ROOT/shared/.backup-key"
chmod 600 "$TEST_ROOT/shared/.env" "$TEST_ROOT/shared/.backup-key"
export APPGOG_INSTALL_ROOT=$TEST_ROOT APPGOG_HOST_ENV_FILE=$TEST_ROOT/shared/.env PYTHONDONTWRITEBYTECODE=1
lifecycle() { sh "$RELEASE/scripts/install-host-security.sh" "$1"; }
cleanup() {
  result=$?
  trap - 0 INT TERM
  if [ "$result" -ne 0 ]; then journalctl -u appgog-host-security.service --no-pager -n 25 || true; fi
  # Active failed incidents deliberately remain fenced, even during CI teardown.
  lifecycle uninstall || true
  exit "$result"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM
lifecycle prepare
lifecycle install
systemctl is-active --quiet appgog-host-security.service
# Avoid racing the periodic evaluator against the deliberate fixture incident.
systemctl stop appgog-local-response.timer appgog-host-security.service
docker pull node:24-bookworm-slim
python3 -I "$SOURCE/scripts/verify-host-security-response-linux.py" "$TEST_ROOT" --official-recovery
python3 -I - "$STATE/incident.json" <<'PY'
import json,sys
record=json.load(open(sys.argv[1]))
assert record['state']=='released' and not record.get('ci_teardown_only')
assert record.get('data_reviewed_by_root_at')
PY
echo 'Official database recovery acceptance completed; no test-only release marker used.'
