#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[[ $EUID -eq 0 ]] || { echo 'release-install.test.sh must run as root' >&2; exit 1; }
for tool in curl node jq openssl tar sha256sum python3; do
  command -v "$tool" >/dev/null || { echo "Missing test tool: $tool" >&2; exit 1; }
done
id nobody >/dev/null 2>&1 || { echo 'Test service user nobody is required' >&2; exit 1; }

WORK=$(mktemp -d)
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf -- "$WORK"
}
trap cleanup EXIT
openssl genpkey -algorithm Ed25519 -out "$WORK/release-private.pem" >/dev/null 2>&1
openssl pkey -in "$WORK/release-private.pem" -pubout -out "$WORK/release-public.pem" >/dev/null 2>&1

source_copy() {
  local destination=$1 version=$2
  mkdir -p "$destination"
  tar -C "$ROOT" --exclude=.git --exclude=.codex --exclude=dist -cf - . | tar -C "$destination" -xf -
  node -e 'const fs=require("fs");const p=process.argv[1];const j=JSON.parse(fs.readFileSync(p));j.version=process.argv[2];fs.writeFileSync(p,JSON.stringify(j,null,2)+"\n")' \
    "$destination/package.json" "$version"
}
package_version() {
  local source_dir=$1 output_dir=$2
  APPGOG_SECURITY_ALLOW_TEST_KEY=true bash "$ROOT/scripts/package-release.sh" --source-dir "$source_dir" \
    --output-dir "$output_dir" --signing-key "$WORK/release-private.pem"
  node "$ROOT/scripts/verify-release.js" --dir "$output_dir" --public-key "$WORK/release-public.pem"
}
wait_for_port() {
  local file=$1
  for _ in $(seq 1 100); do [[ -s $file ]] && return 0; sleep 0.1; done
  echo "Server did not publish its port: $file" >&2
  exit 1
}
set_service_state() {
  printf '%s\n' "$1" > "$SECURITY_TEST_ACTIVE_FILE"
  printf '%s\n' "$2" > "$SECURITY_TEST_ENABLED_FILE"
}
assert_service_state() {
  [[ $(cat "$SECURITY_TEST_ACTIVE_FILE") == "$1" ]]
  [[ $(cat "$SECURITY_TEST_ENABLED_FILE") == "$2" ]]
}
arm_systemctl_failure() {
  printf '%s\n' "$1" > "$SECURITY_TEST_SYSTEMCTL_FAIL_FILE"
  rm -f -- "$SECURITY_TEST_SYSTEMCTL_FAIL_FILE.used"
}
clear_systemctl_failure() {
  rm -f -- "$SECURITY_TEST_SYSTEMCTL_FAIL_FILE" "$SECURITY_TEST_SYSTEMCTL_FAIL_FILE.used"
}

source_copy "$WORK/source-014" 0.1.4
package_version "$WORK/source-014" "$WORK/dist-014"

cp "$WORK/dist-014/APPGOG-Cloud-Security-Center-0.1.4.run" "$WORK/tampered.run"
printf 'tampered\n' >> "$WORK/tampered.run"
cp -R "$WORK/dist-014" "$WORK/tampered-dist"
mv "$WORK/tampered.run" "$WORK/tampered-dist/APPGOG-Cloud-Security-Center-0.1.4.run"
if node "$ROOT/scripts/verify-release.js" --dir "$WORK/tampered-dist" --public-key "$WORK/release-public.pem" >/dev/null 2>&1; then
  echo 'Tampered artifact was accepted' >&2
  exit 1
fi

cp -R "$WORK/dist-014" "$WORK/contract-tampered-dist"
jq '.environment.node_major = 99' "$WORK/contract-tampered-dist/release-manifest.json" > "$WORK/contract-manifest.next"
mv "$WORK/contract-manifest.next" "$WORK/contract-tampered-dist/release-manifest.json"
openssl pkeyutl -sign -inkey "$WORK/release-private.pem" -rawin \
  -in "$WORK/contract-tampered-dist/release-manifest.json" \
  -out "$WORK/contract-tampered-dist/release-manifest.json.sig"
if node "$ROOT/scripts/verify-release.js" --dir "$WORK/contract-tampered-dist" --public-key "$WORK/release-public.pem" >/dev/null 2>&1; then
  echo 'Re-signed release contract tampering was accepted' >&2
  exit 1
fi

mkdir -p "$WORK/bin" "$WORK/systemd" "$WORK/commands"
cat > "$WORK/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
active=${SECURITY_TEST_ACTIVE_FILE:?}
enabled=${SECURITY_TEST_ENABLED_FILE:?}
fail_file=${SECURITY_TEST_SYSTEMCTL_FAIL_FILE:?}
log_file=${SECURITY_TEST_SYSTEMCTL_LOG_FILE:?}
command=${1:-}
shift || true
printf '%s %s\n' "$command" "$*" >> "$log_file"
if [[ -s $fail_file && ! -e $fail_file.used && $(cat "$fail_file") == "$command" ]]; then
  : > "$fail_file.used"
  echo "Injected systemctl failure: $command" >&2
  exit 96
fi
case "$command" in
  is-active) [[ $(cat "$active") == active ]] && { echo active; exit 0; }; echo inactive; exit 3 ;;
  is-enabled) [[ $(cat "$enabled") == enabled ]] && { echo enabled; exit 0; }; echo disabled; exit 1 ;;
  start) printf 'active\n' > "$active" ;;
  restart) printf 'active\n' > "$active" ;;
  stop) printf 'inactive\n' > "$active" ;;
  enable)
    printf 'enabled\n' > "$enabled"
    [[ ${1:-} != --now ]] || printf 'active\n' > "$active"
    ;;
  disable)
    printf 'disabled\n' > "$enabled"
    [[ ${1:-} != --now ]] || printf 'inactive\n' > "$active"
    ;;
  daemon-reload|status) ;;
  *) echo "Unexpected systemctl command: $command $*" >&2; exit 1 ;;
esac
STUB
cat > "$WORK/bin/health" <<'HEALTH'
#!/usr/bin/env bash
[[ $(cat "${SECURITY_TEST_HEALTH_FILE:?}") == healthy ]]
HEALTH
chmod 700 "$WORK/bin/systemctl" "$WORK/bin/health"

export SECURITY_INSTALL_DIR="$WORK/opt/appgog-security"
export SECURITY_CONFIG_DIR="$WORK/etc/appgog-security"
export SECURITY_DATA_DIR="$WORK/var/appgog-security"
export SECURITY_SYSTEMD_DIR="$WORK/systemd"
export SECURITY_BIN_DIR="$WORK/commands"
export SECURITY_SYSTEMCTL="$WORK/bin/systemctl"
export SECURITY_HEALTHCHECK_CMD="$WORK/bin/health"
export SECURITY_TEST_ACTIVE_FILE="$WORK/service-active"
export SECURITY_TEST_ENABLED_FILE="$WORK/service-enabled"
export SECURITY_TEST_SYSTEMCTL_FAIL_FILE="$WORK/systemctl-fail"
export SECURITY_TEST_SYSTEMCTL_LOG_FILE="$WORK/systemctl.log"
export SECURITY_TEST_HEALTH_FILE="$WORK/health-state"
export SECURITY_TEST_MODE=true
export APPGOG_SECURITY_ALLOW_TEST_MODE=true
export SECURITY_TEST_SERVICE_USER=nobody
printf 'healthy\n' > "$SECURITY_TEST_HEALTH_FILE"
: > "$SECURITY_TEST_SYSTEMCTL_FAIL_FILE"
: > "$SECURITY_TEST_SYSTEMCTL_LOG_FILE"
set_service_state inactive disabled

arm_systemctl_failure daemon-reload
if bash "$WORK/dist-014/APPGOG-Cloud-Security-Center-0.1.4.run" --host 127.0.0.1 >/dev/null 2>&1; then
  echo 'First-install daemon-reload failure was accepted' >&2
  exit 1
fi
clear_systemctl_failure
[[ ! -e $SECURITY_INSTALL_DIR && ! -e $SECURITY_CONFIG_DIR && ! -e $SECURITY_DATA_DIR ]]
[[ ! -e $SECURITY_SYSTEMD_DIR/appgog-security.service && ! -e $SECURITY_BIN_DIR/appgog-security ]]
assert_service_state inactive disabled

bash "$WORK/dist-014/APPGOG-Cloud-Security-Center-0.1.4.run" --host 127.0.0.1
[[ $(jq -r .version "$SECURITY_INSTALL_DIR/current/package.json") == 0.1.4 ]]
assert_service_state active enabled
[[ $(stat -c '%U:%G %a' "$SECURITY_CONFIG_DIR/server.key") == root:nogroup\ 640 ]]
[[ $(stat -c '%U:%G %a' "$SECURITY_CONFIG_DIR/server.crt") == root:nogroup\ 640 ]]
[[ $(stat -c '%U:%G %a' "$SECURITY_CONFIG_DIR/ca.crt") == root:nogroup\ 640 ]]
[[ $(stat -c %U "$SECURITY_CONFIG_DIR/ca.key") == root ]]
[[ $(stat -c '%U:%G %a' "$SECURITY_DATA_DIR") == root:nogroup\ 750 ]]
[[ $(stat -c %U "$SECURITY_DATA_DIR/runtime") == nobody && $(stat -c %a "$SECURITY_DATA_DIR/runtime") == 700 ]]
[[ $(stat -c %U "$SECURITY_DATA_DIR/backups") == root && $(stat -c %a "$SECURITY_DATA_DIR/backups") == 700 ]]
backups_before=$(find "$SECURITY_DATA_DIR/backups" -type f -name '*.tar.gz.enc' 2>/dev/null | wc -l)
bash "$WORK/dist-014/APPGOG-Cloud-Security-Center-0.1.4.run" --host 127.0.0.1
backups_after=$(find "$SECURITY_DATA_DIR/backups" -type f -name '*.tar.gz.enc' 2>/dev/null | wc -l)
[[ $backups_before == "$backups_after" ]]
rm -f -- "$SECURITY_DATA_DIR/runtime/state.json"
printf '{"sentinel":"preserved"}\n' > "$SECURITY_DATA_DIR/state.json"

source_copy "$WORK/source-015" 0.1.5
package_version "$WORK/source-015" "$WORK/dist-015"
bash "$WORK/dist-015/APPGOG-Cloud-Security-Center-0.1.5.run" --host 127.0.0.1
[[ $(jq -r .version "$SECURITY_INSTALL_DIR/current/package.json") == 0.1.5 ]]
[[ $(jq -r .sentinel "$SECURITY_DATA_DIR/runtime/state.json") == preserved ]]
[[ ! -e $SECURITY_DATA_DIR/state.json ]]
find "$SECURITY_DATA_DIR/backups" -type f -name '*.tar.gz.enc' -print -quit | grep -q .

cp "$SECURITY_INSTALL_DIR/releases/0.1.5/scripts/appgog-security.sh" "$WORK/original-menu.sh"
printf '\n# conflict\n' >> "$SECURITY_INSTALL_DIR/releases/0.1.5/scripts/appgog-security.sh"
if bash "$WORK/dist-015/APPGOG-Cloud-Security-Center-0.1.5.run" --host 127.0.0.1 >/dev/null 2>&1; then
  echo 'Same-version security script conflict was accepted' >&2
  exit 1
fi
mv "$WORK/original-menu.sh" "$SECURITY_INSTALL_DIR/releases/0.1.5/scripts/appgog-security.sh"

source_copy "$WORK/source-016" 0.1.6
package_version "$WORK/source-016" "$WORK/dist-016"
for failed_command in daemon-reload enable restart; do
  set_service_state inactive disabled
  arm_systemctl_failure "$failed_command"
  if bash "$WORK/dist-016/APPGOG-Cloud-Security-Center-0.1.6.run" --host 127.0.0.1 >/dev/null 2>&1; then
    echo "Upgrade systemctl failure was accepted: $failed_command" >&2
    exit 1
  fi
  clear_systemctl_failure
  [[ $(jq -r .version "$SECURITY_INSTALL_DIR/current/package.json") == 0.1.5 ]]
  [[ $(jq -r .sentinel "$SECURITY_DATA_DIR/runtime/state.json") == preserved ]]
  assert_service_state inactive disabled
done

set_service_state active enabled
printf 'failed\n' > "$SECURITY_TEST_HEALTH_FILE"
if bash "$WORK/dist-016/APPGOG-Cloud-Security-Center-0.1.6.run" --host 127.0.0.1 >/dev/null 2>&1; then
  echo 'Failed health check did not stop the upgrade' >&2
  exit 1
fi
[[ $(jq -r .version "$SECURITY_INSTALL_DIR/current/package.json") == 0.1.5 ]]
[[ $(jq -r .sentinel "$SECURITY_DATA_DIR/runtime/state.json") == preserved ]]
assert_service_state active enabled
printf 'healthy\n' > "$SECURITY_TEST_HEALTH_FILE"

manual_backup=$(bash "$SECURITY_INSTALL_DIR/current/scripts/backup.sh" --print-path)
printf '{"sentinel":"mutated"}\n' > "$SECURITY_DATA_DIR/runtime/state.json"
printf 'local-only\n' > "$SECURITY_CONFIG_DIR/local-only.marker"
chmod 751 "$SECURITY_CONFIG_DIR"
chmod 753 "$SECURITY_DATA_DIR"
for checkpoint in after-config-clear after-data-clear; do
  if SECURITY_TEST_FAIL_RESTORE_STEP=$checkpoint \
    bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$manual_backup" --no-service >/dev/null 2>&1; then
    echo "Injected restore failure was accepted: $checkpoint" >&2
    exit 1
  fi
  [[ $(jq -r .sentinel "$SECURITY_DATA_DIR/runtime/state.json") == mutated ]]
  [[ -f $SECURITY_CONFIG_DIR/local-only.marker ]]
  [[ $(stat -c %a "$SECURITY_CONFIG_DIR") == 751 ]]
  [[ $(stat -c %a "$SECURITY_DATA_DIR") == 753 ]]
done

set_service_state active enabled
arm_systemctl_failure restart
if bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$manual_backup" >/dev/null 2>&1; then
  echo 'Restore restart failure was accepted' >&2
  exit 1
fi
clear_systemctl_failure
[[ $(jq -r .sentinel "$SECURITY_DATA_DIR/runtime/state.json") == mutated ]]
[[ -f $SECURITY_CONFIG_DIR/local-only.marker ]]
[[ $(stat -c %a "$SECURITY_CONFIG_DIR") == 751 ]]
[[ $(stat -c %a "$SECURITY_DATA_DIR") == 753 ]]
assert_service_state active enabled

bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$manual_backup" --no-service
[[ $(jq -r .sentinel "$SECURITY_DATA_DIR/runtime/state.json") == preserved ]]
[[ ! -e $SECURITY_CONFIG_DIR/local-only.marker ]]

PUBLIC_PORT_FILE="$WORK/public-http-port"
python3 - "$WORK/dist-015" "$PUBLIC_PORT_FILE" <<'PY' &
import http.server, os, pathlib, sys
os.chdir(sys.argv[1])
server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), http.server.SimpleHTTPRequestHandler)
pathlib.Path(sys.argv[2]).write_text(str(server.server_port))
server.serve_forever()
PY
PIDS+=("$!")
wait_for_port "$PUBLIC_PORT_FILE"
PUBLIC_PORT=$(cat "$PUBLIC_PORT_FILE")
APPGOG_SECURITY_RELEASE_PUBLIC_KEY_FILE="$WORK/release-public.pem" APPGOG_SECURITY_ALLOW_TEST_KEY=true \
  APPGOG_SECURITY_ALLOW_INSECURE_TEST_SOURCE=true sh "$ROOT/install.sh" --source custom \
  --release-base "http://127.0.0.1:$PUBLIC_PORT" --host 127.0.0.1

cp "$WORK/dist-015/APPGOG-Cloud-Security-Center-0.1.5.run" "$WORK/original.run"
printf 'tampered\n' >> "$WORK/dist-015/APPGOG-Cloud-Security-Center-0.1.5.run"
if APPGOG_SECURITY_RELEASE_PUBLIC_KEY_FILE="$WORK/release-public.pem" APPGOG_SECURITY_ALLOW_TEST_KEY=true \
  APPGOG_SECURITY_ALLOW_INSECURE_TEST_SOURCE=true sh "$ROOT/install.sh" --source custom \
  --release-base "http://127.0.0.1:$PUBLIC_PORT" --host 127.0.0.1 >/dev/null 2>&1; then
  echo 'Bootstrap accepted a tampered installer' >&2
  exit 1
fi
mv "$WORK/original.run" "$WORK/dist-015/APPGOG-Cloud-Security-Center-0.1.5.run"

OBJECT_PORT_FILE="$WORK/object-port"
OBJECT_LOG="$WORK/object-authorization.log"
python3 - "$WORK/dist-015" "$OBJECT_PORT_FILE" "$OBJECT_LOG" <<'PY' &
import http.server, os, pathlib, sys
os.chdir(sys.argv[1])
log = pathlib.Path(sys.argv[3])
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        with log.open('a') as handle:
            handle.write((self.headers.get('Authorization') or '<none>') + '\n')
        super().do_GET()
server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
pathlib.Path(sys.argv[2]).write_text(str(server.server_port))
server.serve_forever()
PY
PIDS+=("$!")
wait_for_port "$OBJECT_PORT_FILE"
OBJECT_PORT=$(cat "$OBJECT_PORT_FILE")

API_PORT_FILE="$WORK/api-port"
API_LOG="$WORK/api-authorization.log"
python3 - "$API_PORT_FILE" "$API_LOG" "$OBJECT_PORT" <<'PY' &
import http.server, json, pathlib, sys
port_file, log_file, object_port = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), int(sys.argv[3])
assets = {
    '1': 'release-manifest.json',
    '2': 'release-manifest.json.sig',
    '3': 'APPGOG-Cloud-Security-Center-0.1.5.run',
}
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with log_file.open('a') as handle:
            handle.write((self.headers.get('Authorization') or '<none>') + '\n')
        if self.path == '/releases/latest':
            payload = {'assets': [
                {'name': name, 'state': 'uploaded', 'url': f'http://127.0.0.1:{self.server.server_port}/releases/assets/{asset_id}'}
                for asset_id, name in assets.items()
            ]}
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        prefix = '/releases/assets/'
        if self.path.startswith(prefix) and self.path[len(prefix):] in assets:
            name = assets[self.path[len(prefix):]]
            self.send_response(302)
            self.send_header('Location', f'http://127.0.0.1:{object_port}/{name}')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        self.send_error(404)
    def log_message(self, *_):
        pass
server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
port_file.write_text(str(server.server_port))
server.serve_forever()
PY
PIDS+=("$!")
wait_for_port "$API_PORT_FILE"
API_PORT=$(cat "$API_PORT_FILE")
printf 'github_pat_TEST_TOKEN_123\n' > "$WORK/github-release.token"
chmod 600 "$WORK/github-release.token"
APPGOG_SECURITY_GITHUB_TOKEN_FILE="$WORK/github-release.token" \
  APPGOG_SECURITY_GITHUB_API_BASE="http://127.0.0.1:$API_PORT/releases" \
  APPGOG_SECURITY_RELEASE_PUBLIC_KEY_FILE="$WORK/release-public.pem" \
  APPGOG_SECURITY_ALLOW_TEST_KEY=true APPGOG_SECURITY_ALLOW_INSECURE_TEST_SOURCE=true \
  sh "$ROOT/install.sh" --source github --host 127.0.0.1
[[ -s $API_LOG && -s $OBJECT_LOG ]]
if grep -q '^<none>$' "$API_LOG"; then
  echo 'Private GitHub API request omitted its Authorization header' >&2
  exit 1
fi
if grep -qv '^<none>$' "$OBJECT_LOG"; then
  echo 'Private GitHub token leaked to the redirected object server' >&2
  exit 1
fi

mkdir -p "$WORK/danger"
printf 'keep\n' > "$WORK/danger/marker"
if SECURITY_INSTALL_DIR="$WORK/safe/../danger" SECURITY_CONFIG_DIR="$SECURITY_CONFIG_DIR" \
  SECURITY_DATA_DIR="$SECURITY_DATA_DIR" SECURITY_SYSTEMD_DIR="$SECURITY_SYSTEMD_DIR" \
  SECURITY_BIN_DIR="$SECURITY_BIN_DIR" bash "$ROOT/scripts/appgog-security.sh" uninstall --yes >/dev/null 2>&1; then
  echo 'Unsafe uninstall path was accepted' >&2
  exit 1
fi
[[ -f $WORK/danger/marker ]]

if SECURITY_INSTALL_DIR="$SECURITY_INSTALL_DIR" SECURITY_CONFIG_DIR="$SECURITY_CONFIG_DIR" \
  SECURITY_DATA_DIR="$SECURITY_DATA_DIR" SECURITY_SYSTEMD_DIR=/ \
  SECURITY_BIN_DIR="$SECURITY_BIN_DIR" bash "$ROOT/scripts/appgog-security.sh" uninstall --yes >/dev/null 2>&1; then
  echo 'Unsafe systemd root path was accepted' >&2
  exit 1
fi
[[ -L $SECURITY_INSTALL_DIR/current ]]

mkdir -p "$WORK/foreign/current" "$WORK/foreign/releases"
printf '{"product":"another-product"}\n' > "$WORK/foreign/current/release-contract.json"
printf 'keep\n' > "$WORK/foreign/releases/marker"
if SECURITY_INSTALL_DIR="$WORK/foreign" SECURITY_CONFIG_DIR="$SECURITY_CONFIG_DIR" \
  SECURITY_DATA_DIR="$SECURITY_DATA_DIR" SECURITY_SYSTEMD_DIR="$SECURITY_SYSTEMD_DIR" \
  SECURITY_BIN_DIR="$SECURITY_BIN_DIR" bash "$ROOT/scripts/appgog-security.sh" uninstall --yes >/dev/null 2>&1; then
  echo 'Foreign product uninstall was accepted' >&2
  exit 1
fi
[[ -f $WORK/foreign/releases/marker ]]

bash "$SECURITY_INSTALL_DIR/current/scripts/appgog-security.sh" uninstall --yes
[[ ! -e $SECURITY_INSTALL_DIR/current && ! -e $SECURITY_INSTALL_DIR/releases && ! -e $SECURITY_INSTALL_DIR/runtime ]]
[[ -d $SECURITY_CONFIG_DIR && -d $SECURITY_DATA_DIR ]]
echo 'Signed release install/update/rollback/private-download/backup/restore/uninstall tests passed'
