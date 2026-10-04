#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[[ $EUID -eq 0 ]] || { echo 'release-install.test.sh must run as root' >&2; exit 1; }
for tool in curl node jq openssl tar sha256sum python3 flock runuser timeout; do
  command -v "$tool" >/dev/null || { echo "Missing test tool: $tool" >&2; exit 1; }
done
id nobody >/dev/null 2>&1 || { echo 'Test service user nobody is required' >&2; exit 1; }

WORK=$(mktemp -d)
chmod 755 "$WORK"
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
mutate_file_byte() {
  python3 - "$1" "$2" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
offset = int(sys.argv[2])
data = bytearray(path.read_bytes())
if offset < 0:
    offset += len(data)
if offset < 0 or offset >= len(data):
    raise SystemExit('mutation offset outside file')
data[offset] ^= 1
path.write_bytes(data)
PY
}
pack_v3_archive() (
  local archive=$1 output=$2 pack_work
  pack_work=$(mktemp -d "$WORK/pack-v3.XXXXXX")
  trap 'rm -rf -- "$pack_work"' EXIT
  { printf 'APPGOG-BACKUP-V3\n'; cat "$archive"; } > "$pack_work/plaintext"
  "$PRIVATE_NODE" "$SECURITY_INSTALL_DIR/current/scripts/backup-auth.js" derive "$SECURITY_CONFIG_DIR/backup.key" \
    | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 -pass stdin \
      -in "$pack_work/plaintext" -out "$pack_work/ciphertext"
  "$PRIVATE_NODE" "$SECURITY_INSTALL_DIR/current/scripts/backup-auth.js" pack \
    "$SECURITY_CONFIG_DIR/backup.mac.key" "$pack_work/ciphertext" "$output"
)

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
operation_log=${SECURITY_TEST_OPERATION_LOG_FILE:-}
command=${1:-}
shift || true
printf '%s %s\n' "$command" "$*" >> "$log_file"
[[ -z $operation_log ]] || printf 'systemctl-%s\n' "$command" >> "$operation_log"
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
export SECURITY_LOCK_FILE="$WORK/run/appgog-security.lock"
export SECURITY_HEALTHCHECK_CMD="$WORK/bin/health"
export SECURITY_TEST_ACTIVE_FILE="$WORK/service-active"
export SECURITY_TEST_ENABLED_FILE="$WORK/service-enabled"
export SECURITY_TEST_SYSTEMCTL_FAIL_FILE="$WORK/systemctl-fail"
export SECURITY_TEST_SYSTEMCTL_LOG_FILE="$WORK/systemctl.log"
export SECURITY_TEST_OPERATION_LOG_FILE="$WORK/operation.log"
export SECURITY_TEST_HEALTH_FILE="$WORK/health-state"
export SECURITY_TEST_MODE=true
export APPGOG_SECURITY_ALLOW_TEST_MODE=true
export SECURITY_TEST_SERVICE_USER=nobody
printf 'healthy\n' > "$SECURITY_TEST_HEALTH_FILE"
mkdir -p "$(dirname "$SECURITY_LOCK_FILE")"
mkdir -p "$WORK/opt" "$WORK/etc" "$WORK/var"
chmod 755 "$WORK/opt" "$WORK/etc" "$WORK/var"
: > "$SECURITY_TEST_SYSTEMCTL_FAIL_FILE"
: > "$SECURITY_TEST_SYSTEMCTL_LOG_FILE"
: > "$SECURITY_TEST_OPERATION_LOG_FILE"
set_service_state inactive disabled

missing_service_user="appgog_missing_$$"
if id "$missing_service_user" >/dev/null 2>&1; then
  echo "Unexpected test service user exists: $missing_service_user" >&2
  exit 1
fi
if SECURITY_TEST_SERVICE_USER="$missing_service_user" \
  bash "$WORK/dist-014/APPGOG-Cloud-Security-Center-0.1.4.run" --host 127.0.0.1 >/dev/null 2>&1; then
  echo 'Installer accepted a missing test service user' >&2
  exit 1
fi
[[ ! -e $SECURITY_INSTALL_DIR && ! -e $SECURITY_CONFIG_DIR && ! -e $SECURITY_DATA_DIR ]]

printf 'lock-target\n' > "$WORK/maintenance-lock-target"
ln -s "$WORK/maintenance-lock-target" "$SECURITY_LOCK_FILE"
if bash "$WORK/dist-014/APPGOG-Cloud-Security-Center-0.1.4.run" --host 127.0.0.1 >/dev/null 2>&1; then
  echo 'Installer accepted a symbolic-link maintenance lock' >&2
  exit 1
fi
[[ $(cat "$WORK/maintenance-lock-target") == lock-target ]]
[[ ! -e $SECURITY_INSTALL_DIR && ! -e $SECURITY_CONFIG_DIR && ! -e $SECURITY_DATA_DIR ]]
rm -f -- "$SECURITY_LOCK_FILE"

mkdir "$SECURITY_LOCK_FILE"
if bash "$WORK/dist-014/APPGOG-Cloud-Security-Center-0.1.4.run" --host 127.0.0.1 >/dev/null 2>&1; then
  echo 'Installer accepted a directory maintenance lock' >&2
  exit 1
fi
[[ ! -e $SECURITY_INSTALL_DIR && ! -e $SECURITY_CONFIG_DIR && ! -e $SECURITY_DATA_DIR ]]
rmdir "$SECURITY_LOCK_FILE"

printf 'installer-lock-content\n' > "$SECURITY_LOCK_FILE"
arm_systemctl_failure daemon-reload
if bash "$WORK/dist-014/APPGOG-Cloud-Security-Center-0.1.4.run" --host 127.0.0.1 >/dev/null 2>&1; then
  echo 'First-install daemon-reload failure was accepted' >&2
  exit 1
fi
clear_systemctl_failure
[[ $(cat "$SECURITY_LOCK_FILE") == installer-lock-content ]]
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
[[ $(stat -c '%U:%G %a' "$SECURITY_CONFIG_DIR/install.env") == root:root\ 600 ]]
[[ $(grep -c '^SECURITY_PUBLIC_HOST=' "$SECURITY_CONFIG_DIR/install.env") == 1 ]]
[[ $(grep -c '^SECURITY_SERVICE_USER=' "$SECURITY_CONFIG_DIR/install.env") == 1 ]]
grep -qx 'SECURITY_PUBLIC_HOST=127.0.0.1' "$SECURITY_CONFIG_DIR/install.env"
grep -qx 'SECURITY_SERVICE_USER=nobody' "$SECURITY_CONFIG_DIR/install.env"
runuser -u nobody -- "$SECURITY_INSTALL_DIR/runtime/bin/node" -e '
  const fs=require("node:fs");
  for (const path of process.argv.slice(1, 5)) fs.accessSync(path, fs.constants.R_OK);
  fs.accessSync(process.argv[5], fs.constants.R_OK | fs.constants.W_OK);
' "$SECURITY_INSTALL_DIR/current/src/server.js" "$SECURITY_CONFIG_DIR/config.json" \
  "$SECURITY_CONFIG_DIR/server.key" "$SECURITY_CONFIG_DIR/ca.crt" "$SECURITY_DATA_DIR/runtime"
backups_before=$(find "$SECURITY_DATA_DIR/backups" -type f -name '*.tar.gz.enc' 2>/dev/null | wc -l)
cat >> "$SECURITY_CONFIG_DIR/install.env" <<'ENV'
FUTURE_SETTING=preserved
SECURITY_PUBLIC_HOST=duplicate.invalid
SECURITY_SERVICE_USER=duplicate-user
ENV
chmod 777 "$SECURITY_CONFIG_DIR/install.env"
bash "$WORK/dist-014/APPGOG-Cloud-Security-Center-0.1.4.run" --host 127.0.0.1
backups_after=$(find "$SECURITY_DATA_DIR/backups" -type f -name '*.tar.gz.enc' 2>/dev/null | wc -l)
[[ $backups_before == "$backups_after" ]]
grep -qx 'FUTURE_SETTING=preserved' "$SECURITY_CONFIG_DIR/install.env"
[[ $(grep -c '^SECURITY_PUBLIC_HOST=' "$SECURITY_CONFIG_DIR/install.env") == 1 ]]
[[ $(grep -c '^SECURITY_SERVICE_USER=' "$SECURITY_CONFIG_DIR/install.env") == 1 ]]
grep -qx 'SECURITY_PUBLIC_HOST=127.0.0.1' "$SECURITY_CONFIG_DIR/install.env"
grep -qx 'SECURITY_SERVICE_USER=nobody' "$SECURITY_CONFIG_DIR/install.env"
[[ $(stat -c '%U:%G %a' "$SECURITY_CONFIG_DIR/install.env") == root:root\ 600 ]]

cp "$SECURITY_CONFIG_DIR/backup.key" "$WORK/backup.key.saved"
printf 'short\n' > "$SECURITY_CONFIG_DIR/backup.key"
if bash "$WORK/dist-014/APPGOG-Cloud-Security-Center-0.1.4.run" --host 127.0.0.1 >/dev/null 2>&1; then
  echo 'Installer accepted a short backup encryption key' >&2
  exit 1
fi
[[ $(cat "$SECURITY_CONFIG_DIR/backup.key") == short ]]
mv "$WORK/backup.key.saved" "$SECURITY_CONFIG_DIR/backup.key"
chmod 600 "$SECURITY_CONFIG_DIR/backup.key"
assert_service_state active enabled

mv "$SECURITY_CONFIG_DIR/backup.mac.key" "$WORK/backup.mac.key.saved"
printf 'external-mac-key-target\n' > "$WORK/external-mac-key-target"
ln -s "$WORK/external-mac-key-target" "$SECURITY_CONFIG_DIR/backup.mac.key"
if bash "$WORK/dist-014/APPGOG-Cloud-Security-Center-0.1.4.run" --host 127.0.0.1 >/dev/null 2>&1; then
  echo 'Installer accepted a symbolic-link backup authentication key' >&2
  exit 1
fi
[[ -L $SECURITY_CONFIG_DIR/backup.mac.key ]]
[[ $(cat "$WORK/external-mac-key-target") == external-mac-key-target ]]
rm -f -- "$SECURITY_CONFIG_DIR/backup.mac.key"
mv "$WORK/backup.mac.key.saved" "$SECURITY_CONFIG_DIR/backup.mac.key"
chmod 600 "$SECURITY_CONFIG_DIR/backup.mac.key"
assert_service_state active enabled

rm -f -- "$SECURITY_DATA_DIR/runtime/state.json"
printf '{"sentinel":"preserved"}\n' > "$SECURITY_DATA_DIR/state.json"

preserved_identity_paths=(
  "$SECURITY_CONFIG_DIR/ca.key"
  "$SECURITY_CONFIG_DIR/ca.crt"
  "$SECURITY_CONFIG_DIR/credentials/reader.key"
  "$SECURITY_CONFIG_DIR/credentials/reader.crt"
  "$SECURITY_CONFIG_DIR/credentials/reader.token"
  "$SECURITY_CONFIG_DIR/config.json"
  "$SECURITY_CONFIG_DIR/backup.key"
  "$SECURITY_CONFIG_DIR/backup.mac.key"
)
sha256sum "${preserved_identity_paths[@]}" > "$WORK/identity-before-upgrade.sha256"

source_copy "$WORK/source-015" 0.1.5
package_version "$WORK/source-015" "$WORK/dist-015"
bash "$WORK/dist-015/APPGOG-Cloud-Security-Center-0.1.5.run" --host 127.0.0.1
[[ $(jq -r .version "$SECURITY_INSTALL_DIR/current/package.json") == 0.1.5 ]]
[[ $(jq -r .sentinel "$SECURITY_DATA_DIR/runtime/state.json") == preserved ]]
[[ ! -e $SECURITY_DATA_DIR/state.json ]]
sha256sum "${preserved_identity_paths[@]}" > "$WORK/identity-after-upgrade.sha256"
cmp -s "$WORK/identity-before-upgrade.sha256" "$WORK/identity-after-upgrade.sha256"
find "$SECURITY_DATA_DIR/backups" -type f -name '*.tar.gz.enc' -print -quit | grep -q .
for script in appgog-security.sh enroll-node.sh export-business-bundle.sh rotate-identity.sh; do
  [[ -s $SECURITY_INSTALL_DIR/current/scripts/$script ]]
done
grep -q '节点对接管理' "$SECURITY_INSTALL_DIR/current/scripts/appgog-security.sh"
grep -q 'nodes) nodes' "$SECURITY_INSTALL_DIR/current/scripts/appgog-security.sh"
grep -q 'enroll) enroll_node' "$SECURITY_INSTALL_DIR/current/scripts/appgog-security.sh"
grep -q 'export) export_bundle' "$SECURITY_INSTALL_DIR/current/scripts/appgog-security.sh"
grep -q 'rotate) rotate_identity' "$SECURITY_INSTALL_DIR/current/scripts/appgog-security.sh"
bash "$SECURITY_INSTALL_DIR/current/scripts/appgog-security.sh" doctor >/dev/null

state_hash_before_downgrade=$(sha256sum "$SECURITY_DATA_DIR/runtime/state.json" | awk '{print $1}')
active_before_downgrade=$(cat "$SECURITY_TEST_ACTIVE_FILE")
enabled_before_downgrade=$(cat "$SECURITY_TEST_ENABLED_FILE")
if bash "$WORK/dist-014/APPGOG-Cloud-Security-Center-0.1.4.run" --host 127.0.0.1 >/dev/null 2>&1; then
  echo 'Installer accepted a downgrade from 0.1.5 to 0.1.4' >&2
  exit 1
fi
[[ $(jq -r .version "$SECURITY_INSTALL_DIR/current/package.json") == 0.1.5 ]]
[[ $(sha256sum "$SECURITY_DATA_DIR/runtime/state.json" | awk '{print $1}') == "$state_hash_before_downgrade" ]]
[[ $(cat "$SECURITY_TEST_ACTIVE_FILE") == "$active_before_downgrade" ]]
[[ $(cat "$SECURITY_TEST_ENABLED_FILE") == "$enabled_before_downgrade" ]]
sha256sum "${preserved_identity_paths[@]}" > "$WORK/identity-after-downgrade-refusal.sha256"
cmp -s "$WORK/identity-after-upgrade.sha256" "$WORK/identity-after-downgrade-refusal.sha256"

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
: > "$SECURITY_TEST_OPERATION_LOG_FILE"
if bash "$WORK/dist-016/APPGOG-Cloud-Security-Center-0.1.6.run" --host 127.0.0.1 >/dev/null 2>&1; then
  echo 'Failed health check did not stop the upgrade' >&2
  exit 1
fi
[[ $(jq -r .version "$SECURITY_INSTALL_DIR/current/package.json") == 0.1.5 ]]
[[ $(jq -r .sentinel "$SECURITY_DATA_DIR/runtime/state.json") == preserved ]]
assert_service_state active enabled
stop_line=$(awk '/^systemctl-stop$/{print NR; exit}' "$SECURITY_TEST_OPERATION_LOG_FILE")
inactive_check_line=$(awk '/^systemctl-stop$/{seen=1; next} seen && /^systemctl-is-active$/{print NR; exit}' "$SECURITY_TEST_OPERATION_LOG_FILE")
backup_line=$(awk '/^backup-start$/{print NR; exit}' "$SECURITY_TEST_OPERATION_LOG_FILE")
[[ -n $stop_line && -n $inactive_check_line && -n $backup_line ]]
((stop_line < inactive_check_line && inactive_check_line < backup_line))
printf 'healthy\n' > "$SECURITY_TEST_HEALTH_FILE"

printf 'backup-lock-content\n' > "$SECURITY_LOCK_FILE"
manual_backup=$(bash "$SECURITY_INSTALL_DIR/current/scripts/backup.sh" --print-path)
[[ $(cat "$SECURITY_LOCK_FILE") == backup-lock-content ]]
[[ $(head -n 1 "$manual_backup") == APPGOG-BACKUP-V3 ]]
[[ ! -e $manual_backup.hmac && ! -e $manual_backup.sha256 ]]

mv "$SECURITY_CONFIG_DIR/config.json" "$WORK/config.json.saved"
if bash "$SECURITY_INSTALL_DIR/current/scripts/backup.sh" --print-path >/dev/null 2>&1; then
  echo 'Backup accepted an installation with missing critical configuration' >&2
  exit 1
fi
mv "$WORK/config.json.saved" "$SECURITY_CONFIG_DIR/config.json"

mkdir -p "$WORK/install-recovery"
printf 'failed\n' > "$SECURITY_TEST_HEALTH_FILE"
if rollback_output=$(TMPDIR="$WORK/install-recovery" \
  SECURITY_TEST_FAIL_RESTORE_STEP=after-config-clear \
  SECURITY_TEST_FAIL_ROLLBACK_STEP=before-original-restore \
  bash "$WORK/dist-016/APPGOG-Cloud-Security-Center-0.1.6.run" --host 127.0.0.1 2>&1); then
  echo 'Upgrade succeeded despite injected restore and rollback failures' >&2
  exit 1
fi
recovery_dir=$(printf '%s\n' "$rollback_output" | sed -n 's/^Installation recovery directory preserved: //p' | tail -n 1)
[[ -n $recovery_dir && $recovery_dir == "$WORK/install-recovery/"* && -d $recovery_dir ]]
assert_service_state inactive enabled
ln -sfn "$SECURITY_INSTALL_DIR/releases/0.1.5" "$SECURITY_INSTALL_DIR/current.repair"
mv -Tf "$SECURITY_INSTALL_DIR/current.repair" "$SECURITY_INSTALL_DIR/current"
bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$manual_backup" --no-service
printf 'healthy\n' > "$SECURITY_TEST_HEALTH_FILE"
set_service_state active enabled

LOCK_READY="$WORK/maintenance-lock.ready"
(
  exec 10>"$SECURITY_LOCK_FILE"
  flock -n 10
  printf 'ready\n' > "$LOCK_READY"
  sleep 30
) &
LOCK_PID=$!
PIDS+=("$LOCK_PID")
for _ in $(seq 1 100); do [[ -s $LOCK_READY ]] && break; sleep 0.05; done
[[ -s $LOCK_READY ]]
if bash "$SECURITY_INSTALL_DIR/current/scripts/backup.sh" --print-path >/dev/null 2>&1; then
  echo 'Concurrent backup bypassed the maintenance lock' >&2
  exit 1
fi
kill "$LOCK_PID" 2>/dev/null || true
wait "$LOCK_PID" 2>/dev/null || true
if SECURITY_MAINTENANCE_LOCK_FD=9 \
  bash "$SECURITY_INSTALL_DIR/current/scripts/backup.sh" --print-path >/dev/null 2>&1; then
  echo 'Invalid inherited maintenance lock descriptor was accepted' >&2
  exit 1
fi

mv "$SECURITY_LOCK_FILE" "$WORK/maintenance-lock.saved"
printf 'runtime-lock-target\n' > "$WORK/runtime-lock-target"
ln -s "$WORK/runtime-lock-target" "$SECURITY_LOCK_FILE"
if bash "$SECURITY_INSTALL_DIR/current/scripts/backup.sh" --print-path >/dev/null 2>&1; then
  echo 'Backup accepted a symbolic-link maintenance lock' >&2
  exit 1
fi
if bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$manual_backup" --no-service >/dev/null 2>&1; then
  echo 'Restore accepted a symbolic-link maintenance lock' >&2
  exit 1
fi
[[ $(cat "$WORK/runtime-lock-target") == runtime-lock-target ]]
rm -f -- "$SECURITY_LOCK_FILE"
mv "$WORK/maintenance-lock.saved" "$SECURITY_LOCK_FILE"

mv "$SECURITY_LOCK_FILE" "$WORK/maintenance-lock.saved"
mkdir "$SECURITY_LOCK_FILE"
if bash "$SECURITY_INSTALL_DIR/current/scripts/backup.sh" --print-path >/dev/null 2>&1; then
  echo 'Backup accepted a directory maintenance lock' >&2
  exit 1
fi
if bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$manual_backup" --no-service >/dev/null 2>&1; then
  echo 'Restore accepted a directory maintenance lock' >&2
  exit 1
fi
rmdir "$SECURITY_LOCK_FILE"

mkfifo "$SECURITY_LOCK_FILE"
if timeout 5 bash "$SECURITY_INSTALL_DIR/current/scripts/backup.sh" --print-path >/dev/null 2>&1; then
  echo 'Backup accepted a FIFO maintenance lock' >&2
  exit 1
else
  fifo_status=$?
  [[ $fifo_status -ne 124 ]] || { echo 'Backup blocked on a FIFO maintenance lock' >&2; exit 1; }
fi
if timeout 5 bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$manual_backup" --no-service >/dev/null 2>&1; then
  echo 'Restore accepted a FIFO maintenance lock' >&2
  exit 1
else
  fifo_status=$?
  [[ $fifo_status -ne 124 ]] || { echo 'Restore blocked on a FIFO maintenance lock' >&2; exit 1; }
fi
rm -f -- "$SECURITY_LOCK_FILE"
mv "$WORK/maintenance-lock.saved" "$SECURITY_LOCK_FILE"

mkdir -p "$WORK/no-system-node"
cat > "$WORK/no-system-node/node" <<'NO_NODE'
#!/usr/bin/env bash
exit 99
NO_NODE
chmod 700 "$WORK/no-system-node/node"
private_runtime_backup=$(PATH="$WORK/no-system-node:$PATH" \
  bash "$SECURITY_INSTALL_DIR/current/scripts/backup.sh" --print-path)
[[ -s $private_runtime_backup ]]
same_second_one=$(bash "$SECURITY_INSTALL_DIR/current/scripts/backup.sh" --print-path)
same_second_two=$(bash "$SECURITY_INSTALL_DIR/current/scripts/backup.sh" --print-path)
[[ $same_second_one != "$same_second_two" && -s $same_second_one && -s $same_second_two ]]

if bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$manual_backup" --no-service >/dev/null 2>&1; then
  echo '--no-service restore was accepted while the service was active' >&2
  exit 1
fi
set_service_state inactive enabled

printf 'restore-lock-content\n' > "$SECURITY_LOCK_FILE"
bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$manual_backup" --no-service
[[ $(cat "$SECURITY_LOCK_FILE") == restore-lock-content ]]

PRIVATE_NODE="$SECURITY_INSTALL_DIR/runtime/bin/node"
mkdir -p "$SECURITY_CONFIG_DIR/custom" "$SECURITY_DATA_DIR/private"
custom_key="$SECURITY_CONFIG_DIR/custom/encryption.key"
custom_mac_key="$SECURITY_DATA_DIR/private/authentication.key"
custom_backup=$(SECURITY_BACKUP_KEY_FILE="$custom_key" SECURITY_BACKUP_MAC_KEY_FILE="$custom_mac_key" \
  bash "$SECURITY_INSTALL_DIR/current/scripts/backup.sh" --print-path)
[[ -f $custom_key && ! -L $custom_key && -f $custom_mac_key && ! -L $custom_mac_key ]]
[[ $(stat -c '%U:%G %a' "$custom_key") == root:root\ 600 ]]
[[ $(stat -c '%U:%G %a' "$custom_mac_key") == root:root\ 600 ]]
chmod 777 "$custom_key" "$custom_mac_key"
SECURITY_BACKUP_KEY_FILE="$custom_key" SECURITY_BACKUP_MAC_KEY_FILE="$custom_mac_key" \
  bash "$SECURITY_INSTALL_DIR/current/scripts/backup.sh" --print-path >/dev/null
[[ $(stat -c '%U:%G %a' "$custom_key") == root:root\ 600 ]]
[[ $(stat -c '%U:%G %a' "$custom_mac_key") == root:root\ 600 ]]
custom_key_hash=$(sha256sum "$custom_key" | awk '{print $1}')
custom_mac_hash=$(sha256sum "$custom_mac_key" | awk '{print $1}')
"$PRIVATE_NODE" "$SECURITY_INSTALL_DIR/current/scripts/backup-auth.js" verify-extract \
  "$custom_mac_key" "$custom_backup" "$WORK/custom-ciphertext"
"$PRIVATE_NODE" "$SECURITY_INSTALL_DIR/current/scripts/backup-auth.js" derive "$custom_key" \
  | openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass stdin \
    -in "$WORK/custom-ciphertext" -out "$WORK/custom-plaintext"
tail -c +18 "$WORK/custom-plaintext" > "$WORK/custom-archive.tar.gz"
if tar -tzf "$WORK/custom-archive.tar.gz" | grep -Eq '(^|/)(custom/encryption\.key|private/authentication\.key)$'; then
  echo 'Custom backup key material was included in the backup payload' >&2
  exit 1
fi
printf '{"sentinel":"custom-mutated"}\n' > "$SECURITY_DATA_DIR/runtime/state.json"
SECURITY_BACKUP_KEY_FILE="$custom_key" SECURITY_BACKUP_MAC_KEY_FILE="$custom_mac_key" \
  bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$custom_backup" --no-service
[[ $(sha256sum "$custom_key" | awk '{print $1}') == "$custom_key_hash" ]]
[[ $(sha256sum "$custom_mac_key" | awk '{print $1}') == "$custom_mac_hash" ]]
[[ $(jq -r .sentinel "$SECURITY_DATA_DIR/runtime/state.json") == preserved ]]

printf 'short\n' > "$SECURITY_CONFIG_DIR/custom/short.key"
if SECURITY_BACKUP_KEY_FILE="$SECURITY_CONFIG_DIR/custom/short.key" SECURITY_BACKUP_MAC_KEY_FILE="$custom_mac_key" \
  bash "$SECURITY_INSTALL_DIR/current/scripts/backup.sh" --print-path >/dev/null 2>&1; then
  echo 'Backup accepted a short custom encryption key' >&2
  exit 1
fi
mkdir "$SECURITY_CONFIG_DIR/custom/directory.key"
if SECURITY_BACKUP_KEY_FILE="$SECURITY_CONFIG_DIR/custom/directory.key" SECURITY_BACKUP_MAC_KEY_FILE="$custom_mac_key" \
  bash "$SECURITY_INSTALL_DIR/current/scripts/backup.sh" --print-path >/dev/null 2>&1; then
  echo 'Backup accepted a directory as a custom encryption key' >&2
  exit 1
fi
printf 'external-key-target\n' > "$WORK/external-key-target"
ln -s "$WORK/external-key-target" "$SECURITY_CONFIG_DIR/custom/symlink.key"
if SECURITY_BACKUP_KEY_FILE="$SECURITY_CONFIG_DIR/custom/symlink.key" SECURITY_BACKUP_MAC_KEY_FILE="$custom_mac_key" \
  bash "$SECURITY_INSTALL_DIR/current/scripts/backup.sh" --print-path >/dev/null 2>&1; then
  echo 'Backup accepted a symbolic-link custom encryption key' >&2
  exit 1
fi
[[ $(cat "$WORK/external-key-target") == external-key-target ]]
rm -rf -- "$SECURITY_CONFIG_DIR/custom" "$SECURITY_DATA_DIR/private"

for tamper_case in header hmac ciphertext; do
  tampered_backup="$WORK/tampered-$tamper_case.tar.gz.enc"
  cp "$manual_backup" "$tampered_backup"
  case "$tamper_case" in
    header) mutate_file_byte "$tampered_backup" 0 ;;
    hmac) mutate_file_byte "$tampered_backup" 18 ;;
    ciphertext) mutate_file_byte "$tampered_backup" -1 ;;
  esac
  if bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$tampered_backup" --no-service >/dev/null 2>&1; then
    echo "V3 backup tampering was accepted: $tamper_case" >&2
    exit 1
  fi
done

openssl rand -hex 48 > "$WORK/wrong-mac.key"
if SECURITY_BACKUP_MAC_KEY_FILE="$WORK/wrong-mac.key" \
  bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$manual_backup" --no-service >/dev/null 2>&1; then
  echo 'V3 backup with wrong MAC key was accepted' >&2
  exit 1
fi

openssl rand -hex 48 > "$WORK/wrong-encryption.key"
if SECURITY_BACKUP_KEY_FILE="$WORK/wrong-encryption.key" \
  bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$manual_backup" --no-service >/dev/null 2>&1; then
  echo 'V3 backup with wrong encryption key was accepted' >&2
  exit 1
fi

downgraded_backup="$WORK/downgraded-backup.tar.gz.enc"
tail -c +84 "$manual_backup" > "$downgraded_backup"
(cd "$WORK" && sha256sum "$(basename "$downgraded_backup")" > "$(basename "$downgraded_backup").sha256")
if bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$downgraded_backup" --no-service --allow-legacy >/dev/null 2>&1; then
  echo 'Authenticated backup was downgraded into the legacy restore path' >&2
  exit 1
fi

"$PRIVATE_NODE" "$SECURITY_INSTALL_DIR/current/scripts/backup-auth.js" verify-extract \
  "$SECURITY_CONFIG_DIR/backup.mac.key" "$manual_backup" "$WORK/v3-ciphertext"
"$PRIVATE_NODE" "$SECURITY_INSTALL_DIR/current/scripts/backup-auth.js" derive "$SECURITY_CONFIG_DIR/backup.key" \
  | openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass stdin \
    -in "$WORK/v3-ciphertext" -out "$WORK/v3-plaintext"
tail -c +18 "$WORK/v3-plaintext" > "$WORK/legacy-archive.tar.gz"

mkdir "$WORK/install-env-payload"
tar -xzf "$WORK/legacy-archive.tar.gz" -C "$WORK/install-env-payload"
cat >> "$WORK/install-env-payload/config/install.env" <<'ENV'
RESTORE_FUTURE_SETTING=kept
SECURITY_PUBLIC_HOST=duplicate.invalid
SECURITY_SERVICE_USER=duplicate-user
ENV
tar -C "$WORK/install-env-payload" -czf "$WORK/install-env-archive.tar.gz" .
install_env_backup="$WORK/install-env-backup.tar.gz.enc"
pack_v3_archive "$WORK/install-env-archive.tar.gz" "$install_env_backup"
bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$install_env_backup" --no-service
grep -qx 'RESTORE_FUTURE_SETTING=kept' "$SECURITY_CONFIG_DIR/install.env"
[[ $(grep -c '^SECURITY_PUBLIC_HOST=' "$SECURITY_CONFIG_DIR/install.env") == 1 ]]
[[ $(grep -c '^SECURITY_SERVICE_USER=' "$SECURITY_CONFIG_DIR/install.env") == 1 ]]
grep -qx 'SECURITY_PUBLIC_HOST=127.0.0.1' "$SECURITY_CONFIG_DIR/install.env"
grep -qx 'SECURITY_SERVICE_USER=nobody' "$SECURITY_CONFIG_DIR/install.env"
[[ $(stat -c '%U:%G %a' "$SECURITY_CONFIG_DIR/install.env") == root:root\ 600 ]]

mkdir "$WORK/symlink-payload"
tar -xzf "$WORK/legacy-archive.tar.gz" -C "$WORK/symlink-payload"
printf 'external-install-env-target\n' > "$WORK/external-install-env-target"
rm -f -- "$WORK/symlink-payload/config/install.env"
ln -s "$WORK/external-install-env-target" "$WORK/symlink-payload/config/install.env"
tar -C "$WORK/symlink-payload" -czf "$WORK/symlink-archive.tar.gz" .
symlink_backup="$WORK/symlink-backup.tar.gz.enc"
pack_v3_archive "$WORK/symlink-archive.tar.gz" "$symlink_backup"
if bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$symlink_backup" --no-service >/dev/null 2>&1; then
  echo 'Restore accepted a symbolic link in the backup payload' >&2
  exit 1
fi
[[ $(cat "$WORK/external-install-env-target") == external-install-env-target ]]

mkdir "$WORK/hardlink-payload"
tar -xzf "$WORK/legacy-archive.tar.gz" -C "$WORK/hardlink-payload"
ln "$WORK/hardlink-payload/config/config.json" "$WORK/hardlink-payload/data/hardlink-config.json"
tar -C "$WORK/hardlink-payload" -czf "$WORK/hardlink-archive.tar.gz" .
hardlink_backup="$WORK/hardlink-backup.tar.gz.enc"
pack_v3_archive "$WORK/hardlink-archive.tar.gz" "$hardlink_backup"
if bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$hardlink_backup" --no-service >/dev/null 2>&1; then
  echo 'Restore accepted a hard link in the backup payload' >&2
  exit 1
fi

{ printf 'APPGOG-BACKUP-V2\n'; cat "$WORK/legacy-archive.tar.gz"; } > "$WORK/v2-plaintext"
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 -pass file:"$SECURITY_CONFIG_DIR/backup.key" \
  -in "$WORK/v2-plaintext" -out "$WORK/v2-ciphertext"
v2_backup="$WORK/v2-backup.tar.gz.enc"
{ printf 'APPGOG-BACKUP-V2\n'; cat "$WORK/v2-ciphertext"; } > "$v2_backup"
"$PRIVATE_NODE" "$SECURITY_INSTALL_DIR/current/scripts/backup-auth.js" create \
  "$SECURITY_CONFIG_DIR/backup.mac.key" "$v2_backup" > "$v2_backup.hmac"
if bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$v2_backup" --no-service >/dev/null 2>&1; then
  echo 'V2 backup was accepted without --allow-legacy' >&2
  exit 1
fi
cp "$v2_backup.hmac" "$WORK/v2-backup.hmac.valid"
rm -f -- "$v2_backup.hmac"
if bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$v2_backup" --no-service --allow-legacy >/dev/null 2>&1; then
  echo 'V2 backup without its HMAC sidecar was accepted' >&2
  exit 1
fi
printf '%064d\n' 0 > "$v2_backup.hmac"
if bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$v2_backup" --no-service --allow-legacy >/dev/null 2>&1; then
  echo 'V2 backup with a damaged HMAC sidecar was accepted' >&2
  exit 1
fi
mv "$WORK/v2-backup.hmac.valid" "$v2_backup.hmac"
printf '{"sentinel":"v2-mutated"}\n' > "$SECURITY_DATA_DIR/runtime/state.json"
bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$v2_backup" --no-service --allow-legacy
[[ $(jq -r .sentinel "$SECURITY_DATA_DIR/runtime/state.json") == preserved ]]

legacy_backup="$WORK/legacy-backup.tar.gz.enc"
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 -pass file:"$SECURITY_CONFIG_DIR/backup.key" \
  -in "$WORK/legacy-archive.tar.gz" -out "$legacy_backup"
(cd "$WORK" && sha256sum "$(basename "$legacy_backup")" > "$(basename "$legacy_backup").sha256")
printf '{"sentinel":"legacy-mutated"}\n' > "$SECURITY_DATA_DIR/runtime/state.json"
if bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$legacy_backup" --no-service >/dev/null 2>&1; then
  echo 'Legacy backup was accepted without --allow-legacy' >&2
  exit 1
fi
bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$legacy_backup" --no-service --allow-legacy
[[ $(jq -r .sentinel "$SECURITY_DATA_DIR/runtime/state.json") == preserved ]]

printf '{"sentinel":"mutated"}\n' > "$SECURITY_DATA_DIR/runtime/state.json"
printf 'local-only\n' > "$SECURITY_CONFIG_DIR/local-only.marker"
chmod 751 "$SECURITY_CONFIG_DIR"
chmod 753 "$SECURITY_DATA_DIR"
install_env_hash_before_restore=$(sha256sum "$SECURITY_CONFIG_DIR/install.env" | awk '{print $1}')
config_hash_before_restore=$(sha256sum "$SECURITY_CONFIG_DIR/config.json" | awk '{print $1}')
current_before_restore=$(readlink "$SECURITY_INSTALL_DIR/current")
for checkpoint in after-config-clear after-data-clear after-install-env; do
  if SECURITY_TEST_FAIL_RESTORE_STEP=$checkpoint \
    bash "$SECURITY_INSTALL_DIR/current/scripts/restore.sh" --backup "$manual_backup" --no-service >/dev/null 2>&1; then
    echo "Injected restore failure was accepted: $checkpoint" >&2
    exit 1
  fi
  [[ $(jq -r .sentinel "$SECURITY_DATA_DIR/runtime/state.json") == mutated ]]
  [[ -f $SECURITY_CONFIG_DIR/local-only.marker ]]
  [[ $(stat -c %a "$SECURITY_CONFIG_DIR") == 751 ]]
  [[ $(stat -c %a "$SECURITY_DATA_DIR") == 753 ]]
  [[ $(sha256sum "$SECURITY_CONFIG_DIR/install.env" | awk '{print $1}') == "$install_env_hash_before_restore" ]]
  [[ $(sha256sum "$SECURITY_CONFIG_DIR/config.json" | awk '{print $1}') == "$config_hash_before_restore" ]]
  [[ $(readlink "$SECURITY_INSTALL_DIR/current") == "$current_before_restore" ]]
  [[ $(stat -c '%U:%G %a' "$SECURITY_CONFIG_DIR/install.env") == root:root\ 600 ]]
  [[ $(grep -c '^SECURITY_SERVICE_USER=' "$SECURITY_CONFIG_DIR/install.env") == 1 ]]
  grep -qx 'SECURITY_SERVICE_USER=nobody' "$SECURITY_CONFIG_DIR/install.env"
  assert_service_state inactive enabled
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

set_service_state inactive enabled
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
