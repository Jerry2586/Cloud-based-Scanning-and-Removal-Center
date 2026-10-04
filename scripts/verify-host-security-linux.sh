#!/usr/bin/env sh
# Ephemeral CI only. Never runs on an existing APPGOG security installation.
set -eu
[ "${GITHUB_ACTIONS:-}" = true ] || { echo 'Only isolated GitHub Actions runners are supported' >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo 'Requires root on the isolated runner' >&2; exit 1; }
SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
TEST_ROOT=/appgog-host-security-ci
UNIT=/etc/systemd/system/appgog-host-security.service
STATE=/var/lib/appgog-security
AGENT=/usr/local/lib/appgog-security/host-security-agent.py
[ -d /run/systemd/system ] || { echo 'Running systemd required' >&2; exit 1; }
for target in "$TEST_ROOT" "$UNIT" "$STATE" "$AGENT"; do
  [ ! -e "$target" ] && [ ! -L "$target" ] || { echo "Existing installation: $target" >&2; exit 1; }
done
install -d -o root -g root -m 0700 "$TEST_ROOT/releases/candidate" "$TEST_ROOT/shared"
RELEASE=$TEST_ROOT/releases/candidate
cp -R "$SOURCE/apps" "$SOURCE/packages" "$SOURCE/scripts" "$RELEASE/"
for name in package.json pnpm-lock.yaml release-contract.json Dockerfile compose.yaml compose.license.yaml compose.build.yaml Caddyfile Caddyfile.license Caddyfile.build .env.example .env.docker.example .dockerignore install-docker.sh; do cp "$SOURCE/$name" "$RELEASE/$name"; done
chown -R root:root "$TEST_ROOT"
ln -s releases/candidate "$TEST_ROOT/current"
printf 'AUTH_DOMAIN=license.appgog.test
BUILD_DOMAIN=build.appgog.test
' > "$TEST_ROOT/shared/.env"
chmod 600 "$TEST_ROOT/shared/.env"
export APPGOG_INSTALL_ROOT=$TEST_ROOT APPGOG_HOST_ENV_FILE=$TEST_ROOT/shared/.env PYTHONDONTWRITEBYTECODE=1
LOGIN_USER=appgog-security-ci
LOGIN_HOME=/home/appgog-security-ci
LOGIN_CREATED=0
checkpoint=setup
lifecycle() { sh "$RELEASE/scripts/install-host-security.sh" "$1"; }
wait_report() {
  previous_checked_at=${1:-}
  attempt=0
  while [ "$attempt" -lt 90 ]; do
    if curl -fsS --max-time 5 --unix-socket /run/appgog-security/scan.sock http://localhost/status > "$TEST_ROOT/report.json" &&
       jq -e --arg previous "$previous_checked_at" '.state == "finished" and (.checked_at | type == "string") and ($previous == "" or .checked_at != $previous)' "$TEST_ROOT/report.json" >/dev/null; then
      python3 - "$AGENT" "$TEST_ROOT/report.json" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location('accepted_agent', sys.argv[1])
a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)
with open(sys.argv[2], encoding='utf-8') as stream:
    report = json.load(stream)
assert a.complete_scan_checks(report.get('checks'), report.get('checked_at')), 'Incomplete live Linux scan report'
PY
      return
    fi
    attempt=$((attempt + 1)); sleep 2
  done
  echo 'Initial/upgrade inspection did not finish' >&2
  return 1
}
request_fresh_scan() {
  wait_report
  prior_checked_at=$(jq -er '.checked_at' "$TEST_ROOT/report.json")
  attempt=0
  while [ "$attempt" -lt 90 ]; do
    # Respect the production cooldown and active scan lock; never weaken either.
    code=$(curl -sS --max-time 5 --unix-socket /run/appgog-security/scan.sock \
      -o "$TEST_ROOT/scan-trigger.json" -w '%{http_code}' -X POST http://localhost/scan) || return 1
    case "$code" in
      202) wait_report "$prior_checked_at"; return $? ;;
      409|429) attempt=$((attempt + 1)); sleep 2 ;;
      *) echo "Scan trigger failed: HTTP $code" >&2; return 1 ;;
    esac
  done
  echo 'Scan trigger did not become available within the bounded retry window' >&2
  return 1
}
cleanup() {
  result=$?
  trap - 0 INT TERM
  if [ "$result" -ne 0 ]; then
    echo "Local acceptance failed at: $checkpoint" >&2
    journalctl -u appgog-host-security.service -u appgog-firewall-monitor.service --no-pager -n 35 || true
    if [ -s "$STATE/firewall-report.json" ]; then cat "$STATE/firewall-report.json"; fi
  fi
  lifecycle uninstall || true
  # Fixed CI-only paths and account; never recursively remove a user-supplied home.
  if [ "$LOGIN_CREATED" = 1 ] && [ "$LOGIN_HOME" = /home/appgog-security-ci ]; then
    rm -f "$LOGIN_HOME/.ssh/authorized_keys" "$LOGIN_HOME/.ssh/environment"
    rmdir "$LOGIN_HOME/.ssh" "$LOGIN_HOME" 2>/dev/null || true
    userdel "$LOGIN_USER" || true
  fi
  # The baseline/history/group remain as required by the uninstall contract.
  exit "$result"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM
# Disposable disabled-password login account; never use a runner/root key file.
[ ! -e "$LOGIN_HOME" ] && [ ! -L "$LOGIN_HOME" ] || { echo 'Existing login fixture home' >&2; exit 1; }
if getent passwd "$LOGIN_USER" >/dev/null; then echo 'Existing login fixture account' >&2; exit 1; fi
useradd --no-create-home --home-dir "$LOGIN_HOME" --shell /bin/sh "$LOGIN_USER"
LOGIN_CREATED=1
install -d -o "$LOGIN_USER" -g "$LOGIN_USER" -m 0700 "$LOGIN_HOME" "$LOGIN_HOME/.ssh"
printf 'CI-only nonfunctional public-key marker\n' > "$LOGIN_HOME/.ssh/authorized_keys"
chown "$LOGIN_USER:$LOGIN_USER" "$LOGIN_HOME/.ssh/authorized_keys"
chmod 600 "$LOGIN_HOME/.ssh/authorized_keys"
# Do not make lifecycle acceptance depend on a third-party feed CDN.
# An invalid CI-only daily file intentionally leaves production malware status unknown.
if [ ! -f /var/lib/clamav/daily.cvd ] && [ ! -f /var/lib/clamav/daily.cld ]; then
  systemctl stop clamav-freshclam.service || true
  printf 'CI-only invalid daily database; never a trusted feed' > /var/lib/clamav/daily.cvd
fi
# Reject environment overrides before privileged scripts can execute.
UNTRUSTED=$TEST_ROOT/untrusted
install -d -m 0777 "$UNTRUSTED/scripts"
printf 'touch %s/unsafe-executed\n' "$TEST_ROOT" > "$UNTRUSTED/scripts/install-host-security.sh"
if APPGOG_INSTALL_ROOT="$UNTRUSTED" sh "$SOURCE/scripts/security-local.sh" engine; then echo 'Untrusted local root accepted' >&2; exit 1; fi
if APPGOG_ROOT="$UNTRUSTED" sh "$SOURCE/scripts/appgog.sh" status; then echo 'Untrusted manager root accepted' >&2; exit 1; fi
[ ! -e "$TEST_ROOT/unsafe-executed" ]
python3 -I "$SOURCE/tests/fixtures/host-security-cloudflare.py"
lifecycle prepare
lifecycle install
# Preserve a completed pre-mutation report before testing transition history.
# New Docker inspection may outlive installer readiness; socket readiness alone is insufficient.
wait_report
jq -e 'any(.checks[]; .id == "integrity.program" and .state == "ok")' "$TEST_ROOT/report.json" >/dev/null
# Enabling an installer-owned timer must not invalidate the fresh host baseline.
jq -e 'any(.checks[]; .id == "host.configuration" and .state == "ok")' "$TEST_ROOT/report.json" >/dev/null
checkpoint=host-login-persistence
python3 -I "$SOURCE/tests/fixtures/host-security-login.py"
grep -Fxq 'ProtectHome=read-only' "$UNIT"
jq -e --arg key "$LOGIN_HOME/.ssh/authorized_keys" '.schema == 1 and .files[$key].digest != null' "$STATE/host-baseline.json" >/dev/null
login_baseline_hash=$(sha256sum "$STATE/host-baseline.json" | cut -d' ' -f1)
printf 'CI-only additional login-key marker\n' >> "$LOGIN_HOME/.ssh/authorized_keys"
request_fresh_scan
jq -e 'any(.checks[]; .id == "host.configuration" and .state == "finding")' "$TEST_ROOT/report.json" >/dev/null
if grep -Fq 'CI-only additional login-key marker' "$TEST_ROOT/report.json"; then echo 'Key content escaped into report' >&2; exit 1; fi
[ "$(sha256sum "$STATE/host-baseline.json" | cut -d' ' -f1)" = "$login_baseline_hash" ]
printf 'CI-only nonfunctional public-key marker\n' > "$LOGIN_HOME/.ssh/authorized_keys"
request_fresh_scan
jq -e 'any(.checks[]; .id == "host.configuration" and .state == "ok")' "$TEST_ROOT/report.json" >/dev/null
printf 'CI_ONLY=not-a-secret\n' > "$LOGIN_HOME/.ssh/environment"
chown "$LOGIN_USER:$LOGIN_USER" "$LOGIN_HOME/.ssh/environment"
chmod 600 "$LOGIN_HOME/.ssh/environment"
request_fresh_scan
jq -e 'any(.checks[]; .id == "host.configuration" and .state == "finding")' "$TEST_ROOT/report.json" >/dev/null
rm -f "$LOGIN_HOME/.ssh/environment"
chmod 666 "$LOGIN_HOME/.ssh/authorized_keys"
request_fresh_scan
jq -e 'any(.checks[]; .id == "host.configuration" and .state == "unavailable")' "$TEST_ROOT/report.json" >/dev/null
if sh "$RELEASE/scripts/security-local.sh" approve-host APPROVE-HOST; then echo 'Unsafe login permissions approved' >&2; exit 1; fi
[ "$(sha256sum "$STATE/host-baseline.json" | cut -d' ' -f1)" = "$login_baseline_hash" ]
chmod 600 "$LOGIN_HOME/.ssh/authorized_keys"
request_fresh_scan
jq -e 'any(.checks[]; .id == "host.configuration" and .state == "ok")' "$TEST_ROOT/report.json" >/dev/null
checkpoint=host-network
# Actual host proc reads must work under the hardened unit; no automatic route approval.
if ! jq -e '(.checks | length <= 26) and any(.checks[]; .id == "network.udp-listeners" and (.state == "ok" or .state == "warning")) and any(.checks[]; .id == "network.routes" and .state == "unavailable") and any(.checks[]; .id == "host.kernel-security" and (.state == "ok" or .state == "warning"))' "$TEST_ROOT/report.json" >/dev/null; then
  jq '{state, check_count: (.checks | length), network: [.checks[] | select(.id == "network.udp-listeners" or .id == "network.routes" or .id == "host.kernel-security") | {id,state,detail}]}' "$TEST_ROOT/report.json" >&2
  exit 1
fi
[ "$(wc -c < "$TEST_ROOT/report.json")" -le 32768 ]
[ ! -e "$STATE/network-baseline.json" ]
# Exercise proc network lookups across kernel timestamp refresh boundaries.
python3 - "$AGENT" <<'PY'
import importlib.util
import sys
import time
spec = importlib.util.spec_from_file_location('acceptance_agent', sys.argv[1])
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)
for attempt in range(4):
    agent.route_snapshot()
    agent.fixed_proc_text('/proc/net/udp')
    agent.fixed_proc_text('/proc/net/udp6')
    for path in agent.KERNEL_POLICY:
        agent.fixed_proc_text(path)
    if attempt < 3:
        time.sleep(0.55)
PY
checkpoint=route-approval
fingerprint=$(sh "$RELEASE/scripts/security-local.sh" network-fingerprint)
if sh "$RELEASE/scripts/security-local.sh" approve-network invalid > "$TEST_ROOT/network-refusal.log" 2>&1; then echo 'Invalid network fingerprint accepted' >&2; exit 1; fi
[ ! -e "$STATE/network-baseline.json" ]
sh "$RELEASE/scripts/security-local.sh" approve-network "$fingerprint"
[ "$(stat -c '%u:%g:%a' "$STATE/network-baseline.json")" = '0:0:600' ]
network_hash=$(sha256sum "$STATE/network-baseline.json" | cut -d' ' -f1)
wait_report
jq -e 'any(.checks[]; .id == "network.routes" and .state == "ok")' "$TEST_ROOT/report.json" >/dev/null

checkpoint=firewall-host-snapshot
# Read-only actual host snapshot; never approve a snapshot implicitly.
systemctl start appgog-firewall-monitor.service
if ! jq -e '.state == "finished" and .snapshot.sources.nftables and .snapshot.sources.iptables and .snapshot.sources.ip6tables' "$STATE/firewall-report.json" >/dev/null; then
  # CI-only probe retains the installed service's exact sandbox. Do not print rules.
  diagnostic=/usr/local/lib/appgog-security/ci-firewall-diagnostic.py
  diagnostic_dropin=/etc/systemd/system/appgog-firewall-monitor.service.d
  cat > "$diagnostic" <<'PY'
import importlib.util,json,os
s=importlib.util.spec_from_file_location('diagnostic_firewall','/usr/local/lib/appgog-security/host-security-firewall.py')
f=importlib.util.module_from_spec(s); s.loader.exec_module(f)
f.SERVICE_COLLECTION=True
for label, operation in (
    ('self-network-namespace',lambda: os.readlink('/proc/self/ns/net')),
    ('init-network-namespace',lambda: os.readlink('/proc/1/ns/net')),
    ('container-detection',lambda: f.trusted_executable('/usr/bin/systemd-detect-virt')),
    ('complete-snapshot',lambda: f.snapshot())):
    try:
        operation()
        print(json.dumps({'probe':label,'state':'ok'}),flush=True)
    except Exception as error:
        print(json.dumps({'probe':label,'state':'failed','error':type(error).__name__,'errno':getattr(error,'errno',None)}),flush=True)
PY
  chmod 700 "$diagnostic"
  install -d -m 0755 "$diagnostic_dropin"
  cat > "$diagnostic_dropin/ci.conf" <<EOF
[Service]
ExecStart=
ExecStart=/usr/bin/python3 -I $diagnostic
StandardOutput=journal
EOF
  systemctl daemon-reload
  systemctl start appgog-firewall-monitor.service
  journalctl -u appgog-firewall-monitor.service --no-pager -n 20
  rm -f "$diagnostic" "$diagnostic_dropin/ci.conf"
  rmdir "$diagnostic_dropin"
  systemctl daemon-reload
  exit 1
fi
[ "$(stat -c '%u:%g:%a' "$STATE/firewall-report.json")" = '0:0:600' ]
[ ! -e "$STATE/firewall-baseline.json" ]
python3 -I - "$AGENT" <<'PY'
import importlib.util,sys
spec=importlib.util.spec_from_file_location('firewall_backend',sys.argv[1])
a=importlib.util.module_from_spec(spec); spec.loader.exec_module(a)
assert a.firewall_check()['state']=='warning'
PY
if sh "$RELEASE/scripts/security-local.sh" firewall approve invalid; then echo 'Invalid firewall approval accepted' >&2; exit 1; fi
[ ! -e "$STATE/firewall-baseline.json" ]
checkpoint=firewall-approval
firewall_fingerprint=$(sh "$RELEASE/scripts/security-local.sh" firewall fingerprint)
sh "$RELEASE/scripts/security-local.sh" firewall approve "$firewall_fingerprint"
[ "$(stat -c '%u:%g:%a' "$STATE/firewall-baseline.json")" = '0:0:600' ]
firewall_baseline_hash=$(sha256sum "$STATE/firewall-baseline.json" | cut -d' ' -f1)
firewall_executable_hash=$(sha256sum /usr/local/lib/appgog-security/host-security-firewall.py | cut -d' ' -f1)
systemctl is-enabled --quiet appgog-firewall-monitor.timer
systemctl is-active --quiet appgog-firewall-monitor.timer
grep -Fxq 'RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6' /etc/systemd/system/appgog-firewall-monitor.service
grep -Fxq 'ExecStartPre=+/usr/bin/python3 -I /usr/local/lib/appgog-security/host-security-firewall.py prepare-namespace' /etc/systemd/system/appgog-firewall-monitor.service
grep -Fxq 'ExecStart=/usr/bin/python3 -I /usr/local/lib/appgog-security/host-security-firewall.py collect-service' /etc/systemd/system/appgog-firewall-monitor.service
[ "$(stat -c '%u:%g:%a' "$STATE/firewall-namespace.json")" = '0:0:600' ]
grep -Fxq 'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW' /etc/systemd/system/appgog-firewall-monitor.service
[ "$(stat -c '%u:%g:%a' /usr/local/lib/appgog-security/host-security-firewall.py)" = '0:0:700' ]
checkpoint=firewall-isolated-namespace
python3 -I "$SOURCE/scripts/verify-host-security-firewall-linux.py"
checkpoint=firewall-parser-regressions
python3 -I "$SOURCE/tests/fixtures/host-security-firewall.py"
checkpoint=firewall-backend-scan
request_fresh_scan
jq -e 'any(.checks[]; .id == "network.firewall" and (.state == "ok" or .state == "warning"))' "$TEST_ROOT/report.json" >/dev/null

gid=$(getent group appgog-security | cut -d: -f3)
[ "$(stat -c '%u:%g:%a' /run/appgog-security)" = "0:$gid:750" ]
[ "$(stat -c '%u:%g:%a' /run/appgog-security/scan.sock)" = "0:$gid:660" ]
[ "$(stat -c '%u:%g:%a' "$STATE/baseline.json")" = '0:0:600' ]
[ "$(stat -c '%u:%g:%a' "$STATE/host-baseline.json")" = '0:0:600' ]
systemctl is-active --quiet appgog-host-security.service
systemctl is-enabled --quiet appgog-local-response.timer
systemctl is-active --quiet appgog-local-response.timer
systemctl is-enabled --quiet appgog-cloudflare-monitor.timer
systemctl is-active --quiet appgog-cloudflare-monitor.timer
[ "$(stat -c '%u:%g:%a' /usr/local/lib/appgog-security/host-security-cloudflare.py)" = '0:0:700' ]
systemctl start appgog-cloudflare-monitor.service
jq -e '.checks | length == 4 and all(.[]; .state == "unavailable")' "$STATE/cloudflare-report.json" >/dev/null
grep -Fxq 'RestrictAddressFamilies=AF_UNIX' "$UNIT"
grep -Fxq 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' /etc/systemd/system/appgog-cloudflare-monitor.service
[ "$(stat -c '%u:%g:%a' /usr/local/sbin/appgog-security-response)" = '0:0:700' ]
[ "$(stat -c '%u:%g:%a' /usr/local/lib/appgog-security/response-config.json)" = '0:0:600' ]
[ "$(stat -c '%u:%g:%a' /usr/local/lib/appgog-security/release-public.pem)" = '0:0:600' ]
cloudflare_hash=$(sha256sum /usr/local/lib/appgog-security/host-security-cloudflare.py | cut -d' ' -f1)
response_hash=$(sha256sum /usr/local/lib/appgog-security/host-security-response.py | cut -d' ' -f1)
config_hash=$(sha256sum /usr/local/lib/appgog-security/response-config.json | cut -d' ' -f1)
key_hash=$(sha256sum /usr/local/lib/appgog-security/release-public.pem | cut -d' ' -f1)
program_hash=$(sha256sum "$STATE/baseline.json" | cut -d' ' -f1)
host_hash=$(sha256sum "$STATE/host-baseline.json" | cut -d' ' -f1)
printf '
// acceptance-only mutation
' >> "$RELEASE/apps/web/public/assets/portal/security-poller.js"
lifecycle install
[ "$(sha256sum "$STATE/baseline.json" | cut -d' ' -f1)" = "$program_hash" ]
[ "$(sha256sum "$STATE/host-baseline.json" | cut -d' ' -f1)" = "$host_hash" ]
[ "$(sha256sum "$STATE/network-baseline.json" | cut -d' ' -f1)" = "$network_hash" ]
[ "$(sha256sum "$STATE/firewall-baseline.json" | cut -d' ' -f1)" = "$firewall_baseline_hash" ]
wait_report
if ! jq -e '.state == "finished" and any(.checks[]; .id == "integrity.program" and .state == "finding") and (.history | length > 0)' "$TEST_ROOT/report.json" >/dev/null; then
  jq '{state, checks: [.checks[] | {id,state}], history_count: (.history | length)}' "$TEST_ROOT/report.json" >&2
  exit 1
fi
# A rejected upgrade must restore the prior active executable and service.
agent_hash=$(sha256sum "$AGENT" | cut -d' ' -f1)
printf '
invalid python syntax (
' >> "$RELEASE/scripts/host-security-agent.py"
if lifecycle install; then echo 'Broken candidate unexpectedly installed' >&2; exit 1; fi
[ "$(sha256sum "$AGENT" | cut -d' ' -f1)" = "$agent_hash" ]
systemctl is-active --quiet appgog-host-security.service
cp "$SOURCE/scripts/host-security-agent.py" "$RELEASE/scripts/host-security-agent.py"
[ "$(sha256sum /usr/local/lib/appgog-security/host-security-response.py | cut -d' ' -f1)" = "$response_hash" ]
[ "$(sha256sum /usr/local/lib/appgog-security/response-config.json | cut -d' ' -f1)" = "$config_hash" ]
[ "$(sha256sum /usr/local/lib/appgog-security/release-public.pem | cut -d' ' -f1)" = "$key_hash" ]
systemctl is-active --quiet appgog-local-response.timer
# A later-phase error must restore all independent files and a stopped-but-enabled timer.
systemctl stop appgog-local-response.timer
printf '
invalid response syntax (
' >> "$RELEASE/scripts/host-security-response.py"
if lifecycle install; then echo 'Broken response candidate unexpectedly installed' >&2; exit 1; fi
[ "$(sha256sum /usr/local/lib/appgog-security/host-security-response.py | cut -d' ' -f1)" = "$response_hash" ]
systemctl is-enabled --quiet appgog-local-response.timer
if systemctl is-active --quiet appgog-local-response.timer; then echo 'Rollback changed prior inactive timer state' >&2; exit 1; fi
cp "$SOURCE/scripts/host-security-response.py" "$RELEASE/scripts/host-security-response.py"
lifecycle install
systemctl is-active --quiet appgog-local-response.timer
# Collector parse failure must preserve its executable and inactive enabled timer.
systemctl stop appgog-cloudflare-monitor.timer
printf '
invalid cloudflare syntax (
' >> "$RELEASE/scripts/host-security-cloudflare.py"
if lifecycle install; then echo 'Broken Cloudflare candidate unexpectedly installed' >&2; exit 1; fi
[ "$(sha256sum /usr/local/lib/appgog-security/host-security-cloudflare.py | cut -d' ' -f1)" = "$cloudflare_hash" ]
systemctl is-enabled --quiet appgog-cloudflare-monitor.timer
if systemctl is-active --quiet appgog-cloudflare-monitor.timer; then echo 'Rollback changed Cloudflare inactive timer state' >&2; exit 1; fi
systemctl is-active --quiet appgog-host-security.service
systemctl is-active --quiet appgog-local-response.timer
cp "$SOURCE/scripts/host-security-cloudflare.py" "$RELEASE/scripts/host-security-cloudflare.py"
lifecycle install
systemctl is-active --quiet appgog-cloudflare-monitor.timer
# Independent key pin mismatch fails without silently rotating the trust root.
printf 'invalid key
' > "$RELEASE/scripts/release-public.pem"
if lifecycle install; then echo 'Changed independent signing pin accepted' >&2; exit 1; fi
[ "$(sha256sum /usr/local/lib/appgog-security/release-public.pem | cut -d' ' -f1)" = "$key_hash" ]
cp "$SOURCE/scripts/release-public.pem" "$RELEASE/scripts/release-public.pem"

# Failed upgrade restores an enabled-but-inactive firewall timer exactly.
systemctl stop appgog-firewall-monitor.timer appgog-firewall-monitor.service
printf '\ninvalid python syntax (\n' >> "$RELEASE/scripts/host-security-firewall.py"
if lifecycle install; then echo 'Broken firewall collector installed' >&2; exit 1; fi
[ "$(sha256sum /usr/local/lib/appgog-security/host-security-firewall.py | cut -d' ' -f1)" = "$firewall_executable_hash" ]
[ "$(sha256sum "$STATE/firewall-baseline.json" | cut -d' ' -f1)" = "$firewall_baseline_hash" ]
systemctl is-enabled --quiet appgog-firewall-monitor.timer
if systemctl is-active --quiet appgog-firewall-monitor.timer; then echo 'Inactive firewall timer was incorrectly started during rollback' >&2; exit 1; fi
systemctl is-active --quiet appgog-host-security.service
cp "$SOURCE/scripts/host-security-firewall.py" "$RELEASE/scripts/host-security-firewall.py"
systemctl start appgog-firewall-monitor.timer

# Verify real non-root containers can use only the explicitly granted socket.
docker pull node:24-bookworm-slim
client='const http=require("http"); const r=http.get({socketPath:"/scan/scan.sock",path:"/status"},s=>{let b="";s.on("data",c=>b+=c);s.on("end",()=>{if(s.statusCode!==200||!JSON.parse(b).state)process.exit(2)});});r.on("error",()=>process.exit(3));'
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user "65534:$gid" --group-add "$gid" -v /run/appgog-security:/scan:ro node:24-bookworm-slim node -e "$client"
if docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 -v /run/appgog-security:/scan:ro node:24-bookworm-slim node -e "$client"; then echo 'Unauthorized container accessed scan socket' >&2; exit 1; fi
python3 -I "$SOURCE/scripts/verify-host-security-engine.py" "$SOURCE/scripts/host-security-agent.py"
python3 -I "$SOURCE/scripts/verify-host-security-response-linux.py" "$TEST_ROOT"
# Successful signed repair creates a new approved source baseline; preserve that exact baseline thereafter.
program_hash=$(sha256sum "$STATE/baseline.json" | cut -d' ' -f1)
lifecycle uninstall
[ ! -e "$UNIT" ] && [ ! -e "$AGENT" ] && [ ! -e /run/appgog-security/scan.sock ]
[ ! -e /usr/local/sbin/appgog-security-response ]
[ ! -e /etc/systemd/system/appgog-local-response.timer ]
[ ! -e /etc/systemd/system/appgog-local-response.service ]
[ ! -e /etc/systemd/system/appgog-cloudflare-monitor.service ]
[ ! -e /etc/systemd/system/appgog-cloudflare-monitor.timer ]
[ ! -e /usr/local/lib/appgog-security/host-security-cloudflare.py ]
[ -s "$STATE/cloudflare-report.json" ]
[ ! -e /etc/systemd/system/appgog-firewall-monitor.service ]
[ ! -e /etc/systemd/system/appgog-firewall-monitor.timer ]
[ ! -e /usr/local/lib/appgog-security/host-security-firewall.py ]
[ -s "$STATE/firewall-report.json" ]
if systemctl is-active --quiet appgog-firewall-monitor.timer; then echo 'Firewall timer survived uninstall' >&2; exit 1; fi
if systemctl is-active --quiet appgog-cloudflare-monitor.timer; then echo 'CF timer survived uninstall' >&2; exit 1; fi
[ "$(sha256sum /usr/local/lib/appgog-security/response-config.json | cut -d' ' -f1)" = "$config_hash" ]
[ "$(sha256sum /usr/local/lib/appgog-security/release-public.pem | cut -d' ' -f1)" = "$key_hash" ]
if systemctl is-active --quiet appgog-local-response.timer; then echo 'Response timer survived uninstall' >&2; exit 1; fi
[ "$(sha256sum "$STATE/baseline.json" | cut -d' ' -f1)" = "$program_hash" ]
[ "$(sha256sum "$STATE/host-baseline.json" | cut -d' ' -f1)" = "$host_hash" ]
[ "$(sha256sum "$STATE/network-baseline.json" | cut -d' ' -f1)" = "$network_hash" ]
[ "$(sha256sum "$STATE/firewall-baseline.json" | cut -d' ' -f1)" = "$firewall_baseline_hash" ]
[ -s "$STATE/events.json" ] && getent group appgog-security >/dev/null
# Released history survives repeated uninstall and must not block a safe reinstall.
incident_hash=$(sha256sum "$STATE/incident.json" | cut -d' ' -f1)
cp -p "$STATE/incident.json" "$TEST_ROOT/released-incident.json"
lifecycle uninstall
[ "$(sha256sum "$STATE/incident.json" | cut -d' ' -f1)" = "$incident_hash" ]
# No CLI remains: active, malformed, oversized, foreign or linked records stay fenced.
for invalid in active malformed oversized foreign-root bad-container unsafe-mode symlink; do
  python3 -I - "$STATE/incident.json" "$TEST_ROOT/released-incident.json" "$invalid" <<'PY'
import json,os,sys
path,backup,case=sys.argv[1:]
if os.path.lexists(path): os.unlink(path)
item=json.load(open(backup))
if case == 'symlink':
    os.symlink(backup,path)
else:
    if case == 'active': item['state']='contained'
    if case == 'foreign-root': item['root']='/foreign-installation'
    if case == 'bad-container': item['container_id']='short-id'
    payload='invalid JSON' if case == 'malformed' else json.dumps(item)
    if case == 'oversized': payload += ' ' * 32769
    with open(path,'w') as stream: stream.write(payload)
    os.chmod(path,0o666 if case == 'unsafe-mode' else 0o600)
PY
  for action in install uninstall; do
    if lifecycle "$action" > "$TEST_ROOT/incident-guard.log" 2>&1; then
      echo "Invalid retained incident accepted: $invalid / $action" >&2; exit 1
    fi
    [ ! -e /usr/local/sbin/appgog-security-response ] && [ ! -e "$UNIT" ]
    [ "$(sha256sum /usr/local/lib/appgog-security/response-config.json | cut -d' ' -f1)" = "$config_hash" ]
    [ "$(sha256sum "$STATE/baseline.json" | cut -d' ' -f1)" = "$program_hash" ]
  done
done
rm -f "$STATE/incident.json"
cp -p "$TEST_ROOT/released-incident.json" "$STATE/incident.json"
lifecycle install
[ "$(sha256sum "$STATE/incident.json" | cut -d' ' -f1)" = "$incident_hash" ]
systemctl is-active --quiet appgog-host-security.service
systemctl is-active --quiet appgog-local-response.timer
[ "$(sha256sum "$STATE/baseline.json" | cut -d' ' -f1)" = "$program_hash" ]
[ "$(sha256sum "$STATE/host-baseline.json" | cut -d' ' -f1)" = "$host_hash" ]
[ "$(sha256sum "$STATE/network-baseline.json" | cut -d' ' -f1)" = "$network_hash" ]
[ "$(sha256sum "$STATE/firewall-baseline.json" | cut -d' ' -f1)" = "$firewall_baseline_hash" ]
echo 'Isolated Linux agent: install, upgrade, rollback, socket grants, engine and preserving uninstall passed'
