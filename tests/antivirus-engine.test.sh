#!/usr/bin/env bash
# Disposable Linux runner only. Real packages and clamscan, no dependency on public DB availability.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[[ $EUID == 0 && $(uname -s) == Linux && -n ${GITHUB_ACTIONS:-} ]] || { echo 'Disposable GitHub Linux runner required' >&2; exit 1; }
# This disposable-runner-only drop-in prevents systemd itself from bypassing
# the explicit service-start fixture when the runner has booted >5 minutes ago.
DROPIN=/etc/systemd/system/ironcurtain-antivirus-update.timer.d
[[ ! -e $DROPIN && ! -L $DROPIN ]] || { echo 'Existing timer overrides; refuse to replace them' >&2; exit 1; }
install -d -m 755 "$DROPIN"
cat > "$DROPIN/ci-isolation.conf" <<'EOF'
[Timer]
OnBootSec=
OnUnitActiveSec=
OnActiveSec=6h
RandomizedDelaySec=0
Persistent=false
EOF
chmod 644 "$DROPIN/ci-isolation.conf"
cleanup() {
  /usr/bin/systemctl disable --now ironcurtain-antivirus-update.timer >/dev/null 2>&1 || true
  rm -f -- "$DROPIN/ci-isolation.conf"
  rmdir -- "$DROPIN"
  /usr/bin/systemctl daemon-reload
}
trap cleanup EXIT
# Keep freshclam network retrieval separate from deterministic engine acceptance.
systemctl() {
  if [[ ${1:-} == start && ${2:-} == ironcurtain-antivirus-update.service ]]; then
    echo 'Fixture: official database download deferred; metadata must remain unavailable.'
    return 0
  fi
  /usr/bin/systemctl "$@"
}
export -f systemctl
bash "$ROOT/scripts/antivirus-engine.sh" install
[[ $(stat -c %a /etc/ironcurtain-antivirus) == 755 ]]
[[ $(stat -c %a /var/lib/ironcurtain-antivirus) == 755 ]]
[[ $(stat -c %a /var/lib/ironcurtain-antivirus/database) == 755 ]]
[[ $(stat -c %u /var/lib/ironcurtain-antivirus/database) == "$(id -u ironcurtain-av)" ]]
runuser -u ironcurtain-av -- test -r /etc/ironcurtain-antivirus/freshclam.conf
runuser -u ironcurtain-av -- test -w /var/lib/ironcurtain-antivirus/database
systemd-analyze verify /etc/systemd/system/ironcurtain-antivirus-update.service /etc/systemd/system/ironcurtain-antivirus-update.timer
python3 "$ROOT/tests/antivirus-metadata.test.py"
python3 "$ROOT/tests/antivirus-real.test.py"
python3 "$ROOT/src/host/antivirus.py" | python3 -c 'import json,sys;v=json.load(sys.stdin);assert v["installed"] and v["state"]=="unavailable" and v["updater"]=="scheduled", json.dumps(v)'
systemctl disable --now ironcurtain-antivirus-update.timer
