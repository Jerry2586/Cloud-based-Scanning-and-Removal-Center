#!/usr/bin/env bash
# Disposable Linux runner only. Real packages and clamscan, no dependency on public DB availability.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[[ $EUID == 0 && $(uname -s) == Linux && -n ${GITHUB_ACTIONS:-} ]] || { echo 'Disposable GitHub Linux runner required' >&2; exit 1; }
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
python3 "$ROOT/src/host/antivirus.py" | python3 -c 'import json,sys;v=json.load(sys.stdin);assert v["installed"] and v["state"]=="unavailable" and v["updater"]=="scheduled"'
systemctl disable --now ironcurtain-antivirus-update.timer
