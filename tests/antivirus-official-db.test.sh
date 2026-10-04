#!/usr/bin/env bash
# Explicit disposable Linux acceptance: public database retrieval is not mocked.
set -euo pipefail
umask 077
export LC_ALL=C
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[[ $EUID == 0 && $(uname -s) == Linux && ${GITHUB_ACTIONS:-} == true && ${IRONCURTAIN_ACCEPT_DISPOSABLE_RUNNER:-} == 1 ]] || {
  echo 'Explicit disposable GitHub Linux runner acceptance required' >&2; exit 1;
}
for target in /etc/ironcurtain-antivirus /var/lib/ironcurtain-antivirus /etc/systemd/system/ironcurtain-antivirus-update.service /etc/systemd/system/ironcurtain-antivirus-update.timer; do
  [[ ! -e $target && ! -L $target ]] || { echo 'Existing antivirus installation; refusing test replacement' >&2; exit 1; }
done
WORK=$(mktemp -d)
cleanup() {
  systemctl disable --now ironcurtain-antivirus-update.timer >/dev/null 2>&1 || true
  rm -f -- "$WORK/clean.txt" "$WORK/eicar.txt" "$WORK/scan-clean.log" "$WORK/scan-eicar.log" "$WORK/database-info.log"
  rmdir -- "$WORK"
}
trap cleanup EXIT
# Calls the real installer and real systemd updater. HTTP/CDN failures fail this gate.
bash "$ROOT/scripts/antivirus-engine.sh" install
systemctl is-enabled --quiet ironcurtain-antivirus-update.timer
systemctl is-active --quiet ironcurtain-antivirus-update.timer
DATABASE=/var/lib/ironcurtain-antivirus/database
for family in main daily bytecode; do
  matches=("$DATABASE/$family.cvd" "$DATABASE/$family.cld")
  file=''
  for candidate in "${matches[@]}"; do
    if [[ -f $candidate && ! -L $candidate ]]; then
      [[ -z $file ]] || { echo 'Duplicate official database family' >&2; exit 1; }
      file=$candidate
    fi
  done
  [[ -n $file ]] || { echo "Missing official $family database" >&2; exit 1; }
  sigtool --info "$file" > "$WORK/database-info.log"
  grep -q 'Verification OK' "$WORK/database-info.log"
  grep -E '^(File:|Version:|Signatures:|Verification OK)' "$WORK/database-info.log"
done
python3 "$ROOT/src/host/antivirus.py" | python3 -c 'import json,sys;v=json.load(sys.stdin);assert v["installed"] and v["state"]=="configured" and v["updater"]=="scheduled",json.dumps(v);print("Official database metadata: configured")'
python3 - "$WORK" <<'PY'
import pathlib, sys
root=pathlib.Path(sys.argv[1])
(root/'clean.txt').write_text('IronCurtain clean acceptance sample\n')
(root/'eicar.txt').write_bytes(b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
PY
clamscan --database="$DATABASE" --no-summary "$WORK/clean.txt" > "$WORK/scan-clean.log" 2>&1
result=0
clamscan --database="$DATABASE" --no-summary "$WORK/eicar.txt" > "$WORK/scan-eicar.log" 2>&1 || result=$?
[[ $result == 1 ]]
grep -q 'FOUND' "$WORK/scan-eicar.log"
grep -qi 'Eicar' "$WORK/scan-eicar.log"
echo 'Official signed databases load; clean sample passes and EICAR test sample is detected.'
