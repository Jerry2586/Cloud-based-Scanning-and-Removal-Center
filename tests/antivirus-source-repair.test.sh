#!/usr/bin/env bash
# Disposable Linux only. Package commands are explicit fixtures; this tests source preservation, not official DB acceptance.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[[ $EUID == 0 && $(uname -s) == Linux && -n ${GITHUB_ACTIONS:-} ]] || exit 1
DATA=/var/lib/ironcurtain-antivirus
[[ -d $DATA/database && ! -e $DATA/source.json && ! -L $DATA/source.json && ! -e $DATA/cloud-highwater.json ]]
WORK=$(mktemp -d)
export IC_REPAIR_CALLS=$WORK/package-calls IC_REPAIR_FAIL=0
original_owner=$(stat -c %u:%g "$DATA/database")
cleanup() {
  rm -f -- "$DATA/source.json" "$DATA/cloud-highwater.json" "$DATA/activation.json" "$DATA/database/manifest.json" "$DATA/database/manifest.json.sig" "$DATA/database/repair-fixture.hdb"
  chown "$original_owner" "$DATA/database"
  rm -rf -- "$WORK"
}
trap cleanup EXIT
apt-get() {
  printf '%s\n' "$*" >> "$IC_REPAIR_CALLS"
  [[ $IC_REPAIR_FAIL == 0 ]]
}
export -f apt-get
chown root:root "$DATA/database"
printf '%s\n' '{"schema":"ironcurtain-virus-db-source/v1","source":"xuanwu-signed","snapshot":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' > "$DATA/source.json"
chmod 600 "$DATA/source.json"
printf '%s\n' '{"fixture":"signed-source preservation only"}' > "$DATA/database/manifest.json"
printf '%s\n' 'explicit test signature fixture' > "$DATA/database/manifest.json.sig"
printf '%s\n' 'd41d8cd98f00b204e9800998ecf8427e:0:RepairFixture' > "$DATA/database/repair-fixture.hdb"
chmod 644 "$DATA/database/manifest.json" "$DATA/database/manifest.json.sig" "$DATA/database/repair-fixture.hdb"
snapshot() {
  for file in "$DATA/source.json" "$DATA/database" "$DATA/database/manifest.json" "$DATA/database/manifest.json.sig" "$DATA/database/repair-fixture.hdb" /etc/ironcurtain-antivirus/freshclam.conf; do
    [[ -d $file ]] || sha256sum "$file"
    stat -c '%u:%g:%a:%n' "$file"
  done
}
snapshot > "$WORK/before"
bash "$ROOT/scripts/antivirus-engine.sh" install > "$WORK/success" 2>&1
[[ $(wc -l < "$IC_REPAIR_CALLS") == 2 ]]
snapshot > "$WORK/after"; cmp "$WORK/before" "$WORK/after"
! /usr/bin/systemctl is-enabled --quiet ironcurtain-antivirus-update.timer
export IC_REPAIR_FAIL=1
if bash "$ROOT/scripts/antivirus-engine.sh" install > "$WORK/failure" 2>&1; then echo 'Package failure reported success' >&2; exit 1; fi
snapshot > "$WORK/after"; cmp "$WORK/before" "$WORK/after"
# A pending activation must never dispatch even a package repair.
printf '{}' > "$DATA/activation.json"
count=$(wc -l < "$IC_REPAIR_CALLS")
if bash "$ROOT/scripts/antivirus-engine.sh" install > "$WORK/activation" 2>&1; then exit 1; fi
[[ $(wc -l < "$IC_REPAIR_CALLS") == "$count" ]]
rm -f -- "$DATA/activation.json"
# Each retained cloud artifact, including a dangling link, independently blocks direct-source fallback.
cp -p "$DATA/source.json" "$WORK/source.json"
rm -f -- "$DATA/source.json" "$DATA/database/manifest.json" "$DATA/database/manifest.json.sig"
for evidence in "$DATA/cloud-highwater.json" "$DATA/database/manifest.json" "$DATA/database/manifest.json.sig"; do
  for form in file link; do
    if [[ $form == file ]]; then printf '{}' > "$evidence"; else ln -s "$WORK/absent" "$evidence"; fi
    for action in install update policy; do
      if bash "$ROOT/scripts/antivirus-engine.sh" "$action" > "$WORK/missing-source" 2>&1; then echo "Missing source accepted: $evidence $form $action" >&2; exit 1; fi
      [[ $(wc -l < "$IC_REPAIR_CALLS") == "$count" ]]
    done
    rm -f -- "$evidence"
  done
done
printf '%s\n' 'Signed-source package repair: preservation, real failure, activation and lost-marker guards passed.'
