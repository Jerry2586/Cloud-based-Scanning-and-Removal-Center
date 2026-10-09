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
  systemctl stop ironcurtain-antivirus-update.service >/dev/null 2>&1 || true
  systemctl disable --now ironcurtain-antivirus-update.timer >/dev/null 2>&1 || true
  [[ $WORK == /tmp/tmp.* && -d $WORK && ! -L $WORK ]] || return 1
  rm -rf -- "$WORK"
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

# Independently sign only genuine freshly downloaded CVD files. CLD is not
# silently converted: unsupported input fails this cloud acceptance explicitly.
systemctl disable --now ironcurtain-antivirus-update.timer
systemctl stop ironcurtain-antivirus-update.service
install -d -m 700 "$WORK/publisher-input" "$WORK/signed" "$WORK/cloud-cache"
for family in main daily bytecode; do
  [[ -f $DATABASE/$family.cvd && ! -L $DATABASE/$family.cvd ]] || { echo 'Official retrieval produced CLD; CVD cloud delivery was not accepted' >&2; exit 1; }
  install -m 600 "$DATABASE/$family.cvd" "$WORK/publisher-input/$family.cvd"
done
openssl genpkey -algorithm ED25519 -out "$WORK/publisher-private.pem"
openssl pkey -in "$WORK/publisher-private.pem" -pubout -out "$WORK/publisher-public.pem"
chmod 600 "$WORK/publisher-private.pem" "$WORK/publisher-public.pem"
python3 "$ROOT/scripts/sign-virus-db.py" --input "$WORK/publisher-input" --output "$WORK/signed" --signing-key "$WORK/publisher-private.pem"
python3 - "$ROOT" "$WORK" <<'PY'
import importlib.util,pathlib,sys
root,work=map(pathlib.Path,sys.argv[1:]);s=importlib.util.spec_from_file_location('cache',root/'scripts/virus-db-cache.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
a=m.import_database(work/'signed',work/'cloud-cache',work/'publisher-public.pem');b=m.import_database(work/'signed',work/'cloud-cache',work/'publisher-public.pem');assert a['snapshot']==b['snapshot'];print('Genuine CVD cache import/reuse and vendor verification: accepted')
PY
rm -f -- "$WORK/publisher-private.pem"
IRONCURTAIN_OFFICIAL_DB_WORK="$WORK" node --test "$ROOT/tests/virus-db-official.accept.js"
python3 "$ROOT/src/host/antivirus.py" | python3 -c 'import json,sys;v=json.load(sys.stdin);assert v["installed"] and v["state"]=="configured" and v["updater"]=="disabled" and v["source"]=="xuanwu-signed",json.dumps(v);print("Cloud-activated official database metadata: configured, updater disabled")'

# Repair genuine cloud-activated databases through the real trusted package manager.
# Engine maintenance must not rewrite signatures, database bytes, ownership or provenance.
python3 - "$WORK/snapshot.py" <<'PY'
import pathlib,sys
pathlib.Path(sys.argv[1]).write_text('''import hashlib,json,pathlib,stat
items={}
for base in (pathlib.Path('/etc/ironcurtain-antivirus'),pathlib.Path('/var/lib/ironcurtain-antivirus')):
 for p in sorted(base.rglob('*')):
  s=p.lstat()
  if stat.S_ISREG(s.st_mode):
   items[str(p)]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)}
  elif not stat.S_ISDIR(s.st_mode):
   raise AssertionError('Unexpected artifact type: '+str(p))
print(json.dumps(items,sort_keys=True))
''')
PY
python3 "$WORK/snapshot.py" > "$WORK/before-repair.json"
bash "$ROOT/scripts/antivirus-engine.sh" install
python3 "$WORK/snapshot.py" > "$WORK/after-repair.json"
cmp "$WORK/before-repair.json" "$WORK/after-repair.json"
! systemctl is-enabled --quiet ironcurtain-antivirus-update.timer
! systemctl is-active --quiet ironcurtain-antivirus-update.timer
! systemctl is-active --quiet ironcurtain-antivirus-update.service
python3 "$ROOT/src/host/antivirus.py" | python3 -c 'import json,sys;v=json.load(sys.stdin);assert v["installed"] and v["state"]=="configured" and v["source"]=="xuanwu-signed" and v["updater"]=="disabled",json.dumps(v)'
clamscan --database="$DATABASE" --no-summary "$WORK/clean.txt" > "$WORK/repair-clean.log" 2>&1
result=0
clamscan --database="$DATABASE" --no-summary "$WORK/eicar.txt" > "$WORK/repair-eicar.log" 2>&1 || result=$?
[[ $result == 1 ]]
grep -qi 'Eicar.*FOUND' "$WORK/repair-eicar.log"
echo 'Real signed-source package repair: provenance/bytes/ownership retained; clean and EICAR scans passed.'
