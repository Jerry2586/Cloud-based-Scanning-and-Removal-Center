#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 && $(uname -s) == Linux ]] || { echo 'Linux root required' >&2; exit 1; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/lib/independent.sh"
source "$ROOT/scripts/lib/antivirus-apparmor.sh"
WORK=$(mktemp -d /root/ironcurtain-apparmor-test.XXXXXXXX)
cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT
export LOG=$WORK/parse.log
apparmor_parser() { printf '%s\n' "$*" >> "$LOG"; }
export -f apparmor_parser
install -d -m 755 "$WORK/local"
printf '#include <local/usr.bin.freshclam>\n' > "$WORK/usr.bin.freshclam"
printf '# retain administrator settings\n/etc/admin-example r,\n' > "$WORK/local/usr.bin.freshclam"
ic_av_apparmor "$WORK"
grep -Fq '/etc/admin-example r,' "$WORK/local/usr.bin.freshclam"
grep -Fxq '/etc/ironcurtain-antivirus/freshclam.conf r,' "$WORK/local/ironcurtain-freshclam"
grep -Fxq '/var/lib/ironcurtain-antivirus/database/** rwk,' "$WORK/local/ironcurtain-freshclam"
[[ $(stat -c %a "$WORK/local/ironcurtain-freshclam") == 644 ]]
first=$(sha256sum "$WORK/local/usr.bin.freshclam")
ic_av_apparmor "$WORK"
[[ $(sha256sum "$WORK/local/usr.bin.freshclam") == "$first" ]]
[[ $(grep -Fc '#include <local/ironcurtain-freshclam>' "$WORK/local/usr.bin.freshclam") == 1 ]]
chmod 666 "$WORK/local/usr.bin.freshclam"
if (ic_av_apparmor "$WORK"); then echo 'Writable profile accepted' >&2; exit 1; fi
chmod 644 "$WORK/local/usr.bin.freshclam"
mv "$WORK/local/ironcurtain-freshclam" "$WORK/policy.saved"
ln -s "$WORK/policy.saved" "$WORK/local/ironcurtain-freshclam"
if (ic_av_apparmor "$WORK"); then echo 'Symlink policy accepted' >&2; exit 1; fi
rm -- "$WORK/local/ironcurtain-freshclam"
printf '# owned by someone else\n' > "$WORK/local/ironcurtain-freshclam"
if (ic_av_apparmor "$WORK"); then echo 'Unrelated policy overwritten' >&2; exit 1; fi
rm -- "$WORK/local/ironcurtain-freshclam"
printf '/usr/bin/freshclam { /etc/** r, }\n' > "$WORK/usr.bin.freshclam"
if (ic_av_apparmor "$WORK"); then echo 'Unknown distro profile accepted' >&2; exit 1; fi
echo 'AppArmor preservation, idempotence, ownership and refusal cases accepted'
