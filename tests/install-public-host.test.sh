#!/usr/bin/env bash
# Exercise shared discovery and both callers without real network or host changes.
set -euo pipefail
SOURCE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$SOURCE/scripts/lib/install-host.sh"
if [[ -n ${IC_TEST_PYTHON:-} ]]; then python3() { "$IC_TEST_PYTHON" "$@"; }; fi
fail() { printf 'TEST FAILURE: %s\n' "$*" >&2; exit 1; }
assert() { [[ $1 == "$2" ]] || fail "expected [$2], got [$1]"; }
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
calls=$work/calls
curl() {
  local destination='' url='' arg previous=''
  for arg; do
    [[ $previous != -o ]] || destination=$arg
    case "$arg" in https://*) url=$arg ;; esac
    previous=$arg
  done
  [[ " $* " == *" -q "* && " $* " == *" -4 "* && " $* " == *" --noproxy * "* && " $* " == *" --max-filesize 64 "* ]] || fail 'discovery must use direct IPv4 and bounded HTTPS'
  [[ " $* " == *" --proto =https "* && " $* " == *" --tlsv1.2 "* && " $* " == *" --connect-timeout 5 "* && " $* " == *" --max-time 10 "* ]] || fail 'TLS or request timeout missing'
  printf '%s\n' "$url" >> "$calls"
  case "$url" in
    https://api.ipify.org) [[ ${primary_status:-0} == 0 ]] || return "$primary_status"; printf '%s' "$primary" > "$destination" ;;
    https://checkip.amazonaws.com) [[ ${fallback_status:-0} == 0 ]] || return "$fallback_status"; printf '%s' "$fallback" > "$destination" ;;
    *) fail "unapproved provider: $url" ;;
  esac
}
passed=0
ok() { passed=$((passed+1)); printf 'PASS %s\n' "$1"; }
primary=154.219.110.71 fallback=45.136.15.122
assert "$(ic_host_select '' '')" "$primary"
assert "$(wc -l < "$calls" | tr -d ' ')" 1
ok 'first install selects a public IPv4 without interaction'
: > "$calls"
primary_status=28
assert "$(ic_host_detect)" "$fallback"
assert "$(wc -l < "$calls" | tr -d ' ')" 2
ok 'timeout uses the independent fallback'
primary_status=0
for primary in 10.0.65.2 172.17.0.1 192.168.1.1 127.0.0.1 0.0.0.0 169.254.1.1 100.64.0.1 192.0.2.1 198.51.100.1 203.0.113.1 198.18.0.1 224.0.0.1 240.0.0.1 255.255.255.255 ::1 '<html>error</html>' '1.1.1.1 extra' '01.1.1.1' '1.1.1' '1.1.1.256' ''; do
  : > "$calls"
  assert "$(ic_host_detect)" "$fallback"
  assert "$(wc -l < "$calls" | tr -d ' ')" 2
  ok "rejects unsafe response [$primary]"
done
primary=$'154.219.110.71\r\n'
assert "$(ic_host_detect)" 154.219.110.71
ok 'normalizes a valid line response'
: > "$calls"
assert "$(ic_host_select security.example.com '')" security.example.com
assert "$(ic_host_select '' original.example.com)" original.example.com
assert "$(ic_host_select chosen.example.com original.example.com)" chosen.example.com
[[ ! -s $calls ]] || fail 'explicit or saved address must bypass discovery'
ok 'explicit and saved addresses bypass all network discovery'
primary_status=28 fallback_status=28
if output=$(ic_host_select '' '' 2>&1); then fail 'network failure must stop'; fi
[[ $output == *'无法自动识别公网 IPv4'* && $output == *'--host'* ]] || fail 'network failure missing actionable error'
ok 'no prompt or private-IP fallback when discovery fails'
primary_status=0 fallback_status=0 primary=127.0.0.1 fallback=192.168.0.1
if ic_host_detect >/dev/null 2>&1; then fail 'unsafe results accepted'; fi
ok 'both nonpublic provider results stop installation'
bootstrap_selection=$(sed -n '/^# Resolve before invoking older signed payloads/,/^set --/p' "$SOURCE/install.sh" | sed '$d')
jq() { printf '%s\n' existing.example.com; }
log() { printf '%s\n' "$*" >&2; }
INSTALL_ROOT=$work/install INSTALL_ROLE=local PUBLIC_HOST=''
mkdir -p "$INSTALL_ROOT"
primary=154.219.110.71 fallback=45.136.15.122
: > "$calls"
eval "$bootstrap_selection"
assert "$PUBLIC_HOST" 154.219.110.71
ok 'standalone bootstrap passes autodetected IP to older signed payload'
printf '{}\n' > "$INSTALL_ROOT/install.json"
PUBLIC_HOST='' INSTALL_ROLE=cloud
: > "$calls"
eval "$bootstrap_selection"
assert "$PUBLIC_HOST" existing.example.com
[[ ! -s $calls ]] || fail 'upgrade must not re-detect'
ok 'bootstrap upgrade uses persisted hostname offline'
PUBLIC_HOST=manual.example.com
: > "$calls"
eval "$bootstrap_selection"
assert "$PUBLIC_HOST" manual.example.com
[[ ! -s $calls ]] || fail 'manual hostname must not re-detect'
ok 'explicit domain remains supported'
jq() { return 1; }
PUBLIC_HOST=''
if ( eval "$bootstrap_selection" ) >/dev/null 2>&1; then fail 'corrupt saved address must stop'; fi
ok 'corrupt persisted state fails closed'
role_selection=$(sed -n '/^if \[\[ -z \$HOST \]\]; then/,/^fi$/p' "$SOURCE/scripts/install-independent.sh")
[[ -n $role_selection ]] || fail 'role host selection missing'
HOST=''
eval "$role_selection" >/dev/null
assert "$HOST" 154.219.110.71
ok 'role source installer also auto-detects with no TTY'
HOST=kept.example.com
: > "$calls"
eval "$role_selection"
assert "$HOST" kept.example.com
[[ ! -s $calls ]] || fail 'role installer changed existing address'
ok 'role installer preserves previously loaded address'
# Run the generated embedded helper in an actual POSIX shell as well.
# Use a POSIX mock so the standalone shell never needs Bash.
sed -n '/^# BEGIN INSTALL-HOST$/,/^# END INSTALL-HOST$/p' "$SOURCE/install.sh" > "$work/posix-helper.sh"
{
  printf 'set -eu\n. "%s"\n' "$work/posix-helper.sh"
  if [[ -n ${IC_TEST_PYTHON:-} ]]; then printf 'python3() { "%s" "$@"; }\n' "$IC_TEST_PYTHON"; fi
  printf '%s\n' 'curl() { destination=""; previous=""; for arg; do if [ "$previous" = -o ]; then destination=$arg; fi; previous=$arg; done; printf "154.219.110.71\n" > "$destination"; }' 'ic_host_select "" ""'
} > "$work/posix.sh"
assert "$(sh "$work/posix.sh")" 154.219.110.71
ok 'standalone embedded helper executes under POSIX sh'
printf 'Public host decisions: %s passed\n' "$passed"
