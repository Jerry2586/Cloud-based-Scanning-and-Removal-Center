#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
CONF="$WORK/config"
mkdir -p "$CONF/credentials" "$WORK/bin"

fail() { echo "identity script test failed: $*" >&2; exit 1; }
assert_jq() { jq -e "$1" "$2" >/dev/null || fail "$3"; }

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 30 -subj '/CN=test-ca' \
  -keyout "$CONF/ca.key" -out "$CONF/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=reader' -keyout "$CONF/credentials/reader.key" \
  -out "$CONF/credentials/reader.csr" >/dev/null 2>&1
openssl x509 -req -in "$CONF/credentials/reader.csr" -CA "$CONF/ca.crt" -CAkey "$CONF/ca.key" \
  -CAcreateserial -out "$CONF/credentials/reader.crt" -days 30 -sha256 >/dev/null 2>&1
openssl rand -hex 32 > "$CONF/credentials/reader.token"
FP=$(openssl x509 -in "$CONF/credentials/reader.crt" -noout -fingerprint -sha256 | cut -d= -f2)
TOKEN=$(cat "$CONF/credentials/reader.token")

source "$ROOT/scripts/lib/identity-config.sh"

printf '{"nodes":{},"readers":[],"policy":{"rules":{"require_signed_updates":false,"allow_remote_commands":true,"allow_cloud_push":true}}}\n' > "$CONF/empty.json"
appgog_normalize_reader_config "$CONF/empty.json" "$CONF/credentials/reader.crt" \
  "$CONF/credentials/reader.token" > "$CONF/empty.normalized.json"
jq -e --arg fp "$FP" --arg token "$TOKEN" '
  .readers[0].role == "reader" and .readers[0].identities[0].fingerprint256 == $fp and
  .readers[0].identities[0].token == $token and .readers[0].identities[0].status == "active" and
  (.readers[0].identities[0].issued_at | type == "string") and
  (.readers[0].identities[0].cert_not_after | type == "string") and
  .policy.rules.require_signed_updates == true and .policy.rules.allow_remote_commands == false and
  .policy.rules.allow_cloud_push == false
' "$CONF/empty.normalized.json" >/dev/null || fail 'empty readers were not repaired'

jq -n --arg fp "$FP" --arg token "$TOKEN" \
  '{nodes:{},readers:[{fingerprint256:$fp,token:$token}]}' > "$CONF/legacy.json"
appgog_normalize_reader_config "$CONF/legacy.json" "$CONF/credentials/reader.crt" \
  "$CONF/credentials/reader.token" > "$CONF/legacy.normalized.json"
jq -e '(.readers[0] | has("fingerprint256") | not) and (.readers[0] | has("token") | not) and
  (.readers[0].identities | length == 1)' "$CONF/legacy.normalized.json" >/dev/null || fail 'legacy reader was not migrated'

jq -n '{nodes:{},readers:[{role:"reader",identities:[{fingerprint256:"AA",token:"bad",status:"active"}]}]}' \
  > "$CONF/mismatch.json"
if appgog_normalize_reader_config "$CONF/mismatch.json" "$CONF/credentials/reader.crt" \
  "$CONF/credentials/reader.token" > "$CONF/mismatch.normalized.json" 2>/dev/null; then
  fail 'mismatched reader identity was accepted'
fi

if (( EUID != 0 )); then
  echo 'Reader migration tests passed; root-only enrollment and rotation tests skipped.'
  exit 0
fi

printf '#!/usr/bin/env bash\nexit 0\n' > "$WORK/bin/chown"
printf '#!/usr/bin/env bash\nif [[ -n ${SYSTEMCTL_FAIL_ONCE_FILE:-} && -f $SYSTEMCTL_FAIL_ONCE_FILE ]]; then rm -f "$SYSTEMCTL_FAIL_ONCE_FILE"; exit 1; fi\nexit 0\n' > "$WORK/bin/systemctl"
chmod +x "$WORK/bin/chown" "$WORK/bin/systemctl"
export PATH="$WORK/bin:$PATH"
cp "$CONF/empty.normalized.json" "$CONF/config.json"
printf '{"app.js":"%064d"}\n' 0 > "$WORK/baseline.json"

if (cd "$WORK" && SECURITY_CONFIG_DIR="$CONF" bash "$ROOT/scripts/enroll-node.sh" \
  license-center https://license.example.test/health baseline.json >/dev/null 2>&1); then
  fail 'relative baseline path was accepted'
fi
ln -s "$WORK/baseline.json" "$WORK/baseline-link.json"
if SECURITY_CONFIG_DIR="$CONF" bash "$ROOT/scripts/enroll-node.sh" license-center \
  https://license.example.test/health "$WORK/baseline-link.json" >/dev/null 2>&1; then
  fail 'symbolic-link baseline was accepted'
fi
printf '{}\n' > "$WORK/empty-baseline.json"
if SECURITY_CONFIG_DIR="$CONF" bash "$ROOT/scripts/enroll-node.sh" license-center \
  https://license.example.test/health "$WORK/empty-baseline.json" >/dev/null 2>&1; then
  fail 'empty baseline was accepted'
fi
if SECURITY_CONFIG_DIR="$CONF" bash "$ROOT/scripts/enroll-node.sh" license-center \
  'https://user@example.test/health' "$WORK/baseline.json" >/dev/null 2>&1; then
  fail 'credential-bearing health URL was accepted'
fi

config_hash=$(sha256sum "$CONF/config.json" | awk '{print $1}')
touch "$WORK/systemctl-fail-once"
if SYSTEMCTL_FAIL_ONCE_FILE="$WORK/systemctl-fail-once" SECURITY_CONFIG_DIR="$CONF" \
  bash "$ROOT/scripts/enroll-node.sh" license-center https://license.example.test/health \
  "$WORK/baseline.json" >/dev/null 2>&1; then
  fail 'enrollment succeeded after service restart failure'
fi
[[ $(sha256sum "$CONF/config.json" | awk '{print $1}') == "$config_hash" ]] \
  || fail 'enrollment restart failure did not restore configuration'
compgen -G "$CONF/credentials/license-center.*" >/dev/null \
  && fail 'enrollment restart failure left role credentials'

for role in license-center build-center; do
  SECURITY_CONFIG_DIR="$CONF" bash "$ROOT/scripts/enroll-node.sh" "$role" \
    "https://$role.example.test/health" "$WORK/baseline.json" >/dev/null
  assert_jq ".nodes[\"$role\"].role == \"$role\" and (.nodes[\"$role\"].identities | length == 1)" \
    "$CONF/config.json" "$role enrollment failed"
done

for profile in all license build; do
  destination="$WORK/export-$profile"
  SECURITY_CONFIG_DIR="$CONF" bash "$ROOT/scripts/export-business-bundle.sh" "$profile" "$destination" >/dev/null
  [[ -s $destination/ca.crt && -s $destination/bundle.json ]] || fail "$profile export is incomplete"
  [[ ! -e $destination/ca.key && ! -e $destination/reader.crt && ! -e $destination/reader.key \
    && ! -e $destination/reader.token ]] || fail "$profile export leaked cloud or reader credentials"
  assert_jq ".profile == \"$profile\" and .ca_sha256_fingerprint == \"$(openssl x509 -in "$CONF/ca.crt" -noout -fingerprint -sha256 | cut -d= -f2)\"" \
    "$destination/bundle.json" "$profile bundle metadata is invalid"
done
jq -e '.roles == ["license","build"]' "$WORK/export-all/bundle.json" >/dev/null \
  || fail 'all export roles are invalid'
jq -e '.roles == ["license"]' "$WORK/export-license/bundle.json" >/dev/null \
  || fail 'license export roles are invalid'
jq -e '.roles == ["build"]' "$WORK/export-build/bundle.json" >/dev/null \
  || fail 'build export roles are invalid'
[[ -s $WORK/export-all/license.key && -s $WORK/export-all/build.key ]] || fail 'all export missed a business identity'
[[ -s $WORK/export-license/license.key && ! -e $WORK/export-license/build.key ]] || fail 'license export crossed role boundary'
[[ -s $WORK/export-build/build.key && ! -e $WORK/export-build/license.key ]] || fail 'build export crossed role boundary'

mkdir -p "$WORK/existing-export"
if SECURITY_CONFIG_DIR="$CONF" bash "$ROOT/scripts/export-business-bundle.sh" all \
  "$WORK/existing-export" >/dev/null 2>&1; then
  fail 'existing export destination was accepted'
fi
if (cd "$WORK" && SECURITY_CONFIG_DIR="$CONF" bash "$ROOT/scripts/export-business-bundle.sh" all \
  relative-export >/dev/null 2>&1); then
  fail 'relative export destination was accepted'
fi
if SECURITY_CONFIG_DIR="$CONF" bash "$ROOT/scripts/export-business-bundle.sh" all /root >/dev/null 2>&1; then
  fail 'dangerous export destination was accepted'
fi

for role in reader license-center build-center; do
  old_fp=$(jq -r "if \"$role\" == \"reader\" then .readers[0].identities[0].fingerprint256 else .nodes[\"$role\"].identities[0].fingerprint256 end" "$CONF/config.json")

  if [[ $role == reader ]]; then
    config_hash=$(sha256sum "$CONF/config.json" | awk '{print $1}')
    touch "$WORK/systemctl-fail-once"
    if SYSTEMCTL_FAIL_ONCE_FILE="$WORK/systemctl-fail-once" SECURITY_CONFIG_DIR="$CONF" \
      bash "$ROOT/scripts/rotate-identity.sh" stage "$role" >/dev/null 2>&1; then
      fail 'stage succeeded after service restart failure'
    fi
    [[ $(sha256sum "$CONF/config.json" | awk '{print $1}') == "$config_hash" ]] || fail 'stage restart failure did not restore configuration'
    compgen -G "$CONF/credentials/$role.next.*" >/dev/null && fail 'stage restart failure left next artifacts'

    for suffix in key csr crt token; do
      touch "$CONF/credentials/$role.next.$suffix"
      if SECURITY_CONFIG_DIR="$CONF" bash "$ROOT/scripts/rotate-identity.sh" stage "$role" >/dev/null 2>&1; then
        fail "stage accepted isolated .next.$suffix artifact"
      fi
      rm -f "$CONF/credentials/$role.next.$suffix"
    done
  fi

  SECURITY_CONFIG_DIR="$CONF" bash "$ROOT/scripts/rotate-identity.sh" stage "$role" >/dev/null
  [[ $(stat -c %a "$CONF/credentials/$role.next.key") == 600 ]] || fail "$role next key permissions are not 600"
  [[ $(stat -c %a "$CONF/credentials/$role.next.token") == 600 ]] || fail "$role next token permissions are not 600"
  jq -e "if \"$role\" == \"reader\" then
    (.readers[0].identities | length == 2) and (.readers[0].identities | any(.status == \"staged\"))
    else (.nodes[\"$role\"].identities | length == 2) and (.nodes[\"$role\"].identities | any(.status == \"staged\")) end" \
    "$CONF/config.json" >/dev/null || fail "$role stage failed"

  staged_hash=$(sha256sum "$CONF/config.json" | awk '{print $1}')
  if SECURITY_CONFIG_DIR="$CONF" bash "$ROOT/scripts/rotate-identity.sh" stage "$role" >/dev/null 2>&1; then
    fail "$role accepted a second stage"
  fi
  [[ $(sha256sum "$CONF/config.json" | awk '{print $1}') == "$staged_hash" ]] || fail "$role second stage changed configuration"

  cp "$CONF/config.json" "$WORK/$role.clean.json"
  active_hash=$(sha256sum "$CONF/credentials/$role.key" "$CONF/credentials/$role.crt" \
    "$CONF/credentials/$role.token" | sha256sum | awk '{print $1}')
  if [[ $role == reader ]]; then
    touch "$WORK/systemctl-fail-once"
    if SYSTEMCTL_FAIL_ONCE_FILE="$WORK/systemctl-fail-once" SECURITY_CONFIG_DIR="$CONF" \
      bash "$ROOT/scripts/rotate-identity.sh" commit "$role" >/dev/null 2>&1; then
      fail 'commit succeeded after service restart failure'
    fi
    [[ $(sha256sum "$CONF/config.json" | awk '{print $1}') == "$staged_hash" ]] || fail 'commit restart failure did not restore configuration'
    [[ $(sha256sum "$CONF/credentials/$role.key" "$CONF/credentials/$role.crt" \
      "$CONF/credentials/$role.token" | sha256sum | awk '{print $1}') == "$active_hash" ]] || fail 'commit restart failure changed active credentials'
    for suffix in key csr crt token; do
      [[ -f $CONF/credentials/$role.next.$suffix ]] || fail "commit restart failure removed .next.$suffix"
    done
  fi

  fake_fp=$(printf 'DD:%.0s' {1..31}; printf 'DD')
  jq --arg role "$role" --arg fp "$fake_fp" '
    if $role == "reader" then
      .readers[0].identities |= map(if .status == "staged" then .fingerprint256 = $fp else . end)
    else
      .nodes[$role].identities |= map(if .status == "staged" then .fingerprint256 = $fp else . end)
    end
  ' "$WORK/$role.clean.json" > "$CONF/config.json"
  mismatch_hash=$(sha256sum "$CONF/config.json" | awk '{print $1}')
  if SECURITY_CONFIG_DIR="$CONF" bash "$ROOT/scripts/rotate-identity.sh" commit "$role" >/dev/null 2>&1; then
    fail "$role commit accepted a mismatched staged fingerprint"
  fi
  [[ $(sha256sum "$CONF/config.json" | awk '{print $1}') == "$mismatch_hash" ]] || fail "$role failed fingerprint commit changed configuration"
  [[ $(sha256sum "$CONF/credentials/$role.key" "$CONF/credentials/$role.crt" \
    "$CONF/credentials/$role.token" | sha256sum | awk '{print $1}') == "$active_hash" ]] || fail "$role failed fingerprint commit changed active credentials"

  jq --arg role "$role" --arg token "$(printf 'f%.0s' {1..64})" '
    if $role == "reader" then
      .readers[0].identities |= map(if .status == "staged" then .token = $token else . end)
    else
      .nodes[$role].identities |= map(if .status == "staged" then .token = $token else . end)
    end
  ' "$WORK/$role.clean.json" > "$CONF/config.json"
  mismatch_hash=$(sha256sum "$CONF/config.json" | awk '{print $1}')
  if SECURITY_CONFIG_DIR="$CONF" bash "$ROOT/scripts/rotate-identity.sh" commit "$role" >/dev/null 2>&1; then
    fail "$role commit accepted a mismatched staged token"
  fi
  [[ $(sha256sum "$CONF/config.json" | awk '{print $1}') == "$mismatch_hash" ]] || fail "$role failed token commit changed configuration"
  [[ $(sha256sum "$CONF/credentials/$role.key" "$CONF/credentials/$role.crt" \
    "$CONF/credentials/$role.token" | sha256sum | awk '{print $1}') == "$active_hash" ]] || fail "$role failed token commit changed active credentials"

  cp "$WORK/$role.clean.json" "$CONF/config.json"
  SECURITY_CONFIG_DIR="$CONF" bash "$ROOT/scripts/rotate-identity.sh" commit "$role" >/dev/null
  jq -e --arg old "$old_fp" "if \"$role\" == \"reader\" then
    (.readers[0].identities | length == 1) and (.readers[0].identities[0].status == \"active\") and
      (.readers[0].identities | all(.fingerprint256 != \$old))
    else (.nodes[\"$role\"].identities | length == 1) and (.nodes[\"$role\"].identities[0].status == \"active\") and
      (.nodes[\"$role\"].identities | all(.fingerprint256 != \$old)) end" \
    "$CONF/config.json" >/dev/null || fail "$role commit did not revoke the old identity"
  [[ $(stat -c %a "$CONF/credentials/$role.key") == 600 ]] || fail "$role key permissions are not 600"
  [[ $(stat -c %a "$CONF/credentials/$role.token") == 600 ]] || fail "$role token permissions are not 600"
  compgen -G "$CONF/credentials/$role.next.*" >/dev/null && fail "$role commit left next artifacts"
done

echo 'Identity migration, enrollment, and rotation tests passed.'
