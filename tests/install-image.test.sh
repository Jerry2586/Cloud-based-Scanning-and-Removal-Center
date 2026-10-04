#!/usr/bin/env bash
# Bounded, mocked registry failures; no daemon, DNS or host-service mutation.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ -n ${IC_TEST_PYTHON:-} ]]; then python3() { "$IC_TEST_PYTHON" "$@"; }; fi
if [[ ${1:-} == --case ]]; then
  scenario=$2 work=$3
  source "$ROOT/scripts/lib/install-image.sh"
  ic_fail() { echo "ERROR: $*" >&2; exit 1; }
  ic_trusted_dir() { mkdir -p "$1"; }
  jq() { echo 24.19.0; }
  timeout() {
    [[ $1 == --signal=TERM && $2 == --kill-after=10s && ( $3 == 180s || $3 == 300s ) ]] || exit 90
    printf 'timeout %s\n' "$3" >> "$work/calls"
    shift 3; "$@"
  }
  docker() {
    printf '%s\n' "$*" >> "$work/calls"
    local reference=${!#} repository
    case "$1 $2" in
      'image inspect')
        [[ $scenario == cache || -e $work/pulled-${reference%%/*} ]] || return 1
        repository=${reference%@*}; repository=${repository%:*}
        if [[ $scenario == mismatch ]]; then echo '["node@sha256:0000000000000000000000000000000000000000000000000000000000000000"]'
        elif [[ $scenario == bad_json ]]; then echo 'not-json'
        elif [[ $scenario == alias && $repository == docker.io/* ]]; then printf '["node@%s"]\n' "${reference##*@}"
        else printf '["%s@%s"]\n' "$repository" "${reference##*@}"; fi ;;
      'pull '*)
        case "$scenario" in
          timeout) [[ $reference != docker.io/* ]] || return 124 ;;
          network) [[ $reference != docker.io/* ]] || { echo 'dial tcp: i/o timeout'; return 1; } ;;
          both) echo 'no such host'; return 1 ;;
          permission) echo 'permission denied'; return 1 ;;
          permission_digest) echo 'permission denied for sha256:abcdef502abcdef'; return 1 ;;
          unavailable) [[ $reference != docker.io/* ]] || { echo 'unexpected status: 503 Service Unavailable'; return 1; } ;;
          missing) echo 'manifest unknown'; return 1 ;;
          rate) [[ $reference != docker.io/* ]] || { echo 'toomanyrequests: 429'; return 1; } ;;
        esac
        touch "$work/pulled-${reference%%/*}" ;;
      'build '*)
        [[ " $* " == *' --pull=false '* && " $* " == *' --build-arg IRONCURTAIN_NODE_IMAGE='* ]] || return 91
        if [[ $scenario == build_network && " $* " != *'IRONCURTAIN_NODE_IMAGE=m.daocloud.io/'* ]]; then echo 'failed to resolve source metadata: DeadlineExceeded'; return 1; fi
        [[ $scenario != build_invalid ]] || { echo 'Dockerfile syntax error'; return 1; } ;;
      *) echo 'Unexpected Docker action'; return 92 ;;
    esac
  }
  cp "$ROOT/docker/Dockerfile" "$work/Dockerfile"
  mkdir -p "$work/source/docker"
  cp "$work/Dockerfile" "$work/source/docker/Dockerfile"
  if [[ $scenario == unpinned ]]; then sed -i 's/@sha256:[a-f0-9]*//' "$work/source/docker/Dockerfile"; fi
  if [[ $scenario == version ]]; then sed -i 's/24.19.0/24.18.0/' "$work/source/docker/Dockerfile"; fi
  ic_image_build "$work/source" ironcurtain-security:test "$work/logs"
  exit 0
fi
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
passed=0
for scenario in official cache alias timeout network rate unavailable build_network both permission permission_digest missing mismatch bad_json build_invalid unpinned version; do
  mkdir -p "$work/$scenario"
  : > "$work/$scenario/calls"
  status=0
  bash "$0" --case "$scenario" "$work/$scenario" > "$work/$scenario/output" 2>&1 || status=$?
  case "$scenario" in
    official|cache|alias|timeout|network|rate|unavailable|build_network) [[ $status == 0 ]] || { cat "$work/$scenario/output"; exit 1; } ;;
    *) [[ $status != 0 ]] || { echo "Unexpected success: $scenario"; exit 1; } ;;
  esac
  case "$scenario" in
    cache) ! grep -q '^pull ' "$work/$scenario/calls" ;;
    timeout|network|rate|unavailable|build_network) grep -q '^pull m.daocloud.io/' "$work/$scenario/calls"; grep -q '^build .*IRONCURTAIN_NODE_IMAGE=m.daocloud.io/' "$work/$scenario/calls" ;;
    permission|permission_digest|missing|mismatch|bad_json|build_invalid) ! grep -q '^pull m.daocloud.io/' "$work/$scenario/calls" ;;
    unpinned|version) [[ ! -s $work/$scenario/calls ]] ;;
    both) ! grep -q '^build ' "$work/$scenario/calls" ;;
  esac
  ! grep -Eq 'systemctl|daemon.json|resolv.conf|--insecure|--pull ' "$work/$scenario/calls"
  passed=$((passed+1)); echo "PASS $scenario"
done
[[ $(grep -c '^ARG IRONCURTAIN_NODE_IMAGE=' "$ROOT/docker/Dockerfile") == 1 ]]
grep -q '^FROM ${IRONCURTAIN_NODE_IMAGE}$' "$ROOT/docker/Dockerfile"
grep -q 'ic_image_build "$RELEASE" "$IMAGE" "$DATA/logs"' "$ROOT/scripts/install-independent.sh"
echo "$passed image source tests passed"
