#!/usr/bin/env bash
# Runs only on an explicitly disposable GitHub Linux runner. Hub failure is
# injected locally; mirror pull, digest inspection, build and Node run are real.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${IRONCURTAIN_ACCEPT_DISPOSABLE_RUNNER:-} == 1 && $( id -u ) == 0 ]] || { echo 'Disposable GitHub root runner required' >&2; exit 1; }
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d /tmp/ironcurtain-mirror.XXXXXXXX)
REAL_DOCKER=$(command -v docker)
export REAL_DOCKER
image="ironcurtain-mirror-acceptance:${GITHUB_RUN_ID:-local}"
trap '"$REAL_DOCKER" image rm "$image" >/dev/null 2>&1 || true; rm -rf -- "$work"' EXIT
mkdir -m 700 "$work/bin"
cat > "$work/bin/docker" <<'WRAPPER'
#!/usr/bin/env bash
set -eu
if [[ ${1:-} == pull && ${2:-} == docker.io/library/node:* ]]; then
  echo 'injected official registry connection timeout' >&2
  exit 1
fi
if [[ ${1:-} == image && ${2:-} == inspect && ${*: -1} == docker.io/library/node:* ]]; then exit 1; fi
exec "$REAL_DOCKER" "$@"
WRAPPER
chmod 700 "$work/bin/docker"
export PATH="$work/bin:$PATH"
ic_fail() { echo "$*" >&2; exit 1; }
ic_trusted_dir() { mkdir -p -m 700 "$1"; chmod 700 "$1"; }
source "$ROOT/scripts/lib/install-image.sh"
ic_image_build "$ROOT" "$image" "$work/logs"
"$REAL_DOCKER" run --rm --network none --entrypoint node "$image" -p 'process.version' | grep -Fx 'v24.19.0'
grep -F 'm.daocloud.io/docker.io/library/node:' "$work"/logs/image-build.*.log >/dev/null
echo 'Actual mirror digest pull, program build and Node runtime accepted.'
