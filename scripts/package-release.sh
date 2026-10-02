#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SOURCE=$ROOT
OUTPUT=$ROOT/dist
SIGNING_KEY=${APPGOG_SECURITY_RELEASE_PRIVATE_KEY:-}
while (($#)); do
  case "$1" in
    --source-dir) SOURCE=$(cd "${2:?missing source directory}" && pwd); shift 2 ;;
    --output-dir) OUTPUT=${2:?missing output directory}; shift 2 ;;
    --signing-key) SIGNING_KEY=${2:?missing signing key}; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

for required in package.json release-contract.json release-public.pem install.sh scripts/install-linux.sh scripts/appgog-security.sh scripts/backup.sh scripts/restore.sh src/server.js; do
  [[ -f $SOURCE/$required ]] || { echo "Missing release input: $required" >&2; exit 1; }
done
[[ -n $SIGNING_KEY && -s $SIGNING_KEY ]] || { echo 'Set APPGOG_SECURITY_RELEASE_PRIVATE_KEY or use --signing-key.' >&2; exit 1; }

VERSION=$(node -p "JSON.parse(require('fs').readFileSync(process.argv[1])).version" "$SOURCE/package.json")
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'package.json version must use x.y.z' >&2; exit 1; }
PRODUCT=$(node -p "JSON.parse(require('fs').readFileSync(process.argv[1])).product" "$SOURCE/release-contract.json")
[[ $PRODUCT == appgog-cloud-security-center ]] || { echo 'Unexpected release product' >&2; exit 1; }
PREFIX=$(node -p "JSON.parse(require('fs').readFileSync(process.argv[1])).artifact_prefix" "$SOURCE/release-contract.json")
[[ $PREFIX == APPGOG-Cloud-Security-Center ]] || { echo 'Unexpected artifact prefix' >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
PAYLOAD=$WORK/payload
mkdir -p "$PAYLOAD/scripts/lib" "$PAYLOAD/src" "$OUTPUT"
cp "$SOURCE/package.json" "$SOURCE/release-contract.json" "$SOURCE/release-public.pem" "$SOURCE/install.sh" "$PAYLOAD/"
cp "$SOURCE/src/"*.js "$PAYLOAD/src/"
cp "$SOURCE/scripts/"*.sh "$PAYLOAD/scripts/"
cp "$SOURCE/scripts/lib/"*.sh "$PAYLOAD/scripts/lib/"

if [[ ${APPGOG_SECURITY_ALLOW_TEST_KEY:-false} != true ]]; then
  openssl pkey -in "$SIGNING_KEY" -pubout -out "$WORK/signing-public.pem" >/dev/null 2>&1
  cmp -s "$WORK/signing-public.pem" "$SOURCE/release-public.pem" || {
    echo 'Signing key does not match release-public.pem' >&2; exit 1;
  }
fi

TAR_NAME="$PREFIX-$VERSION.tar.gz"
RUN_NAME="$PREFIX-$VERSION.run"
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -czf "$OUTPUT/$TAR_NAME" -C "$PAYLOAD" .

cat > "$WORK/run-header" <<'HEADER'
#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $(id -u) -eq 0 ]] || { echo 'Run this signed installer as root.' >&2; exit 1; }
archive_line=$(awk '/^__ARCHIVE_BELOW__$/{print NR + 1; exit}' "$0")
[[ -n $archive_line ]] || { echo 'Embedded archive marker is missing.' >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tail -n +"$archive_line" "$0" | tar -xzf - -C "$work"
bash "$work/scripts/install-linux.sh" "$@"
exit $?
__ARCHIVE_BELOW__
HEADER
cp "$WORK/run-header" "$OUTPUT/$RUN_NAME"
cat "$OUTPUT/$TAR_NAME" >> "$OUTPUT/$RUN_NAME"
chmod 700 "$OUTPUT/$RUN_NAME"

TAR_SHA=$(sha256sum "$OUTPUT/$TAR_NAME" | awk '{print $1}')
RUN_SHA=$(sha256sum "$OUTPUT/$RUN_NAME" | awk '{print $1}')
jq -n --arg product "$PRODUCT" --arg version "$VERSION" --arg tar_name "$TAR_NAME" \
  --arg tar_sha256 "$TAR_SHA" --arg run_name "$RUN_NAME" --arg run_sha256 "$RUN_SHA" \
  --slurpfile environment "$SOURCE/release-contract.json" \
  '{schema:1,product:$product,version:$version,tar_name:$tar_name,tar_sha256:$tar_sha256,run_name:$run_name,run_sha256:$run_sha256,environment:$environment[0]}' \
  > "$OUTPUT/release-manifest.json"
openssl pkeyutl -sign -inkey "$SIGNING_KEY" -rawin -in "$OUTPUT/release-manifest.json" \
  -out "$OUTPUT/release-manifest.json.sig"
sha256sum "$OUTPUT/$TAR_NAME" > "$OUTPUT/$TAR_NAME.sha256"
sha256sum "$OUTPUT/$RUN_NAME" > "$OUTPUT/$RUN_NAME.sha256"
printf 'Release candidate v%s created in %s\n' "$VERSION" "$OUTPUT"
