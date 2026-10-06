#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT=${1:-$ROOT/src/manager/bin}
command -v go >/dev/null || { echo 'Go toolchain required on the build machine, not the protected server.' >&2; exit 1; }
mkdir -p "$OUTPUT"
OUTPUT=$(cd "$OUTPUT" && pwd)
cd "$ROOT/manager"
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOTOOLCHAIN=local go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$OUTPUT/ironcurtain-manager-linux-$arch" ./cmd/ironcurtain-manager
  chmod 755 "$OUTPUT/ironcurtain-manager-linux-$arch"
done
