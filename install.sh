#!/usr/bin/env sh
set -eu

PROJECT='Jerry2586/Cloud-based-Scanning-and-Removal-Center'
PRODUCT='appgog-cloud-security-center'
ARTIFACT_PREFIX='APPGOG-Cloud-Security-Center'
INSTALL_ROOT=${SECURITY_INSTALL_DIR:-/opt/appgog-security}
SOURCE_MODE=${APPGOG_SECURITY_SOURCE:-auto}
RELEASE_BASE=${APPGOG_SECURITY_RELEASE_BASE:-}
REQUESTED_VERSION=${APPGOG_SECURITY_VERSION:-}
PUBLIC_HOST=${APPGOG_SECURITY_HOST:-}
TOKEN_FILE=${APPGOG_SECURITY_GITHUB_TOKEN_FILE:-/etc/appgog-security/github-release.token}

log() { printf '\n==> %s\n' "$*"; }
fail() { printf '错误：%s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail '请使用 root 运行。'
[ "$(uname -s 2>/dev/null || true)" = Linux ] || fail '仅支持 Linux。'
[ -r /etc/os-release ] || fail '无法识别 Linux 发行版。'
. /etc/os-release
DISTRO=${ID:-unknown}
case "$(uname -m 2>/dev/null || true)" in x86_64|amd64|aarch64|arm64) ;; *) fail '仅支持 amd64 与 arm64。' ;; esac

expect=''
for argument do
  if [ -n "$expect" ]; then
    case "$expect" in
      source) SOURCE_MODE=$argument ;;
      base) RELEASE_BASE=$argument ;;
      version) REQUESTED_VERSION=${argument#v} ;;
      host) PUBLIC_HOST=$argument ;;
    esac
    expect=''
    continue
  fi
  case "$argument" in
    --source) expect=source ;;
    --release-base) expect=base ;;
    --version) expect=version ;;
    --host) expect=host ;;
    *) fail "未知参数：$argument" ;;
  esac
done
[ -z "$expect" ] || fail "参数 --$expect 缺少值。"
case "$SOURCE_MODE" in auto|github|custom) ;; *) fail '--source 只能是 auto、github 或 custom。' ;; esac
[ "$SOURCE_MODE" != custom ] || [ -n "$RELEASE_BASE" ] || fail '--source custom 必须同时提供 --release-base。'
printf '%s\n' "$REQUESTED_VERSION" | grep -Eq '^$|^[0-9]+\.[0-9]+\.[0-9]+$' || fail '版本号格式无效。'

install_tools() {
  missing=false
  for tool in curl openssl sha256sum jq sort mktemp stat tar; do command -v "$tool" >/dev/null 2>&1 || missing=true; done
  [ "$missing" = true ] || return 0
  log '识别 Linux 并补齐发布验证工具'
  case "$DISTRO" in
    ubuntu|debian)
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl openssl coreutils jq tar
      ;;
    centos|rhel|rocky|almalinux|fedora|ol)
      manager=dnf; command -v dnf >/dev/null 2>&1 || manager=yum
      "$manager" install -y ca-certificates curl openssl coreutils jq tar
      ;;
    *) fail "不支持自动补齐环境的发行版：$DISTRO" ;;
  esac
}

private_release_enabled() { [ -s "$TOKEN_FILE" ]; }

private_release_file() (
  release=$1 name=$2 destination=$3
  case "$name" in release-manifest.json|release-manifest.json.sig|APPGOG-Cloud-Security-Center-*.run|APPGOG-Cloud-Security-Center-*.tar.gz) ;; *) return 1 ;; esac
  [ -r "$TOKEN_FILE" ] || return 1
  [ "$(stat -c %u "$TOKEN_FILE")" = "$(id -u)" ] || return 1
  case "$(stat -c %a "$TOKEN_FILE")" in 600|400) ;; *) return 1 ;; esac
  scratch=$(mktemp -d) || return 1
  trap 'rm -rf "$scratch"' 0
  token=$(tr -d '\r\n' < "$TOKEN_FILE")
  case "$token" in ''|*[!A-Za-z0-9_]*) return 1 ;; esac
  printf 'Authorization: Bearer %s\n' "$token" > "$scratch/headers"
  unset token
  api=${APPGOG_SECURITY_GITHUB_API_BASE:-https://api.github.com/repos/$PROJECT/releases}
  if [ "$api" != "https://api.github.com/repos/$PROJECT/releases" ]; then
    [ "${SECURITY_TEST_MODE:-false}" = true ] && [ "${APPGOG_SECURITY_ALLOW_TEST_MODE:-false}" = true ] \
      && [ "${APPGOG_SECURITY_ALLOW_INSECURE_TEST_SOURCE:-false}" = true ] || return 1
    printf '%s\n' "$api" | grep -Eq '^http://(127\.0\.0\.1|localhost):[0-9]+/' || return 1
  fi
  if [ "$release" = latest ]; then endpoint="$api/latest"; else endpoint="$api/tags/v$release"; fi
  curl -fsS --connect-timeout 15 --max-time 180 --retry 2 \
    -H @"$scratch/headers" -H 'Accept: application/vnd.github+json' "$endpoint" -o "$scratch/release" || return 1
  asset=$(jq -er --arg name "$name" '.assets[] | select(.name == $name and .state == "uploaded") | .url' "$scratch/release") || return 1
  printf '%s\n' "$asset" | grep -Eq "^$api/assets/[0-9]+$" || return 1
  status=$(curl -fsS --connect-timeout 15 --max-time 180 --retry 2 -D "$scratch/asset.headers" \
    -H @"$scratch/headers" -H 'Accept: application/octet-stream' "$asset" -o "$destination" -w '%{http_code}') || return 1
  case "$status" in
    200) return 0 ;;
    301|302|303|307|308) ;;
    *) return 1 ;;
  esac
  rm -f "$destination"
  location=$(awk 'BEGIN{IGNORECASE=1} /^Location:/{sub(/\r$/,""); sub(/^[^:]*:[[:space:]]*/,""); value=$0} END{print value}' "$scratch/asset.headers")
  case "$location" in
    https://*) ;;
    http://127.0.0.1:*|http://localhost:*)
      [ "${SECURITY_TEST_MODE:-false}" = true ] && [ "${APPGOG_SECURITY_ALLOW_TEST_MODE:-false}" = true ] \
        && [ "${APPGOG_SECURITY_ALLOW_INSECURE_TEST_SOURCE:-false}" = true ] || return 1
      ;;
    *) return 1 ;;
  esac
  printf '%s\n' "$location" | grep -Eq '^[a-z]+://[^/@]+(:[0-9]+)?/[^[:space:]]+$' || return 1
  curl -fsS --connect-timeout 15 --max-time 300 --retry 2 "$location" -o "$destination"
)

download_file() {
  base=$1 name=$2 destination=$3
  case "$base" in
    private:*) private_release_file "${base#private:}" "$name" "$destination" ;;
    http://127.0.0.1:*|http://localhost:*)
      [ "${APPGOG_SECURITY_ALLOW_INSECURE_TEST_SOURCE:-false}" = true ] || return 1
      [ "${SECURITY_TEST_MODE:-false}" = true ] && [ "${APPGOG_SECURITY_ALLOW_TEST_MODE:-false}" = true ] || return 1
      curl --proto =http -fsSL --connect-timeout 5 --max-time 30 "${base%/}/$name" -o "$destination"
      ;;
    *) curl --proto =https --proto-redir =https -fsSL --connect-timeout 15 --max-time 300 --retry 2 "${base%/}/$name" -o "$destination" ;;
  esac
}

write_public_key() {
  destination=$1
  if [ -n "${APPGOG_SECURITY_RELEASE_PUBLIC_KEY_FILE:-}" ]; then
    [ "${APPGOG_SECURITY_ALLOW_TEST_KEY:-false}" = true ] || fail '外部发布公钥只允许受控测试使用。'
    cp "$APPGOG_SECURITY_RELEASE_PUBLIC_KEY_FILE" "$destination"
    return
  fi
  cat > "$destination" <<'EOF'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEASovXSUYB8pbR/a1ChjO/OFlqQhHECKP5lh0FzJ2ypvI=
-----END PUBLIC KEY-----
EOF
}

try_release() {
  base=$1
  download_file "$base" release-manifest.json "$WORK/release-manifest.json" || return 1
  download_file "$base" release-manifest.json.sig "$WORK/release-manifest.json.sig" || return 1
  openssl pkeyutl -verify -pubin -inkey "$WORK/release-public.pem" -rawin \
    -in "$WORK/release-manifest.json" -sigfile "$WORK/release-manifest.json.sig" >/dev/null 2>&1 || return 1
  schema=$(jq -er '.schema' "$WORK/release-manifest.json") || return 1
  product=$(jq -er '.product' "$WORK/release-manifest.json") || return 1
  TARGET_VERSION=$(jq -er '.version' "$WORK/release-manifest.json") || return 1
  RUN_NAME=$(jq -er '.run_name' "$WORK/release-manifest.json") || return 1
  RUN_SHA256=$(jq -er '.run_sha256' "$WORK/release-manifest.json") || return 1
  [ "$schema" = 1 ] && [ "$product" = "$PRODUCT" ] || return 1
  printf '%s\n' "$TARGET_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || return 1
  [ "$RUN_NAME" = "$ARTIFACT_PREFIX-$TARGET_VERSION.run" ] || return 1
  printf '%s\n' "$RUN_SHA256" | grep -Eq '^[0-9a-f]{64}$' || return 1
  [ -z "$REQUESTED_VERSION" ] || [ "$REQUESTED_VERSION" = "$TARGET_VERSION" ] || return 1
  download_file "$base" "$RUN_NAME" "$WORK/installer.run" || return 1
  printf '%s  %s\n' "$RUN_SHA256" "$WORK/installer.run" | sha256sum -c - >/dev/null 2>&1 || return 1
}

install_tools
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' 0
trap 'exit 130' 2
trap 'exit 143' 15
write_public_key "$WORK/release-public.pem"

release_path='releases/latest/download'
[ -z "$REQUESTED_VERSION" ] || release_path="releases/download/v$REQUESTED_VERSION"
[ -n "$RELEASE_BASE" ] || RELEASE_BASE="https://github.com/$PROJECT/$release_path"
if private_release_enabled && [ "$SOURCE_MODE" != custom ]; then
  if [ -n "$REQUESTED_VERSION" ]; then SELECTED_BASE="private:$REQUESTED_VERSION"; else SELECTED_BASE='private:latest'; fi
else
  SELECTED_BASE=$RELEASE_BASE
fi

case "$SOURCE_MODE" in
  custom) try_release "$RELEASE_BASE" || fail '自定义发布源不可用或签名校验失败。' ;;
  github) try_release "$SELECTED_BASE" || fail 'GitHub Release 不可用或签名校验失败。' ;;
  auto) try_release "$SELECTED_BASE" || fail '发布源不可用、私有令牌权限不正确，或签名/哈希校验失败。' ;;
esac

installed=''
if [ -f "$INSTALL_ROOT/current/package.json" ]; then installed=$(jq -er '.version' "$INSTALL_ROOT/current/package.json" 2>/dev/null || true); fi
if [ -n "$installed" ] && [ "$installed" != "$TARGET_VERSION" ]; then
  newest=$(printf '%s\n%s\n' "$installed" "$TARGET_VERSION" | sort -V | tail -n 1)
  [ "$newest" = "$TARGET_VERSION" ] || fail "拒绝自动降级：当前 v$installed，发布源 v$TARGET_VERSION。"
fi

log "发布清单签名与安装包 SHA-256 已验证：v$TARGET_VERSION"
if [ -n "$PUBLIC_HOST" ]; then bash "$WORK/installer.run" --host "$PUBLIC_HOST"; else bash "$WORK/installer.run"; fi
