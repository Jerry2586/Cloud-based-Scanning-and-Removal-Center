#!/usr/bin/env sh
set -eu
set +x
umask 077

PROJECT='Jerry2586/Cloud-based-Scanning-and-Removal-Center'
PRODUCT='appgog-cloud-security-center'
ARTIFACT_PREFIX='APPGOG-Cloud-Security-Center'
INSTALL_ROOT=${SECURITY_INSTALL_DIR:-/opt/appgog-security}
SOURCE_MODE=${APPGOG_SECURITY_SOURCE:-auto}
RELEASE_BASE=${APPGOG_SECURITY_RELEASE_BASE:-}
REQUESTED_VERSION=${APPGOG_SECURITY_VERSION:-}
PUBLIC_HOST=${APPGOG_SECURITY_HOST:-}
INSTALL_ROLE=${IRONCURTAIN_ROLE:-}
LISTEN_BIND=${IRONCURTAIN_BIND:-}
TOKEN_FILE=${IRONCURTAIN_GITHUB_TOKEN_FILE:-${APPGOG_SECURITY_GITHUB_TOKEN_FILE:-}}

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
      role) INSTALL_ROLE=$argument ;;
      bind) LISTEN_BIND=$argument ;;
      token) TOKEN_FILE=$argument ;;
    esac
    expect=''
    continue
  fi
  case "$argument" in
    --source) expect=source ;;
    --release-base) expect=base ;;
    --version) expect=version ;;
    --host) expect=host ;;
    --role) expect=role ;;
    --bind) expect=bind ;;
    --token-file) expect=token ;;
    *) fail "未知参数：$argument" ;;
  esac
done
case "$INSTALL_ROLE" in ""|local|cloud) ;; *) fail "--role 只能是 local 或 cloud。" ;; esac
if [ -z "$TOKEN_FILE" ]; then
  if [ -n "$INSTALL_ROLE" ]; then TOKEN_FILE=/etc/ironcurtain/github-release.token;
  else TOKEN_FILE=/etc/appgog-security/github-release.token; fi
fi
[ -z "$LISTEN_BIND" ] || [ -n "$INSTALL_ROLE" ] || fail '--bind 只用于独立 local/cloud 安装。'
[ -z "$expect" ] || fail "参数 --$expect 缺少值。"
case "$SOURCE_MODE" in auto|github|custom) ;; *) fail '--source 只能是 auto、github 或 custom。' ;; esac
[ "$SOURCE_MODE" != custom ] || [ -n "$RELEASE_BASE" ] || fail '--source custom 必须同时提供 --release-base。'
printf '%s\n' "$REQUESTED_VERSION" | grep -Eq '^$|^[0-9]+\.[0-9]+\.[0-9]+$' || fail '版本号格式无效。'

ca_ready() {
  for bundle in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    [ ! -s "$bundle" ] || return 0
  done
  return 1
}
bootstrap_crypto_ready() (
  crypto_dir=$(mktemp -d) || return 1
  trap 'rm -rf -- "$crypto_dir"' 0
  printf 'ironcurtain-bootstrap-check\n' > "$crypto_dir/message"
  openssl genpkey -algorithm ED25519 -out "$crypto_dir/key" >/dev/null 2>&1     && openssl pkeyutl -sign -rawin -inkey "$crypto_dir/key" -in "$crypto_dir/message" -out "$crypto_dir/signature" >/dev/null 2>&1
)
tools_ready() {
  for tool in bash curl openssl sha256sum jq sort mktemp stat tar gzip awk sed grep tail     tr dirname cp mv rm mkdir chmod install stty; do
    command -v "$tool" >/dev/null 2>&1 || return 1
  done
  ca_ready || return 1
  bootstrap_crypto_ready || return 1
  [ "$(printf '2.24.0\n2.9.0\n' | sort -V | head -n1)" = 2.9.0 ]
}
install_tools() {
  tools_ready && return 0
  log '识别 Linux 并补齐下载、发布验证和解包工具'
  case "$DISTRO" in
    ubuntu|debian)
      apt-get update || fail '系统软件源不可用；检查 DNS、HTTPS 和 apt 源后重试。'
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-remove bash ca-certificates curl openssl coreutils jq tar gzip util-linux         || fail '发布验证工具安装失败；请修复软件源或包管理锁后重试。'
      ;;
    centos|rhel|rocky|almalinux|fedora|ol)
      manager=dnf; command -v dnf >/dev/null 2>&1 || manager=yum
      command -v "$manager" >/dev/null 2>&1 || fail "缺少包管理器 $manager。"
      "$manager" install -y bash ca-certificates curl openssl coreutils jq tar gzip util-linux         || fail '发布验证工具安装失败；请修复系统软件源后重试。'
      ;;
    *) fail "不支持自动补齐环境的发行版：$DISTRO" ;;
  esac
  tools_ready || fail '基础工具、CA 包或 Ed25519 签名能力仍不可用；请使用提供当前 OpenSSL 的受支持 Linux 版本。'
}
check_token_file() {
  [ ! -e "$TOKEN_FILE" ] && [ ! -L "$TOKEN_FILE" ] && return 0
  [ -f "$TOKEN_FILE" ] && [ ! -L "$TOKEN_FILE" ] && [ -r "$TOKEN_FILE" ] || fail 'GitHub 令牌必须是可读的普通文件，不能是符号链接。'
  [ "$(stat -c %u "$TOKEN_FILE")" = 0 ] || fail 'GitHub 令牌文件必须归 root 所有。'
  case "$(stat -c %a "$TOKEN_FILE")" in 600|400) ;; *) fail 'GitHub 令牌文件权限必须是 600 或 400。' ;; esac
  [ -s "$TOKEN_FILE" ] || fail 'GitHub 令牌文件为空，请更新令牌文件后重试。'
}
request_release_token() (
  # Read only from the controlling terminal, never from piped installation input.
  saved_terminal=$(stty -g </dev/tty 2>/dev/null) || return 1
  case "$TOKEN_FILE" in /*) ;; *) fail '首次保存令牌需要绝对路径。' ;; esac
  case "$TOKEN_FILE" in */../*|*/./*|*/..|*/.) fail '令牌路径包含不安全组件。' ;; esac
  parent=$(dirname "$TOKEN_FILE")
  check=$parent
  while [ "$check" != / ]; do
    if [ -e "$check" ] || [ -L "$check" ]; then
      [ -d "$check" ] && [ ! -L "$check" ] && [ "$(stat -c %u "$check")" = 0 ] || fail '令牌目录必须由 root 控制，不能含符号链接。'
      mode=$(stat -c %a "$check")
      [ "$((0$mode & 0022))" -eq 0 ] || fail '令牌目录不能对其他用户开放写入。'
    fi
    check=$(dirname "$check")
  done
  scratch=''
  trap 'stty "$saved_terminal" </dev/tty 2>/dev/null || true; [ -z "$scratch" ] || rm -f -- "$scratch"' 0
  trap 'exit 130' 2
  trap 'exit 143' 15
  printf '\n公开下载不可用。如为私有仓库，请输入本仓库只读 GitHub Token。\n令牌隐藏输入，并保存为 root 专属文件：%s\nToken：' "$TOKEN_FILE" >/dev/tty
  stty -echo </dev/tty
  IFS= read -r token </dev/tty || return 1
  stty "$saved_terminal" </dev/tty
  printf '\n' >/dev/tty
  case "$token" in ''|*[!A-Za-z0-9_]*) fail '令牌格式无效。' ;; esac
  mkdir -p -- "$parent"
  scratch=$(mktemp "$parent/.github-release.token.XXXXXXXX")
  chmod 600 "$scratch"
  printf '%s\n' "$token" > "$scratch"
  unset token
  [ ! -e "$TOKEN_FILE" ] && [ ! -L "$TOKEN_FILE" ] || fail '令牌目标已存在，停止覆盖。'
  mv -- "$scratch" "$TOKEN_FILE"
  scratch=''
)

private_release_enabled() { [ -s "$TOKEN_FILE" ]; }

private_release_file() (
  release=$1 name=$2 destination=$3
  case "$name" in release-manifest.json|release-manifest.json.sig|APPGOG-Cloud-Security-Center-*.run|APPGOG-Cloud-Security-Center-*.tar.gz) ;; *) return 1 ;; esac
  [ -f "$TOKEN_FILE" ] && [ ! -L "$TOKEN_FILE" ] && [ -r "$TOKEN_FILE" ] || return 1
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
  curl -q -fsS --connect-timeout 15 --max-time 180 --retry 2 \
    -H @"$scratch/headers" -H 'Accept: application/vnd.github+json' "$endpoint" -o "$scratch/release" || return 1
  asset=$(jq -er --arg name "$name" '.assets[] | select(.name == $name and .state == "uploaded") | .url' "$scratch/release") || return 1
  printf '%s\n' "$asset" | grep -Eq "^$api/assets/[0-9]+$" || return 1
  status=$(curl -q -fsS --connect-timeout 15 --max-time 180 --retry 2 -D "$scratch/asset.headers" \
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
  curl -q -fsS --connect-timeout 15 --max-time 300 --retry 2 "$location" -o "$destination"
)

download_file() {
  base=$1 name=$2 destination=$3
  RELEASE_FAILURE=download
  case "$base" in
    private:*) private_release_file "${base#private:}" "$name" "$destination" ;;
    http://127.0.0.1:*|http://localhost:*)
      [ "${APPGOG_SECURITY_ALLOW_INSECURE_TEST_SOURCE:-false}" = true ] || return 1
      [ "${SECURITY_TEST_MODE:-false}" = true ] && [ "${APPGOG_SECURITY_ALLOW_TEST_MODE:-false}" = true ] || return 1
      curl -q --proto =http -fsSL --connect-timeout 5 --max-time 30 "${base%/}/$name" -o "$destination"
      ;;
    *)
      if curl -q --proto =https --proto-redir =https -fsSL --connect-timeout 15 --max-time 300 --retry 2 \
        "${base%/}/$name" -o "$destination" -w '%{http_code}' > "$WORK/http-status"; then return 0; fi
      case "$(cat "$WORK/http-status")" in 401|404) RELEASE_FAILURE=auth ;; esac
      printf '公开下载失败：%s（HTTP %s）。\n' "$name" "$(cat "$WORK/http-status")" >&2
      return 1
      ;;
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
MCowBQYDK2VwAyEAVBI4YhrFDROYGYbD6FvJTnYvn5+ryDmCcJSL5TszJfY=
-----END PUBLIC KEY-----
EOF
}

try_release() {
  base=$1
  download_file "$base" release-manifest.json "$WORK/release-manifest.json" || return 1
  download_file "$base" release-manifest.json.sig "$WORK/release-manifest.json.sig" || return 1
  RELEASE_FAILURE=signature
  openssl pkeyutl -verify -pubin -inkey "$WORK/release-public.pem" -rawin \
    -in "$WORK/release-manifest.json" -sigfile "$WORK/release-manifest.json.sig" >/dev/null 2>&1 || {
      printf '发布清单签名验证失败；停止安装，不需要输入 Token。\n' >&2; return 1;
    }
  RELEASE_FAILURE=manifest
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
  RELEASE_FAILURE=hash
  printf '%s  %s\n' "$RUN_SHA256" "$WORK/installer.run" | sha256sum -c - >/dev/null 2>&1 || return 1
}

install_tools
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' 0
trap 'exit 130' 2
trap 'exit 143' 15
check_token_file
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
  auto|github)
    if try_release "$SELECTED_BASE"; then :
    elif [ "$RELEASE_FAILURE" = auth ] && ! private_release_enabled && request_release_token; then
      check_token_file
      if [ -n "$REQUESTED_VERSION" ]; then SELECTED_BASE="private:$REQUESTED_VERSION"; else SELECTED_BASE=private:latest; fi
      try_release "$SELECTED_BASE" || fail '认证下载或签名/哈希验证失败；检查令牌仓库权限、正式 Release 和网络。'
    else
      fail "正式包安装被阻止（阶段：$RELEASE_FAILURE）。请检查上方下载/验签错误；已保存 Token 时另核对其仓库权限。"
    fi ;;
esac

case "$INSTALL_ROLE" in local) INSTALL_ROOT=/opt/ironcurtain/local ;; cloud) INSTALL_ROOT=/opt/ironcurtain/cloud ;; esac
installed=''
if [ -f "$INSTALL_ROOT/current/package.json" ]; then installed=$(jq -er '.version' "$INSTALL_ROOT/current/package.json" 2>/dev/null || true); fi
if [ -n "$installed" ] && [ "$installed" != "$TARGET_VERSION" ]; then
  newest=$(printf '%s\n%s\n' "$installed" "$TARGET_VERSION" | sort -V | tail -n 1)
  [ "$newest" = "$TARGET_VERSION" ] || fail "拒绝自动降级：当前 v$installed，发布源 v$TARGET_VERSION。"
fi

log "发布清单签名与安装包 SHA-256 已验证：v$TARGET_VERSION"
set --
[ -z "$PUBLIC_HOST" ] || set -- "$@" --host "$PUBLIC_HOST"
[ -z "$INSTALL_ROLE" ] || set -- "$@" --role "$INSTALL_ROLE"
[ -z "$LISTEN_BIND" ] || set -- "$@" --bind "$LISTEN_BIND"
export IRONCURTAIN_GITHUB_TOKEN_FILE="$TOKEN_FILE"
bash "$WORK/installer.run" "$@"
