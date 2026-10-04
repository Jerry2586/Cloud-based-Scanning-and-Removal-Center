#!/usr/bin/env sh
# Online entry: the same body is rendered into README so no local file is required.
set -eu
set +x
umask 077
fail() { printf '错误：%s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail '请使用 sudo 或 root。'
[ "$(uname -s)" = Linux ] || fail '仅支持 Linux。'
[ "$#" = 1 ] || fail '请选择 local（铁幕）或 cloud（玄武）。'
case "$1" in local|cloud) role=$1 ;; *) fail '角色只能是 local 或 cloud。' ;; esac
ca_ready() {
  for ca in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    [ ! -s "$ca" ] || return 0
  done
  return 1
}
if ! command -v curl >/dev/null 2>&1 || ! command -v sha256sum >/dev/null 2>&1 || ! ca_ready; then
  [ -r /etc/os-release ] || fail '找不到发行版信息。'
  . /etc/os-release
  case "$ID" in
    debian|ubuntu) apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-remove curl ca-certificates coreutils ;;
    centos|rhel|rocky|almalinux|fedora|ol)
      if command -v dnf >/dev/null 2>&1; then dnf install -y curl ca-certificates coreutils
      elif command -v yum >/dev/null 2>&1; then yum install -y curl ca-certificates coreutils
      else fail '缺少 dnf/yum。'; fi ;;
    *) fail "不支持自动补环境：$ID" ;;
  esac
  ca_ready || fail '系统 CA 未就绪，请修复软件源。'
fi
work=$(mktemp -d /tmp/ironcurtain-online.XXXXXXXX)
trap 'rm -rf -- "$work"' 0
trap 'exit 130' 2
trap 'exit 143' 15
url=https://api.github.com/repos/Jerry2586/Cloud-based-Scanning-and-Removal-Center/contents/install.sh?ref=ebceaf3a7a7aabd749f185f43c9b0c02deeadc62
token_file=/etc/ironcurtain/github-release.token
fetch() { curl -q --proto '=https' --tlsv1.2 -fsS --connect-timeout 15 --max-time 120 -H 'Accept: application/vnd.github.raw+json' "$@" "$url" -o "$work/install.sh" -w '%{http_code}' > "$work/http-status"; }
if [ -e "$token_file" ] || [ -L "$token_file" ]; then
  for parent in /etc/ironcurtain /etc; do
    [ -d "$parent" ] && [ ! -L "$parent" ] && [ "$(stat -c %u "$parent")" = 0 ] || fail '令牌目录必须由 root 控制，不能是符号链接。'
    mode=$(stat -c %a "$parent")
    [ "$((0$mode & 0022))" = 0 ] || fail '令牌目录不能对其他用户开放写入。'
  done
  [ -f "$token_file" ] && [ ! -L "$token_file" ] && [ "$(stat -c %u "$token_file")" = 0 ] || fail '令牌必须是 root 的普通文件。'
  case "$(stat -c %a "$token_file")" in 600|400) ;; *) fail '令牌权限须为 600/400。' ;; esac
  token=$(tr -d '
' < "$token_file")
  case "$token" in ''|*[!A-Za-z0-9_]*) fail '令牌格式无效。' ;; esac
  printf 'Authorization: Bearer %s\n' "$token" > "$work/headers"
  unset token
  fetch -H @"$work/headers" || fail 'Git 下载失败：检查网络和已保存的只读 Token。'
elif ! fetch; then
  case "$(cat "$work/http-status")" in
    401|404) ;;
    *) fail "Git 匿名下载失败（HTTP $(cat "$work/http-status")）：请先检查网络、CA、限流或服务状态，不需要输入 Token。" ;;
  esac
  printf '\n私有仓库需要只读 GitHub Token。下一行 password 提示输入 Token，不是服务器或 GitHub 登录密码。\n安装器稍后再次询问同一个 Token，用于保存后续更新凭据。\n' >&2
  fetch --user Jerry2586 || fail 'Git 下载失败，请核对 Token 权限与网络。'
fi
printf '%s  %s\n' 5852387ff3f35d7499be3e7e52fdaec4f90f703d80a32949965de150fc4cabc4 "$work/install.sh" | sha256sum -c - || fail '引导器校验失败，停止执行。'
sh "$work/install.sh" --role "$role" --token-file "$token_file"
