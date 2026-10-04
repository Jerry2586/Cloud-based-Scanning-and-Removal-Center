#!/usr/bin/env sh
set -eu; set +x; umask 077
[ "$(id -u)" = 0 ] && [ "$(uname -s)" = Linux ] || { echo '请在 Linux 使用 sudo 或 root。' >&2; exit 1; }
[ "$#" = 1 ]; case "$1" in local|cloud) ;; *) exit 1 ;; esac
ca_ready() { for ca in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do [ ! -s "$ca" ] || return 0; done; return 1; }
if ! command -v curl >/dev/null || ! command -v sha256sum >/dev/null || ! ca_ready; then
  . /etc/os-release; case "$ID" in debian|ubuntu) apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-remove curl ca-certificates coreutils ;; centos|rhel|rocky|almalinux|fedora|ol) if command -v dnf >/dev/null; then dnf install -y curl ca-certificates coreutils; else yum install -y curl ca-certificates coreutils; fi ;; *) echo '软件源不受支持。' >&2; exit 1 ;; esac
  ca_ready || exit 1
fi
work=$(mktemp -d /tmp/ironcurtain-online.XXXXXXXX); trap 'rm -rf -- "$work"' 0; trap 'exit 130' 2; trap 'exit 143' 15
url=https://api.github.com/repos/Jerry2586/Cloud-based-Scanning-and-Removal-Center/contents/install.sh?ref=d1e381b437d19d501675a1f20980d77a8a7900b2
fetch() { curl -q --proto '=https' --tlsv1.2 -fsS --connect-timeout 15 --max-time 120 -H 'Accept: application/vnd.github.raw+json' "$@" "$url" -o "$work/install.sh" -w '%{http_code}' > "$work/http-status"; }
if ! fetch; then case "$(cat "$work/http-status")" in 401|404) echo 'password 提示请输入 GitHub 只读 Token；安装器首次保存时会再询问一次。' >&2; fetch --user Jerry2586 ;; *) echo '下载失败，请检查网络、CA 或限流；不需要输入 Token。' >&2; exit 1 ;; esac; fi
printf '%s  %s\n' b06aa388a69add6ed2573eccd7e88004be467e551802ef8ec46e0d87f859d826 "$work/install.sh" | sha256sum -c -
sh "$work/install.sh" --role "$1"
