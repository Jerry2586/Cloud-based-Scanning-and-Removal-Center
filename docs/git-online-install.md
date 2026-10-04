# Git 在线安装：空服务器也能直接运行

README 中 local/cloud 的代码框各只有一行，复制对应的一行命令，粘贴到 Linux SSH 终端执行。任何目录都能运行，不要求服务器已有 `install.sh`、源码或 Git。

## 首次准备

1. 登录 GitHub，为 `Jerry2586/Cloud-based-Scanning-and-Removal-Center` 创建只读细粒度 Token，只选择此仓库，授予 `Contents: Read`。如仓库受组织审批或 SSO 约束，还需完成相应授权。
2. 在需要保护的服务器复制 README 的 local 完整命令；在独立安全服务器复制 cloud 完整命令。
3. 若匿名请求报 404/401，接下来 curl 会提示 `Enter host password for user 'Jerry2586'`，输入 Token，输入不显示。安装器随后再次隐藏询问同一个 Token，用于保存更新凭据；第一次 curl 的交互输入不会被保存。
4. 首次安装自动识别公网 IPv4，无需填写；升级保留已有地址，等待安装检查。以后使用角色菜单；更新分别运行 `sudo ironcurtain update` 或 `sudo xuanwu update`。重复 README 短命令也会检查最新签名正式版本，但下载私有引导器会重新询问 Token；安装器读取已保存令牌。日常更新优先使用一行菜单命令。需要下载时自动复用令牌，请使用本页下方完整入口。

## 获取和更新的边界

入口从 GitHub Contents API 获取固定提交 `ebceaf3a7a7aabd749f185f43c9b0c02deeadc62` 中的 `install.sh`，并校验固定 SHA-256。随后引导器下载 Latest 签名正式 Release，验证项目身份、Ed25519 签名、安装包摘要和安全路径。固定入口不代表固定程序版本。安装临时文件在 root 私有临时目录，执行结束清理，不覆盖 `/root/install.sh`。

公开仓库匿名请求成功时不用 Token；私有仓库必须获得授权。令牌只发送到固定 GitHub API，通过受保护的请求头文件或 curl 终端交互传递；不写进 URL、命令参数或下载日志，不随重定向转发。已有令牌必须是 root 所有、600/400 权限的普通文件，目录不能被其他用户写入或使用符号链接。

首次脚本只补齐 curl、CA 和基础校验工具。完整环境准备仍由引导器和角色安装器负责，支持范围见 README。系统软件源、DNS 或 HTTPS 不能访问时应修复网络；脚本不会关闭 TLS 或绕过签名。

当前 Latest 为 v0.4.0。本轮环境修复与在线入口在 main 源码中，尚未发布新的签名安装包；源码上传不能代替正式发布。使用本入口会获取当前正式包，不能声称安装了未发布修复。

## 常见问题

- `scripts/install-independent.sh: No such file`：复制了源码内部命令；空服务器应复制 README 的在线完整命令。
- `cannot open /root/install.sh`：服务器没有手动上传文件；在线入口无需这个文件。
- Token 无效或权限不足：确认 Token 选择此私有仓库并有 Contents: Read。若已保存的 Token 过期，通过可信终端更新 `/etc/ironcurtain/github-release.token`，恢复 root 所有与600权限后重试；不要将它发给助手。
- 签名、摘要或 HTTPS 失败：安装停止，检查可信发布源与网络，不能删除校验步骤继续执行。
- Git 已更新但程序仍是旧版本：更新入口读取签名 Release；应发布更高版本的正式包，不能替换同版本附件。

## 维护这些命令

README 短入口源文件是 `scripts/git-install-short.sh`；完整入口是 `scripts/git-install-entry.sh`。`node scripts/render-git-install.js` 同时生成 README 短命令和本页完整命令，`--check` 检查两者是否一致。CI 对渲染结果、固定摘要、下载失败和权限边界进行检查。修改固定引导器引用时先验收该提交，再同步 SHA-256；不要改成从 main 下载后直接执行。

## 高级入口：自动复用已保存的下载令牌

以下较长命令保留全部令牌文件与目录检查，适合重复运行时不再交互输入下载令牌。首次安装优先使用 README 的短命令。

<!-- ONLINE-INSTALL:START -->

**需要保护的服务器：铁幕安全。**

```sh
sudo sh -s -- local <<'IRONCURTAIN_INSTALL'
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
url=https://api.github.com/repos/Jerry2586/Cloud-based-Scanning-and-Removal-Center/contents/install.sh?ref=d1e381b437d19d501675a1f20980d77a8a7900b2
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
printf '%s  %s\n' b06aa388a69add6ed2573eccd7e88004be467e551802ef8ec46e0d87f859d826 "$work/install.sh" | sha256sum -c - || fail '引导器校验失败，停止执行。'
sh "$work/install.sh" --role "$role" --token-file "$token_file"
IRONCURTAIN_INSTALL
```

**独立安全服务器：玄武引擎。**

```sh
sudo sh -s -- cloud <<'IRONCURTAIN_INSTALL'
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
url=https://api.github.com/repos/Jerry2586/Cloud-based-Scanning-and-Removal-Center/contents/install.sh?ref=d1e381b437d19d501675a1f20980d77a8a7900b2
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
printf '%s  %s\n' b06aa388a69add6ed2573eccd7e88004be467e551802ef8ec46e0d87f859d826 "$work/install.sh" | sha256sum -c - || fail '引导器校验失败，停止执行。'
sh "$work/install.sh" --role "$role" --token-file "$token_file"
IRONCURTAIN_INSTALL
```

<!-- ONLINE-INSTALL:END -->
