#!/usr/bin/env bash
# Environment preparation only; sourcing this file never installs packages.
# Shared decision functions are exercised with mocks on non-Linux developer hosts.
ic_env_has() { command -v "$1" >/dev/null 2>&1; }
ic_env_select() {
  case "$ID" in
    ubuntu|debian) MANAGER=apt-get ;;
    centos|rhel|rocky|almalinux|fedora|ol)
      if ic_env_has dnf; then MANAGER=dnf; else MANAGER=yum; fi ;;
    *) ic_fail "不支持的发行版：$ID；需要 Debian/Ubuntu 或受支持的 RHEL 系 Linux" ;;
  esac
  ic_env_has "$MANAGER" || ic_fail "系统缺少包管理器 $MANAGER，无法自动补环境"
}
ic_env_ca_ready() {
  local bundle
  for bundle in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    [[ ! -s $bundle ]] || return 0
  done
  return 1
}
ic_env_python_ready() {
  # The systemd host agent uses this exact interpreter; PATH alone is insufficient.
  /usr/bin/python3 -c 'import sys,sqlite3,ssl;assert sys.version_info >= (3,9)' >/dev/null 2>&1 \
    && python3 -c 'import sys,sqlite3,ssl;assert sys.version_info >= (3,9)' >/dev/null 2>&1
}
ic_env_base_ready() {
  local tool
  for tool in curl openssl jq flock python3 tar gzip find realpath readlink sha256sum sort     mktemp stat install timeout ss ip awk sed grep cut head tail getent useradd groupadd systemctl gpg; do
    ic_env_has "$tool" || return 1
  done
  ic_env_ca_ready || return 1
  ic_env_python_ready || return 1
  [[ $(printf '2.24.0\n2.9.0\n' | sort -V | head -n1) == 2.9.0 ]] || return 1
}
ic_env_install_base() {
  ic_env_base_ready && return 0
  echo '正在补齐 HTTPS、归档、扫描代理与系统诊断依赖…'
  if [[ $MANAGER == apt-get ]]; then
    apt-get update || ic_fail '系统软件源更新失败；检查 DNS、HTTPS 和 apt 源后重试同一安装命令'
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-remove       bash ca-certificates curl openssl coreutils jq tar gzip findutils util-linux       python3 iproute2 passwd systemd gnupg || ic_fail '基础依赖安装失败；未删除现有软件，请修复软件源/包管理锁后重试'
  else
    "$MANAGER" install -y bash ca-certificates curl openssl coreutils jq tar gzip findutils       util-linux python3 iproute shadow-utils systemd gnupg2 || ic_fail '基础依赖安装失败；请检查系统受信任软件源和包管理锁'
  fi
  ic_env_base_ready || ic_fail '依赖仍不满足：需要 Python >=3.9（含 sqlite3/ssl）、GNU 工具和有效 CA 包；旧发行版需先升级系统'
}
ic_env_crypto_ready() (
  local scratch
  scratch=$(mktemp -d) || return 1
  trap 'rm -rf -- "$scratch"' EXIT
  umask 077
  printf 'ironcurtain-environment-check\n' > "$scratch/message"
  openssl req -help 2>&1 | grep -- -addext >/dev/null || return 1
  openssl genpkey -algorithm ED25519 -out "$scratch/key" >/dev/null 2>&1 || return 1
  openssl pkey -in "$scratch/key" -pubout -out "$scratch/public" >/dev/null 2>&1 || return 1
  openssl pkeyutl -sign -rawin -inkey "$scratch/key" -in "$scratch/message" -out "$scratch/signature" >/dev/null 2>&1 || return 1
  openssl pkeyutl -verify -rawin -pubin -inkey "$scratch/public" -in "$scratch/message" -sigfile "$scratch/signature" >/dev/null 2>&1
)
ic_env_prepare() {
  [[ -r /etc/os-release ]] || ic_fail '缺少 /etc/os-release，无法识别系统'
  . /etc/os-release
  case "$(uname -m)" in x86_64|aarch64) ;; *) ic_fail '仅支持 x86_64 / aarch64 CPU' ;; esac
  ic_env_select
  ic_env_install_base
  if ! ic_env_crypto_ready; then
    echo '正在从受信任软件源升级 OpenSSL 发布验签工具…'
    if [[ $MANAGER == apt-get ]]; then
      apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-remove openssl \
        || ic_fail 'OpenSSL 软件包升级失败，请修复系统软件源后重试'
    else
      "$MANAGER" install -y openssl || ic_fail 'OpenSSL 软件包升级失败，请修复系统软件源后重试'
    fi
    ic_env_crypto_ready || ic_fail '系统软件源中的 OpenSSL 缺少 Ed25519 发布验签或证书扩展能力；请升级受支持的 Linux 版本'
  fi
  # A remote Docker context would install onto the wrong server.
  [[ -z ${DOCKER_HOST:-} && -z ${DOCKER_CONTEXT:-} ]] || ic_fail '请清除 DOCKER_HOST/DOCKER_CONTEXT；此安装器只管理当前服务器的 Docker'
}
ic_env_docker_repo() {
  local distro codename repo key scratch
  if [[ $MANAGER == apt-get ]]; then
    distro=$ID
    codename=${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}
    [[ $distro =~ ^(ubuntu|debian)$ && $codename =~ ^[a-z][a-z0-9-]*$ ]] || ic_fail '系统代号不可识别，无法选择 Docker 受信任软件源'
    repo="https://download.docker.com/linux/$distro"
    # Reuse an existing official repo rather than adding a second Signed-By entry.
    if ! grep -RqE "^[[:space:]]*(deb .*|URIs:[[:space:]]*)https://download\.docker\.com/linux/$distro([[:space:]]|/)" /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
      for directory in /etc/apt/keyrings /etc/apt/sources.list.d; do
        ic_check_dir "$directory"; [[ -d $directory ]] || install -d -m 755 "$directory"
      done
      key=/etc/apt/keyrings/ironcurtain-docker.asc
      [[ ! -L $key && ! -L /etc/apt/sources.list.d/ironcurtain-docker.list ]] || ic_fail 'Docker 软件源路径是符号链接，停止覆盖'
      scratch=$(mktemp /etc/apt/keyrings/.ironcurtain-docker.XXXXXXXX)
      if ! curl -fsS --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 --retry 2 "$repo/gpg" -o "$scratch"; then
        rm -f -- "$scratch"; ic_fail '无法通过 HTTPS 获取 Docker 软件源公钥；检查网络后重试'
      fi
      if ! gpg --batch --show-keys "$scratch" >/dev/null 2>&1; then
        rm -f -- "$scratch"; ic_fail 'Docker 软件源公钥格式无效'
      fi
      chmod 644 "$scratch"; mv -f -- "$scratch" "$key"
      printf 'deb [arch=%s signed-by=%s] %s %s stable\n' "$(dpkg --print-architecture)" "$key" "$repo" "$codename" > /etc/apt/sources.list.d/ironcurtain-docker.list
    fi
    apt-get update || ic_fail 'Docker 软件源更新失败；未修改已有 Docker 服务'
  else
    distro=centos; [[ $ID != fedora ]] || distro=fedora; [[ $ID != rhel ]] || distro=rhel
    repo="https://download.docker.com/linux/$distro/docker-ce.repo"
    if [[ $MANAGER == yum ]]; then
      yum install -y yum-utils || ic_fail '无法安装 yum 软件源管理工具'
      yum-config-manager --add-repo "$repo" || ic_fail '无法登记 Docker 软件源'
    else
      dnf install -y dnf-plugins-core || ic_fail '无法安装 dnf 软件源管理工具'
      if dnf --version 2>/dev/null | head -n1 | grep -Eq '(^|[^0-9])5\.'; then
        dnf config-manager addrepo --from-repofile "$repo" || ic_fail '无法登记 Docker 软件源'
      else
        dnf config-manager --add-repo "$repo" || ic_fail '无法登记 Docker 软件源'
      fi
    fi
  fi
}
ic_env_docker_install() {
  ic_env_docker_repo
  if [[ $MANAGER == apt-get ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-remove "$@" || ic_fail 'Docker 软件包安装失败；禁止自动删除/替换现有容器运行时，请检查包冲突或软件源'
  else
    "$MANAGER" install -y "$@" || ic_fail 'Docker 软件包安装失败；未允许移除冲突运行时，请检查软件源/包冲突'
  fi
}
ic_env_compose_ready() {
  local version
  version=$(docker compose version --short 2>/dev/null) || return 1
  version=${version#v}
  [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$ && $version != *-* ]] || return 1
  [[ $(printf '%s\n' 2.24.0 "$version" | sort -V | head -n1) == 2.24.0 ]]
}
ic_env_plugin_install() {
  local kind=$1 package
  # Respect distro-managed Engine: do not replace it with docker-ce to get plugins.
  if [[ $MANAGER == apt-get ]] && dpkg-query -W -f='${Status}' docker.io 2>/dev/null | grep -q 'install ok installed'; then
    [[ $kind == compose ]] && package=docker-compose-v2 || package=docker-buildx
    apt-get update || ic_fail '发行版 Docker 插件软件源不可用'
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-remove "$package" || ic_fail "发行版未提供可用的 $package；保留现有 Docker，请升级系统或单独维护插件"
  else
    [[ $kind == compose ]] && package=docker-compose-plugin || package=docker-buildx-plugin
    ic_env_docker_install "$package"
  fi
}
ic_env_docker_prepare() {
  local endpoint state
  if ! ic_env_has docker; then
    ic_env_docker_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  fi
  endpoint=$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null) || ic_fail 'Docker context 无法读取；请修复 Docker CLI 配置'
  [[ $endpoint == unix:///var/run/docker.sock || $endpoint == unix:///run/docker.sock ]] || ic_fail "Docker context 指向非本机系统服务：$endpoint；请切换到本机 default context"
  state=$(systemctl show docker.service --property=LoadState --value 2>/dev/null) || ic_fail '无法读取 Docker systemd 服务'
  [[ $state == loaded ]] || ic_fail '只有 Docker 客户端或服务被屏蔽；请先恢复本机 docker.service，安装器不会替换已有运行时'
  systemctl start docker || ic_fail 'Docker 服务启动失败；请运行 journalctl -u docker.service 排查，安装器不会清理现有容器'
  docker info >/dev/null 2>&1 || ic_fail 'Docker 守护进程不可用，请检查本机 socket 与服务日志'
  if ! ic_env_compose_ready; then
    echo '正在安装或升级 Docker Compose（最低 v2.24.0）…'
    ic_env_plugin_install compose
    ic_env_compose_ready || ic_fail 'Compose 仍低于 v2.24.0 或版本无效；请检查用户目录旧插件是否遮蔽系统插件'
  fi
  if ! docker buildx version >/dev/null 2>&1; then
    echo '正在补齐 Docker Buildx…'
    ic_env_plugin_install buildx
    docker buildx version >/dev/null 2>&1 || ic_fail 'Buildx 仍不可用；请检查旧插件覆盖与软件源'
  fi
  echo "环境检查通过：$ID / $(uname -m)，Python $(python3 -c 'import platform;print(platform.python_version())')，Compose $(docker compose version --short)"
}
