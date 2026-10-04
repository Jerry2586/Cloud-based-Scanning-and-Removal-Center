#!/usr/bin/env bash
# Safe decision tests: package managers and Docker/systemd are mocked, no host mutation.
set -euo pipefail
SOURCE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$SOURCE/scripts/lib/install-environment.sh"
log() { printf '%s\n' "$*"; }
ic_fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
assert() { [[ $1 == "$2" ]] || ic_fail "expected [$2], got [$1]"; }
expect_failure() {
  local expected=$1 output; shift
  if output=$("$@" 2>&1); then ic_fail "expected failure: $expected"; fi
  [[ $output == *"$expected"* ]] || ic_fail "unexpected failure: $output"
}
passed=0 skipped=0
run_case() {
  local result
  set +e
  ( set -e; "$1" )
  result=$?
  set -e
  case "$result" in
    0) passed=$((passed+1)); printf 'PASS %s\n' "$1" ;;
    77) skipped=$((skipped+1)); printf 'SKIP %s (Windows filesystem has no real POSIX symlink)\n' "$1" ;;
    *) printf 'FAIL %s\n' "$1" >&2; return "$result" ;;
  esac
}

# All test overrides are shell functions, not production bypass flags.
base_state=ready package_fail=false update_fail=false rpm_calls=0 apt_calls=0
have_docker=true have_dnf=true compose=2.24.0 buildx=true
docker_endpoint=unix:///var/run/docker.sock docker_state=loaded service_ok=true daemon_ok=true
plugin_calls='' engine_calls='' shadow=false
ic_env_has() {
  case "$1" in docker) $have_docker ;; dnf) $have_dnf ;; *) return 0 ;; esac
}
ic_env_base_ready() { [[ $base_state == ready ]]; }
apt-get() {
  if [[ $1 == update ]]; then ! $update_fail; return; fi
  apt_calls=$((apt_calls+1)); apt_args="$*"
  ! $package_fail || return 1
  base_state=ready
}
dnf() { rpm_calls=$((rpm_calls+1)); rpm_args="$*"; ! $package_fail || return 1; base_state=ready; }
yum() { dnf "$@"; }
docker() {
  case "$1 ${2:-}" in
    'context inspect') printf '%s\n' "$docker_endpoint" ;;
    'compose version') [[ $compose != absent ]] || return 1; printf '%s\n' "$compose" ;;
    'buildx version') $buildx ;;
    'info ') $daemon_ok ;;
    *) ic_fail "unexpected Docker command $*" ;;
  esac
}
systemctl() {
  case "$1" in show) printf '%s\n' "$docker_state" ;; start) $service_ok ;; *) ic_fail 'unexpected systemctl' ;; esac
}
python3() { printf '3.11.0\n'; }
uname() { printf 'x86_64\n'; }
ic_env_docker_install() { engine_calls="$*"; have_docker=true; compose=2.24.0; buildx=true; }
ic_env_plugin_install() {
  plugin_calls="$plugin_calls $1"
  if [[ $1 == compose ]]; then $shadow || compose=2.24.0; else buildx=true; fi
}

ready_environment() { MANAGER=apt-get; ic_env_install_base; assert "$apt_calls" 0; }
missing_apt_tools() { MANAGER=apt-get; base_state=missing; ic_env_install_base; assert "$apt_calls" 1; [[ $apt_args == *--no-remove* && $apt_args == *gzip* && $apt_args == *python3* ]]; }
missing_rpm_tools() { MANAGER=yum; base_state=missing; ic_env_install_base; assert "$rpm_calls" 1; [[ $rpm_args == *shadow-utils* && $rpm_args == *findutils* ]]; }
apt_update_failure() { MANAGER=apt-get; base_state=missing; update_fail=true; expect_failure '软件源更新失败' ic_env_install_base; }
package_failure() { MANAGER=apt-get; base_state=missing; package_fail=true; expect_failure '基础依赖安装失败' ic_env_install_base; }
yum_selection() { ID=rocky; have_dnf=false; ic_env_select; assert "$MANAGER" yum; }
dnf_selection() { ID=almalinux; ic_env_select; assert "$MANAGER" dnf; }
unsupported_distro() { ID=alpine; expect_failure '不支持的发行版' ic_env_select; }
missing_manager() { ID=ubuntu; ic_env_has() { return 1; }; expect_failure '缺少包管理器' ic_env_select; }
ready_docker_preserved() { ID=ubuntu; ic_env_docker_prepare; assert "$plugin_calls$engine_calls" ''; }
old_compose_upgraded() { ID=ubuntu; compose=v2.9.0; ic_env_docker_prepare; assert "$plugin_calls" ' compose'; }
missing_compose_installed() { ID=ubuntu; compose=absent; ic_env_docker_prepare; assert "$plugin_calls" ' compose'; }
missing_buildx_installed() { ID=ubuntu; buildx=false; ic_env_docker_prepare; assert "$plugin_calls" ' buildx'; }
fresh_docker_installed() { ID=debian; have_docker=false; ic_env_docker_prepare; assert "$engine_calls" 'docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin'; }
shadowed_compose_rejected() { ID=ubuntu; compose=2.9.0; shadow=true; expect_failure 'Compose 仍低于' ic_env_docker_prepare; }
remote_context_rejected() { ID=ubuntu; docker_endpoint=tcp://192.0.2.1:2376; expect_failure '非本机系统服务' ic_env_docker_prepare; }
client_only_rejected() { ID=ubuntu; docker_state=not-found; expect_failure '只有 Docker 客户端' ic_env_docker_prepare; }
service_failure_reported() { ID=ubuntu; service_ok=false; expect_failure 'Docker 服务启动失败' ic_env_docker_prepare; }
daemon_failure_reported() { ID=ubuntu; daemon_ok=false; expect_failure '守护进程不可用' ic_env_docker_prepare; }
compose_boundary_versions() {
  for compose in v2.24.0 2.39.1 5.0.0; do ic_env_compose_ready || ic_fail "rejected $compose"; done
  for compose in 2.23.9 2.9.0 2.24.0-rc1 invalid absent; do
    if ic_env_compose_ready; then ic_fail "accepted $compose"; fi
  done
}
distro_engine_preserved() {
  # Exercise the actual plugin selection, preventing accidental docker-ce replacement.
  source "$SOURCE/scripts/lib/install-environment.sh"
  MANAGER=apt-get
  dpkg-query() { printf 'install ok installed'; }
  apt-get() { native_args="$*"; }
  ic_env_docker_install() { ic_fail 'must not replace distro Engine'; }
  ic_env_plugin_install compose
  assert "$native_args" 'install -y --no-remove docker-compose-v2'
  ic_env_plugin_install buildx
  assert "$native_args" 'install -y --no-remove docker-buildx'
}

# Standalone bootstrap must repair prerequisites BEFORE executing a Bash payload.
bootstrap_definitions=$(sed -n '/^ca_ready() {/,/^private_release_enabled()/p' "$SOURCE/install.sh" | sed '$d')
bootstrap_missing_tools() {
  eval "$bootstrap_definitions"
  tools_state=missing DISTRO=ubuntu
  tools_ready() { [[ $tools_state == ready ]]; }
  apt-get() { bootstrap_args="$*"; tools_state=ready; }
  install_tools
  [[ $bootstrap_args == *bash* && $bootstrap_args == *gzip* && $bootstrap_args == *ca-certificates* && $bootstrap_args == *--no-remove* ]]
}
bootstrap_dependency_failure() {
  eval "$bootstrap_definitions"
  fail() { ic_fail "$@"; }
  DISTRO=ubuntu
  tools_ready() { return 1; }
  apt-get() { return 1; }
  expect_failure '系统软件源不可用' install_tools
}
bootstrap_ca_missing() {
  eval "$bootstrap_definitions"
  command() { [[ ${1:-} == -v ]] && return 0; builtin command "$@"; }
  ca_ready() { return 1; }
  if tools_ready; then ic_fail 'missing CA accepted'; fi
}
bootstrap_symlink_token_rejected() {
  eval "$bootstrap_definitions"
  fail() { ic_fail "$@"; }
  temp=$(mktemp -d)
  trap 'rm -rf -- "$temp"' EXIT
  printf 'not-a-secret' > "$temp/token"
  ln -s "$temp/token" "$temp/link"
  if [[ ! -L "$temp/link" ]]; then
    case "$OSTYPE" in msys*|cygwin*) return 77 ;; esac
    ic_fail 'test filesystem did not create the required symbolic link'
  fi
  TOKEN_FILE="$temp/link"
  expect_failure '不能是符号链接' check_token_file
}
bootstrap_bad_token_permissions() {
  eval "$bootstrap_definitions"
  fail() { ic_fail "$@"; }
  TOKEN_FILE="$SOURCE/install.sh"
  stat() { [[ $2 != %u ]] || { printf '0'; return; }; printf '644'; }
  expect_failure '权限必须是 600 或 400' check_token_file
}
bootstrap_missing_token_is_allowed() {
  eval "$bootstrap_definitions"
  TOKEN_FILE="$SOURCE/.codex/not-a-token"
  check_token_file
}

for case_name in ready_environment missing_apt_tools missing_rpm_tools apt_update_failure package_failure   yum_selection dnf_selection unsupported_distro missing_manager ready_docker_preserved old_compose_upgraded   missing_compose_installed missing_buildx_installed fresh_docker_installed shadowed_compose_rejected   remote_context_rejected client_only_rejected service_failure_reported daemon_failure_reported   compose_boundary_versions distro_engine_preserved bootstrap_missing_tools bootstrap_dependency_failure   bootstrap_ca_missing bootstrap_symlink_token_rejected bootstrap_bad_token_permissions bootstrap_missing_token_is_allowed; do run_case "$case_name"; done

printf "Environment decisions: %s passed, %s skipped\n" "$passed" "$skipped"
