#!/usr/bin/env bash
# Sourced by the root-only engine installer. Preserve distro/local rules.
ic_av_policy_file() {
  local file=$1 mode
  [[ -f $file && ! -L $file && $(stat -c %u "$file") == 0 && $(stat -c %s "$file") -le 65536 ]] || ic_fail "AppArmor 文件不受 root 控制：$file"
  mode=$(stat -c %a "$file")
  (( (8#$mode & 0022) == 0 )) || ic_fail "AppArmor 文件可被其他用户写入：$file"
}
ic_av_apparmor() {
  local directory=${1:-/etc/apparmor.d} profile localfile managed include
  profile=$directory/usr.bin.freshclam
  if [[ ! -e $profile && ! -L $profile ]]; then return 0; fi
  ic_check_dir "$directory"
  ic_av_policy_file "$profile"
  grep -Eq '^[[:space:]]*#include[[:space:]]+(if[[:space:]]+exists[[:space:]]+)?<local/usr\.bin\.freshclam>[[:space:]]*$' "$profile" || ic_fail '未知 freshclam AppArmor 配置；停止自动修改'
  command -v apparmor_parser >/dev/null || ic_fail '已有 AppArmor 配置但缺少策略加载器'
  ic_trusted_dir "$directory/local"
  localfile=$directory/local/usr.bin.freshclam
  managed=$directory/local/ironcurtain-freshclam
  include='#include <local/ironcurtain-freshclam>'
  if [[ -e $localfile || -L $localfile ]]; then ic_av_policy_file "$localfile"; fi
  if [[ -e $managed || -L $managed ]]; then
    ic_av_policy_file "$managed"
    [[ $(head -n 1 "$managed") == '# Managed by IronCurtain: freshclam isolated database' ]] || ic_fail '已有同名 AppArmor 规则，停止覆盖'
  fi
  local staging
  staging=$(mktemp "$directory/local/.ironcurtain-policy.XXXXXXXX")
  cat > "$staging" <<'POLICY'
# Managed by IronCurtain: freshclam isolated database
/etc/ironcurtain-antivirus/freshclam.conf r,
/var/lib/ironcurtain-antivirus/database/ r,
/var/lib/ironcurtain-antivirus/database/** rwk,
POLICY
  chmod 644 "$staging"
  mv -f -- "$staging" "$managed"
  if [[ ! -e $localfile ]] || ! grep -Fxq "$include" "$localfile"; then
    staging=$(mktemp "$directory/local/.ironcurtain-local.XXXXXXXX")
    [[ ! -e $localfile ]] || cat -- "$localfile" > "$staging"
    printf '\n%s\n' "$include" >> "$staging"
    chmod 644 "$staging"
    mv -f -- "$staging" "$localfile"
  fi
  apparmor_parser --skip-kernel-load --skip-cache "$profile"
  if [[ -r /sys/module/apparmor/parameters/enabled && $(cat /sys/module/apparmor/parameters/enabled) == Y ]]; then
    apparmor_parser --replace --skip-cache "$profile"
  fi
}
