#!/usr/bin/env sh
# Shared POSIX host discovery. No network requests or mutations when sourced.
ic_host_public_ipv4() {
  python3 -c 'import ipaddress,re,sys
value=sys.argv[1].strip(" \t\r\n")
if len(value)>15 or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}",value): sys.exit(1)
try: address=ipaddress.IPv4Address(value)
except ValueError: sys.exit(1)
if not address.is_global or address.is_multicast or address.is_reserved: sys.exit(1)
print(address)' "$1" 2>/dev/null
}
ic_host_detect() (
  host_work=$(mktemp -d) || return 1
  trap 'rm -rf -- "$host_work"' 0
  trap 'exit 130' 2
  trap 'exit 143' 15
  for host_url in https://api.ipify.org https://checkip.amazonaws.com; do
    if curl -q -4 --noproxy '*' --proto '=https' --tlsv1.2 -fsS \
      --connect-timeout 5 --max-time 10 --max-filesize 64 \
      "$host_url" -o "$host_work/address" 2>/dev/null; then
      host_value=$(cat "$host_work/address") || continue
      if ic_host_public_ipv4 "$host_value"; then return 0; fi
    fi
  done
  printf '错误：无法自动识别公网 IPv4，请检查 HTTPS 网络；可用 --host 指定已确认的域名或固定 IP。\n' >&2
  return 1
)
ic_host_select() {
  if [ -n "$1" ]; then printf '%s\n' "$1";
  elif [ -n "$2" ]; then printf '%s\n' "$2";
  else ic_host_detect; fi
}
