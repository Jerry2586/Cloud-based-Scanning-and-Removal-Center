#!/usr/bin/env bash
# Independent security installer/menu. No APPGOG dependencies.
set -euo pipefail
umask 077
ic_fail() { echo "错误：$*" >&2; exit 1; }

# Interactive maintenance may briefly overlap with a scheduled rules/domain job.
# Never remove the lock inode or unlock a different process to resolve contention.
ic_wait_management_lock() {
  local descriptor=$1 path=$2 result
  if flock -n "$descriptor"; then return 0; else result=$?; fi
  [[ $result == 1 ]] || ic_fail "无法获取管理锁（退出码 $result）：$path"
  printf '另一安装、管理或定时维护任务正在运行；等待释放管理锁（最多 15 秒）…\n' >&2
  if flock -w 15 "$descriptor"; then
    printf '管理锁已释放，继续当前操作。\n' >&2
    return 0
  else result=$?; fi
  [[ $result == 1 ]] || ic_fail "等待管理锁失败（退出码 $result）：$path"
  printf '占用的管理锁：%s\n查看占用进程：sudo lslocks --notruncate -o PID,COMMAND,PATH\n查看后台任务：sudo systemctl status ironcurtain-rules-sync.service ironcurtain-panel-update.service ironcurtain-domain-%s-apply.service --no-pager\n请等待正在运行的任务结束后重试；不要删除锁文件或强制并行更新。\n' "$path" "$ROLE" >&2
  ic_fail '等待 15 秒后管理锁仍被占用，本次操作未取得锁，已停止。'
}
ic_role() {
  case "$1" in local|cloud) ROLE=$1 ;; *) ic_fail '角色须为 local 或 cloud' ;; esac
  BASE=/opt/ironcurtain/$ROLE
  CONF=/etc/ironcurtain/$ROLE
  DATA=/var/lib/ironcurtain/$ROLE
  PROJECT=ironcurtain-$ROLE
  CONTAINER=ironcurtain-$ROLE
  [[ $ROLE == local ]] && PORT=8790 || PORT=9443
  if [[ $ROLE == local ]]; then MENU_COMMAND=tiemu; PRODUCT_NAME=铁幕安全;
  else MENU_COMMAND=xuanwu; PRODUCT_NAME=玄武引擎; fi
}
ic_check_dir() {
  local dir=$1 parent mode
  [[ $dir == /* && $(realpath -m -- "$dir") == "$dir" ]] || ic_fail "目录路径不安全：$dir"
  parent=$dir
  while [[ $parent != / ]]; do
    if [[ -e $parent || -L $parent ]]; then
      [[ -d $parent && ! -L $parent && $(stat -c %u "$parent") == 0 ]] || ic_fail "目录不受 root 控制：$parent"
      mode=$(stat -c %a "$parent")
      (( (8#$mode & 0022) == 0 )) || ic_fail "目录可被其他用户写入：$parent"
    fi
    parent=$(dirname -- "$parent")
  done
}
ic_trusted_dir() {
  ic_check_dir "$1"
  install -d -m 750 -o root -g root "$1"
}
ic_private_file() {
  [[ -f $1 && ! -L $1 && $(stat -c %u "$1") == 0 && $(stat -c %a "$1") == 600 ]] || ic_fail "私有文件权限错误：$1"
}
ic_load() {
  ic_check_dir "$BASE"
  ic_private_file "$BASE/install.json"
  jq -e --arg role "$ROLE" '.schema == 1 and .role == $role and (.host|type == "string") and (.bind|type == "string") and (.image|test("^ironcurtain-security:[0-9]+\\.[0-9]+\\.[0-9]+-(local|cloud)-[a-f0-9]{64}$"))' "$BASE/install.json" >/dev/null || ic_fail '安装记录格式错误'
  jq -e --arg role "$ROLE" '.image | startswith("ironcurtain-security:" + $version + "-" + $role + "-")' --arg version "$(jq -er '.version' "$BASE/install.json")" "$BASE/install.json" >/dev/null || ic_fail '安装镜像与角色版本不符'
  HOST=$(jq -er '.host' "$BASE/install.json")
  BIND=$(jq -er '.bind' "$BASE/install.json")
  IMAGE=$(jq -er '.image' "$BASE/install.json")
  local current
  current=$(readlink -f "$BASE/current")
  [[ $current == "$BASE/releases/"* && $(dirname "$current") == "$BASE/releases" ]] || ic_fail '当前版本目录不在 releases 内'
  ic_check_dir "$current"
  [[ $(jq -er '.version' "$current/package.json") == "$(jq -er '.version' "$BASE/install.json")" ]] || ic_fail '版本链接与安装记录不符'
  python3 -c 'import ipaddress,sys,re;h,b=sys.argv[1:];ipaddress.IPv4Address(b);assert len(h)<=253 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]",h)' "$HOST" "$BIND" || ic_fail '安装地址无效'
  ic_env
}
ic_env() {
  export IRONCURTAIN_IMAGE=$IMAGE IRONCURTAIN_CONFIG=$CONF IRONCURTAIN_DATA=$DATA/runtime
  export IRONCURTAIN_RELEASES=$DATA/releases IRONCURTAIN_VIRUS_DATABASES=$DATA/virus-db
  export IRONCURTAIN_PUBLIC_HOST=$HOST IRONCURTAIN_BIND=$BIND
}
ic_compose() { docker compose --project-name "$PROJECT" -f "$BASE/current/docker/compose.$ROLE.yml" "$@"; }
ic_helper() {
  local directory=$1 action=$2
  docker run --rm -i --network none --user 0:0 --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 32 --memory 192m --mount "type=bind,source=$directory,target=/work" "$IMAGE" node scripts/control.js "$action"
}
ic_probe() {
  local directory=$1
  docker run --rm -i --network bridge --user 0:0 --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 32 --memory 192m --mount "type=bind,source=$directory,target=/work,readonly" "$IMAGE" node scripts/control.js probe
}
ic_healthy() { [[ $(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || true) == healthy ]]; }
ic_wait() { local i; for i in {1..30}; do ic_healthy && return 0; sleep 2; done; return 1; }
ic_fingerprint() { openssl x509 -in "$CONF/ca.crt" -noout -fingerprint -sha256; }
ic_certificate() {
  local dir=$1 name=$2 subject=$3 purpose=$4 san=${5:-}
  openssl req -newkey rsa:3072 -nodes -subj "/CN=$subject" -keyout "$dir/$name.key" -out "$dir/$name.csr" >/dev/null 2>&1
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=%s\n' "$purpose" > "$dir/$name.ext"
  [[ -z $san ]] || printf 'subjectAltName=%s\n' "$san" >> "$dir/$name.ext"
  openssl x509 -req -in "$dir/$name.csr" -CA "$CONF/ca.crt" -CAkey "$CONF/ca.key" -CAserial "$CONF/ca.srl" -CAcreateserial -out "$dir/$name.crt" -days 365 -sha256 -extfile "$dir/$name.ext" >/dev/null 2>&1
  rm -f -- "$dir/$name.csr" "$dir/$name.ext"
}

ic_agent_wait() {
  local i
  for i in {1..20}; do
    if systemctl is-active --quiet ironcurtain-agent.service && curl --max-time 2 -fsS --unix-socket /run/ironcurtain/scan.sock http://localhost/status >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

ic_scan_wait() {
  ic_agent_wait || return 1
  local i
  for i in {1..10}; do
    docker exec "$CONTAINER" node --input-type=module -e 'import {localSecurityScan} from "./src/local/scan-client.js"; const result=await localSecurityScan("status"); if(result.state==="unavailable")process.exit(1);' >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

# Menu destinations are regular root-owned files; use a private atomic replacement.
ic_menu_check() {
  local target=$1 mode
  ic_check_dir "$(dirname "$target")"
  if [[ -e $target || -L $target ]]; then
    [[ -f $target && ! -L $target && $(stat -c %u "$target") == 0 && $(stat -c %h "$target") == 1 ]] || ic_fail '菜单入口不受 root 控制'
    mode=$(stat -c %a "$target")
    (( (8#$mode & 0022) == 0 )) || ic_fail '菜单入口不能对其他用户开放写入'
  fi
}
ic_menu_write() {
  local target=$1 temporary
  ic_menu_check "$target"
  temporary=$(mktemp "$target.XXXXXXXX") || return 1
  if ! { printf '#!/usr/bin/env bash\nexec bash /opt/ironcurtain/%s/current/scripts/ironcurtain.sh --role %s "$@"\n' "$ROLE" "$ROLE" > "$temporary" && chmod 755 "$temporary" && mv -Tf -- "$temporary" "$target"; }; then
    rm -f -- "$temporary"
    return 1
  fi
}
