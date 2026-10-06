#!/usr/bin/env bash
# Root-only local management; the browser and cloud cannot call this interface.
set -euo pipefail
umask 077
ROLE=''
if [[ ${1:-} == --role ]]; then ROLE=${2:?}; shift 2; fi
case "${ROLE:-$(basename "$0")}" in local|tiemu|ironcurtain) ROLE=local ;; cloud|xuanwu) ROLE=cloud ;; *) echo '角色无效' >&2; exit 1 ;; esac
SOURCE=/opt/ironcurtain/$ROLE/current
source "$SOURCE/scripts/lib/independent.sh"
source "$SOURCE/scripts/lib/domain-services.sh"
source "$SOURCE/scripts/lib/management-transaction.sh"
source "$SOURCE/scripts/lib/menu-display.sh"
[[ $EUID == 0 ]] || ic_fail '请用 sudo 运行管理菜单'
ic_role "$ROLE"
ic_load
[[ ! -e $BASE/transaction.json ]] || ic_fail '存在未完成的安装事务，请先重复运行安装命令恢复'
STAGE='' RELEASE_STAGE='' IC_ADMIN_TX='' MANAGEMENT_LOCKED=false AV_TIMER_RESTORE=false
cleanup() {
  local result=$?
  trap - EXIT INT TERM
  if $AV_TIMER_RESTORE; then
    if [[ ! -e /var/lib/ironcurtain-antivirus/source.json && ! -L /var/lib/ironcurtain-antivirus/source.json && ! -e /var/lib/ironcurtain-antivirus/activation.json && ! -L /var/lib/ironcurtain-antivirus/activation.json ]]; then
      systemctl start ironcurtain-antivirus-update.timer || result=1
    else
      systemctl disable --now ironcurtain-antivirus-update.timer || result=1
    fi
  fi
  if $MANAGEMENT_LOCKED && [[ -e $BASE/admin-transaction.json || -L $BASE/admin-transaction.json ]]; then
    ic_admin_recover || { echo '管理操作恢复尚未完成，请重复运行菜单继续恢复。' >&2; result=1; }
  fi
  if [[ -n $STAGE && -e $STAGE ]]; then
    [[ $STAGE == "$CONF/.admin."* && $(dirname "$STAGE") == "$CONF" ]] || exit 1
    ic_check_dir "$STAGE"
    rm -rf -- "$STAGE"
  fi
  if [[ -n $RELEASE_STAGE && -e $RELEASE_STAGE ]]; then
    [[ $RELEASE_STAGE == "$DATA/.release."* && $(dirname "$RELEASE_STAGE") == "$DATA" ]] || exit 1
    ic_check_dir "$RELEASE_STAGE"
    rm -rf -- "$RELEASE_STAGE"
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
stage() { ic_check_dir "$CONF"; STAGE=$(mktemp -d "$CONF/.admin.XXXXXXXX"); chmod 700 "$STAGE"; }
lock() {
  exec 9>"/run/lock/ironcurtain-$ROLE.lock"
  ic_wait_management_lock 9 "/run/lock/ironcurtain-$ROLE.lock"
  MANAGEMENT_LOCKED=true
  ic_admin_recover || ic_fail '原管理事务尚未恢复，停止新操作'
}
if [[ -e $BASE/admin-transaction.json || -L $BASE/admin-transaction.json ]]; then
  lock
  flock -u 9
  MANAGEMENT_LOCKED=false
fi
ask() { read -r -p "$1" "$2" </dev/tty; }
password() {
  read -r -s -p '请输入身份包解锁密码（至少 16 字符）：' PAIR_PASSWORD </dev/tty; echo
  [[ ${#PAIR_PASSWORD} -ge 16 && ${#PAIR_PASSWORD} -le 256 ]] || ic_fail '密码长度应为 16–256 字符'
}
audit() {
  jq -nc --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg action "$1" --arg subject "${2:-$ROLE}" '{at:$at,action:$action,subject:$subject}' >> "$CONF/management-audit.jsonl"
  chmod 600 "$CONF/management-audit.jsonl"
}
status() {
  local version installed_release agent_state sync_state engine_json engine_state engine_detail engine_source engine_color
  version=$(jq -r .version "$BASE/install.json")
  installed_release=$(basename "$(readlink -f "$SOURCE")")
  ic_menu_header "$version" "$installed_release"
  ic_menu_row '部署角色' "$PRODUCT_NAME"
  if ic_healthy; then ic_menu_row '运行状态' '正常（容器健康）' "$IC_MENU_GREEN";
  else ic_menu_row '运行状态' '容器未通过健康检查，请运行环境诊断' "$IC_MENU_RED"; fi
  local panel_port=8790 panel_origin
  [[ $ROLE != cloud ]] || panel_port=8791
  panel_origin=$(jq -r '.origin // empty' "$CONF/runtime/domain.json" 2>/dev/null || true)
  ic_menu_row '网页面板' "${panel_origin:-https://$HOST:$panel_port}" "$IC_MENU_GREEN"
  [[ $ROLE != cloud ]] || ic_menu_row '节点接口' "https://$HOST:9443（双向证书认证）"
  ic_menu_row '更新状态' "本地 v$version（选 6 检查并更新最新签名正式版）"
  ic_menu_row '打开菜单' "sudo $MENU_COMMAND"
  ic_menu_row '更新程序' "sudo $MENU_COMMAND update"
  if [[ $ROLE == local ]]; then
    agent_state=$(systemctl is-active ironcurtain-agent.service || true)
    sync_state=$(systemctl is-active ironcurtain-rules-sync.timer || true)
    if [[ $agent_state == active ]]; then ic_menu_row '扫描代理' '运行中' "$IC_MENU_GREEN";
    else ic_menu_row '扫描代理' "未运行（$agent_state）" "$IC_MENU_RED"; fi
    if [[ $sync_state == active ]]; then ic_menu_row '规则同步' '定时器运行中（配对后每 15 分钟尝试同步）' "$IC_MENU_GREEN";
    else ic_menu_row '规则同步' "定时器未运行（$sync_state）" "$IC_MENU_YELLOW"; fi
    if engine_json=$(python3 "$SOURCE/src/host/antivirus.py") &&
       jq -e 'type == "object" and (.state | type == "string")' <<< "$engine_json" >/dev/null; then
      engine_state=$(jq -r '.state' <<< "$engine_json")
      engine_detail=$(jq -r '.detail // "详情请选 17 查看"' <<< "$engine_json")
      engine_source=$(jq -r '.source // "unknown"' <<< "$engine_json")
      engine_color=$IC_MENU_YELLOW
      case "$engine_state" in
        configured) ic_menu_row '病毒引擎' 'ClamAV · 病毒库已配置，实际加载由扫描确认' "$engine_color" ;;
        stale) ic_menu_row '病毒引擎' "ClamAV · 病毒库需要更新：$engine_detail" "$engine_color" ;;
        *) ic_menu_row '病毒引擎' "未就绪：$engine_detail" "$IC_MENU_RED" ;;
      esac
      case "$engine_source" in official-direct) engine_source='官方直接更新' ;; xuanwu-signed) engine_source='玄武签名病毒库' ;; *) engine_source='尚未确认（选 17 检查）' ;; esac
      ic_menu_row '病毒库源' "$engine_source"
    else ic_menu_row '病毒引擎' '状态读取失败（选 17 检查）' "$IC_MENU_RED"; fi
    if [[ -d $CONF/runtime/cloud ]]; then ic_menu_row '玄武连接' '身份已配置（选 11 检查实时握手）' "$IC_MENU_YELLOW";
    else ic_menu_row '玄武连接' '尚未配对（选 10 导入身份包）' "$IC_MENU_YELLOW"; fi
  else
    ic_menu_row '登记节点' "$(jq -r '.nodes | length' "$CONF/runtime/config.json") 个（选 10 查看）"
    ic_menu_row '安全连接' '节点证书与独立令牌认证；连接状态以实际检查为准'
  fi
}
scan() {
  [[ $ROLE == local ]] || ic_fail '此操作仅用于铁幕本地节点'
  curl --max-time 10 -fsS --unix-socket /run/ironcurtain/scan.sock -X POST -H 'Content-Length: 0' http://localhost/scan | jq .
  echo '扫描任务已提交；在独立网页查看实际进度和逐项结果。'
}
full_scan() {
  [[ $ROLE == local ]] || ic_fail '此操作仅用于铁幕本地节点'
  curl --max-time 10 -fsS --unix-socket /run/ironcurtain/scan.sock -X POST -H 'Content-Length: 0' http://localhost/full-scan | jq .
  echo '已提交文件深度查杀；只检查纳管目录。暂停任务将在相同范围与病毒库版本下继续。'
}
engines() {
  [[ $ROLE == local ]] || ic_fail '引擎就绪检查仅用于铁幕'
  local result
  result=$(curl -q --max-time 8 --max-filesize 16384 -fsS --unix-socket /run/ironcurtain/scan.sock http://localhost/engines) || ic_fail '本机检查代理不可用，请运行环境诊断'
  printf '%s\n' "$result" | jq -e 'select(.schema == "ironcurtain-engine-readiness/v1") | {state,checked_at,reason,ready_count,engines}'
  echo '检查在后台执行；如显示 checking，请稍后再次运行 sudo tiemu engines。'
}
scan_status() {
  [[ $ROLE == local ]] || ic_fail '此操作仅用于铁幕本地节点'
  curl --max-time 10 -fsS --unix-socket /run/ironcurtain/scan.sock http://localhost/status | jq '{state,protection,inventory,full_scan,findings_source}'
}
discover_scope() {
  [[ $ROLE == local ]] || ic_fail '此操作仅用于铁幕本地节点'
  python3 "$SOURCE/src/host/inventory.py" discover --profile "$CONF/profile.json"
}
enroll_scope() {
  [[ $ROLE == local ]] || ic_fail '此操作仅用于铁幕本地节点'
  lock; stage
  python3 "$SOURCE/src/host/inventory.py" discover --profile "$CONF/profile.json" --output "$STAGE/inventory.json"
  ask '选择需要保护的对象序号（英文逗号分隔；留空取消）：' selected
  [[ -n $selected ]] || { echo '已取消'; return; }
  printf '%s\n' "$selected" | python3 "$SOURCE/src/host/inventory.py" enroll --profile "$CONF/profile.json" --inventory "$STAGE/inventory.json" --output "$STAGE/profile.json"
  python3 "$SOURCE/src/host/agent.py" --validate-profile --profile "$STAGE/profile.json"
  ic_admin_begin profile
  install -m 600 "$STAGE/profile.json" "$CONF/profile.json.new"; mv -f "$CONF/profile.json.new" "$CONF/profile.json"
  if ! systemctl restart ironcurtain-agent.service || ! ic_scan_wait; then ic_fail '扫描代理未启动，将恢复之前的保护配置'; fi
  audit scope-enrolled; ic_admin_finish
  echo '保护范围已保存；镜像批准、端口允许清单和独立签名基线仍需单独核验。'
}
response() {
  [[ $ROLE == local ]] || ic_fail '文件处置仅用于铁幕本机'
  lock
  local operation=$1 evidence_id=''
  if [[ $operation == quarantine || $operation == restore ]]; then
    ask '完整证据 ID（从命中详情或隔离记录复制）：' evidence_id
    [[ $evidence_id =~ ^[a-f0-9]{64}$ ]] || ic_fail '证据 ID 无效'
    if [[ $operation == restore ]]; then
      echo '恢复将重新引入命中文件；仅供确认误报后人工取回。恢复为 root:0600、不覆盖目标、保留副本。'
    else
      echo '隔离前核对已扫描文件身份；配置、凭据、数据库、系统文件和共享可写文件不自动处置。'
      echo '隔离路径不等于停止正在运行的进程。'
    fi
    ask '确认请输入 YES：' response_confirm
    [[ $response_confirm == YES ]] || ic_fail '操作取消'
  fi
  local args=("$operation" --profile "$CONF/profile.json" --state "$DATA/agent")
  [[ -z $evidence_id ]] || args+=("$evidence_id")
  python3 "$SOURCE/src/host/response.py" "${args[@]}" | jq .
  audit "file-$operation" "$evidence_id"
}
profile() {
  [[ $ROLE == local ]] || ic_fail '此操作仅用于本地节点'
  lock; stage
  echo '配置由本机管理员保存。路径使用绝对路径；多个值用英文逗号分隔。'
  echo '留空保留原值；输入 - 清空。签名基线与 Cloudflare 配置会保留。'
  ask '程序目录：' programs; ask '业务数据目录：' business
  ask '关键配置文件：' configs; ask '凭据文件（只核对权限）：' secrets
  ask 'SQLite 文件：' databases; ask '容器名称：' containers
  ask '允许 TCP 端口：' tcp; ask '允许 UDP 端口：' udp
  cp -p "$CONF/profile.json" "$STAGE/profile.json"
  printf '%s\n' "$programs" "$business" "$configs" "$secrets" "$databases" "$containers" "$tcp" "$udp" |
    python3 -c '
import sys,json,os
file=sys.argv[1]; value=json.load(open(file)); keys=["program_roots","business_roots","config_files","secret_files","sqlite_files","containers","approved_tcp_ports","approved_udp_ports"]
for key,line in zip(keys,sys.stdin.read().splitlines()):
    if not line: continue
    items=[] if line=="-" else [x.strip() for x in line.split(",")]
    if key.endswith("ports"): items=[int(x) for x in items]
    if key=="containers":
        old={x["name"]:x for x in value.get(key,[])}; items=[old.get(x,{"name":x}) for x in items]
    value[key]=items
with open(file,"w") as out: json.dump(value,out,ensure_ascii=False); out.write("\n")
os.chmod(file,0o600)
' "$STAGE/profile.json"
  python3 "$SOURCE/src/host/agent.py" --validate-profile --profile "$STAGE/profile.json"
  ic_admin_begin profile
  install -m 600 "$STAGE/profile.json" "$CONF/profile.json.new"; mv -f "$CONF/profile.json.new" "$CONF/profile.json"
  if ! systemctl restart ironcurtain-agent.service || ! ic_scan_wait; then
    ic_fail '扫描代理未启动，将恢复之前的保护配置'
  fi
  audit profile-saved; ic_admin_finish; echo '保护配置已保存。缺少签名基线或病毒引擎的项目会显示未就绪。'
}
pair() {
  [[ $ROLE == local ]] || ic_fail '配对导入仅用于铁幕本地节点'
  lock; stage
  ask '加密身份包在本机的绝对路径：' bundle
  [[ $bundle == /* && -f $bundle && ! -L $bundle && $(stat -c %s "$bundle") -le 100000 ]] || ic_fail '身份包路径或大小无效'
  ask '请核对并输入玄武 CA 的 SHA-256 指纹：' fingerprint
  password
  install -m 600 "$bundle" "$STAGE/pairing.icpair"
  printf '%s\n%s\n' "$PAIR_PASSWORD" "$fingerprint" | python3 -c 'import sys,json;v=sys.stdin.read().splitlines();json.dump({"password":v[0],"fingerprint":v[1]},sys.stdout)' | ic_helper "$STAGE" unseal
  unset PAIR_PASSWORD
  ic_probe "$STAGE" || ic_fail '真实 mTLS 握手失败，现有配对保持原状'
  chown root:10001 "$STAGE/identity" "$STAGE/identity/"*; chmod 750 "$STAGE/identity"; chmod 640 "$STAGE/identity/"*
  ic_admin_begin pair
  old=''
  if [[ -e $CONF/runtime/cloud ]]; then
    [[ -d $CONF/runtime/cloud && ! -L $CONF/runtime/cloud ]] || ic_fail '旧身份目录异常'
    old=$CONF/cloud-retired-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM
    mv "$CONF/runtime/cloud" "$old"; chmod 700 "$old"
  fi
  if ! mv "$STAGE/identity" "$CONF/runtime/cloud"; then
    [[ -z $old ]] || mv "$old" "$CONF/runtime/cloud"
    ic_fail '身份提交失败，已保留旧配对'
  fi
  audit paired; ic_admin_finish; echo '加密身份、CA 指纹及在线握手均通过。面板将在下一次刷新显示连接状态。'
}
cloud_status() {
  [[ $ROLE == local ]] || ic_fail '云端握手检查仅用于本地节点'
  lock; stage
  [[ -d $CONF/runtime/cloud ]] || ic_fail '尚未配对玄武'
  cp -a "$CONF/runtime/cloud" "$STAGE/identity"
  ic_probe "$STAGE" || ic_fail '身份或连接检查失败；本地扫描继续独立运行'
  echo '玄武 mTLS、节点证书和令牌握手通过。'
}
unpair() {
  [[ $ROLE == local ]] || ic_fail '解绑仅用于本地节点'
  lock
  [[ -d $CONF/runtime/cloud && ! -L $CONF/runtime/cloud ]] || ic_fail '没有可解绑的身份'
  ic_admin_begin unpair
  retired=$CONF/cloud-retired-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM
  mv "$CONF/runtime/cloud" "$retired"; chmod 700 "$retired"
  audit unpaired; ic_admin_finish; echo '云端连接已停用。身份留在 root 私有目录；本地扫描继续。请在玄武撤销该节点。'
}
commit_cloud() {
  ic_helper "$STAGE" validate-cloud
  [[ -n ${IC_ADMIN_TX:-} ]] || ic_admin_begin cloud-config
  install -m 640 -o root -g 10001 "$STAGE/config.json" "$CONF/runtime/config.json.new"
  mv -f "$CONF/runtime/config.json.new" "$CONF/runtime/config.json"
  if ! ic_compose restart || ! ic_wait; then
    ic_fail '云端健康检查失败，将恢复之前的配置'
  fi
}
register() {
  [[ $ROLE == cloud ]] || ic_fail '登记节点仅用于玄武'
  lock; stage
  ask '节点名称（如 node-server1）：' node
  [[ $node =~ ^node-[a-z0-9][a-z0-9-]{0,63}$ ]] || ic_fail '节点名称格式错误'
  jq -e --arg name "$node" '.nodes | has($name) | not' "$CONF/runtime/config.json" >/dev/null || ic_fail '节点名称已登记'
  # Generate a separate 256-bit unlock secret for each node; never trace it or
  # put it in command arguments, the encrypted pack, audit logs or the runtime mount.
  set +x
  openssl rand -hex 32 > "$STAGE/pairing-password"
  chmod 600 "$STAGE/pairing-password"
  install -m 600 "$CONF/ca.crt" "$STAGE/ca.crt"
  ic_certificate "$STAGE" client "$node" clientAuth
  openssl rand -hex 32 > "$STAGE/token"
  jq -n --arg node "$node" --arg endpoint "https://$HOST:$PORT/" '{schema:"ironcurtain-cloud/v1",node_id:$node,endpoint:$endpoint}' > "$STAGE/cloud.json"
  cp "$CONF/runtime/config.json" "$STAGE/config.json"
  ic_helper "$STAGE" register-node
  ic_helper "$STAGE" seal < "$STAGE/pairing-password"
  mv "$STAGE/config.next.json" "$STAGE/config.json"
  ic_admin_begin register
  ic_trusted_dir "$CONF/exports"; chmod 700 "$CONF/exports"
  export_path=$CONF/exports/$node-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM.icpair
  install -m 600 -o root -g root "$STAGE/pairing.icpair" "$export_path.pending"
  install -m 600 -o root -g root "$STAGE/pairing-password" "$export_path.unlock.pending"
  commit_cloud
  audit node-registered "$node"
  ic_admin_finish
  # Publish the separate root-only secret before making the pack available.
  mv -- "$export_path.unlock.pending" "$export_path.unlock"
  mv -- "$export_path.pending" "$export_path"
  echo "节点已登记。将加密包传到本地节点：$export_path"
  echo "解锁密码已自动生成，root 专属备份：$export_path.unlock"
  IFS= read -r PAIR_PASSWORD < "$export_path.unlock"
  printf '系统生成的身份包解锁密码：%s\n' "$PAIR_PASSWORD" > /dev/tty
  unset PAIR_PASSWORD
  echo '铁幕导入时粘贴上述密码；请将密码与加密身份包分开保管和传递。'
  ic_fingerprint
}
revoke() {
  [[ $ROLE == cloud ]] || ic_fail '撤销节点仅用于玄武'
  lock; stage
  ask '要撤销的节点名称：' node
  cp "$CONF/runtime/config.json" "$STAGE/config.json"
  printf '%s\n' "$node" | python3 -c 'import sys,json;json.dump({"node_id":sys.stdin.read().strip()},sys.stdout)' | ic_helper "$STAGE" revoke-node
  mv "$STAGE/config.next.json" "$STAGE/config.json"
  commit_cloud; audit node-revoked "$node"; ic_admin_finish
  echo '该节点证书与令牌已从允许名单撤销。本地扫描不受影响。'
}
reader() {
  [[ $ROLE == cloud ]] || ic_fail '浏览器身份仅用于玄武'
  echo "浏览器证书：$CONF/credentials/reader.p12"
  echo '通过可信管理通道复制证书；P12 导入密码与 reader 登录密码保存在以下 root 私有文件：'
  echo "$CONF/credentials/token"
  echo "只读网页：https://$HOST:$PORT/dashboard"
  ic_fingerprint
}
doctor() {
  status
  ic_check_dir "$CONF"; ic_check_dir "$DATA"; ic_compose config --quiet
  if [[ $ROLE == local ]]; then
    python3 "$SOURCE/src/host/agent.py" --validate-profile --profile "$CONF/profile.json"
    curl --max-time 10 -fsS --unix-socket /run/ironcurtain/scan.sock http://localhost/status | jq '{state,checked_at,progress,history_state}'
    openssl x509 -in "$CONF/runtime/panel.crt" -noout -fingerprint -sha256 -dates
  else
    openssl verify -CAfile "$CONF/ca.crt" "$CONF/runtime/server.crt" "$CONF/runtime/health.crt"
    stage; cp "$CONF/runtime/config.json" "$STAGE/config.json"; ic_helper "$STAGE" validate-cloud
    ic_fingerprint
  fi
  ic_healthy || ic_fail '容器健康检查尚未通过'
}
update() { exec bash "$SOURCE/install.sh" --role "$ROLE" --host "$HOST" --bind "$BIND"; }
credentials() {
  ic_private_file "$CONF/credentials/initial-credentials.txt"
  echo '仅在可信的本机终端查看：'
  cat "$CONF/credentials/initial-credentials.txt"
}
reset_password() {
  lock; stage; ic_helper "$STAGE" init-local
  ic_admin_begin reset-password
  install -m 600 -o 10001 -g 10001 "$STAGE/panel-auth.json" "$CONF/runtime/panel-auth.json"
  if ! ic_compose restart || ! ic_wait; then
    ic_fail '更换密码失败，将恢复旧密码'
  fi
  install -m 600 "$STAGE/panel-auth.json" "$CONF/credentials/panel-auth.json"
  install -m 600 "$STAGE/initial-credentials.txt" "$CONF/credentials/initial-credentials.txt"
  audit password-reset; ic_admin_finish; credentials
}
recovery() {
  local operation=$1 path='' confirmation=''
  if [[ $operation != backup ]]; then
    ask '加密恢复包绝对路径：' path
    if [[ $operation == restore-backup ]]; then
      echo '仅恢复同一机器、同一角色、同一程序版本；短暂停服，保留当前身份与撤销状态。'
      echo '程序源码、病毒库与其他网站数据不在此恢复包范围内。'
      ask '确认请输入 SAME-HOST-RESTORE：' confirmation
      [[ $confirmation == SAME-HOST-RESTORE ]] || ic_fail '恢复取消'
    fi
  fi
  exec bash "$SOURCE/scripts/independent-backup.sh" "$ROLE" "$operation" "$path" "$confirmation"
}
rules_action() {
  local operation=$1 input=''
  lock
  if [[ $operation == rules-sync && $ROLE == cloud ]]; then
    ask '独立发布环境签名的规则包绝对路径：' input
    python3 "$SOURCE/scripts/rules-client.py" cloud import "$input"
  else
    [[ $operation != rules-sync ]] || operation=update
    [[ $operation != rules-status ]] || operation=status
    python3 "$SOURCE/scripts/rules-client.py" "$ROLE" "$operation"
  fi
}
release_stage() {
  ic_check_dir "$DATA"
  RELEASE_STAGE=$(mktemp -d "$DATA/.release.XXXXXXXX")
  chmod 700 "$RELEASE_STAGE"
}
release_cache() {
  docker run --rm --network none --user 0:10001 --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 32 --memory 384m \
    --mount "type=bind,source=$DATA/releases,target=/store" \
    --mount "type=bind,source=$RELEASE_STAGE,target=/input,readonly" "$IMAGE" node scripts/release-cache.js "$1"
}
release_action() {
  local operation=$1 input='' result='' run_name='' version=''
  lock; release_stage
  if [[ $ROLE == cloud ]]; then
    [[ $operation != release-update ]] || ic_fail '玄武程序自身更新请选择签名安全更新'
    if [[ $operation == release-import ]]; then
      ask '六个正式签名附件所在的绝对目录：' input
      [[ $input == /* ]] || ic_fail '请输入绝对目录'
      python3 "$SOURCE/scripts/release-snapshot.py" "$input" "$RELEASE_STAGE"
      release_cache import
      audit release-import
    else release_cache status; fi
  else
    [[ $operation == release-update ]] || ic_fail '本地程序从玄武更新请选择 release-update'
    [[ -d $CONF/runtime/cloud ]] || ic_fail '请先加密配对玄武'
    version=$(jq -er .version "$BASE/install.json")
    result=$(docker run --rm --network bridge --user 0:0 --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 32 --memory 384m \
      --mount "type=bind,source=$CONF/runtime/cloud,target=/identity,readonly" \
      --mount "type=bind,source=$RELEASE_STAGE,target=/output" "$IMAGE" node scripts/release-pull.js "$version")
    run_name=$(printf '%s' "$result" | jq -er 'select(.state == "verified") | .run_name')
    [[ $run_name =~ ^APPGOG-Cloud-Security-Center-[0-9]+\.[0-9]+\.[0-9]+\.run$ ]] || ic_fail '验证结果无效'
    audit release-pull-verified
    # The installer takes this same lock and performs the existing transaction.
    flock -u 9; exec 9>&-; MANAGEMENT_LOCKED=false
    bash "$RELEASE_STAGE/$run_name" --role local --host "$HOST" --bind "$BIND"
  fi
}
virus_database_action() {
  lock
  local input='' result=''
  if [[ $ROLE == cloud ]]; then
    [[ $1 != virus-db-update ]] || ic_fail '玄武导入签名库；铁幕负责下载启用'
    if [[ $1 == virus-db-import ]]; then
      ask '独立发布环境签名的五个病毒库附件所在绝对目录：' input
      [[ $input == /* ]] || ic_fail '请输入绝对目录'
      if ! command -v sigtool >/dev/null; then
        if command -v apt-get >/dev/null; then apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y clamav;
        elif command -v dnf >/dev/null; then dnf install -y clamav;
        else ic_fail '系统软件源暂不支持提供官方验证器 sigtool'; fi
      fi
      python3 "$SOURCE/scripts/virus-db-cache.py" import "$input" "$DATA/virus-db"
      audit virus-db-import
    else python3 "$SOURCE/scripts/virus-db-cache.py" status "$DATA/virus-db"; fi
    return
  fi
  [[ $1 == virus-db-update ]] || ic_fail '铁幕从玄武更新请选择 virus-db-update'
  [[ -d $CONF/runtime/cloud ]] || ic_fail '请先加密配对玄武'
  command -v sigtool >/dev/null && command -v clamscan >/dev/null || ic_fail '请先安装本地病毒引擎'
  [[ -d /var/lib/ironcurtain-antivirus/database && -f /etc/systemd/system/ironcurtain-antivirus-update.timer ]] || ic_fail '请先安装本地官方病毒库'
  exec 8>/run/lock/ironcurtain-antivirus.lock
  flock -n 8 || ic_fail '病毒引擎安装或更新正在运行'
  release_stage
  docker run --rm --network bridge --user 0:0 --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 32 --memory 192m \
    --mount "type=bind,source=$CONF/runtime/cloud,target=/identity,readonly" \
    --mount "type=bind,source=$RELEASE_STAGE,target=/output" "$IMAGE" node scripts/virus-db-pull.js
  if systemctl is-active --quiet ironcurtain-antivirus-update.timer; then AV_TIMER_RESTORE=true; fi
  systemctl stop ironcurtain-antivirus-update.timer ironcurtain-antivirus-update.service
  if result=$(python3 "$SOURCE/scripts/virus-db-activate.py" "$RELEASE_STAGE"); then
    systemctl disable ironcurtain-antivirus-update.timer
    audit virus-db-activated
    printf '%s\n' "$result"
    echo '玄武签名病毒库已启用；以后使用菜单 29 更新。官方直连计时器已停用，避免两种更新源同时写库。'
  else
    # EXIT cleanup resumes the official updater only when no cloud commit exists.
    ic_fail '启用未完成；交换前保留原库，交换后保留已验证的新库与恢复日志。请检查记录后重试菜单 29'
  fi
}
domain_status() {
  curl -q -sS --max-time 8 --unix-socket "/run/ironcurtain-domain-$ROLE/control.sock" http://localhost/domain | jq '{state,domain,requested_domain,reason,certificate,updated_at}'
}
configure_domain() {
  local domain payload response
  IFS= read -r -p '请输入已解析到本服务器的域名（例如 tiemu.example.com）：' domain </dev/tty
  domain=$(printf '%s' "$domain" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  payload=$(jq -nc --arg domain "$domain" '{domain:$domain}')
  response=$(curl -q -f -sS --max-time 8 --unix-socket "/run/ironcurtain-domain-$ROLE/control.sock" -H 'Content-Type: application/json' -d "$payload" http://localhost/domain) || {
    echo '域名设置未受理，请检查域名格式、任务状态及服务日志。' >&2
    return 1
  }
  printf '%s\n' "$response" | jq . || return 1
  printf '%s\n' "$response" | jq -e '.state == "running"' >/dev/null || {
    echo '域名任务未启动，请查看菜单 36 的状态。' >&2
    return 1
  }
  echo '后台正在验证域名并申请证书，原 IP 地址继续可用；选 36 查看实际结果。'
}
dispatch() {
  case "$1" in
    status) status ;; logs) ic_compose logs --tail 100 ;;
    start) lock; [[ $ROLE != local ]] || systemctl start ironcurtain-agent.service ironcurtain-rules-sync.timer ironcurtain-panel-check.timer; ic_compose up -d --wait --wait-timeout 90 ;;
    stop) lock; ic_compose stop; [[ $ROLE != local ]] || systemctl stop ironcurtain-agent.service ironcurtain-rules-sync.timer ironcurtain-panel-check.timer ;;
    restart) lock; [[ $ROLE != local ]] || systemctl restart ironcurtain-agent.service; ic_compose restart; ic_wait ;;
    engine-install|engine-update|engine-status) [[ $ROLE == local ]] || ic_fail '病毒引擎仅用于铁幕'; lock; bash "$SOURCE/scripts/antivirus-engine.sh" "${1#engine-}" ;;
    findings|quarantine-list) response "$([[ $1 == findings ]] && echo findings || echo list)" ;;
    quarantine|restore-file) response "$([[ $1 == quarantine ]] && echo quarantine || echo restore)" ;;
    backup|verify-backup|restore-backup) recovery "$1" ;;
    rules-sync|rules-status) rules_action "$1" ;;
    release-import|release-status|release-update) release_action "$1" ;;
    virus-db-import|virus-db-status|virus-db-update) virus_database_action "$1" ;;
    domain) configure_domain ;; domain-status) domain_status ;;
    update) update ;; doctor) doctor ;; scan) scan ;; profile) profile ;;
    engines) engines ;;
    discover) discover_scope ;; enroll) enroll_scope ;; full-scan) full_scan ;; scan-status) scan_status ;;
    pair) pair ;; cloud-status) cloud_status ;; unpair) unpair ;;
    register) register ;; revoke) revoke ;; nodes) [[ $ROLE == cloud ]] || ic_fail '仅用于玄武'; jq -r '.nodes | keys[]' "$CONF/runtime/config.json" ;;
    reader) reader ;; credentials) credentials ;; reset-password) reset_password ;;
    *) ic_fail '未知菜单动作' ;;
  esac
}
if (($#)); then [[ $# == 1 ]] || ic_fail '此管理接口不接受其他参数'; dispatch "$1"; exit; fi
while true; do
  echo
  status
  echo
  ic_menu_item 1 '查看系统状态'
  ic_menu_item 2 '查看服务日志'
  ic_menu_item 3 '启动服务'
  ic_menu_item 4 '停止服务'
  ic_menu_item 5 '重启服务'
  ic_menu_item 6 '签名安全更新'
  ic_menu_item 7 '环境诊断'
  if [[ $ROLE == local ]]; then
    ic_menu_item 8 '环境与范围核验'
    ic_menu_item 9 '配置保护范围'
    ic_menu_item 10 '导入玄武身份包'
    ic_menu_item 11 '检查加密连接'
    ic_menu_item 12 '解绑玄武'
    ic_menu_item 13 '查看面板凭据'
    ic_menu_item 14 '重置面板密码'
    ic_menu_item 15 '安装病毒引擎'
    ic_menu_item 16 '更新官方病毒库'
    ic_menu_item 17 '病毒引擎状态'
    ic_menu_item 18 '命中文件证据'
    ic_menu_item 19 '隔离命中文件'
    ic_menu_item 20 '隔离记录'
    ic_menu_item 21 '恢复隔离文件'
  else
    ic_menu_item 8 '登记节点与加密导出'
    ic_menu_item 9 '撤销节点'
    ic_menu_item 10 '查看节点'
    ic_menu_item 11 '只读节点接口证书'
    ic_menu_item 13 '查看面板凭据'
    ic_menu_item 14 '重置面板密码'
  fi
  ic_menu_item 22 '创建加密恢复包'
  ic_menu_item 23 '验证恢复包'
  ic_menu_item 24 '同机恢复（保留当前身份）'
  if [[ $ROLE == local ]]; then
    ic_menu_item 25 '从玄武验签更新哈希规则'
    ic_menu_item 26 '本机规则状态'
    ic_menu_item 27 '从玄武验签下载并更新铁幕程序'
    ic_menu_item 29 '从玄武下载并启用签名病毒库'
    ic_menu_item 31 '发现保护对象'
    ic_menu_item 32 '选择对象纳管'
    ic_menu_item 33 '文件深度查杀/继续'
    ic_menu_item 34 '保护覆盖与扫描进度'
  else
    ic_menu_item 25 '导入已签名哈希规则'
    ic_menu_item 26 '云端规则状态'
    ic_menu_item 27 '导入正式签名程序包'
    ic_menu_item 28 '云端程序发布状态'
    ic_menu_item 29 '导入签名官方病毒库'
    ic_menu_item 30 '云端病毒库状态'
  fi
  ic_menu_item 35 '设置域名并自动申请 HTTPS'
  ic_menu_item 36 '查看域名与证书状态'
  if [[ $ROLE == local ]]; then ic_menu_item 37 '四引擎就绪检查'; fi
  ic_menu_item 0 '退出'
  echo
  echo '身份变更、隔离与恢复请核对提示；更新仅接受已验签的正式包。'
  echo
  # Read only the menu number here; business inputs and passwords keep their own rules.
  while true; do
    if ! IFS= read -r -p "$PRODUCT_NAME · 请输入菜单编号（0 退出）：" choice </dev/tty; then
      echo
      exit 0
    fi
    choice=${choice#"${choice%%[![:space:]]*}"}
    choice=${choice%"${choice##*[![:space:]]}"}
    [[ -n $choice ]] || continue
    case "$choice" in
      0) exit 0 ;; 1) action=status ;; 2) action=logs ;; 3) action=start ;; 4) action=stop ;; 5) action=restart ;; 6) action=update ;; 7) action=doctor ;;
      8) [[ $ROLE == local ]] && action=scan || action=register ;;
      9) [[ $ROLE == local ]] && action=profile || action=revoke ;;
      10) [[ $ROLE == local ]] && action=pair || action=nodes ;;
      11) [[ $ROLE == local ]] && action=cloud-status || action=reader ;;
      12) [[ $ROLE == local ]] || { echo '请选择当前角色显示的有效菜单项'; continue; }; action=unpair ;;
      13) action=credentials ;;
      14) action=reset-password ;;
      15) [[ $ROLE == local ]] || { echo '请选择当前角色显示的有效菜单项'; continue; }; action=engine-install ;;
      16) [[ $ROLE == local ]] || { echo '请选择当前角色显示的有效菜单项'; continue; }; action=engine-update ;;
      17) [[ $ROLE == local ]] || { echo '请选择当前角色显示的有效菜单项'; continue; }; action=engine-status ;;
      18) [[ $ROLE == local ]] || { echo '请选择当前角色显示的有效菜单项'; continue; }; action=findings ;;
      19) [[ $ROLE == local ]] || { echo '请选择当前角色显示的有效菜单项'; continue; }; action=quarantine ;;
      20) [[ $ROLE == local ]] || { echo '请选择当前角色显示的有效菜单项'; continue; }; action=quarantine-list ;;
      21) [[ $ROLE == local ]] || { echo '请选择当前角色显示的有效菜单项'; continue; }; action=restore-file ;;
      22) action=backup ;; 23) action=verify-backup ;; 24) action=restore-backup ;;
      25) action=rules-sync ;; 26) action=rules-status ;;
      27) [[ $ROLE == local ]] && action=release-update || action=release-import ;;
      28) [[ $ROLE == cloud ]] || { echo '请选择当前角色显示的有效菜单项'; continue; }; action=release-status ;;
      29) if [[ $ROLE == cloud ]]; then action=virus-db-import; else action=virus-db-update; fi ;;
      30) [[ $ROLE == cloud ]] || { echo '请选择当前角色显示的有效菜单项'; continue; }; action=virus-db-status ;;
      31) [[ $ROLE == local ]] || { echo '请选择当前角色显示的有效菜单项'; continue; }; action=discover ;;
      32) [[ $ROLE == local ]] || { echo '请选择当前角色显示的有效菜单项'; continue; }; action=enroll ;;
      33) [[ $ROLE == local ]] || { echo '请选择当前角色显示的有效菜单项'; continue; }; action=full-scan ;;
      34) [[ $ROLE == local ]] || { echo '请选择当前角色显示的有效菜单项'; continue; }; action=scan-status ;;
      37) [[ $ROLE == local ]] || { echo '请选择当前角色显示的有效菜单项'; continue; }; action=engines ;;
      35) action=domain ;; 36) action=domain-status ;;
      *) echo '请选择有效菜单项'; continue ;;
    esac
    break
  done
  echo
  bash "$SOURCE/scripts/ironcurtain.sh" --role "$ROLE" "$action" || echo '操作未完成；现有状态请运行诊断核对。'
  echo
  # Keep success and failure output visible until the operator acknowledges it.
  if ! IFS= read -r -p '按回车返回管理菜单（Ctrl+C 退出）：' menu_ack </dev/tty; then
    echo
    exit 0
  fi
done
