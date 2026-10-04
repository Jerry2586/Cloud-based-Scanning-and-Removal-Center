#!/usr/bin/env bash
# Root-only local management; the browser and cloud cannot call this interface.
set -euo pipefail
umask 077
ROLE=''
if [[ ${1:-} == --role ]]; then ROLE=${2:?}; shift 2; fi
case "${ROLE:-$(basename "$0")}" in local|ironcurtain) ROLE=local ;; cloud|xuanwu) ROLE=cloud ;; *) echo '角色无效' >&2; exit 1 ;; esac
SOURCE=/opt/ironcurtain/$ROLE/current
source "$SOURCE/scripts/lib/independent.sh"
source "$SOURCE/scripts/lib/management-transaction.sh"
[[ $EUID == 0 ]] || ic_fail '请用 sudo 运行管理菜单'
ic_role "$ROLE"
ic_load
[[ ! -e $BASE/transaction.json ]] || ic_fail '存在未完成的安装事务，请先重复运行安装命令恢复'
STAGE='' IC_ADMIN_TX='' MANAGEMENT_LOCKED=false
cleanup() {
  local result=$?
  trap - EXIT INT TERM
  if $MANAGEMENT_LOCKED && [[ -e $BASE/admin-transaction.json || -L $BASE/admin-transaction.json ]]; then
    ic_admin_recover || { echo '管理操作恢复尚未完成，请重复运行菜单继续恢复。' >&2; result=1; }
  fi
  if [[ -n $STAGE && -e $STAGE ]]; then
    [[ $STAGE == "$CONF/.admin."* && $(dirname "$STAGE") == "$CONF" ]] || exit 1
    ic_check_dir "$STAGE"
    rm -rf -- "$STAGE"
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
stage() { ic_check_dir "$CONF"; STAGE=$(mktemp -d "$CONF/.admin.XXXXXXXX"); chmod 700 "$STAGE"; }
lock() {
  exec 9>"/run/lock/ironcurtain-$ROLE.lock"
  flock -n 9 || ic_fail '安装或管理操作正在运行'
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
  echo "$([[ $ROLE == local ]] && echo 铁幕安全 || echo 玄武引擎) · $(jq -r .version "$BASE/install.json")"
  echo "独立面板：https://$HOST:$PORT"
  if ic_healthy; then echo '容器：健康'; else echo '容器：未通过健康检查'; fi
  if [[ $ROLE == local ]]; then
    echo "扫描代理：$(systemctl is-active ironcurtain-agent.service || true)"
    echo "规则同步：$(systemctl is-active ironcurtain-rules-sync.timer || true)（配对后每 15 分钟）"
    python3 "$SOURCE/src/host/antivirus.py"
    [[ ! -d $CONF/runtime/cloud ]] || echo '云端：已配置身份，实时握手请选择连接检查'
    [[ -d $CONF/runtime/cloud ]] || echo '云端：未配对'
  else jq -r '"登记节点："+(.nodes|keys|join(", "))' "$CONF/runtime/config.json"; fi
}
scan() {
  [[ $ROLE == local ]] || ic_fail '此操作仅用于铁幕本地节点'
  curl --max-time 10 -fsS --unix-socket /run/ironcurtain/scan.sock -X POST -H 'Content-Length: 0' http://localhost/scan | jq .
  echo '扫描任务已提交；在独立网页查看实际进度和逐项结果。'
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
  password
  install -m 600 "$CONF/ca.crt" "$STAGE/ca.crt"
  ic_certificate "$STAGE" client "$node" clientAuth
  openssl rand -hex 32 > "$STAGE/token"
  jq -n --arg node "$node" --arg endpoint "https://$HOST:$PORT/" '{schema:"ironcurtain-cloud/v1",node_id:$node,endpoint:$endpoint}' > "$STAGE/cloud.json"
  cp "$CONF/runtime/config.json" "$STAGE/config.json"
  ic_helper "$STAGE" register-node
  printf '%s' "$PAIR_PASSWORD" | ic_helper "$STAGE" seal
  unset PAIR_PASSWORD
  mv "$STAGE/config.next.json" "$STAGE/config.json"
  ic_admin_begin register
  ic_trusted_dir "$CONF/exports"; chmod 700 "$CONF/exports"
  export_path=$CONF/exports/$node-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM.icpair
  install -m 600 "$STAGE/pairing.icpair" "$export_path.pending"
  commit_cloud
  audit node-registered "$node"
  ic_admin_finish
  mv -- "$export_path.pending" "$export_path"
  echo "节点已登记。将加密包传到本地节点：$export_path"
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
  [[ $ROLE == local ]] || ic_fail '此操作只显示本地面板凭据'
  ic_private_file "$CONF/credentials/initial-credentials.txt"
  echo '仅在可信的本机终端查看：'
  cat "$CONF/credentials/initial-credentials.txt"
}
reset_password() {
  [[ $ROLE == local ]] || ic_fail '此操作仅用于本地面板'
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
dispatch() {
  case "$1" in
    status) status ;; logs) ic_compose logs --tail 100 ;;
    start) lock; [[ $ROLE != local ]] || systemctl start ironcurtain-agent.service ironcurtain-rules-sync.timer; ic_compose up -d --wait --wait-timeout 90 ;;
    stop) lock; ic_compose stop; [[ $ROLE != local ]] || systemctl stop ironcurtain-agent.service ironcurtain-rules-sync.timer ;;
    restart) lock; [[ $ROLE != local ]] || systemctl restart ironcurtain-agent.service; ic_compose restart; ic_wait ;;
    engine-install|engine-update|engine-status) [[ $ROLE == local ]] || ic_fail '病毒引擎仅用于铁幕'; lock; bash "$SOURCE/scripts/antivirus-engine.sh" "${1#engine-}" ;;
    findings|quarantine-list) response "$([[ $1 == findings ]] && echo findings || echo list)" ;;
    quarantine|restore-file) response "$([[ $1 == quarantine ]] && echo quarantine || echo restore)" ;;
    backup|verify-backup|restore-backup) recovery "$1" ;;
    rules-sync|rules-status) rules_action "$1" ;;
    update) update ;; doctor) doctor ;; scan) scan ;; profile) profile ;;
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
  echo ' 1. 状态   2. 日志   3. 启动   4. 停止   5. 重启'
  echo ' 6. 签名安全更新   7. 环境诊断'
  if [[ $ROLE == local ]]; then
    echo ' 8. 一键扫描   9. 配置保护范围   10. 导入玄武身份包'
    echo '11. 检查加密连接   12. 解绑玄武   13. 查看面板凭据   14. 重置面板密码'
    echo '15. 安装病毒引擎   16. 更新官方病毒库   17. 病毒引擎状态'
    echo '18. 命中文件证据   19. 隔离命中文件   20. 隔离记录   21. 恢复隔离文件'
  else
    echo ' 8. 登记节点与加密导出   9. 撤销节点   10. 查看节点'
    echo '11. 浏览器面板证书'
  fi
  echo '22. 创建加密恢复包   23. 验证恢复包   24. 同机恢复（保留当前身份）'
  [[ $ROLE == local ]] && echo '25. 从玄武验签更新哈希规则   26. 本机规则状态' || echo '25. 导入已签名哈希规则   26. 云端规则状态'
  echo ' 0. 退出'
  ask '选择：' choice
  case "$choice" in
    0) exit 0 ;; 1) action=status ;; 2) action=logs ;; 3) action=start ;; 4) action=stop ;; 5) action=restart ;; 6) action=update ;; 7) action=doctor ;;
    8) [[ $ROLE == local ]] && action=scan || action=register ;;
    9) [[ $ROLE == local ]] && action=profile || action=revoke ;;
    10) [[ $ROLE == local ]] && action=pair || action=nodes ;;
    11) [[ $ROLE == local ]] && action=cloud-status || action=reader ;;
    12) [[ $ROLE == local ]] || continue; action=unpair ;;
    13) [[ $ROLE == local ]] || continue; action=credentials ;;
    14) [[ $ROLE == local ]] || continue; action=reset-password ;;
    15) [[ $ROLE == local ]] || continue; action=engine-install ;;
    16) [[ $ROLE == local ]] || continue; action=engine-update ;;
    17) [[ $ROLE == local ]] || continue; action=engine-status ;;
    18) [[ $ROLE == local ]] || continue; action=findings ;;
    19) [[ $ROLE == local ]] || continue; action=quarantine ;;
    20) [[ $ROLE == local ]] || continue; action=quarantine-list ;;
    21) [[ $ROLE == local ]] || continue; action=restore-file ;;
    22) action=backup ;; 23) action=verify-backup ;; 24) action=restore-backup ;;
    25) action=rules-sync ;; 26) action=rules-status ;;
    *) echo '请选择有效菜单项'; continue ;;
  esac
  bash "$SOURCE/scripts/ironcurtain.sh" --role "$ROLE" "$action" || echo '操作未完成；现有状态请运行诊断核对。'
done
