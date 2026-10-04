#!/usr/bin/env bash
# Root-only recovery for configuration changes. Contains private, plaintext snapshots.
ic_admin_begin() {
  [[ ! -e $BASE/admin-transaction.json && ! -L $BASE/admin-transaction.json ]] || ic_fail '尚有未恢复的管理事务'
  ic_trusted_dir "$BASE/backups"
  IC_ADMIN_TX=$(mktemp -d "$BASE/backups/admin.XXXXXXXX")
  chmod 700 "$IC_ADMIN_TX"
  # Staging and exports are not live configuration and must not become trusted identities on rollback.
  tar --exclude='./.admin.*' --exclude='./exports' -cf "$IC_ADMIN_TX/config.tar" -C "$CONF" .
  chmod 600 "$IC_ADMIN_TX/config.tar"
  ic_private_file "$IC_ADMIN_TX/config.tar"
  docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -qx true && touch "$IC_ADMIN_TX/container-running" || true
  if [[ $ROLE == local ]]; then
    systemctl is-active --quiet ironcurtain-agent.service && touch "$IC_ADMIN_TX/agent-active" || true
  fi
  jq -n --arg role "$ROLE" --arg action "$1" --arg snapshot "$IC_ADMIN_TX" '{schema:1,role:$role,action:$action,snapshot:$snapshot}' > "$BASE/admin-transaction.json.new"
  chmod 600 "$BASE/admin-transaction.json.new"
  mv -f "$BASE/admin-transaction.json.new" "$BASE/admin-transaction.json"
  touch "$IC_ADMIN_TX/mutating"
}
ic_admin_finish() {
  touch "$IC_ADMIN_TX/committed"
  rm -f -- "$BASE/admin-transaction.json" || return 1
  IC_ADMIN_TX=''
}
ic_admin_recover() {
  [[ -e $BASE/admin-transaction.json || -L $BASE/admin-transaction.json ]] || return 0
  ic_private_file "$BASE/admin-transaction.json"
  jq -e --arg role "$ROLE" '.schema == 1 and .role == $role and (.snapshot|type=="string")' "$BASE/admin-transaction.json" >/dev/null || ic_fail '管理事务记录无效'
  local snapshot displaced result=0
  snapshot=$(jq -er '.snapshot' "$BASE/admin-transaction.json") || return 1
  [[ $snapshot == "$BASE/backups/admin."* && $(dirname "$snapshot") == "$BASE/backups" ]] || ic_fail '管理恢复目录越界'
  ic_check_dir "$snapshot"
  [[ -d $snapshot && $(stat -c %a "$snapshot") == 700 ]] || ic_fail '管理恢复目录权限无效'
  if [[ -f $snapshot/committed ]]; then rm -f -- "$BASE/admin-transaction.json" || return 1; return 0; fi
  if [[ -f $snapshot/mutating ]]; then
    [[ -f $snapshot/config.tar && ! -L $snapshot/config.tar ]] || ic_fail '管理恢复快照缺失'
    ic_private_file "$snapshot/config.tar"
    tar -tf "$snapshot/config.tar" >/dev/null || return 1
    ic_check_dir "$CONF"
    echo '发现未完成的管理操作，正在恢复原配置和身份。' >&2
    # Recreate the container: restart alone would keep a bind mount attached to the retired directory inode.
    ic_compose down || return 1
    if [[ $ROLE == local ]]; then systemctl stop ironcurtain-agent.service || return 1; fi
    displaced=$snapshot/failed-config-$(date -u +%s)-$RANDOM
    [[ ! -e $displaced ]] || return 1
    mv -- "$CONF" "$displaced" || return 1
    install -d -m 750 "$CONF" || return 1
    tar -xpf "$snapshot/config.tar" -C "$CONF" || return 1
    # Exported identity packages stay evidence, never live trust. They may belong to an uncommitted registration.
    if [[ -d $displaced/exports && ! -L $displaced/exports ]]; then
      mv -- "$displaced/exports" "$CONF/exports" || return 1
    fi
    if [[ $ROLE == local && -f $snapshot/agent-active ]]; then
      systemctl start ironcurtain-agent.service || result=1
      ic_agent_wait || result=1
    fi
    if [[ -f $snapshot/container-running ]]; then
      ic_compose up -d || result=1
      ic_wait || result=1
      if [[ $ROLE == local && -f $snapshot/agent-active ]]; then ic_scan_wait || result=1; fi
    fi
    (( result == 0 )) || { echo '旧配置恢复未通过健康检查，恢复记录保留。' >&2; return 1; }
  fi
  rm -f -- "$BASE/admin-transaction.json" || return 1
  IC_ADMIN_TX=''
  echo '原配置和身份已恢复。失败状态留存在 root 私有目录。' >&2
}
