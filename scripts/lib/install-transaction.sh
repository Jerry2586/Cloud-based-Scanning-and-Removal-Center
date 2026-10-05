#!/usr/bin/env bash
# Durable root-only installation recovery. Caller supplies fixed role paths.
ic_tx_begin() {
  ic_trusted_dir "$BASE/backups"
  IC_TX=$(mktemp -d "$BASE/backups/install.XXXXXXXX")
  chmod 700 "$IC_TX"
  if [[ -e $BASE/install.json ]]; then ic_private_file "$BASE/install.json"; cp -p "$BASE/install.json" "$IC_TX/install.json"; fi
  if [[ -L $BASE/current ]]; then readlink "$BASE/current" > "$IC_TX/current"; elif [[ -e $BASE/current ]]; then ic_fail 'current 必须为受控版本链接'; fi
  for name in "$MENU"; do
    if [[ -e $name || -L $name ]]; then
      ic_menu_check "$name"
      cp -p "$name" "$IC_TX/menu"
    fi
  done
  if [[ $ROLE == local && -n ${MENU_EXTRA:-} ]]; then
    ic_menu_check "$MENU_EXTRA"
    if [[ -e $MENU_EXTRA ]]; then cp -p "$MENU_EXTRA" "$IC_TX/menu-extra"; fi
    touch "$IC_TX/menu-extra-managed"
  fi
  if [[ $ROLE == local ]]; then
    if [[ -e $AGENT_UNIT || -L $AGENT_UNIT ]]; then
      [[ -f $AGENT_UNIT && ! -L $AGENT_UNIT && $(stat -c %u "$AGENT_UNIT") == 0 ]] || ic_fail '扫描服务定义不受 root 控制'
      cp -p "$AGENT_UNIT" "$IC_TX/agent.service"
    fi
    if [[ -n ${RULES_TIMER:-} ]]; then
      for unit in "$RULES_SERVICE" "$RULES_TIMER"; do
        if [[ -e $unit || -L $unit ]]; then
          [[ -f $unit && ! -L $unit && $(stat -c %u "$unit") == 0 && $(stat -c %h "$unit") == 1 ]] || ic_fail '规则同步服务定义不受 root 控制'
          cp -p "$unit" "$IC_TX/$(basename "$unit")"
        fi
      done
      systemctl is-enabled --quiet ironcurtain-rules-sync.timer && touch "$IC_TX/rules-timer-enabled" || true
      systemctl is-active --quiet ironcurtain-rules-sync.timer && touch "$IC_TX/rules-timer-active" || true
    fi
    if [[ -n ${PANEL_CHECK:-} ]]; then
      touch "$IC_TX/panel-units-managed"
      for unit in "$PANEL_CHECK" "$PANEL_UPDATE" "$PANEL_TIMER"; do
        if [[ -e $unit || -L $unit ]]; then
          [[ -f $unit && ! -L $unit && $(stat -c %u "$unit") == 0 && $(stat -c %h "$unit") == 1 ]] || ic_fail '版本更新服务定义不受 root 控制'
          cp -p "$unit" "$IC_TX/$(basename "$unit")"
        fi
      done
      systemctl is-enabled --quiet ironcurtain-panel-check.timer && touch "$IC_TX/panel-timer-enabled" || true
      systemctl is-active --quiet ironcurtain-panel-check.timer && touch "$IC_TX/panel-timer-active" || true
    fi
    systemctl is-enabled --quiet ironcurtain-agent.service && touch "$IC_TX/agent-enabled" || true
    systemctl is-active --quiet ironcurtain-agent.service && touch "$IC_TX/agent-active" || true
  fi
  docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -qx true && touch "$IC_TX/container-running" || true
  jq -n --arg role "$ROLE" --arg snapshot "$IC_TX" '{schema:1,role:$role,snapshot:$snapshot}' > "$BASE/transaction.json.new"
  chmod 600 "$BASE/transaction.json.new"; mv -f "$BASE/transaction.json.new" "$BASE/transaction.json"
  if [[ $ROLE == local && -n ${PANEL_TIMER:-} && -f $PANEL_TIMER ]]; then systemctl stop ironcurtain-panel-check.timer; fi
  if [[ -s $IC_TX/install.json ]]; then ic_compose stop; fi
  [[ $ROLE != local || ! -f $IC_TX/agent.service ]] || systemctl stop ironcurtain-agent.service
  if [[ $ROLE == local && -n ${RULES_TIMER:-} && -f $RULES_TIMER ]]; then systemctl stop ironcurtain-rules-sync.timer; fi
  tar -cf "$IC_TX/config.tar" -C "$CONF" .
  tar -cf "$IC_TX/data.tar" -C "$DATA" .
  chmod 600 "$IC_TX/config.tar" "$IC_TX/data.tar"
  ic_private_file "$IC_TX/config.tar"; ic_private_file "$IC_TX/data.tar"
  touch "$IC_TX/snapshot-ready"
}
ic_tx_mutating() { touch "$IC_TX/mutating"; }
ic_tx_finish() {
  # If interrupted after this marker, recovery retains the healthy new installation.
  if [[ $ROLE == local && -n ${RULES_TIMER:-} && -f $IC_TX/rules-timer-active ]]; then systemctl start ironcurtain-rules-sync.timer || return 1; fi
  if [[ $ROLE == local && -n ${PANEL_TIMER:-} && -f $IC_TX/panel-timer-active ]]; then systemctl start ironcurtain-panel-check.timer || return 1; fi
  touch "$IC_TX/committed"
  rm -f -- "$BASE/transaction.json" || return 1
}
ic_tx_recover() {
  [[ -e $BASE/transaction.json || -L $BASE/transaction.json ]] || return 0
  ic_private_file "$BASE/transaction.json"
  jq -e --arg role "$ROLE" '.schema == 1 and .role == $role and (.snapshot|type=="string")' "$BASE/transaction.json" >/dev/null || ic_fail '安装事务记录无效'
  local snapshot saved_current result=0
  snapshot=$(jq -er '.snapshot' "$BASE/transaction.json") || return 1
  [[ $snapshot == "$BASE/backups/install."* && $(dirname "$snapshot") == "$BASE/backups" ]] || ic_fail '恢复目录越界'
  ic_check_dir "$snapshot"
  [[ -d $snapshot && $(stat -c %a "$snapshot") == 700 ]] || ic_fail '恢复目录权限无效'
  if [[ -f $snapshot/committed ]]; then rm -f -- "$BASE/transaction.json" || return 1; return 0; fi
  echo '发现未完成的安装事务，正在恢复安装前状态。' >&2
  if [[ -f $snapshot/mutating ]]; then
    [[ -f $snapshot/snapshot-ready ]] || ic_fail '恢复快照不完整，停止自动恢复'
    for item in config data; do
      [[ -f $snapshot/$item.tar && ! -L $snapshot/$item.tar ]] || ic_fail '恢复文件缺失'
      ic_private_file "$snapshot/$item.tar"
      tar -tf "$snapshot/$item.tar" >/dev/null || return 1
    done
    if [[ -L $BASE/current ]]; then ic_compose down || return 1; fi
    if [[ $ROLE == local && -f $AGENT_UNIT ]]; then
      systemctl stop ironcurtain-agent.service || return 1
      # Disable the candidate while its unit still exists; removing it first leaves enable symlinks.
      if [[ ! -f $snapshot/agent-enabled ]]; then systemctl disable ironcurtain-agent.service >/dev/null 2>&1 || return 1; fi
    fi
    if [[ $ROLE == local && -n ${RULES_TIMER:-} && -f $RULES_TIMER ]]; then
      systemctl stop ironcurtain-rules-sync.timer || return 1
      if [[ ! -f $snapshot/rules-timer-enabled ]]; then systemctl disable ironcurtain-rules-sync.timer >/dev/null 2>&1 || return 1; fi
    fi
    # Copy original archives back without moving the archives: retry remains idempotent.
    for item in config data; do
      local target=$CONF
      [[ $item != data ]] || target=$DATA
      ic_check_dir "$target"
      [[ -f $snapshot/$item.tar && ! -L $snapshot/$item.tar ]] || ic_fail '恢复文件缺失'
      if [[ -e $target ]]; then mv -- "$target" "$snapshot/failed-$item-$(date -u +%s)-$RANDOM" || return 1; fi
      install -d -m 750 "$target" || return 1
      tar -xpf "$snapshot/$item.tar" -C "$target" || return 1
    done
    if [[ -s $snapshot/install.json ]]; then cp -p "$snapshot/install.json" "$BASE/install.json" || return 1; else rm -f -- "$BASE/install.json" || return 1; fi
    if [[ -s $snapshot/current ]]; then
      saved_current=$(cat "$snapshot/current")
      [[ $saved_current == "$BASE/releases/"* && $(dirname "$saved_current") == "$BASE/releases" ]] || ic_fail '旧版本链接越界'
      ic_check_dir "$saved_current"
      ln -sfn "$saved_current" "$BASE/current.next" || return 1; mv -Tf "$BASE/current.next" "$BASE/current" || return 1
    else
      [[ ! -e $BASE/current || -L $BASE/current ]] || ic_fail 'current 被替换，停止清理'
      rm -f -- "$BASE/current" || return 1
    fi
    ic_menu_check "$MENU"
    if [[ -s $snapshot/menu ]]; then cp -p "$snapshot/menu" "$MENU" || return 1; else rm -f -- "$MENU" || return 1; fi
    # Old snapshots only know MENU=ironcurtain; never reinterpret or touch the new entry.
    if [[ $ROLE == local && -f $snapshot/menu-extra-managed ]]; then
      [[ -n ${MENU_EXTRA:-} ]] || ic_fail '新菜单恢复路径缺失'
      ic_menu_check "$MENU_EXTRA"
      if [[ -s $snapshot/menu-extra ]]; then cp -p "$snapshot/menu-extra" "$MENU_EXTRA" || return 1; else rm -f -- "$MENU_EXTRA" || return 1; fi
    fi
    if [[ $ROLE == local ]]; then
      if [[ -f $snapshot/panel-units-managed ]]; then
        if [[ -f $PANEL_TIMER ]]; then systemctl stop ironcurtain-panel-check.timer || return 1; systemctl disable ironcurtain-panel-check.timer >/dev/null 2>&1 || return 1; fi
        for unit in "$PANEL_CHECK" "$PANEL_UPDATE" "$PANEL_TIMER"; do
          if [[ -s $snapshot/$(basename "$unit") ]]; then cp -p "$snapshot/$(basename "$unit")" "$unit" || return 1; else rm -f -- "$unit" || return 1; fi
        done
      fi
      if [[ -s $snapshot/agent.service ]]; then cp -p "$snapshot/agent.service" "$AGENT_UNIT" || return 1; else rm -f -- "$AGENT_UNIT" || return 1; fi
      if [[ -n ${RULES_TIMER:-} ]]; then
        for unit in "$RULES_SERVICE" "$RULES_TIMER"; do
          if [[ -s $snapshot/$(basename "$unit") ]]; then cp -p "$snapshot/$(basename "$unit")" "$unit" || return 1; else rm -f -- "$unit" || return 1; fi
        done
      fi
    fi
  fi
  if [[ $ROLE == local ]]; then
    systemctl daemon-reload || result=1
    if [[ -f $snapshot/panel-timer-enabled ]]; then systemctl enable ironcurtain-panel-check.timer || result=1; fi
    if [[ -f $snapshot/panel-timer-active ]]; then systemctl start ironcurtain-panel-check.timer || result=1; fi
    if [[ -f $snapshot/agent-enabled ]]; then systemctl enable ironcurtain-agent.service || result=1;
    elif [[ -f $AGENT_UNIT ]]; then systemctl disable ironcurtain-agent.service >/dev/null 2>&1 || result=1; fi
    if [[ -f $snapshot/agent-active ]]; then systemctl start ironcurtain-agent.service || result=1; ic_agent_wait || result=1; fi
    if [[ -n ${RULES_TIMER:-} ]]; then
      if [[ -f $snapshot/rules-timer-enabled ]]; then systemctl enable ironcurtain-rules-sync.timer || result=1;
      elif [[ -f $RULES_TIMER ]]; then systemctl disable ironcurtain-rules-sync.timer >/dev/null 2>&1 || result=1; fi
      if [[ -f $snapshot/rules-timer-active ]]; then systemctl start ironcurtain-rules-sync.timer || result=1; fi
    fi
  fi
  if [[ -s $snapshot/install.json ]]; then
    ic_load || return 1
    if [[ -f $snapshot/container-running ]]; then ic_compose up -d || result=1; ic_wait || result=1; [[ $ROLE != local ]] || ic_scan_wait || result=1; fi
  fi
  if ((result)); then echo '恢复尚未通过健康检查，事务记录保留，下一次运行将继续恢复。' >&2; return 1; fi
  rm -f -- "$BASE/transaction.json" || return 1
  echo '安装前配置、身份和服务状态已恢复；失败文件保留在 root 私有恢复目录。' >&2
}
