#!/usr/bin/env bash
# Fixed role HTTPS services, shared by install and durable recovery.
ic_domain_units() {
  # Account units share the installer lifecycle snapshot; their Unix service stays independent.
  printf "%s\n" "ironcurtain-account-$ROLE-control.service"
  if [[ $ROLE == cloud ]]; then
    printf "%s\n" ironcurtain-update-cloud-control.service ironcurtain-panel-cloud-check.service ironcurtain-panel-cloud-update.service ironcurtain-panel-cloud-check.timer
  fi
  local suffix
  for suffix in control.service apply.service renew.service renew.timer gateway.socket gateway.service; do
    printf "%s\n" "ironcurtain-domain-$ROLE-$suffix"
  done
}
ic_domain_snapshot() {
  local unit snapshot=${1:-$IC_TX}
  touch "$snapshot/domain-units-managed"
  for unit in $(ic_domain_units); do
    local file=/etc/systemd/system/$unit
    if [[ -e $file || -L $file ]]; then
      [[ -f $file && ! -L $file && $(stat -c %u "$file") == 0 && $(stat -c %h "$file") == 1 ]] || ic_fail "域名服务定义不受 root 控制"
      cp -p "$file" "$snapshot/$unit"
    fi
    systemctl is-active --quiet "$unit" && touch "$snapshot/$unit.active" || true
    systemctl is-enabled --quiet "$unit" && touch "$snapshot/$unit.enabled" || true
  done
}
ic_domain_quiesce() {
  local unit
  if [[ $ROLE == cloud ]]; then
    for unit in ironcurtain-update-cloud-control.service ironcurtain-panel-cloud-check.timer; do
      [[ ! -f /etc/systemd/system/$unit ]] || systemctl stop "$unit" || return 1
    done
  fi
  [[ ! -f /etc/systemd/system/ironcurtain-account-$ROLE-control.service ]] || systemctl stop "ironcurtain-account-$ROLE-control.service" || return 1
  for unit in gateway.socket gateway.service control.service renew.timer; do
    [[ ! -f /etc/systemd/system/ironcurtain-domain-$ROLE-$unit ]] || systemctl stop "ironcurtain-domain-$ROLE-$unit" || return 1
  done
}
ic_domain_restore() {
  local snapshot=$1 unit file
  [[ -f $snapshot/domain-units-managed ]] || return 0
  ic_domain_quiesce || return 1
  for unit in $(ic_domain_units); do
    file=/etc/systemd/system/$unit
    if [[ -f $file ]]; then
      # A signed update may be installing itself; keep the executing worker alive.
      if [[ $unit != ironcurtain-panel-cloud-check.service && $unit != ironcurtain-panel-cloud-update.service ]]; then systemctl stop "$unit" || return 1; fi
      systemctl disable "$unit" >/dev/null 2>&1 || true
    fi
    if [[ -f $snapshot/$unit ]]; then cp -p "$snapshot/$unit" "$file" || return 1; else rm -f -- "$file" || return 1; fi
  done
  systemctl daemon-reload || return 1
  for unit in $(ic_domain_units); do
    [[ ! -f $snapshot/$unit.enabled ]] || systemctl enable "$unit" || return 1
  done
}
ic_domain_resume() {
  local snapshot=$1 unit
  [[ -f $snapshot/domain-units-managed ]] || return 0
  for unit in $(ic_domain_units); do
    [[ $unit != ironcurtain-panel-cloud-check.service && $unit != ironcurtain-panel-cloud-update.service ]] || continue
    [[ ! -f $snapshot/$unit.active ]] || systemctl start "$unit" || return 1
  done
}
ic_domain_install() {
  local prefix=ironcurtain-domain-$ROLE proxy port=8790 action upstream=${BIND:-0.0.0.0}
  [[ $ROLE != cloud ]] || port=8791
  [[ $upstream != 0.0.0.0 ]] || upstream=127.0.0.1
  python3 -c 'import ipaddress,sys;ipaddress.IPv4Address(sys.argv[1])' "$upstream" || ic_fail "HTTPS 上游监听地址无效"
  install -d -m 700 "$CONF/domain-control"
  install -d -m 750 -o root -g 10001 "/run/ironcurtain-domain-$ROLE"
  proxy=
  for candidate in /usr/lib/systemd/systemd-socket-proxyd /lib/systemd/systemd-socket-proxyd; do
    [[ ! -x $candidate ]] || { proxy=$candidate; break; }
  done
  [[ -n $proxy ]] || ic_fail "系统缺少 systemd-socket-proxyd"
  cat > "/etc/systemd/system/$prefix-control.service" <<EOF
[Unit]
Description=IronCurtain $ROLE fixed domain control
After=network-online.target docker.service
[Service]
Type=simple
User=root
Group=10001
ExecStart=/usr/bin/python3 $BASE/current/scripts/domain_control.py --role $ROLE --action serve
Restart=on-failure
RestartSec=5
RuntimeDirectory=$prefix
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=CAP_CHOWN
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=$CONF/domain-control /run/$prefix
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
MemoryMax=128M
TasksMax=16
[Install]
WantedBy=multi-user.target
EOF
  for action in apply renew; do
    cat > "/etc/systemd/system/$prefix-$action.service" <<EOF
[Unit]
Description=IronCurtain $ROLE domain $action
After=network-online.target docker.service
Wants=network-online.target
[Service]
Type=oneshot
User=root
ExecStart=/bin/bash $BASE/current/scripts/domain-apply.sh $ROLE $action
TimeoutStartSec=8min
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=$CONF /run/lock
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
MemoryMax=256M
TasksMax=32
Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin
EOF
  done
  cat > "/etc/systemd/system/$prefix-renew.timer" <<EOF
[Unit]
Description=IronCurtain $ROLE automatic HTTPS renewal
[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=1h
Unit=$prefix-renew.service
[Install]
WantedBy=timers.target
EOF
  cat > "/etc/systemd/system/$prefix-gateway.socket" <<EOF
[Unit]
Description=IronCurtain $ROLE owned HTTPS entry
[Socket]
ListenStream=0.0.0.0:443
NoDelay=true
[Install]
WantedBy=sockets.target
EOF
  cat > "/etc/systemd/system/$prefix-gateway.service" <<EOF
[Unit]
Description=IronCurtain $ROLE TLS passthrough
Requires=$prefix-gateway.socket
After=docker.service
[Service]
ExecStart=$proxy $upstream:$port
DynamicUser=true
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
MemoryMax=32M
TasksMax=4
EOF
  install -d -m 700 "$CONF/account-control"
  install -d -m 750 -o root -g 10001 "/run/ironcurtain-account-$ROLE"
  cat > "/etc/systemd/system/ironcurtain-account-$ROLE-control.service" <<EOF
[Unit]
Description=IronCurtain $ROLE fixed panel account control
After=docker.service
[Service]
Type=simple
User=root
Group=10001
ExecStart=/usr/bin/python3 $BASE/current/scripts/account_control.py --role $ROLE --action serve
Restart=on-failure
RestartSec=5
RuntimeDirectory=ironcurtain-account-$ROLE
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=$CONF/account-control $CONF/runtime $CONF/credentials /run/ironcurtain-account-$ROLE /run/lock
RestrictAddressFamilies=AF_UNIX
MemoryMax=128M
TasksMax=8
[Install]
WantedBy=multi-user.target
EOF
  for unit in $(ic_domain_units); do chmod 644 "/etc/systemd/system/$unit"; done
  if ! command -v certbot >/dev/null; then
    if command -v apt-get >/dev/null; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-remove certbot || ic_fail "自动证书组件安装失败：请检查系统软件源和 certbot 包"
    elif command -v dnf >/dev/null; then
      dnf install -y certbot || ic_fail "自动证书组件安装失败：请检查系统软件源和 certbot 包"
    else
      yum install -y certbot || ic_fail "自动证书组件安装失败：请检查系统软件源和 certbot 包"
    fi
  fi
  command -v certbot >/dev/null || ic_fail "系统缺少自动证书组件 certbot"
  systemctl daemon-reload
  for unit in "$prefix-control.service" "$prefix-renew.timer" "ironcurtain-account-$ROLE-control.service"; do
    if [[ -n ${IC_TX:-} && -f $IC_TX/$unit ]]; then
      [[ ! -f $IC_TX/$unit.enabled ]] || systemctl enable "$unit"
      if [[ $unit == *-control.service || -f $IC_TX/$unit.active ]]; then systemctl restart "$unit"; fi
    else
      systemctl enable --now "$unit"
    fi
  done
}

# A fresh IP installation deliberately leaves 443 free. Restore a previously
# activated gateway only after the role container has passed its health check.
ic_domain_gateway_resume() {
  local prefix=ironcurtain-domain-$ROLE unit
  [[ -n ${IC_TX:-} ]] || return 0
  for unit in "$prefix-gateway.socket" "$prefix-gateway.service"; do
    [[ ! -f $IC_TX/$unit.enabled ]] || systemctl enable "$unit"
    [[ ! -f $IC_TX/$unit.active ]] || systemctl start "$unit"
  done
}

ic_cloud_update_wait() {
  local attempt
  for attempt in {1..20}; do
    if systemctl is-active --quiet ironcurtain-update-cloud-control.service &&
       curl -q --noproxy '*' --max-time 2 --silent --fail --unix-socket /run/ironcurtain-update-cloud/control.sock http://localhost/update-status |
         jq -e '.schema == "ironcurtain-update-status/v1" and (.installed_version | type == "string")' >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  return 1
}

# Container health alone cannot prove that the required host controller runs.
# Authenticate the real Unix endpoint before committing an installation.
ic_domain_wait() {
  local prefix=ironcurtain-domain-$ROLE attempt
  if [[ $ROLE == cloud && -f $BASE/current/src/host/update_control.py ]]; then
    ic_cloud_update_wait || return 1
  fi
  for attempt in {1..20}; do
    if systemctl is-active --quiet "ironcurtain-account-$ROLE-control.service" &&
       curl -q --noproxy '*' --max-time 2 --silent --fail --unix-socket "/run/ironcurtain-account-$ROLE/control.sock" http://localhost/account | jq -e '.ready == true' >/dev/null 2>&1 &&
       systemctl is-active --quiet "$prefix-control.service" &&
       curl -q --noproxy '*' --max-time 2 --silent --show-error --fail --unix-socket "/run/$prefix/control.sock" http://localhost/domain 2>/dev/null |
         jq -e 'type == "object" and (.state | IN("idle", "running", "ready", "failed")) and (.domain | type == "string") and (.certificate | IN("not-issued", "public-ca"))' >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}
