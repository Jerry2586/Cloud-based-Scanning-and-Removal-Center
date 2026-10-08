#!/usr/bin/env bash
# Fixed cloud-only program update jobs, covered by the shared host-unit snapshot.
ic_cloud_update_install() {
  [[ $ROLE == cloud ]] || return 0
  install -d -m 700 "$DATA/panel-update"
  install -d -m 750 -o root -g 10001 /run/ironcurtain-update-cloud
  local action
  for action in check update; do
    cat > "/etc/systemd/system/ironcurtain-panel-cloud-$action.service" <<EOF
[Unit]
Description=Xuanwu fixed signed release $action
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 -B $BASE/current/src/host/updates.py $action --role cloud
TimeoutStartSec=32min
KillMode=control-group
UMask=0077
PrivateTmp=true
Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin
EOF
    chmod 644 "/etc/systemd/system/ironcurtain-panel-cloud-$action.service"
  done
  cat > /etc/systemd/system/ironcurtain-panel-cloud-check.timer <<EOF
[Unit]
Description=Xuanwu periodic Git and signed release calibration
[Timer]
OnBootSec=5min
OnUnitInactiveSec=6h
RandomizedDelaySec=5min
Unit=ironcurtain-panel-cloud-check.service
[Install]
WantedBy=timers.target
EOF
  cat > /etc/systemd/system/ironcurtain-update-cloud-control.service <<EOF
[Unit]
Description=Xuanwu fixed signed update control
After=network-online.target docker.service
[Service]
Type=simple
User=root
Group=10001
ExecStart=/usr/bin/python3 -B $BASE/current/src/host/update_control.py
Restart=on-failure
RestartSec=5
RuntimeDirectory=ironcurtain-update-cloud
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
ReadWritePaths=/run/ironcurtain-update-cloud
[Install]
WantedBy=multi-user.target
EOF
  chmod 644 /etc/systemd/system/ironcurtain-panel-cloud-check.timer /etc/systemd/system/ironcurtain-update-cloud-control.service
  systemctl daemon-reload
  systemctl enable ironcurtain-update-cloud-control.service
  systemctl restart ironcurtain-update-cloud-control.service
  local timer=ironcurtain-panel-cloud-check.timer
  if [[ ! -f $IC_TX/$timer ]]; then
    systemctl enable --now "$timer"
  else
    if [[ -f $IC_TX/$timer.enabled ]]; then systemctl enable "$timer"; else systemctl disable "$timer"; fi
    [[ ! -f $IC_TX/$timer.active ]] || systemctl start "$timer"
  fi
}
