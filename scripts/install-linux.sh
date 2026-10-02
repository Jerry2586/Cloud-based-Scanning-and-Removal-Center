#!/usr/bin/env bash
set -euo pipefail
umask 077
# Run from an authenticated checkout of the private cloud-security repository.
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/lib/identity-config.sh
BASE=${SECURITY_INSTALL_DIR:-/opt/appgog-security}
CONF=${SECURITY_CONFIG_DIR:-/etc/appgog-security}
DATA=${SECURITY_DATA_DIR:-/var/lib/appgog-security}
HOST=''
while (($#)); do
  case "$1" in
    --host) HOST=${2:?missing host}; shift 2 ;;
    *) echo "Usage: sudo ./scripts/install-linux.sh --host DNS-name-or-public-IPv4" >&2; exit 2 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
if [[ $HOST =~ ^((0|[1-9][0-9]{0,2})\.){3}(0|[1-9][0-9]{0,2})$ ]]; then
  IFS=. read -r o1 o2 o3 o4 <<< "$HOST"
  for octet in "$o1" "$o2" "$o3" "$o4"; do
    (( 10#$octet <= 255 )) || { echo 'Invalid IPv4 address' >&2; exit 1; }
  done
  SERVER_SAN="IP:$HOST"
elif [[ $HOST =~ ^[0-9.]+$ ]]; then
  echo 'Invalid IPv4 address' >&2; exit 1
elif [[ ${#HOST} -le 253 && $HOST =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]]; then
  SERVER_SAN="DNS:$HOST"
else
  echo 'Valid DNS hostname or IPv4 address required' >&2; exit 1
fi
[[ $(uname -s) == Linux && -d /run/systemd/system ]] || { echo 'Linux with systemd required' >&2; exit 1; }
ARCH=$(uname -m)
case "$ARCH" in x86_64) ARCH=x64 ;; aarch64) ARCH=arm64 ;; *) echo 'Only x86_64 and aarch64 are supported' >&2; exit 1 ;; esac
if command -v apt-get >/dev/null; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl xz-utils tar openssl jq
elif command -v dnf >/dev/null; then
  dnf install -y ca-certificates curl xz tar openssl jq
else
  echo 'Supported package managers: apt and dnf' >&2; exit 1
fi
NODE_VERSION=24.19.0
TARBALL="node-v${NODE_VERSION}-linux-${ARCH}.tar.xz"
mkdir -p "$BASE/runtime" "$BASE/releases" "$CONF/credentials" "$DATA"
chmod 700 "$CONF" "$CONF/credentials"
if [[ ! -x $BASE/runtime/bin/node ]]; then
  TEMP=$(mktemp -d)
  trap 'rm -rf "$TEMP"' EXIT
  curl -fsS --retry 3 "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt" -o "$TEMP/SHASUMS256.txt"
  curl -fsS --retry 3 "https://nodejs.org/dist/v${NODE_VERSION}/${TARBALL}" -o "$TEMP/${TARBALL}"
  (cd "$TEMP"; grep -E "^[a-f0-9]{64}  ${TARBALL}$" SHASUMS256.txt | sha256sum -c -)
  tar -xJf "$TEMP/${TARBALL}" -C "$BASE/runtime" --strip-components=1
fi
"$BASE/runtime/bin/node" -e 'if (+process.versions.node.split(".")[0] !== 24) process.exit(1)'
if ! id appgog-security >/dev/null 2>&1; then useradd --system --home "$DATA" --shell /usr/sbin/nologin appgog-security; fi
chgrp appgog-security "$CONF"
chmod 750 "$CONF"
if [[ ! -f $CONF/ca.key ]]; then
  openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 -subj '/CN=APPGOG Security Private CA' -keyout "$CONF/ca.key" -out "$CONF/ca.crt" >/dev/null 2>&1
  chmod 600 "$CONF/ca.key"
fi
server_cert_valid=false
if [[ -f $CONF/server.key && -f $CONF/server.crt ]] && openssl x509 -in "$CONF/server.crt" -checkend 2592000 -noout >/dev/null 2>&1; then
  if [[ $SERVER_SAN == IP:* ]]; then
    openssl x509 -in "$CONF/server.crt" -checkip "$HOST" -noout >/dev/null 2>&1 && server_cert_valid=true
  else
    openssl x509 -in "$CONF/server.crt" -checkhost "$HOST" -noout >/dev/null 2>&1 && server_cert_valid=true
  fi
fi
if [[ $server_cert_valid != true ]]; then
  if [[ ! -f $CONF/server.key ]]; then
    openssl req -newkey rsa:3072 -nodes -subj "/CN=$HOST" -keyout "$CONF/server.key" -out "$CONF/server.csr" >/dev/null 2>&1
  else
    openssl req -new -key "$CONF/server.key" -subj "/CN=$HOST" -out "$CONF/server.csr" >/dev/null 2>&1
  fi
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$SERVER_SAN" > "$CONF/server.ext"
  openssl x509 -req -in "$CONF/server.csr" -CA "$CONF/ca.crt" -CAkey "$CONF/ca.key" -CAcreateserial -out "$CONF/server.crt" -days 365 -sha256 -extfile "$CONF/server.ext" >/dev/null 2>&1
  chown appgog-security:appgog-security "$CONF/server.key"
  chmod 600 "$CONF/server.key"
fi
if [[ ! -f $CONF/credentials/reader.key ]]; then
  openssl req -newkey rsa:3072 -nodes -subj '/CN=authorization-dashboard' -keyout "$CONF/credentials/reader.key" -out "$CONF/credentials/reader.csr" >/dev/null 2>&1
  openssl x509 -req -in "$CONF/credentials/reader.csr" -CA "$CONF/ca.crt" -CAkey "$CONF/ca.key" -CAcreateserial -out "$CONF/credentials/reader.crt" -days 365 -sha256 >/dev/null 2>&1
  openssl rand -hex 32 > "$CONF/credentials/reader.token"
fi
if [[ ! -f $CONF/config.json ]]; then
  printf '{}\n' > "$CONF/config.json"
fi
TMP=$(mktemp "$CONF/config.XXXXXX")
if appgog_normalize_reader_config "$CONF/config.json" "$CONF/credentials/reader.crt" \
    "$CONF/credentials/reader.token" > "$TMP" \
    && chown appgog-security:appgog-security "$TMP" \
    && chmod 600 "$TMP" \
    && mv "$TMP" "$CONF/config.json"; then
  :
else
  result=$?
  rm -f "$TMP"
  exit "$result"
fi
chmod 600 "$CONF/config.json" "$CONF/credentials/"*.key "$CONF/credentials/"*.token
chown appgog-security:appgog-security "$CONF/config.json"
chown -R appgog-security:appgog-security "$DATA"
VERSION=$("$BASE/runtime/bin/node" -p "JSON.parse(require('fs').readFileSync('package.json')).version")
RELEASE="$BASE/releases/$VERSION"
if [[ -e $RELEASE ]]; then
  cmp -s package.json "$RELEASE/package.json" && diff -qr src "$RELEASE/src" >/dev/null || {
    echo "Release $VERSION exists with different source; increase the version" >&2; exit 1;
  }
else
  mkdir "$RELEASE"
  cp -R src package.json "$RELEASE/"
fi
chown -R root:root "$RELEASE"
cat > "$CONF/service.env" <<EOF
SECURITY_TLS_KEY=$CONF/server.key
SECURITY_TLS_CERT=$CONF/server.crt
SECURITY_CLIENT_CA=$CONF/ca.crt
SECURITY_CONFIG=$CONF/config.json
SECURITY_STATE_FILE=$DATA/state.json
SECURITY_PORT=9443
EOF
chmod 600 "$CONF/service.env"
cat > /etc/systemd/system/appgog-security.service <<EOF
[Unit]
Description=APPGOG independent cloud security monitor
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=appgog-security
Group=appgog-security
WorkingDirectory=$BASE/current
EnvironmentFile=$CONF/service.env
ExecStart=$BASE/runtime/bin/node $BASE/current/src/server.js
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA
[Install]
WantedBy=multi-user.target
EOF
OLD=$(readlink "$BASE/current" || true)
ln -s "$RELEASE" "$BASE/current.next"
mv -Tf "$BASE/current.next" "$BASE/current"
systemctl daemon-reload
systemctl enable --now appgog-security.service
systemctl restart appgog-security.service
TOKEN=$(cat "$CONF/credentials/reader.token")
for i in $(seq 1 15); do
  if curl -fsS --max-time 3 --resolve "$HOST:9443:127.0.0.1" --cacert "$CONF/ca.crt" \
      --cert "$CONF/credentials/reader.crt" --key "$CONF/credentials/reader.key" \
      -H "Authorization: Bearer $TOKEN" "https://$HOST:9443/v1/status" >/dev/null; then
    echo "Cloud security monitor ready at https://$HOST:9443"
    echo 'Record this CA fingerprint through an independent administrator channel before first business pairing:'
    openssl x509 -in "$CONF/ca.crt" -noout -fingerprint -sha256
    exit 0
  fi
  sleep 2
done
if [[ -n $OLD ]]; then
  ln -s "$OLD" "$BASE/current.rollback"
  mv -Tf "$BASE/current.rollback" "$BASE/current"
  systemctl restart appgog-security.service
fi
echo "Health check failed; previous release restored if available. Diagnose: journalctl -u appgog-security" >&2
exit 1
