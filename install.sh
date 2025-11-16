#!/usr/bin/env bash
# Debian 12 一键部署脚本
# - 初始化系统 & 内核
# - VLESS Reality (SNI=www.apple.com)
# - Hysteria2 官方极简 (SNI=www.apple.com)
# - Hy2 临时节点 + 审计 + GC
# - nftables UDP 上行配额系统（自动持久化）

set -euo pipefail

REPO_BASE="https://raw.githubusercontent.com/liucong552-art/debian12-/main"
UP_BASE="/usr/local/src/debian12-upstream"

# ------------------ 公共函数 ------------------

check_debian12() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "❌ 请以 root 运行本脚本"
    exit 1
  fi
  local codename
  codename=$(grep -E "^VERSION_CODENAME=" /etc/os-release 2>/dev/null | cut -d= -f2)
  if [[ "$codename" != "bookworm" ]]; then
    echo "❌ 本脚本仅适用于 Debian 12 (bookworm)，当前: ${codename:-未知}"
    exit 1
  fi
}

need_basic_tools() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y || true
  apt-get install -y curl wget openssl python3 nftables || apt-get install -y curl wget openssl
}

download_upstreams() {
  echo "⬇ 下载/更新 上游文件到 ${UP_BASE} ..."
  mkdir -p "$UP_BASE"

  # Xray 安装脚本
  curl -fsSL "${REPO_BASE}/xray-install-release.sh" -o "${UP_BASE}/xray-install-release.sh"
  chmod +x "${UP_BASE}/xray-install-release.sh"

  # Hysteria 安装脚本
  curl -fsSL "${REPO_BASE}/hysteria-install.sh" -o "${UP_BASE}/hysteria-install.sh"
  chmod +x "${UP_BASE}/hysteria-install.sh"

  echo "✅ 上游已更新："
  ls -l "$UP_BASE"
}

# ------------------ 1. 系统更新 + 新内核 ------------------

install_update_all() {
  echo "🧩 写入 /usr/local/bin/update-all ..."
  cat >/usr/local/bin/update-all << 'EOF'
#!/bin/bash
set -e

check_debian12() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "❌ 请以 root 身份运行本脚本"; exit 1
  fi
  local codename
  codename=$(grep -E "^VERSION_CODENAME=" /etc/os-release 2>/dev/null | cut -d= -f2)
  if [ "$codename" != "bookworm" ]; then
    echo "❌ 本脚本仅适用于 Debian 12 (bookworm)，当前为: ${codename:-未知}"
    exit 1
  fi
}

check_debian12
echo "🚀 开始系统更新 (Debian 12 / bookworm)..."

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get full-upgrade -y
apt-get --purge autoremove -y
apt-get autoclean -y
apt-get clean -y

echo "✅ 软件包更新完成"

echo "🧱 配置 bookworm-backports 仓库..."
BACKPORTS_FILE=/etc/apt/sources.list.d/backports.list
if [ -f "$BACKPORTS_FILE" ]; then
  cp "$BACKPORTS_FILE" "${BACKPORTS_FILE}.bak.$(date +%F-%H%M%S)"
fi
cat >"$BACKPORTS_FILE" <<BEOF
deb http://deb.debian.org/debian bookworm-backports main contrib non-free non-free-firmware
BEOF

apt-get update -y

echo "🔧 从 backports 安装最新内核 (linux-image-amd64 / linux-headers-amd64)..."
apt-get -t bookworm-backports install -y linux-image-amd64 linux-headers-amd64

echo
echo "📦 当前已安装的内核包 (linux-image)："
dpkg -l | grep "^ii  linux-image" | tail -n 10 || true

echo
echo "🖥 当前正在运行的内核：$(uname -r)"
echo "⚠️ 重启后系统才会真正切换到新内核，请执行：reboot"
EOF

  chmod +x /usr/local/bin/update-all
}

# ------------------ 2. VLESS Reality 一键 ------------------

install_vless_script() {
  echo "🧩 写入 /root/onekey_reality_ipv4.sh ..."
  cat >/root/onekey_reality_ipv4.sh << 'EOF'
#!/usr/bin/env bash
set -e

REPO_BASE="https://raw.githubusercontent.com/liucong552-art/debian12-/main"
UP_BASE="/usr/local/src/debian12-upstream"

check_debian12() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "❌ 请以 root 身份运行"; exit 1
  fi
  local codename
  codename=$(grep -E "^VERSION_CODENAME=" /etc/os-release 2>/dev/null | cut -d= -f2)
  if [ "$codename" != "bookworm" ]; then
    echo "❌ 仅支持 Debian 12 (bookworm)，当前: ${codename:-未知}"
    exit 1
  fi
}

install_xray_from_local_or_repo() {
  mkdir -p "$UP_BASE"
  local xray_installer="$UP_BASE/xray-install-release.sh"
  if [ ! -x "$xray_installer" ]; then
    echo "⬇ 从仓库获取 Xray 安装脚本..."
    curl -fsSL "$REPO_BASE/xray-install-release.sh" -o "$xray_installer"
    chmod +x "$xray_installer"
  fi
  echo "⚙ 安装 / 更新 Xray-core..."
  "$xray_installer" install --without-geodata
  if [ ! -x /usr/local/bin/xray ]; then
    echo "❌ 未找到 /usr/local/bin/xray，请检查安装脚本"; exit 1
  fi
}

check_debian12

REALITY_DOMAIN="www.apple.com"
PORT=443
NODE_NAME="VLESS-REALITY-IPv4-APPLE"

SERVER_IP=$(curl -4fsS https://ifconfig.me \
        || curl -4fsS https://api.ipify.org \
        || hostname -I | awk '{print $1}')
if [[ -z "$SERVER_IP" ]]; then
  echo "❌ 无法检测 IPv4 公网 IP"; exit 1
fi

echo "服务器 IPv4: $SERVER_IP"
echo "伪装域名:   $REALITY_DOMAIN"
echo "端口:       $PORT"
sleep 2

echo "=== 1. 启用 BBR ==="
cat >/etc/sysctl.d/99-bbr.conf <<SYS
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
SYS
modprobe tcp_bbr 2>/dev/null || true
sysctl -p /etc/sysctl.d/99-bbr.conf || true
echo "当前拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"

echo
echo "=== 2. 安装 / 更新 Xray-core ==="
install_xray_from_local_or_repo
systemctl stop xray 2>/dev/null || true

echo
echo "=== 3. 生成 UUID 与 Reality 密钥 ==="
/usr/local/bin/xray uuid >/tmp/xray_uuid.txt
UUID=$(cat /tmp/xray_uuid.txt)

KEY_OUT=$(/usr/local/bin/xray x25519)
PRIVATE_KEY=$(printf '%s\n' "$KEY_OUT" | awk '/^PrivateKey:/ {print $2}')
PUBLIC_KEY=$(printf '%s\n' "$KEY_OUT" | awk '/^Password:/ {print $2}')
if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
  PRIVATE_KEY=$(printf '%s\n' "$KEY_OUT" | awk '/^Private key:/ {print $3}')
  PUBLIC_KEY=$(printf '%s\n' "$KEY_OUT" | awk '/^Public key:/ {print $3}')
fi
if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
  echo "❌ 无法解析 Reality 密钥："
  echo "$KEY_OUT"; exit 1
fi

SHORT_ID=$(openssl rand -hex 8)

CONFIG_DIR=/usr/local/etc/xray
mkdir -p "$CONFIG_DIR"

cat >"$CONFIG_DIR/config.json" <<CONF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": $PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "$UUID", "flow": "xtls-rprx-vision" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$REALITY_DOMAIN:443",
          "xver": 0,
          "serverNames": [ "$REALITY_DOMAIN" ],
          "privateKey": "$PRIVATE_KEY",
          "shortIds": [ "$SHORT_ID" ]
        }
      },
      "sniffing": {
        "enabled": true,
        "routeOnly": true,
        "destOverride": ["http","tls","quic"]
      }
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "block",  "protocol": "blackhole" }
  ]
}
CONF

systemctl daemon-reload
systemctl enable xray || true
systemctl restart xray
sleep 2
systemctl --no-pager --full status xray || true

VLESS_URL="vless://${UUID}@${SERVER_IP}:${PORT}?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&sni=${REALITY_DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}#${NODE_NAME}"

if base64 --help 2>/dev/null | grep -q -- "-w"; then
  echo "$VLESS_URL" | base64 -w0 >/root/v2ray_subscription_base64.txt
else
  echo "$VLESS_URL" | base64 | tr -d '\n' >/root/v2ray_subscription_base64.txt
fi
echo "$VLESS_URL" >/root/vless_reality_vision_url.txt

echo
echo "================== 节点信息 =================="
echo "$VLESS_URL"
echo
echo "Base64 订阅："
cat /root/v2ray_subscription_base64.txt
echo
echo "保存位置："
echo "  /root/vless_reality_vision_url.txt"
echo "  /root/v2ray_subscription_base64.txt"
echo "✅ VLESS+Reality+Vision (IPv4, SNI=www.apple.com) 安装完成"
EOF

  chmod +x /root/onekey_reality_ipv4.sh
}

# ------------------ 3. Hy2 官方极简 一键 ------------------

install_hy2_script() {
  echo "🧩 写入 /root/hy2_official_minimal_ipv4.sh ..."
  cat >/root/hy2_official_minimal_ipv4.sh << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

REPO_BASE="https://raw.githubusercontent.com/liucong552-art/debian12-/main"
UP_BASE="/usr/local/src/debian12-upstream"

check_debian12() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "❌ 请以 root 运行"; exit 1
  fi
  local codename
  codename=$(grep -E "^VERSION_CODENAME=" /etc/os-release 2>/dev/null | cut -d= -f2)
  if [[ "$codename" != "bookworm" ]]; then
    echo "❌ 仅支持 Debian 12 (bookworm)，当前: ${codename:-未知}"
    exit 1
  fi
}

install_hysteria_from_local_or_repo() {
  mkdir -p "$UP_BASE"
  local hy_installer="$UP_BASE/hysteria-install.sh"
  if [[ ! -x "$hy_installer" ]]; then
    echo "⬇ 从仓库获取 Hysteria 安装脚本..."
    curl -fsSL "$REPO_BASE/hysteria-install.sh" -o "$hy_installer"
    chmod +x "$hy_installer"
  fi
  echo "⚙ 安装 / 更新 Hysteria2..."
  "$hy_installer"
}

check_debian12

HY_PORT=8443
SNI_HOST=www.apple.com

echo "== [1] 安装依赖（不改软件源） =="
apt-get update -y || true
apt-get install -y curl openssl python3 || apt-get install -y curl openssl

echo "== [2] 安装 Hysteria2（本地或仓库脚本） =="
install_hysteria_from_local_or_repo

echo "== [3] 获取 IPv4 公网 IP 和随机密码 =="
PUB_IP=$(curl -4fsS https://ifconfig.me || hostname -I | awk '{print $1}')
HY_PASS=$(openssl rand -base64 18 | tr -d "=/+")
echo "公网 IP: ${PUB_IP}"
echo "Hy2 密码: ${HY_PASS}"

install -d -m 0755 /etc/hysteria

echo "== [4] 生成 EC 自签证书（CN = ${SNI_HOST}） =="
openssl ecparam -genkey -name prime256v1 -out /etc/hysteria/server.key
openssl req -x509 -new -key /etc/hysteria/server.key \
  -out /etc/hysteria/server.crt \
  -days 3650 \
  -subj "/CN=${SNI_HOST}"

echo "== [5] 写入官方极简版配置（IPv4 优先 + QUIC 优化） =="
cat >/etc/hysteria/config.yaml <<CFG
listen: :${HY_PORT}

tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key

auth:
  type: password
  password: ${HY_PASS}

quic:
  alpn:
    - h3
    - h3-29
  initStreamReceiveWindow: 26843545
  maxStreamReceiveWindow: 26843545
  initConnReceiveWindow: 67108864
  maxConnReceiveWindow: 67108864
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false

masquerade:
  type: proxy
  proxy:
    url: https://${SNI_HOST}/
    rewriteHost: true
CFG

chown -R hysteria:hysteria /etc/hysteria 2>/dev/null || true
chmod 640 /etc/hysteria/*

echo "== [6] 启动 Hysteria2 服务 =="
systemctl enable --now hysteria-server
sleep 2
systemctl status hysteria-server --no-pager || true

echo "== [7] 生成 Clash 订阅文件（/var/www/html/sub.yaml） =="
install -d -m 0755 /var/www/html
cat >/var/www/html/sub.yaml <<SUB
proxies:
  - name: hy2-${PUB_IP}
    type: hysteria2
    server: ${PUB_IP}
    port: ${HY_PORT}
    password: ${HY_PASS}
    sni: ${SNI_HOST}
    alpn:
      - h3
      - h3-29
    skip-cert-verify: true
    udp: true
SUB

echo "== [8] 启 HTTP 订阅服务 (8081) =="
cat >/etc/systemd/system/sub-http-8081.service <<UNIT
[Unit]
Description=Simple HTTP server for subscription on :8081
After=network.target

[Service]
Type=simple
WorkingDirectory=/var/www/html
ExecStart=/usr/bin/python3 -m http.server 8081
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now sub-http-8081.service

echo
echo "===== ✅ Hysteria2 官方极简版部署完成 (IPv4, SNI=www.apple.com) ====="
echo "Server: ${PUB_IP}:${HY_PORT}"
echo "Password: ${HY_PASS}"
echo
echo "Clash 订阅:  http://${PUB_IP}:8081/sub.yaml"
echo
echo "客户端直链:"
echo "hysteria2://${HY_PASS}@${PUB_IP}:${HY_PORT}/?insecure=1&alpn=h3,h3-29&sni=${SNI_HOST}#hy2-${PUB_IP}"
echo
echo "=================================================="
EOF

  chmod +x /root/hy2_official_minimal_ipv4.sh
}

# ------------------ 4. Hy2 临时节点 + 审计 + GC ------------------

install_hy2_temp_audit() {
  echo "🧩 写入 /root/hy2_temp_audit_ipv4_all.sh 和相关脚本 ..."
  cat >/root/hy2_temp_audit_ipv4_all.sh << 'EOF'
#!/usr/bin/env bash
# Hy2 临时节点 + 审计 + GC (IPv4) 一键部署 / 覆盖
set -euo pipefail

########################################
# 1) 单节点清理脚本
########################################
cat >/usr/local/sbin/hy2_cleanup_one.sh << 'CLEAN'
#!/usr/bin/env bash
set -euo pipefail

TAG="${1:?need TAG}"
UNIT_NAME="${TAG}.service"

echo "[hy2_cleanup_one] 开始清理: ${TAG}"

ACTIVE_STATE="$(systemctl show -p ActiveState --value "${UNIT_NAME}" 2>/dev/null || echo "")"

if [[ "${ACTIVE_STATE}" == "active" || "${ACTIVE_STATE}" == "activating" ]]; then
  if ! timeout 8 systemctl stop "${UNIT_NAME}" >/dev/null 2>&1; then
    systemctl kill "${UNIT_NAME}" >/dev/null 2>&1 || true
  fi
fi

systemctl disable "${UNIT_NAME}" >/dev/null 2>&1 || true

for f in \
  "/etc/systemd/system/${UNIT_NAME}" \
  "/etc/hysteria/${TAG}.yaml" \
  "/etc/hysteria/${TAG}.meta" \
  "/var/log/${TAG}.log"
do
  rm -f "$f" 2>/dev/null || true
done

systemctl daemon-reload >/dev/null 2>&1 || true

echo "[hy2_cleanup_one] 完成清理: ${TAG}"
echo "$(date '+%F %T %Z') cleanup ${TAG}" >> /var/log/hy2-gc.log 2>/dev/null || true
CLEAN
chmod +x /usr/local/sbin/hy2_cleanup_one.sh

########################################
# 2) 创建临时 Hy2 节点：D=秒 hy2_mktemp.sh
########################################
cat >/usr/local/sbin/hy2_mktemp.sh << 'MK'
#!/usr/bin/env bash
set -euo pipefail
: "${D:?请用 D=秒 hy2_mktemp.sh 方式调用，例如：D=300 hy2_mktemp.sh}"

HY2_BIN=$(command -v hysteria || echo /usr/local/bin/hysteria)
[ -x "$HY2_BIN" ] || { echo "❌ 未找到 hysteria 可执行文件"; exit 1; }

TLS_CERT=""
TLS_KEY=""

if [[ -f /etc/hysteria/config.yaml ]]; then
  TLS_CERT=$(grep -E 'cert:' /etc/hysteria/config.yaml | awk '{print $2}' | head -n1 || true)
  TLS_KEY=$(grep -E 'key:'  /etc/hysteria/config.yaml | awk '{print $2}' | head -n1 || true)
fi

[[ -z "$TLS_CERT" || -z "$TLS_KEY" ]] && {
  TLS_CERT="/etc/hysteria/server.crt"
  TLS_KEY="/etc/hysteria/server.key"
}

if [[ ! -f "$TLS_CERT" || ! -f "$TLS_KEY" ]]; then
  echo "❌ 未找到可用证书，请先确保主 Hy2 已安装并生成 /etc/hysteria/server.crt / server.key"
  exit 1
fi

PORT=40000
while :; do
  USED=0

  if ss -lunH 2>/dev/null | awk '{print $5}' | sed "s/.*://g" | grep -qx "$PORT"; then
    USED=1
  fi

  if grep -R "PORT=${PORT}" /etc/hysteria/hy2-temp-*.meta 2>/dev/null >/dev/null; then
    USED=1
  fi

  if (( USED == 0 )); then
    break
  fi

  PORT=$((PORT+1))
  if (( PORT > 50050 )); then
    echo "❌ 在 40000-50050 范围内没有空闲 UDP 端口了。"
    exit 1
  fi
done

PASS=$(head -c16 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-16)
TAG="hy2-temp-$(date +%Y%m%d%H%M%S)-$(openssl rand -hex 2)"
CFG2="/etc/hysteria/${TAG}.yaml"
UNIT="/etc/systemd/system/${TAG}.service"
META="/etc/hysteria/${TAG}.meta"

mkdir -p /etc/hysteria

ADDR=$(curl -4fsS https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
NOW=$(date +%s)
EXP=$((NOW + D))

cat >"$CFG2" <<CFG
listen: ":${PORT}"
tls:
  cert: "$TLS_CERT"
  key: "$TLS_KEY"
auth:
  type: password
  password: "$PASS"

quic:
  alpn:
    - h3
    - h3-29
  initStreamReceiveWindow: 26843545
  maxStreamReceiveWindow: 26843545
  initConnReceiveWindow: 67108864
  maxConnReceiveWindow: 67108864
  maxIdleTimeout: 30s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false

masquerade:
  type: proxy
  proxy:
    url: "https://www.apple.com/"
    rewriteHost: true
CFG

cat >"$UNIT" <<U
[Unit]
Description=Temp HY2 $TAG
After=network.target

[Service]
Type=simple
ExecStart=$HY2_BIN server --config $CFG2
RuntimeMaxSec=$D
ExecStopPost=/usr/local/sbin/hy2_cleanup_one.sh $TAG
Restart=no

[Install]
WantedBy=multi-user.target
U

systemctl daemon-reload
systemctl enable --now "$TAG".service

cat >"$META" <<M
TAG=$TAG
PASS=$PASS
PORT=$PORT
SERVER_ADDR=$ADDR
EXPIRE_EPOCH=$EXP
M

E_STR=$(TZ=Asia/Shanghai date -d "@$EXP" '+%F %T')
echo "✅ 新节点: $TAG
地址: $ADDR:$PORT/UDP
密码: $PASS
有效期: $D 秒
到期: $E_STR
URL:
hysteria2://$PASS@$ADDR:$PORT/?sni=$ADDR&insecure=1#$TAG"
MK
chmod +x /usr/local/sbin/hy2_mktemp.sh

########################################
# 3) 强力 GC：按 meta 过期时间清理
########################################
cat >/usr/local/sbin/hy2_gc.sh << 'GC'
#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

NOW=$(date +%s)

for META in /etc/hysteria/hy2-temp-*.meta; do
  . "$META" 2>/dev/null || continue

  if [[ -z "${TAG:-}" ]]; then
    continue
  fi
  if [[ -z "${EXPIRE_EPOCH:-}" || ! "${EXPIRE_EPOCH}" =~ ^[0-9]+$ ]]; then
    continue
  fi

  if (( EXPIRE_EPOCH <= NOW )); then
    /usr/local/sbin/hy2_cleanup_one.sh "$TAG" || true
  fi
done
GC
chmod +x /usr/local/sbin/hy2_gc.sh

cat >/etc/systemd/system/hy2-gc.service << 'GCSVC'
[Unit]
Description=HY2 Temp Nodes Garbage Collector
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/hy2_gc.sh
GCSVC

cat >/etc/systemd/system/hy2-gc.timer << 'GCTMR'
[Unit]
Description=Run HY2 GC every 15 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
GCTMR

systemctl daemon-reload
systemctl enable --now hy2-gc.timer || true

########################################
# 4) 审计脚本（主服务 + 临时节点）
########################################
cat >/usr/local/sbin/hy2_audit.sh << 'AUDIT'
#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

MAIN_VLESS="${MAIN_VLESS:-xray.service}"
MAIN_HY2="${MAIN_HY2:-hysteria-server.service}"

printf "%-40s %-10s %-6s %-12s %-10s %-20s\n" "NAME" "STATE" "PORT" "LEFT" "NOTE" "EXPIRE(China)"

print_main() {
  local NAME="$1"
  local PORT="$2"
  local NOTE="$3"
  local STATE

  if systemctl list-unit-files "$NAME" >/dev/null 2>&1; then
    STATE=$(systemctl is-active "$NAME" 2>/dev/null || echo "unknown")
    printf "%-40s %-10s %-6s %-12s %-10s %-20s\n" "$NAME" "$STATE" "$PORT" "-" "$NOTE" "-"
  fi
}

print_main "$MAIN_VLESS" "443" "vless-main"
print_main "$MAIN_HY2"  "8443" "hy2-main"

for META in /etc/hysteria/hy2-temp-*.meta; do
  . "$META" 2>/dev/null || continue

  if [[ -z "${TAG:-}" || -z "${PORT:-}" ]]; then
    continue
  fi

  NAME="${TAG}.service"
  STATE="$(systemctl is-active "$NAME" 2>/dev/null || echo "unknown")"
  PORT_STR="${PORT:-?}"
  NOW_TS=$(date +%s)

  if [[ -n "${EXPIRE_EPOCH:-}" && "${EXPIRE_EPOCH}" =~ ^[0-9]+$ ]]; then
    LEFT=$((EXPIRE_EPOCH - NOW_TS))
    if (( LEFT <= 0 )); then
      LEFT_STR="expired"
    else
      D=$((LEFT/86400))
      H=$(((LEFT%86400)/3600))
      M=$(((LEFT%3600)/60))
      LEFT_STR=$(printf "%02dd%02dh%02dm" "$D" "$H" "$M")
    fi
    EXPIRE_AT_FMT="$(TZ='Asia/Shanghai' date -d "@${EXPIRE_EPOCH}" '+%Y-%m-%d %H:%M:%S')"
  else
    LEFT_STR="N/A"
    EXPIRE_AT_FMT="N/A"
  fi

  printf "%-40s %-10s %-6s %-12s %-10s %-20s\n" "$NAME" "$STATE" "$PORT_STR" "$LEFT_STR" "hy2-temp" "$EXPIRE_AT_FMT"
done
AUDIT
chmod +x /usr/local/sbin/hy2_audit.sh

########################################
# 5) 清空全部临时节点
########################################
cat >/usr/local/sbin/hy2_clear_all.sh << 'CLR'
#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

echo "== HY2 临时节点批量清理开始 =="

META_FILES=(/etc/hysteria/hy2-temp-*.meta)

if (( ${#META_FILES[@]} == 0 )); then
  echo "当前没有任何临时 HY2 节点。"
  exit 0
fi

for META in "${META_FILES[@]}"; do
  echo "--- 发现 meta: ${META}"
  . "$META" 2>/dev/null || continue

  if [[ -z "${TAG:-}" ]]; then
    echo "  ⚠️  跳过：${META} 中没有 TAG"
    continue
  fi

  echo "  -> 清理 ${TAG}"
  /usr/local/sbin/hy2_cleanup_one.sh "$TAG" || true
done

systemctl daemon-reload >/dev/null 2>&1 || true
echo "✅ 所有临时 HY2 节点清理流程已执行完毕。"
CLR
chmod +x /usr/local/sbin/hy2_clear_all.sh

echo "✅ Hy2 临时节点 + 审计 + GC 脚本部署/覆盖完成。"

cat <<USE

============ 使用方法（Hy2 临时节点 / 审计） ============

1) 新建一个临时节点（例如 120 秒）：
   D=120 hy2_mktemp.sh

2) 查看主节点 + 所有临时节点状态：
   hy2_audit.sh

3) 等临时节点过期后，GC 定时器会自动清理，
   你也可以手动强制清空所有临时节点：
   hy2_clear_all.sh

==========================================================
USE

EOF

  chmod +x /root/hy2_temp_audit_ipv4_all.sh
}

# ------------------ 5. nftables 配额系统 ------------------

install_port_quota() {
  echo "🧩 部署 UDP 上行配额系统（nftables）..."
  apt-get update -y >/dev/null || true
  apt-get install -y nftables >/dev/null || true
  mkdir -p /etc/portquota

  if ! nft list table inet portquota >/dev/null 2>&1; then
    nft add table inet portquota
  fi
  if ! nft list chain inet portquota down_out >/dev/null 2>&1; then
    nft add chain inet portquota down_out '{ type filter hook output priority filter; policy accept; }'
  fi

  nft list ruleset > /etc/nftables.conf
  systemctl enable --now nftables >/dev/null 2>&1 || true

  cat >/usr/local/sbin/pq_add.sh <<'ADD'
#!/usr/bin/env bash
set -euo pipefail
PORT="${1:-}"; GIB="${2:-}"
if [[ -z "$PORT" || -z "$GIB" ]]; then
  echo "用法: pq_add.sh <端口> <GiB(整数)>" >&2; exit 1
fi
if ! [[ "$GIB" =~ ^[0-9]+$ ]]; then
  echo "❌ GiB 需为整数" >&2; exit 1
fi
BYTES=$((GIB * 1024 * 1024 * 1024))

nft -a list chain inet portquota down_out 2>/dev/null | \
 awk -v p="$PORT" '$0 ~ "udp sport "p" " {print $NF}' | while read -r h; do
   nft delete rule inet portquota down_out handle "$h" 2>/dev/null || true
 done

nft delete counter inet portquota "pq_down_$PORT" 2>/dev/null || true
nft add counter inet portquota "pq_down_$PORT"
nft add rule inet portquota down_out udp sport "$PORT" \
  counter name "pq_down_$PORT" quota over "$BYTES" bytes drop comment "pq-quota-$PORT"
nft add rule inet portquota down_out udp sport "$PORT" \
  counter name "pq_down_$PORT" comment "pq-track-$PORT"

cat >/etc/portquota/pq-"$PORT".meta <<M
PORT=$PORT
LIMIT_BYTES=$BYTES
LIMIT_GIB=$GIB
MODE=quota
M

nft list ruleset > /etc/nftables.conf
systemctl enable --now nftables >/dev/null 2>&1 || true

echo "✅ 已为端口 $PORT 设置限额 ${GIB}GiB（本机 UDP 上行）"
ADD
  chmod +x /usr/local/sbin/pq_add.sh

  cat >/usr/local/sbin/pq_del.sh <<'DEL'
#!/usr/bin/env bash
set -euo pipefail
PORT="${1:-}"
if [[ -z "$PORT" ]]; then echo "用法: pq_del.sh <端口>" >&2; exit 1; fi

nft -a list chain inet portquota down_out 2>/dev/null | \
 awk -v p="$PORT" '$0 ~ "udp sport "p" " {print $NF}' | while read -r h; do
   nft delete rule inet portquota down_out handle "$h" 2>/dev/null || true
 done

nft delete counter inet portquota "pq_down_$PORT" 2>/dev/null || true
rm -f /etc/portquota/pq-"$PORT".meta

nft list ruleset > /etc/nftables.conf
systemctl enable --now nftables >/dev/null 2>&1 || true

echo "✅ 已删除端口 $PORT 的配额"
DEL
  chmod +x /usr/local/sbin/pq_del.sh

  cat >/usr/local/sbin/pq_audit.sh <<'AUDIT'
#!/usr/bin/env bash
# 🔍 实时审计 nft quota（上行统计）
set -e; shopt -s nullglob
printf "%-8s %-8s %-12s %-12s %-8s %-10s\n" \
 "PORT" "STATE" "USED(GiB)" "LIMIT(GiB)" "PERCENT" "MODE"
for META in /etc/portquota/pq-*.meta; do
  unset PORT LIMIT_BYTES MODE
  . "$META" 2>/dev/null || continue
  PORT="${PORT:-}"; [[ -z "$PORT" ]] && continue
  LIMIT_BYTES="${LIMIT_BYTES:-0}"; MODE="${MODE:-quota}"
  QUOTA_LINE="$(nft -a list chain inet portquota down_out 2>/dev/null \
    | awk -v p="$PORT" '$0~"udp sport "p" "&&$0~"pq-quota-"p{print;exit}')"
  CUR=""; QUOTA_LIMIT_BYTES=""
  if [[ -n "$QUOTA_LINE" ]]; then
    CUR="$(awk '{for(i=1;i<=NF;i++)if($i=="used"){print $(i+1);exit}}'<<<"$QUOTA_LINE")"
    read QVAL QUNIT <<< "$(awk '{for(i=1;i<=NF;i++)if($i=="over"){print $(i+1),$(i+2);exit}}'<<<"$QUOTA_LINE")"
    if [[ -n "$QVAL" && -n "$QUNIT" ]]; then
      case "$QUNIT" in
        bytes)QUOTA_LIMIT_BYTES="$QVAL";;
        kbytes)QUOTA_LIMIT_BYTES=$((QVAL*1024));;
        mbytes)QUOTA_LIMIT_BYTES=$((QVAL*1024*1024));;
        gbytes)QUOTA_LIMIT_BYTES=$((QVAL*1024*1024*1024));;
      esac
    fi
  fi
  if [[ -z "$CUR" ]]; then
    CUR="$(nft list counter inet portquota "pq_down_${PORT}" 2>/dev/null \
      | awk '/bytes/{for(i=1;i<=NF;i++)if($i=="bytes"){print $(i+1);exit}}')"
  fi
  [[ -z "$CUR" ]]&&CUR=0
  [[ -n "$QUOTA_LIMIT_BYTES" ]]&&LIMIT_BYTES="$QUOTA_LIMIT_BYTES"
  USED="$(awk -v b="$CUR" 'BEGIN{printf "%.2f",b/1024/1024/1024}')"
  if ((LIMIT_BYTES>0));then
    LIMIT_GIB="$(awk -v b="$LIMIT_BYTES" 'BEGIN{printf "%.2f",b/1024/1024/1024}')"
    PCT="$(awk -v u="$CUR" -v l="$LIMIT_BYTES" 'BEGIN{printf "%.1f%%",(u*100.0)/l}')"
  else LIMIT_GIB="0";PCT="N/A";fi
  STATE="ok"
  if [[ "$MODE"=="quota" ]]&&((LIMIT_BYTES>0))&&((CUR>=LIMIT_BYTES));then
    STATE="dropped"
  elif [[ "$MODE"!="quota"||"$LIMIT_BYTES"=="0" ]];then
    STATE="track"
  fi
  printf "%-8s %-8s %-12s %-12s %-8s %-10s\n" \
    "$PORT" "$STATE" "$USED" "$LIMIT_GIB" "$PCT" "$MODE"
done
AUDIT
  chmod +x /usr/local/sbin/pq_audit.sh

  cat <<USE

============ 使用方法（UDP 上行配额 / 审计） ============

1) 为端口添加配额（例如限制 40000 端口 50GiB）：
   pq_add.sh 40000 50

2) 查看所有端口使用情况：
   pq_audit.sh

3) 删除某个端口的配额：
   pq_del.sh 40000

说明：
- 统计的是本机发出的 UDP 上行流量（chain: output, udp sport）
- 每次 add/del 后脚本会自动：
  - 将当前规则保存到 /etc/nftables.conf
  - 启用 nftables 服务开机自动恢复

==========================================================
USE
}

# ------------------ 主流程 ------------------

main() {
  check_debian12
  need_basic_tools
  download_upstreams

  install_update_all
  install_vless_script
  install_hy2_script
  install_hy2_temp_audit
  install_port_quota

  cat <<'DONE'

==================================================
✅ 所有脚本已生成完毕（适用于 Debian 12）

可用命令一览：

1) 系统更新 + 新内核：
   update-all
   reboot

2) VLESS Reality (IPv4, SNI=www.apple.com)：
   bash /root/onekey_reality_ipv4.sh

3) Hysteria2 官方极简 + Clash 订阅：
   bash /root/hy2_official_minimal_ipv4.sh

4) Hy2 临时节点 + 审计 + GC：
   bash /root/hy2_temp_audit_ipv4_all.sh
   # 部署后：
   D=120 hy2_mktemp.sh     # 新建 120 秒临时节点
   hy2_audit.sh            # 查看全部节点状态
   hy2_clear_all.sh        # 手动清空所有临时节点

5) UDP 上行配额（nftables）：
   pq_add.sh 40000 50      # 端口 40000 限制 50GiB 上行
   pq_audit.sh             # 查看所有端口配额使用
   pq_del.sh 40000         # 删除 40000 端口配额

所有 SNI/伪装域名已统一为： www.apple.com

🎯 建议顺序：
   1) update-all && reboot
   2) 跑 VLESS / Hy2 两个一键脚本
   3) 需要临时节点就跑 hy2_temp_audit_ipv4_all.sh 再 D=xxx hy2_mktemp.sh
   4) 需要限额就用 pq_add.sh / pq_audit.sh / pq_del.sh

==================================================
DONE
}

main "$@"
