#!/usr/bin/env bash
# Debian 12 一键部署脚本（改进版）
# - 初始化系统 & 内核
# - VLESS Reality 主节点 (SNI=www.apple.com)
# - VLESS 临时节点 + 审计 + GC（绝对时间 TTL）
# - nftables TCP 双向配额系统（仅统计 VPS<->用户，自动持久化 + 5 分钟保存快照）
# - 日志 logrotate：保留最近 2 天
# - systemd journal：自动 vacuum 保留 2 天
#
# ✅ 按你要求：让 xray.service 以 root 身份运行
#    - 写入 systemd drop-in: /etc/systemd/system/xray.service.d/99-run-as-root.conf
#
# ✅ 保留你不在乎的部分：GitHub raw 直接下载执行（不加校验）
#
# ✅ 本版修复：
#    - 修正主脚本头部：shebang 独立成行，恢复必要换行/分隔符
#    - vless_cleanup_one.sh：支持 VLESS_LOCK_HELD=1 时跳过再次 flock（修复锁重入导致清理失效）
#    - vless_gc.sh：调用 cleanup_one 时加 VLESS_LOCK_HELD=1
#    - vless_clear_all.sh：调用 cleanup_one 时加 VLESS_LOCK_HELD=1
#    - vless_mktemp.sh：启动失败回滚调用 cleanup_one 时加 VLESS_LOCK_HELD=1
#    -（推荐）onekey_reality_ipv4.sh：重启后用 systemctl is-active --quiet 强校验（不再吞失败）

set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

REPO_BASE="https://raw.githubusercontent.com/liucong552-art/debian12-/main"
UP_BASE="/usr/local/src/debian12-upstream"

# ------------------ 公共函数 ------------------

curl_fs() {
  # 稳定一点：超时 + 重试（不涉及上游安全校验）
  curl -fsSL --connect-timeout 5 --max-time 60 --retry 3 --retry-delay 1 "$@"
}

check_debian12() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "❌ 请以 root 运行本脚本"
    exit 1
  fi
  local codename
  codename=$(grep -E "^VERSION_CODENAME=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
  if [[ "$codename" != "bookworm" ]]; then
    echo "❌ 本脚本仅适用于 Debian 12 (bookworm)，当前: ${codename:-未知}"
    exit 1
  fi
}

need_basic_tools() {
  export DEBIAN_FRONTEND=noninteractive

  apt-get update -o Acquire::Retries=3

  # python3(解析json)、nftables(配额)、iproute2(ss)、coreutils(timeout)、util-linux(flock)、logrotate(日志轮转)
  apt-get install -y --no-install-recommends \
    ca-certificates curl wget openssl python3 nftables iproute2 coreutils util-linux logrotate

  local c
  for c in curl openssl python3 nft timeout ss flock; do
    command -v "$c" >/dev/null 2>&1 || { echo "❌ 缺少命令: $c"; exit 1; }
  done
}

download_upstreams() {
  echo "⬇ 下载/更新 上游文件到 ${UP_BASE} ..."
  mkdir -p "$UP_BASE"

  curl_fs "${REPO_BASE}/xray-install-release.sh" -o "${UP_BASE}/xray-install-release.sh"
  chmod +x "${UP_BASE}/xray-install-release.sh"

  echo "✅ 上游已更新："
  ls -l "$UP_BASE"
}

# ------------------ 1. 系统更新 + 新内核 ------------------

install_update_all() {
  echo "🧩 写入 /usr/local/bin/update-all ..."
  cat >/usr/local/bin/update-all << 'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

check_debian12() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "❌ 请以 root 身份运行本脚本"; exit 1
  fi
  local codename
  codename=$(grep -E "^VERSION_CODENAME=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
  if [ "$codename" != "bookworm" ]; then
    echo "❌ 本脚本仅适用于 Debian 12 (bookworm)，当前为: ${codename:-未知}"
    exit 1
  fi
}

check_debian12
echo "🚀 开始系统更新 (Debian 12 / bookworm)..."

export DEBIAN_FRONTEND=noninteractive
apt-get update -o Acquire::Retries=3
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

apt-get update -o Acquire::Retries=3

echo "🔧 从 backports 安装最新内核..."
arch="$(dpkg --print-architecture)"
case "$arch" in
  amd64) img=linux-image-amd64; hdr=linux-headers-amd64 ;;
  arm64) img=linux-image-arm64; hdr=linux-headers-arm64 ;;
  *)
    echo "❌ 未支持架构: $arch（如需支持请扩展 case）"
    exit 1
    ;;
esac
apt-get -t bookworm-backports install -y "$img" "$hdr"

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
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
umask 077

REPO_BASE="https://raw.githubusercontent.com/liucong552-art/debian12-/main"
UP_BASE="/usr/local/src/debian12-upstream"

curl4() {
  curl -4fsS --connect-timeout 3 --max-time 8 --retry 3 --retry-delay 1 "$@"
}

is_public_ipv4() {
  local ip="${1:-}"
  python3 - "$ip" <<'PY'
import ipaddress, sys
ip = (sys.argv[1] or "").strip()
try:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4 and addr.is_global:
        sys.exit(0)
except Exception:
    pass
sys.exit(1)
PY
}

get_public_ipv4() {
  local ip=""
  for url in \
    "https://api.ipify.org" \
    "https://ifconfig.me/ip" \
    "https://ipv4.icanhazip.com"
  do
    ip="$(curl4 "$url" 2>/dev/null | tr -d ' \n\r' || true)"
    if [[ -n "$ip" ]] && is_public_ipv4 "$ip"; then
      echo "$ip"; return 0
    fi
  done

  ip="$(hostname -I 2>/dev/null | awk '{print $1}' | tr -d ' \n\r' || true)"
  if [[ -n "$ip" ]] && is_public_ipv4 "$ip"; then
    echo "$ip"; return 0
  fi

  return 1
}

check_debian12() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "❌ 请以 root 身份运行"; exit 1
  fi
  local codename
  codename=$(grep -E "^VERSION_CODENAME=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
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
    curl4 -L "$REPO_BASE/xray-install-release.sh" -o "$xray_installer"
    chmod +x "$xray_installer"
  fi
  echo "⚙ 安装 / 更新 Xray-core..."
  "$xray_installer" install --without-geodata
  if [ ! -x /usr/local/bin/xray ]; then
    echo "❌ 未找到 /usr/local/bin/xray，请检查安装脚本"; exit 1
  fi
}

# ✅ 强制 xray.service 以 root 运行（用 drop-in 覆盖 User=nobody）
force_xray_run_as_root() {
  mkdir -p /etc/systemd/system/xray.service.d
  cat >/etc/systemd/system/xray.service.d/99-run-as-root.conf <<'DROPIN'
[Service]
User=root
Group=root
DROPIN
  systemctl daemon-reload
}

# ✅ URL 编码（用于 pbk，避免 +/= 被客户端 Query 解析误处理）
urlencode() {
  python3 - "$1" <<'PY'
import urllib.parse,sys
print(urllib.parse.quote(sys.argv[1], safe=''))
PY
}

check_debian12

REALITY_DOMAIN="www.apple.com"
PORT=443
NODE_NAME="VLESS-REALITY-IPv4-APPLE"

SERVER_IP="$(get_public_ipv4 || true)"
if [[ -z "$SERVER_IP" ]]; then
  echo "❌ 无法检测到可用的公网 IPv4（可能被阻断/在 NAT 后）"
  echo "   你可以："
  echo "   1) 确认 VPS/主机确实有公网 IPv4；"
  echo "   2) 或手动把链接里的 IP 改成你的公网 IP。"
  exit 1
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

force_xray_run_as_root

systemctl stop xray.service 2>/dev/null || true

echo
echo "=== 3. 生成 UUID 与 Reality 密钥 ==="
UUID=$(/usr/local/bin/xray uuid)

KEY_OUT=$(/usr/local/bin/xray x25519)
PRIVATE_KEY=$(
  printf '%s\n' "$KEY_OUT" | awk '
    /^PrivateKey:/   {print $2; exit}
    /^Private key:/  {print $3; exit}
  '
)
PUBLIC_KEY=$(
  printf '%s\n' "$KEY_OUT" | awk '
    /^PublicKey:/    {print $2; exit}
    /^Public key:/   {print $3; exit}
    /^Password:/     {print $2; exit}
  '
)

if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
  echo "❌ 无法解析 Reality 密钥："
  echo "$KEY_OUT"
  exit 1
fi

SHORT_ID=$(openssl rand -hex 8)

CONFIG_DIR=/usr/local/etc/xray
mkdir -p "$CONFIG_DIR"

# ✅ 覆盖前备份（推荐）
if [[ -f "$CONFIG_DIR/config.json" ]]; then
  cp -a "$CONFIG_DIR/config.json" "$CONFIG_DIR/config.json.bak.$(date +%F-%H%M%S)"
fi

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

chown root:root "$CONFIG_DIR/config.json" 2>/dev/null || true
chmod 600 "$CONFIG_DIR/config.json" 2>/dev/null || true

systemctl daemon-reload
systemctl enable xray.service >/dev/null 2>&1 || true
systemctl restart xray.service

# ✅ 强校验：不再吞掉失败（你要求的推荐项）
sleep 2
if ! systemctl is-active --quiet xray.service; then
  echo "❌ xray 启动失败，状态与日志如下：" >&2
  systemctl --no-pager --full status xray.service >&2 || true
  journalctl -u xray.service --no-pager -n 120 >&2 || true
  exit 1
fi

systemctl --no-pager --full status xray.service || true

PBK_Q="$(urlencode "$PUBLIC_KEY")"
VLESS_URL="vless://${UUID}@${SERVER_IP}:${PORT}?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&sni=${REALITY_DOMAIN}&fp=chrome&pbk=${PBK_Q}&sid=${SHORT_ID}#${NODE_NAME}"

if base64 --help 2>/dev/null | grep -q -- "-w"; then
  echo "$VLESS_URL" | base64 -w0 >/root/v2ray_subscription_base64.txt
else
  echo "$VLESS_URL" | base64 | tr -d '\n' >/root/v2ray_subscription_base64.txt
fi
echo "$VLESS_URL" >/root/vless_reality_vision_url.txt

chmod 600 /root/v2ray_subscription_base64.txt /root/vless_reality_vision_url.txt 2>/dev/null || true

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

# ------------------ 3. VLESS 临时节点 + 审计 + GC（绝对时间 TTL） ------------------

install_vless_temp_audit() {
  echo "🧩 写入 /root/vless_temp_audit_ipv4_all.sh 和相关脚本 ..."
  cat >/root/vless_temp_audit_ipv4_all.sh << 'EOF'
#!/usr/bin/env bash
# VLESS 临时节点 + 审计 + GC (IPv4, Reality) 一键部署 / 覆盖（绝对时间 TTL）
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
umask 077

XRAY_DIR="/usr/local/etc/xray"

########################################
# 0) meta 安全读取（禁止 source）
########################################
meta_get() { # meta_get FILE KEY
  local file="$1" key="$2"
  awk -F= -v k="$key" '$1==k {sub($1"=",""); print; exit}' "$file"
}

########################################
# 1) 单节点清理脚本（按 EXPIRE_EPOCH 判断）
########################################
cat >/usr/local/sbin/vless_cleanup_one.sh << 'CLEAN'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

meta_get() { local file="$1" key="$2"; awk -F= -v k="$key" '$1==k {sub($1"=",""); print; exit}' "$file"; }

TAG="${1:?need TAG}"
UNIT_NAME="${TAG}.service"
XRAY_DIR="/usr/local/etc/xray"
CFG="${XRAY_DIR}/${TAG}.json"
META="${XRAY_DIR}/${TAG}.meta"
LOG="/var/log/vless-gc.log"

FORCE="${FORCE:-0}"

LOCK="/run/vless-temp.lock"
# ✅ 修复：支持 VLESS_LOCK_HELD=1 时跳过再次 flock（锁重入避免清理失效）
if [[ "${VLESS_LOCK_HELD:-0}" != "1" ]]; then
  exec 9>"$LOCK"
  # ✅ 拿不到锁就退出，避免竞态（让 GC 兜底）
  flock -w 10 9 || { echo "[vless_cleanup_one] lock busy, skip cleanup: ${TAG}"; exit 0; }
fi

if [[ "$FORCE" != "1" && -f "$META" ]]; then
  EXPIRE_EPOCH="$(meta_get "$META" EXPIRE_EPOCH || true)"
  if [[ -n "${EXPIRE_EPOCH:-}" && "$EXPIRE_EPOCH" =~ ^[0-9]+$ ]]; then
    NOW=$(date +%s)
    if (( EXPIRE_EPOCH > NOW )); then
      echo "[vless_cleanup_one] ${TAG} 未到期 (EXPIRE_EPOCH=${EXPIRE_EPOCH}, NOW=${NOW})，跳过清理"
      exit 0
    fi
  fi
fi

echo "[vless_cleanup_one] 开始清理: ${TAG}"

ACTIVE_STATE="$(systemctl show -p ActiveState --value "${UNIT_NAME}" 2>/dev/null || echo "")"
if [[ "${ACTIVE_STATE}" == "active" || "${ACTIVE_STATE}" == "activating" ]]; then
  if ! timeout 8 systemctl stop "${UNIT_NAME}" >/dev/null 2>&1; then
    systemctl kill "${UNIT_NAME}" >/dev/null 2>&1 || true
  fi
fi

systemctl disable "${UNIT_NAME}" >/dev/null 2>&1 || true

rm -f "$CFG" "$META" "/etc/systemd/system/${UNIT_NAME}" 2>/dev/null || true
systemctl daemon-reload >/dev/null 2>&1 || true

echo "[vless_cleanup_one] 完成清理: ${TAG}"
echo "$(date '+%F %T %Z') cleanup ${TAG}" >> "$LOG" 2>/dev/null || true
CLEAN
chmod +x /usr/local/sbin/vless_cleanup_one.sh

########################################
# 2) 绝对时间 TTL 运行包装脚本：vless_run_temp.sh
########################################
cat >/usr/local/sbin/vless_run_temp.sh << 'RUN'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

meta_get() { local file="$1" key="$2"; awk -F= -v k="$key" '$1==k {sub($1"=",""); print; exit}' "$file"; }

TAG="${1:?need TAG}"
CFG="${2:?need config path}"

XRAY_BIN=$(command -v xray || echo /usr/local/bin/xray)
if [[ ! -x "$XRAY_BIN" ]]; then
  echo "[vless_run_temp] xray binary not found" >&2
  exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
  echo "[vless_run_temp] 请安装 coreutils (缺少 timeout)" >&2
  exit 1
fi

XRAY_DIR="/usr/local/etc/xray"
META="${XRAY_DIR}/${TAG}.meta"
if [[ ! -f "$META" ]]; then
  echo "[vless_run_temp] meta not found: $META" >&2
  exit 1
fi

EXPIRE_EPOCH="$(meta_get "$META" EXPIRE_EPOCH || true)"
if [[ -z "${EXPIRE_EPOCH:-}" || ! "$EXPIRE_EPOCH" =~ ^[0-9]+$ ]]; then
  echo "[vless_run_temp] bad EXPIRE_EPOCH in $META" >&2
  exit 1
fi

NOW=$(date +%s)
REMAIN=$((EXPIRE_EPOCH - NOW))
if (( REMAIN <= 0 )); then
  echo "[vless_run_temp] $TAG already expired (EXPIRE_EPOCH=$EXPIRE_EPOCH, NOW=$NOW)"
  FORCE=1 /usr/local/sbin/vless_cleanup_one.sh "$TAG" 2>/dev/null || true
  exit 0
fi

echo "[vless_run_temp] run $TAG for up to ${REMAIN}s (expire at $EXPIRE_EPOCH)"
exec timeout "$REMAIN" "$XRAY_BIN" run -c "$CFG"
RUN
chmod +x /usr/local/sbin/vless_run_temp.sh

########################################
# 3) 创建临时 VLESS 节点：D=秒 vless_mktemp.sh
########################################
cat >/usr/local/sbin/vless_mktemp.sh << 'MK'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

: "${D:?请用 D=秒 vless_mktemp.sh 方式调用，例如：D=600 vless_mktemp.sh}"

if ! [[ "$D" =~ ^[0-9]+$ ]] || (( D <= 0 )); then
  echo "❌ D 必须是正整数秒，例如：D=600 vless_mktemp.sh" >&2
  exit 1
fi

LOCK="/run/vless-temp.lock"
exec 9>"$LOCK"
flock -w 10 9

curl4() { curl -4fsS --connect-timeout 3 --max-time 8 --retry 3 --retry-delay 1 "$@"; }

is_public_ipv4() {
  local ip="${1:-}"
  python3 - "$ip" <<'PY'
import ipaddress, sys
ip = (sys.argv[1] or "").strip()
try:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4 and addr.is_global:
        sys.exit(0)
except Exception:
    pass
sys.exit(1)
PY
}

get_public_ipv4() {
  local ip=""
  for url in \
    "https://api.ipify.org" \
    "https://ifconfig.me/ip" \
    "https://ipv4.icanhazip.com"
  do
    ip="$(curl4 "$url" 2>/dev/null | tr -d ' \n\r' || true)"
    if [[ -n "$ip" ]] && is_public_ipv4 "$ip"; then
      echo "$ip"; return 0
    fi
  done

  ip="$(hostname -I 2>/dev/null | awk '{print $1}' | tr -d ' \n\r' || true)"
  if [[ -n "$ip" ]] && is_public_ipv4 "$ip"; then
    echo "$ip"; return 0
  fi

  return 1
}

# ✅ URL 编码/解码（避免 pbk 双重编码）
urlencode() { python3 - "$1" <<'PY'
import urllib.parse,sys
print(urllib.parse.quote(sys.argv[1], safe=''))
PY
}
urldecode() { python3 - "$1" <<'PY'
import urllib.parse,sys
print(urllib.parse.unquote(sys.argv[1]))
PY
}

# 单行校验（防止 meta 多行污染）
sanitize_one_line() { [[ "$1" != *$'\n'* && "$1" != *$'\r'* ]]; }

XRAY_BIN=$(command -v xray || echo /usr/local/bin/xray)
[ -x "$XRAY_BIN" ] || { echo "❌ 未找到 xray 可执行文件"; exit 1; }

XRAY_DIR="/usr/local/etc/xray"
MAIN_CFG="${XRAY_DIR}/config.json"
if [[ ! -f "$MAIN_CFG" ]]; then
  echo "❌ 未找到主 VLESS 配置 ${MAIN_CFG}，请先执行 onekey_reality_ipv4.sh" >&2
  exit 1
fi

mapfile -t arr < <(python3 - "$MAIN_CFG" << 'PY'
import json,sys
cfg=json.load(open(sys.argv[1]))
ibs=cfg.get("inbounds",[])
if not ibs:
    print("")
    print("")
    print("")
else:
    ib=ibs[0]
    rs=ib.get("streamSettings",{}).get("realitySettings",{})
    pkey=rs.get("privateKey","")
    dest=rs.get("dest","")
    sns=rs.get("serverNames",[])
    sni=sns[0] if sns else ""
    print(pkey)
    print(dest)
    print(sni)
PY
)

REALITY_PRIVATE_KEY="${arr[0]:-}"
REALITY_DEST="${arr[1]:-}"
REALITY_SNI="${arr[2]:-}"

if [[ -z "$REALITY_PRIVATE_KEY" || -z "$REALITY_DEST" ]]; then
  echo "❌ 无法从 ${MAIN_CFG} 解析 Reality 配置" >&2
  exit 1
fi
if [[ -z "$REALITY_SNI" ]]; then
  REALITY_SNI="${REALITY_DEST%%:*}"
fi

PBK_INPUT="${PBK:-}"
PBK="$PBK_INPUT"

if [[ -z "$PBK" && -f /root/vless_reality_vision_url.txt ]]; then
  LINE=$(sed -n '1p' /root/vless_reality_vision_url.txt 2>/dev/null || true)
  if [[ -n "$LINE" ]]; then
    PBK=$(grep -o 'pbk=[^&]*' <<< "$LINE" | head -n1 | cut -d= -f2)
  fi
fi

if [[ -z "$PBK" ]]; then
  echo "❌ 未能获取 Reality PublicKey (pbk)。" >&2
  echo "   解决方法：" >&2
  echo "   1) 先执行：bash /root/onekey_reality_ipv4.sh（会生成 /root/vless_reality_vision_url.txt）" >&2
  echo "   2) 或手动传入：PBK=<你的publicKey> D=600 vless_mktemp.sh" >&2
  exit 1
fi

# ✅ 关键：归一化 pbk：先 urldecode，再生成链接时 urlencode
PBK_RAW="$(urldecode "$PBK")"
PBK="$PBK_RAW"

PORT_START="${PORT_START:-40000}"
PORT_END="${PORT_END:-50050}"

if ! [[ "$PORT_START" =~ ^[0-9]+$ ]] || ! [[ "$PORT_END" =~ ^[0-9]+$ ]] || \
   (( PORT_START < 1 || PORT_END > 65535 || PORT_START >= PORT_END )); then
  echo "❌ PORT_START/PORT_END 无效（需要 1<=start<end<=65535），当前: ${PORT_START}-${PORT_END}" >&2
  exit 1
fi

declare -A USED_PORTS=()
while read -r p; do
  [[ -n "$p" ]] && USED_PORTS["$p"]=1
done < <(ss -ltnH 2>/dev/null | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/')

shopt -s nullglob
for f in "${XRAY_DIR}"/vless-temp-*.meta; do
  p="$(awk -F= '$1=="PORT"{sub($1"=","");print;exit}' "$f" 2>/dev/null || true)"
  [[ "$p" =~ ^[0-9]+$ ]] && USED_PORTS["$p"]=1
done
shopt -u nullglob

PORT="$PORT_START"
while (( PORT <= PORT_END )); do
  if [[ -z "${USED_PORTS[$PORT]+x}" ]]; then
    break
  fi
  PORT=$((PORT+1))
done
(( PORT <= PORT_END )) || { echo "❌ 在 ${PORT_START}-${PORT_END} 范围内没有空闲 TCP 端口了。" >&2; exit 1; }

UUID="$("$XRAY_BIN" uuid)"
SHORT_ID="$(openssl rand -hex 8)"
TAG="vless-temp-$(date +%Y%m%d%H%M%S)-$(openssl rand -hex 2)"
CFG="${XRAY_DIR}/${TAG}.json"
META="${XRAY_DIR}/${TAG}.meta"

SERVER_ADDR="$(get_public_ipv4 || true)"
if [[ -z "$SERVER_ADDR" ]]; then
  echo "❌ 无法检测到可用的公网 IPv4（可能被阻断/在 NAT 后），无法生成可用链接。" >&2
  exit 1
fi

NOW=$(date +%s)
EXP=$((NOW + D))

mkdir -p "$XRAY_DIR"

cat >"$CFG" <<CFG
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${UUID}", "flow": "xtls-rprx-vision" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${REALITY_DEST}",
          "xver": 0,
          "serverNames": [ "${REALITY_SNI}" ],
          "privateKey": "${REALITY_PRIVATE_KEY}",
          "shortIds": [ "${SHORT_ID}" ]
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
CFG

# meta 写入前做最小约束，避免多行污染（后续读取也不会 source）
sanitize_one_line "$TAG" || { echo "❌ bad TAG"; exit 1; }
sanitize_one_line "$UUID" || { echo "❌ bad UUID"; exit 1; }
sanitize_one_line "$SERVER_ADDR" || { echo "❌ bad SERVER_ADDR"; exit 1; }
sanitize_one_line "$REALITY_DEST" || { echo "❌ bad REALITY_DEST"; exit 1; }
sanitize_one_line "$REALITY_SNI" || { echo "❌ bad REALITY_SNI"; exit 1; }
sanitize_one_line "$SHORT_ID" || { echo "❌ bad SHORT_ID"; exit 1; }
sanitize_one_line "$PBK" || { echo "❌ bad PBK"; exit 1; }

cat >"$META" <<M
TAG=$TAG
UUID=$UUID
PORT=$PORT
SERVER_ADDR=$SERVER_ADDR
EXPIRE_EPOCH=$EXP
REALITY_DEST=$REALITY_DEST
REALITY_SNI=$REALITY_SNI
SHORT_ID=$SHORT_ID
PBK=$PBK
M

chmod 600 "$CFG" "$META" 2>/dev/null || true

UNIT="/etc/systemd/system/${TAG}.service"
cat >"$UNIT" <<U
[Unit]
Description=Temp VLESS $TAG
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/vless_run_temp.sh $TAG $CFG
ExecStopPost=/usr/local/sbin/vless_cleanup_one.sh $TAG
Restart=no
SuccessExitStatus=124 143

[Install]
WantedBy=multi-user.target
U

systemctl daemon-reload

if ! systemctl enable "$TAG".service >/dev/null 2>&1; then
  echo "⚠️ 无法 enable $TAG.service（可以稍后手动 systemctl enable $TAG.service）"
fi

if ! systemctl start "$TAG".service; then
  echo "❌ 启动临时 VLESS 服务失败，正在回滚..."
  # ✅ 修复：回滚清理时带 VLESS_LOCK_HELD=1（避免锁重入导致清理失效）
  VLESS_LOCK_HELD=1 FORCE=1 /usr/local/sbin/vless_cleanup_one.sh "$TAG" || true
  exit 1
fi

E_STR=$(TZ=Asia/Shanghai date -d "@$EXP" '+%F %T')
PBK_Q="$(urlencode "$PBK")"
VLESS_URL="vless://${UUID}@${SERVER_ADDR}:${PORT}?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&sni=${REALITY_SNI}&fp=chrome&pbk=${PBK_Q}&sid=${SHORT_ID}#${TAG}"

echo "✅ 新 VLESS 临时节点: $TAG
地址: ${SERVER_ADDR}:${PORT}
UUID: ${UUID}
有效期: ${D} 秒
到期(北京时间): ${E_STR}
VLESS 订阅链接: ${VLESS_URL}"
MK
chmod +x /usr/local/sbin/vless_mktemp.sh

########################################
# 4) GC：按 meta 过期时间清理
########################################
cat >/usr/local/sbin/vless_gc.sh << 'GC'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
shopt -s nullglob

meta_get() { local file="$1" key="$2"; awk -F= -v k="$key" '$1==k {sub($1"=",""); print; exit}' "$file"; }

LOCK="/run/vless-temp.lock"
exec 9>"$LOCK"
flock -n 9 || exit 0

XRAY_DIR="/usr/local/etc/xray"
NOW=$(date +%s)

for META in "$XRAY_DIR"/vless-temp-*.meta; do
  TAG="$(meta_get "$META" TAG || true)"
  EXPIRE_EPOCH="$(meta_get "$META" EXPIRE_EPOCH || true)"

  [[ -z "${TAG:-}" ]] && continue
  [[ -z "${EXPIRE_EPOCH:-}" || ! "${EXPIRE_EPOCH}" =~ ^[0-9]+$ ]] && continue

  if (( EXPIRE_EPOCH <= NOW )); then
    # ✅ 修复：调用 cleanup 时加 VLESS_LOCK_HELD=1（避免锁重入导致清理失效）
    VLESS_LOCK_HELD=1 /usr/local/sbin/vless_cleanup_one.sh "$TAG" || true
  fi
done
GC
chmod +x /usr/local/sbin/vless_gc.sh

cat >/etc/systemd/system/vless-gc.service << 'GCSVC'
[Unit]
Description=VLESS Temp Nodes Garbage Collector
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vless_gc.sh
GCSVC

cat >/etc/systemd/system/vless-gc.timer << 'GCTMR'
[Unit]
Description=Run VLESS GC every 15 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
GCTMR

systemctl daemon-reload
systemctl enable --now vless-gc.timer || true

########################################
# 5) 审计脚本（主 VLESS + 临时 VLESS）
########################################
cat >/usr/local/sbin/vless_audit.sh << 'AUDIT'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
shopt -s nullglob

meta_get() { local file="$1" key="$2"; awk -F= -v k="$key" '$1==k {sub($1"=",""); print; exit}' "$file"; }

MAIN_VLESS="${MAIN_VLESS:-xray.service}"
XRAY_DIR="/usr/local/etc/xray"
MAIN_CFG="${XRAY_DIR}/config.json"

printf "%-40s %-10s %-6s %-12s %-10s %-20s\n" "NAME" "STATE" "PORT" "LEFT" "NOTE" "EXPIRE(China)"

get_main_port() {
  if [[ -f "$MAIN_CFG" ]]; then
    python3 - "$MAIN_CFG" <<'PY' 2>/dev/null || true
import json,sys
try:
    cfg=json.load(open(sys.argv[1]))
    ibs=cfg.get("inbounds",[])
    if ibs and isinstance(ibs[0], dict):
        p=ibs[0].get("port","")
        if isinstance(p,int):
            print(p); sys.exit(0)
        if isinstance(p,str) and p.isdigit():
            print(p); sys.exit(0)
except Exception:
    pass
print("443")
PY
  else
    echo "443"
  fi
}

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

MAIN_PORT="$(get_main_port)"
print_main "$MAIN_VLESS" "$MAIN_PORT" "vless-main"

for META in "$XRAY_DIR"/vless-temp-*.meta; do
  TAG="$(meta_get "$META" TAG || true)"
  PORT="$(meta_get "$META" PORT || true)"
  EXPIRE_EPOCH="$(meta_get "$META" EXPIRE_EPOCH || true)"

  [[ -z "${TAG:-}" || -z "${PORT:-}" ]] && continue

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

  printf "%-40s %-10s %-6s %-12s %-10s %-20s\n" "$NAME" "$STATE" "$PORT_STR" "$LEFT_STR" "vless-temp" "$EXPIRE_AT_FMT"
done
AUDIT
chmod +x /usr/local/sbin/vless_audit.sh

########################################
# 6) 清空全部临时 VLESS 节点（强制）
########################################
cat >/usr/local/sbin/vless_clear_all.sh << 'CLR'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
shopt -s nullglob

meta_get() { local file="$1" key="$2"; awk -F= -v k="$key" '$1==k {sub($1"=",""); print; exit}' "$file"; }

LOCK="/run/vless-temp.lock"
exec 9>"$LOCK"
flock -w 10 9

XRAY_DIR="/usr/local/etc/xray"

echo "== VLESS 临时节点批量清理开始 =="

META_FILES=("$XRAY_DIR"/vless-temp-*.meta)
if (( ${#META_FILES[@]} == 0 )); then
  echo "当前没有任何临时 VLESS 节点。"
  exit 0
fi

for META in "${META_FILES[@]}"; do
  echo "--- 发现 meta: ${META}"
  TAG="$(meta_get "$META" TAG || true)"

  if [[ -z "${TAG:-}" ]]; then
    echo "  ⚠️  跳过：${META} 中没有 TAG"
    continue
  fi

  echo "  -> 清理 ${TAG}"
  # ✅ 修复：调用 cleanup 时加 VLESS_LOCK_HELD=1（避免锁重入导致清理失效）
  VLESS_LOCK_HELD=1 FORCE=1 /usr/local/sbin/vless_cleanup_one.sh "$TAG" || true
done

systemctl daemon-reload >/dev/null 2>&1 || true
echo "✅ 所有临时 VLESS 节点清理流程已执行完毕。"
CLR
chmod +x /usr/local/sbin/vless_clear_all.sh

echo "✅ VLESS 临时节点 + 审计 + GC 脚本部署/覆盖完成（绝对时间 TTL）。"

cat <<USE
============ 使用方法（VLESS 临时节点 / 审计） ============

1) 新建一个临时 VLESS 节点（例如 600 秒）：
   D=600 vless_mktemp.sh

   # 可自定义临时端口范围（默认 40000-50050）：
   PORT_START=40000 PORT_END=60000 D=600 vless_mktemp.sh

   # 如 pbk 获取失败，可手动传入（可传原始或已编码，脚本会归一化）：
   PBK=<publicKey> D=600 vless_mktemp.sh

   - 创建时记录 EXPIRE_EPOCH = 创建瞬间 + D 秒
   - 之后每次重启都会按 EXPIRE_EPOCH 计算剩余 TTL

2) 查看主 VLESS + 所有临时节点状态（按绝对时间计算剩余）：
   vless_audit.sh

3) 正常情况下：
   - vless_run_temp.sh 使用 timeout(剩余秒数) 控制节点寿命
   - 进程退出后 ExecStopPost -> vless_cleanup_one.sh 清理已过期节点
   - vless-gc.timer 作为兜底，定时扫描 EXPIRE_EPOCH 过期节点

4) 手动强制清空所有临时节点（无视是否过期）：
   vless_clear_all.sh

5) 强制干掉某一个未过期节点示例：
   FORCE=1 vless_cleanup_one.sh vless-temp-YYYYMMDDHHMMSS-ABCD
==========================================================
USE
EOF

  chmod +x /root/vless_temp_audit_ipv4_all.sh
}

# ------------------ 4. nftables 配额系统（TCP 双向，仅统计 VPS<->用户） ------------------

install_port_quota() {
  echo "🧩 部署 TCP 双向配额系统（nftables，仅统计 VPS<->用户，不包含网站流量）..."
  mkdir -p /etc/portquota

  systemctl enable --now nftables >/dev/null 2>&1 || true

  if ! nft list table inet portquota >/dev/null 2>&1; then
    nft add table inet portquota
  fi
  if ! nft list chain inet portquota down_out >/dev/null 2>&1; then
    nft add chain inet portquota down_out '{ type filter hook output priority filter; policy accept; }'
  fi
  if ! nft list chain inet portquota up_in >/dev/null 2>&1; then
    nft add chain inet portquota up_in '{ type filter hook input priority filter; policy accept; }'
  fi

  cat >/usr/local/sbin/pq_save.sh <<'SAVE'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

LOCK="/run/portquota.lock"
if [[ "${PQ_LOCK_HELD:-0}" != "1" ]]; then
  exec 9>"$LOCK"
  flock -w 10 9
fi

OUT="/etc/nftables.d/portquota.nft"
LOG="/var/log/pq-save.log"

mkdir -p /etc/nftables.d

if ! nft list table inet portquota > "${OUT}.tmp" 2>/dev/null; then
  echo "$(date '+%F %T %Z') [pq-save] export portquota failed" >> "$LOG"
  rm -f "${OUT}.tmp" 2>/dev/null || true
  exit 1
fi

mv "${OUT}.tmp" "$OUT"
echo "$(date '+%F %T %Z') [pq-save] saved $OUT" >> "$LOG"

# 确保 /etc/nftables.conf include（Debian 默认通常有，但这里保证一次）
if [[ -f /etc/nftables.conf ]]; then
  if ! grep -qE 'include "/etc/nftables\.d/\*\.nft"' /etc/nftables.conf 2>/dev/null; then
    printf '\ninclude "/etc/nftables.d/*.nft"\n' >> /etc/nftables.conf
  fi
fi
SAVE
  chmod +x /usr/local/sbin/pq_save.sh

  /usr/local/sbin/pq_save.sh >/dev/null 2>&1 || true

  cat >/usr/local/sbin/pq_add.sh <<'ADD'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

PORT="${1:-}"; GIB="${2:-}"
if [[ -z "$PORT" || -z "$GIB" ]]; then
  echo "用法: pq_add.sh <端口> <GiB(整数)>" >&2; exit 1
fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || ((PORT < 1 || PORT > 65535)); then
  echo "❌ 端口必须是 1-65535 的整数" >&2; exit 1
fi
if ! [[ "$GIB" =~ ^[0-9]+$ ]]; then
  echo "❌ GiB 需为整数" >&2; exit 1
fi

BYTES=$((GIB * 1024 * 1024 * 1024))

LOCK="/run/portquota.lock"
exec 9>"$LOCK"
flock -w 10 9

if ! nft list table inet portquota >/dev/null 2>&1; then
  nft add table inet portquota
fi
if ! nft list chain inet portquota down_out >/dev/null 2>&1; then
  nft add chain inet portquota down_out '{ type filter hook output priority filter; policy accept; }'
fi
if ! nft list chain inet portquota up_in >/dev/null 2>&1; then
  nft add chain inet portquota up_in '{ type filter hook input priority filter; policy accept; }'
fi

# ✅ 精确匹配 comment，避免 80/8080 误删
nft -a list chain inet portquota down_out 2>/dev/null | \
 awk -v p="$PORT" '
   $0 ~ "comment \"pq-count-out-"p"\"" ||
   $0 ~ "comment \"pq-drop-out-"p"\""  {print $NF}
 ' | while read -r h; do
   nft delete rule inet portquota down_out handle "$h" 2>/dev/null || true
 done

nft -a list chain inet portquota up_in 2>/dev/null | \
 awk -v p="$PORT" '
   $0 ~ "comment \"pq-count-in-"p"\"" ||
   $0 ~ "comment \"pq-drop-in-"p"\""  {print $NF}
 ' | while read -r h; do
   nft delete rule inet portquota up_in handle "$h" 2>/dev/null || true
 done

nft delete counter inet portquota "pq_out_$PORT" 2>/dev/null || true
nft delete counter inet portquota "pq_in_$PORT" 2>/dev/null || true
nft delete quota   inet portquota "pq_quota_$PORT" 2>/dev/null || true

nft add counter inet portquota "pq_out_$PORT"
nft add counter inet portquota "pq_in_$PORT"
nft add quota inet portquota "pq_quota_$PORT" { over "$BYTES" bytes }

# ✅ 先 quota over drop，再 counter（修复超额后统计爆炸）
nft add rule inet portquota down_out tcp sport "$PORT" \
  quota name "pq_quota_$PORT" drop comment "pq-drop-out-$PORT"
nft add rule inet portquota down_out tcp sport "$PORT" \
  counter name "pq_out_$PORT" comment "pq-count-out-$PORT"

nft add rule inet portquota up_in tcp dport "$PORT" \
  quota name "pq_quota_$PORT" drop comment "pq-drop-in-$PORT"
nft add rule inet portquota up_in tcp dport "$PORT" \
  counter name "pq_in_$PORT" comment "pq-count-in-$PORT"

cat >/etc/portquota/pq-"$PORT".meta <<M
PORT=$PORT
LIMIT_BYTES=$BYTES
LIMIT_GIB=$GIB
MODE=quota
M

PQ_LOCK_HELD=1 /usr/local/sbin/pq_save.sh
systemctl enable --now nftables >/dev/null 2>&1 || true

echo "✅ 已为端口 $PORT 设置限额 ${GIB}GiB（统计=VPS<->用户 双向合计；网站流量不计）"
echo "   统计口径："
echo "   - VPS->用户：output 链 tcp sport=$PORT"
echo "   - 用户->VPS： input 链 tcp dport=$PORT"
ADD
  chmod +x /usr/local/sbin/pq_add.sh

  cat >/usr/local/sbin/pq_del.sh <<'DEL'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

PORT="${1:-}"
if [[ -z "$PORT" ]]; then echo "用法: pq_del.sh <端口>" >&2; exit 1; fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || ((PORT < 1 || PORT > 65535)); then
  echo "❌ 端口必须是 1-65535 的整数" >&2; exit 1
fi

LOCK="/run/portquota.lock"
exec 9>"$LOCK"
flock -w 10 9

if nft list chain inet portquota down_out >/dev/null 2>&1; then
  nft -a list chain inet portquota down_out 2>/dev/null | \
   awk -v p="$PORT" '
     $0 ~ "comment \"pq-count-out-"p"\"" ||
     $0 ~ "comment \"pq-drop-out-"p"\""  {print $NF}
   ' | while read -r h; do
     nft delete rule inet portquota down_out handle "$h" 2>/dev/null || true
   done
fi

if nft list chain inet portquota up_in >/dev/null 2>&1; then
  nft -a list chain inet portquota up_in 2>/dev/null | \
   awk -v p="$PORT" '
     $0 ~ "comment \"pq-count-in-"p"\"" ||
     $0 ~ "comment \"pq-drop-in-"p"\""  {print $NF}
   ' | while read -r h; do
     nft delete rule inet portquota up_in handle "$h" 2>/dev/null || true
   done
fi

nft delete counter inet portquota "pq_out_$PORT" 2>/dev/null || true
nft delete counter inet portquota "pq_in_$PORT" 2>/dev/null || true
nft delete quota   inet portquota "pq_quota_$PORT" 2>/dev/null || true

rm -f /etc/portquota/pq-"$PORT".meta
PQ_LOCK_HELD=1 /usr/local/sbin/pq_save.sh
systemctl enable --now nftables >/dev/null 2>&1 || true

echo "✅ 已删除端口 $PORT 的配额（双向统计/限额）"
DEL
  chmod +x /usr/local/sbin/pq_del.sh

  cat >/usr/local/sbin/pq_audit.sh <<'AUDIT'
#!/usr/bin/env bash
# 🔍 实时审计 nft quota（仅统计 VPS<->用户 双向合计，不包含网站流量）
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
shopt -s nullglob

meta_get() { local file="$1" key="$2"; awk -F= -v k="$key" '$1==k {sub($1"=",""); print; exit}' "$file"; }

printf "%-8s %-8s %-12s %-12s %-12s %-12s %-8s %-10s\n" \
  "PORT" "STATE" "DOWN(GiB)" "UP(GiB)" "TOTAL(GiB)" "LIMIT(GiB)" "PERCENT" "MODE"

get_counter_bytes() {
  local obj="$1"
  nft list counter inet portquota "$obj" 2>/dev/null \
    | awk '/bytes/{for(i=1;i<=NF;i++)if($i=="bytes"){print $(i+1);exit}}'
}

get_quota_used_bytes() {
  local obj="$1"
  nft list quota inet portquota "$obj" 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i=="used"){print $(i+1); exit}}'
}

for META in /etc/portquota/pq-*.meta; do
  PORT="$(meta_get "$META" PORT || true)"
  LIMIT_BYTES="$(meta_get "$META" LIMIT_BYTES || true)"
  MODE="$(meta_get "$META" MODE || true)"

  PORT="${PORT:-}"; [[ -z "$PORT" ]] && continue
  LIMIT_BYTES="${LIMIT_BYTES:-0}"
  MODE="${MODE:-quota}"

  OUT_OBJ="pq_out_${PORT}"
  IN_OBJ="pq_in_${PORT}"
  QUOTA_OBJ="pq_quota_${PORT}"

  OUT_B="$(get_counter_bytes "$OUT_OBJ" || true)"; [[ -z "$OUT_B" ]] && OUT_B=0
  IN_B="$(get_counter_bytes "$IN_OBJ"  || true)"; [[ -z "$IN_B"  ]] && IN_B=0
  TOTAL_B=$((OUT_B + IN_B))

  DOWN_GIB="$(awk -v b="$OUT_B" 'BEGIN{printf "%.2f",b/1024/1024/1024}')"
  UP_GIB="$(awk -v b="$IN_B"  'BEGIN{printf "%.2f",b/1024/1024/1024}')"
  TOTAL_GIB="$(awk -v b="$TOTAL_B" 'BEGIN{printf "%.2f",b/1024/1024/1024}')"

  if [[ "$LIMIT_BYTES" =~ ^[0-9]+$ ]] && (( LIMIT_BYTES > 0 )); then
    LIMIT_GIB="$(awk -v b="$LIMIT_BYTES" 'BEGIN{printf "%.2f",b/1024/1024/1024}')"
  else
    LIMIT_BYTES=0
    LIMIT_GIB="0.00"
  fi

  STATE="ok"
  if [[ "$MODE" == "quota" ]] && (( LIMIT_BYTES > 0 )); then
    QUOTA_USED_B="$(get_quota_used_bytes "$QUOTA_OBJ" 2>/dev/null || true)"
    if [[ "$QUOTA_USED_B" =~ ^[0-9]+$ ]] && (( QUOTA_USED_B >= LIMIT_BYTES )); then
      STATE="dropped"
    elif (( TOTAL_B >= LIMIT_BYTES )); then
      STATE="dropped"
    fi
  elif [[ "$MODE" != "quota" || "$LIMIT_BYTES" == "0" ]]; then
    STATE="track"
  fi

  if (( LIMIT_BYTES > 0 )); then
    USED_FOR_PCT="$TOTAL_B"
    if [[ "$STATE" == "dropped" ]]; then
      USED_FOR_PCT="$LIMIT_BYTES"
    elif (( USED_FOR_PCT > LIMIT_BYTES )); then
      USED_FOR_PCT="$LIMIT_BYTES"
    fi
    PCT="$(awk -v u="$USED_FOR_PCT" -v l="$LIMIT_BYTES" 'BEGIN{printf "%.1f%%",(u*100.0)/l}')"
  else
    PCT="N/A"
  fi

  printf "%-8s %-8s %-12s %-12s %-12s %-12s %-8s %-10s\n" \
    "$PORT" "$STATE" "$DOWN_GIB" "$UP_GIB" "$TOTAL_GIB" "$LIMIT_GIB" "$PCT" "$MODE"
done
AUDIT
  chmod +x /usr/local/sbin/pq_audit.sh

  cat >/etc/systemd/system/pq-save.service <<'PQSVC'
[Unit]
Description=Save nftables portquota table (with counters/quotas)

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/pq_save.sh
PQSVC

  cat >/etc/systemd/system/pq-save.timer <<'PQTMR'
[Unit]
Description=Periodically save nftables portquota snapshot

[Timer]
OnBootSec=30s
OnUnitActiveSec=300s
Persistent=true

[Install]
WantedBy=timers.target
PQTMR

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now pq-save.timer >/dev/null 2>&1 || true

  cat <<USE
============ 使用方法（TCP 双向配额 / 审计，仅统计 VPS<->用户，建议用于 VLESS 端口） ============

1) 为端口添加配额（例如限制 443 端口 总计 500GiB，双向合计）：
   pq_add.sh 443 500

   # 临时 VLESS 节点端口（例如 40000）：
   pq_add.sh 40000 50

2) 查看所有端口使用情况（下行/上行/合计）：
   pq_audit.sh

3) 删除某个端口的配额：
   pq_del.sh 40000

统计口径说明：
- 仅统计“用户 <-> VPS”这条 VLESS TCP 连接的流量：
  - VPS -> 用户：hook output，匹配 tcp sport = 监听端口
  - 用户 -> VPS：hook input， 匹配 tcp dport = 监听端口
- 不统计“VPS <-> 网站”的转发流量：
  因为 VPS 访问网站的连接使用临时源端口，不会命中上述 sport/dport = 监听端口的匹配

持久化说明（更安全）：
- 每次 add/del 会导出 inet portquota 表到 /etc/nftables.d/portquota.nft
- pq-save.timer 每 5 分钟保存一次快照（含 counters/quotas 的 used，如 nft 输出支持重载）
- 不覆盖 /etc/nftables.conf，不 flush 全局 ruleset，避免破坏你已有防火墙
==========================================================
USE
}

# ------------------ 5. 日志轮转（保留 2 天） ------------------

install_logrotate_rules() {
  echo "🧩 写入 logrotate 规则（保留 2 天，压缩）..."
  cat >/etc/logrotate.d/portquota-vless <<'LR'
/var/log/pq-save.log /var/log/vless-gc.log {
    daily
    rotate 2
    maxage 2
    missingok
    notifempty
    compress
    delaycompress
    dateext
    create 0640 root adm
}
LR
}

# ------------------ 6. systemd-journald 清理（保留 2 天） ------------------

install_journal_vacuum() {
  echo "🧩 设置 systemd journal 自动清理（保留 2 天）..."
  cat >/etc/systemd/system/journal-vacuum.service <<'SVC'
[Unit]
Description=Vacuum systemd journal (keep 2 days)

[Service]
Type=oneshot
ExecStart=/usr/bin/journalctl --vacuum-time=2d
SVC

  cat >/etc/systemd/system/journal-vacuum.timer <<'TMR'
[Unit]
Description=Daily vacuum systemd journal

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
TMR

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now journal-vacuum.timer >/dev/null 2>&1 || true
}

# ------------------ 主流程 ------------------

main() {
  check_debian12
  need_basic_tools
  download_upstreams

  install_update_all
  install_vless_script
  install_vless_temp_audit
  install_port_quota
  install_logrotate_rules
  install_journal_vacuum

  cat <<'DONE'
==================================================
✅ 所有脚本已生成完毕（适用于 Debian 12）

可用命令一览：

1) 系统更新 + 新内核：
   update-all
   reboot

2) VLESS Reality (IPv4, SNI=www.apple.com) 主节点：
   bash /root/onekey_reality_ipv4.sh

3) VLESS 临时节点 + 审计 + GC（绝对时间 TTL）：
   bash /root/vless_temp_audit_ipv4_all.sh

   # 部署后：
   D=600 vless_mktemp.sh     # 新建 600 秒 VLESS 临时节点
   PORT_START=40000 PORT_END=60000 D=600 vless_mktemp.sh
   PBK=<publicKey> D=600 vless_mktemp.sh

   vless_audit.sh
   vless_clear_all.sh

4) TCP 配额（nftables + 5 分钟保存快照）：
   pq_add.sh 443 500
   pq_add.sh 40000 50
   pq_audit.sh
   pq_del.sh 40000

5) 日志轮转（保留最近 2 天）：
   - /var/log/pq-save.log
   - /var/log/vless-gc.log
   配置文件：/etc/logrotate.d/portquota-vless

6) systemd journal 自动清理（保留 2 天）：
   systemctl status journal-vacuum.timer

所有 SNI/伪装域名已统一为： www.apple.com

🎯 建议顺序：
   1) update-all && reboot
   2) bash /root/onekey_reality_ipv4.sh
   3) bash /root/vless_temp_audit_ipv4_all.sh
      然后 D=xxx vless_mktemp.sh
   4) 需要限额就 pq_add.sh / pq_audit.sh / pq_del.sh
==================================================
DONE
}

main "$@"
