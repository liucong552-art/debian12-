#!/usr/bin/env bash
# Debian 12 一键部署脚本（HY2 改写版）
# - 初始化系统 & 内核
# - Hysteria 2 主节点 (IPv4, 伪装反代到 https://www.apple.com)
# - Hysteria 2 临时节点 + 审计 + GC（绝对时间 TTL）
# - nftables UDP 双向配额系统（仅统计 VPS<->用户，自动持久化 + 5 分钟保存快照）
# - 日志 logrotate：保留最近 2 天
# - systemd journal：自动 vacuum 保留 2 天
#
# ✅ 服务以 root 身份运行
# ✅ 保留直接下载执行风格（不加校验）
#
# 说明：
# - HY2 不是 VLESS Reality 的原地替换，这里改为官方 Hysteria 2 服务端
# - 主节点与临时节点都使用自签证书 + pinSHA256
# - 未认证的 HTTP/3 请求伪装反代到 https://www.apple.com
# - 配额统计从 TCP 改成 UDP（HY2 / QUIC）

set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

UP_BASE="/usr/local/src/debian12-upstream"

# ------------------ 公共函数 ------------------

curl_fs() {
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
  apt-get install -y --no-install-recommends \
    ca-certificates curl wget openssl python3 nftables iproute2 coreutils util-linux logrotate

  local c
  for c in curl openssl python3 nft timeout ss flock awk sed grep; do
    command -v "$c" >/dev/null 2>&1 || { echo "❌ 缺少命令: $c"; exit 1; }
  done
}

download_upstreams() {
  echo "⬇ 下载/更新 上游文件到 ${UP_BASE} ..."
  mkdir -p "$UP_BASE"

  curl_fs "https://get.hy2.sh/" -o "${UP_BASE}/get_hy2.sh"
  chmod +x "${UP_BASE}/get_hy2.sh"

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

# ------------------ 2. HY2 主节点一键 ------------------

install_hy2_script() {
  echo "🧩 写入 /root/onekey_hy2_ipv4.sh ..."
  cat >/root/onekey_hy2_ipv4.sh << 'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
umask 077

UP_BASE="/usr/local/src/debian12-upstream"
HY_BASE="/etc/hysteria"
CERT_DIR="${HY_BASE}/certs"
MAIN_CFG="${HY_BASE}/main.yaml"
MAIN_SVC="/etc/systemd/system/hy2.service"

curl4() {
  curl -4fsS --connect-timeout 3 --max-time 8 --retry 3 --retry-delay 1 "$@"
}

urlencode() {
  python3 - "$1" <<'PY'
import urllib.parse,sys
print(urllib.parse.quote(sys.argv[1], safe=''))
PY
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

install_hysteria_from_local_or_repo() {
  mkdir -p "$UP_BASE"
  local installer="$UP_BASE/get_hy2.sh"
  if [ ! -x "$installer" ]; then
    echo "⬇ 获取 Hysteria 2 安装脚本..."
    curl4 -L "https://get.hy2.sh/" -o "$installer"
    chmod +x "$installer"
  fi

  echo "⚙ 安装 / 更新 Hysteria 2 ..."
  bash "$installer"

  if ! command -v hysteria >/dev/null 2>&1; then
    echo "❌ 未找到 hysteria 可执行文件，请检查安装结果"; exit 1
  fi
}

ensure_self_signed_cert() {
  local ip="$1"
  mkdir -p "$CERT_DIR"

  local crt="${CERT_DIR}/server.crt"
  local key="${CERT_DIR}/server.key"

  if [[ ! -s "$crt" || ! -s "$key" || "${REGENERATE_CERT:-0}" == "1" ]]; then
    echo "🔐 生成自签证书（SAN=IP:${ip}）..."
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$key" \
      -out "$crt" \
      -days 3650 \
      -subj "/CN=${ip}" \
      -addext "subjectAltName = IP:${ip}" >/dev/null 2>&1
  fi

  chmod 600 "$crt" "$key" 2>/dev/null || true
}

get_pin_sha256() {
  local crt="$1"
  openssl x509 -noout -fingerprint -sha256 -in "$crt" | awk -F= '{print toupper($2)}'
}

check_debian12

MASQ_DOMAIN="www.apple.com"
PORT=443
NODE_NAME="HY2-IPv4-APPLE"

SERVER_IP="$(get_public_ipv4 || true)"
if [[ -z "$SERVER_IP" ]]; then
  echo "❌ 无法检测到可用的公网 IPv4（可能被阻断/在 NAT 后）"
  exit 1
fi

echo "服务器 IPv4: $SERVER_IP"
echo "伪装反代:   https://${MASQ_DOMAIN}"
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
echo "=== 2. 安装 / 更新 Hysteria 2 ==="
install_hysteria_from_local_or_repo

# 避免官方默认服务占端口
systemctl stop hysteria-server.service 2>/dev/null || true
systemctl disable hysteria-server.service 2>/dev/null || true

echo
echo "=== 3. 生成认证信息与证书 ==="
AUTH_PASS="$(openssl rand -hex 16)"
ensure_self_signed_cert "$SERVER_IP"

CRT="${CERT_DIR}/server.crt"
KEY="${CERT_DIR}/server.key"
PIN_SHA256="$(get_pin_sha256 "$CRT")"

mkdir -p "$HY_BASE"

if [[ -f "$MAIN_CFG" ]]; then
  cp -a "$MAIN_CFG" "${MAIN_CFG}.bak.$(date +%F-%H%M%S)"
fi

cat >"$MAIN_CFG" <<CONF
listen: 0.0.0.0:${PORT}

tls:
  cert: ${CRT}
  key: ${KEY}

auth:
  type: password
  password: ${AUTH_PASS}

masquerade:
  type: proxy
  proxy:
    url: https://${MASQ_DOMAIN}
    rewriteHost: true

disableUDP: false
udpIdleTimeout: 60s
speedTest: false
CONF

chmod 600 "$MAIN_CFG" 2>/dev/null || true

cat >"$MAIN_SVC" <<SVC
[Unit]
Description=Hysteria 2 Main Service
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$(command -v hysteria) server -c $MAIN_CFG
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable hy2.service >/dev/null 2>&1 || true
systemctl restart hy2.service

sleep 2
if ! systemctl is-active --quiet hy2.service; then
  echo "❌ hy2 启动失败，状态与日志如下：" >&2
  systemctl --no-pager --full status hy2.service >&2 || true
  journalctl -u hy2.service --no-pager -n 120 >&2 || true
  exit 1
fi

systemctl --no-pager --full status hy2.service || true

PIN_Q="$(urlencode "$PIN_SHA256")"
HY2_URL="hy2://${AUTH_PASS}@${SERVER_IP}:${PORT}/?insecure=1&pinSHA256=${PIN_Q}#${NODE_NAME}"

if base64 --help 2>/dev/null | grep -q -- "-w"; then
  echo "$HY2_URL" | base64 -w0 >/root/hy2_subscription_base64.txt
else
  echo "$HY2_URL" | base64 | tr -d '\n' >/root/hy2_subscription_base64.txt
fi
echo "$HY2_URL" >/root/hy2_url.txt

chmod 600 /root/hy2_subscription_base64.txt /root/hy2_url.txt 2>/dev/null || true

echo
echo "================== 节点信息 =================="
echo "$HY2_URL"
echo
echo "Base64 订阅："
cat /root/hy2_subscription_base64.txt
echo
echo "保存位置："
echo "  /root/hy2_url.txt"
echo "  /root/hy2_subscription_base64.txt"
echo "✅ Hysteria 2 (IPv4, 自签证书 + pinSHA256, 伪装 https://${MASQ_DOMAIN}) 安装完成"
EOF

  chmod +x /root/onekey_hy2_ipv4.sh
}

# ------------------ 3. HY2 临时节点 + 审计 + GC（绝对时间 TTL） ------------------

install_hy2_temp_audit() {
  echo "🧩 写入 /root/hy2_temp_audit_ipv4_all.sh 和相关脚本 ..."
  cat >/root/hy2_temp_audit_ipv4_all.sh << 'EOF'
#!/usr/bin/env bash
# HY2 临时节点 + 审计 + GC (IPv4, Hysteria 2) 一键部署 / 覆盖（绝对时间 TTL）
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
umask 077

HY_BASE="/etc/hysteria"
NODE_DIR="${HY_BASE}/nodes"

meta_get() { # meta_get FILE KEY
  local file="$1" key="$2"
  awk -F= -v k="$key" '$1==k {sub($1"=",""); print; exit}' "$file"
}

########################################
# 1) 单节点清理脚本
########################################
cat >/usr/local/sbin/hy2_cleanup_one.sh << 'CLEAN'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

meta_get() { local file="$1" key="$2"; awk -F= -v k="$key" '$1==k {sub($1"=",""); print; exit}' "$file"; }

TAG="${1:?need TAG}"
UNIT_NAME="${TAG}.service"
HY_BASE="/etc/hysteria"
NODE_DIR="${HY_BASE}/nodes"
CFG="${NODE_DIR}/${TAG}.yaml"
META="${NODE_DIR}/${TAG}.meta"
LOG="/var/log/hy2-gc.log"

FORCE="${FORCE:-0}"

LOCK="/run/hy2-temp.lock"
if [[ "${HY2_LOCK_HELD:-0}" != "1" ]]; then
  exec 9>"$LOCK"
  flock -w 10 9 || { echo "[hy2_cleanup_one] lock busy, skip cleanup: ${TAG}"; exit 0; }
fi

if [[ "$FORCE" != "1" && -f "$META" ]]; then
  EXPIRE_EPOCH="$(meta_get "$META" EXPIRE_EPOCH || true)"
  if [[ -n "${EXPIRE_EPOCH:-}" && "$EXPIRE_EPOCH" =~ ^[0-9]+$ ]]; then
    NOW=$(date +%s)
    if (( EXPIRE_EPOCH > NOW )); then
      echo "[hy2_cleanup_one] ${TAG} 未到期 (EXPIRE_EPOCH=${EXPIRE_EPOCH}, NOW=${NOW})，跳过清理"
      exit 0
    fi
  fi
fi

echo "[hy2_cleanup_one] 开始清理: ${TAG}"

ACTIVE_STATE="$(systemctl show -p ActiveState --value "${UNIT_NAME}" 2>/dev/null || echo "")"
if [[ "${ACTIVE_STATE}" == "active" || "${ACTIVE_STATE}" == "activating" ]]; then
  if ! timeout 8 systemctl stop "${UNIT_NAME}" >/dev/null 2>&1; then
    systemctl kill "${UNIT_NAME}" >/dev/null 2>&1 || true
  fi
fi

systemctl disable "${UNIT_NAME}" >/dev/null 2>&1 || true
rm -f "$CFG" "$META" "/etc/systemd/system/${UNIT_NAME}" 2>/dev/null || true
systemctl daemon-reload >/dev/null 2>&1 || true

echo "[hy2_cleanup_one] 完成清理: ${TAG}"
echo "$(date '+%F %T %Z') cleanup ${TAG}" >> "$LOG" 2>/dev/null || true
CLEAN
chmod +x /usr/local/sbin/hy2_cleanup_one.sh

########################################
# 2) 绝对时间 TTL 运行包装脚本
########################################
cat >/usr/local/sbin/hy2_run_temp.sh << 'RUN'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

meta_get() { local file="$1" key="$2"; awk -F= -v k="$key" '$1==k {sub($1"=",""); print; exit}' "$file"; }

TAG="${1:?need TAG}"
CFG="${2:?need config path}"

HY_BIN="$(command -v hysteria || true)"
if [[ -z "$HY_BIN" || ! -x "$HY_BIN" ]]; then
  echo "[hy2_run_temp] hysteria binary not found" >&2
  exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
  echo "[hy2_run_temp] 请安装 coreutils (缺少 timeout)" >&2
  exit 1
fi

HY_BASE="/etc/hysteria"
NODE_DIR="${HY_BASE}/nodes"
META="${NODE_DIR}/${TAG}.meta"
if [[ ! -f "$META" ]]; then
  echo "[hy2_run_temp] meta not found: $META" >&2
  exit 1
fi

EXPIRE_EPOCH="$(meta_get "$META" EXPIRE_EPOCH || true)"
if [[ -z "${EXPIRE_EPOCH:-}" || ! "$EXPIRE_EPOCH" =~ ^[0-9]+$ ]]; then
  echo "[hy2_run_temp] bad EXPIRE_EPOCH in $META" >&2
  exit 1
fi

NOW=$(date +%s)
REMAIN=$((EXPIRE_EPOCH - NOW))
if (( REMAIN <= 0 )); then
  echo "[hy2_run_temp] $TAG already expired (EXPIRE_EPOCH=$EXPIRE_EPOCH, NOW=$NOW)"
  FORCE=1 /usr/local/sbin/hy2_cleanup_one.sh "$TAG" 2>/dev/null || true
  exit 0
fi

echo "[hy2_run_temp] run $TAG for up to ${REMAIN}s (expire at $EXPIRE_EPOCH)"
exec timeout "$REMAIN" "$HY_BIN" server -c "$CFG"
RUN
chmod +x /usr/local/sbin/hy2_run_temp.sh

########################################
# 3) 创建临时 HY2 节点：D=秒 hy2_mktemp.sh
########################################
cat >/usr/local/sbin/hy2_mktemp.sh << 'MK'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

: "${D:?请用 D=秒 hy2_mktemp.sh 方式调用，例如：D=600 hy2_mktemp.sh}"

if ! [[ "$D" =~ ^[0-9]+$ ]] || (( D <= 0 )); then
  echo "❌ D 必须是正整数秒，例如：D=600 hy2_mktemp.sh" >&2
  exit 1
fi

LOCK="/run/hy2-temp.lock"
exec 9>"$LOCK"
flock -w 10 9

curl4() { curl -4fsS --connect-timeout 3 --max-time 8 --retry 3 --retry-delay 1 "$@"; }

urlencode() {
  python3 - "$1" <<'PY'
import urllib.parse,sys
print(urllib.parse.quote(sys.argv[1], safe=''))
PY
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

sanitize_one_line() { [[ "$1" != *$'\n'* && "$1" != *$'\r'* ]]; }

HY_BIN="$(command -v hysteria || true)"
[[ -n "$HY_BIN" && -x "$HY_BIN" ]] || { echo "❌ 未找到 hysteria 可执行文件"; exit 1; }

HY_BASE="/etc/hysteria"
NODE_DIR="${HY_BASE}/nodes"
MAIN_CFG="${HY_BASE}/main.yaml"
CERT_FILE="${HY_BASE}/certs/server.crt"
KEY_FILE="${HY_BASE}/certs/server.key"

[[ -f "$MAIN_CFG" ]] || { echo "❌ 未找到主 HY2 配置 ${MAIN_CFG}，请先执行 /root/onekey_hy2_ipv4.sh"; exit 1; }
[[ -f "$CERT_FILE" && -f "$KEY_FILE" ]] || { echo "❌ 未找到主证书文件"; exit 1; }

PIN_SHA256="$(openssl x509 -noout -fingerprint -sha256 -in "$CERT_FILE" | awk -F= '{print toupper($2)}')"
[[ -n "$PIN_SHA256" ]] || { echo "❌ 计算 pinSHA256 失败"; exit 1; }

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
done < <(ss -lunH 2>/dev/null | awk '{print $5}' | sed -E 's/.*:([0-9]+)$/\1/')

shopt -s nullglob
for f in "${NODE_DIR}"/hy2-temp-*.meta; do
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
(( PORT <= PORT_END )) || { echo "❌ 在 ${PORT_START}-${PORT_END} 范围内没有空闲 UDP 端口了。" >&2; exit 1; }

AUTH_PASS="$(openssl rand -hex 16)"
TAG="hy2-temp-$(date +%Y%m%d%H%M%S)-$(openssl rand -hex 2)"
CFG="${NODE_DIR}/${TAG}.yaml"
META="${NODE_DIR}/${TAG}.meta"

SERVER_ADDR="$(get_public_ipv4 || true)"
if [[ -z "$SERVER_ADDR" ]]; then
  echo "❌ 无法检测到可用的公网 IPv4，无法生成可用链接。" >&2
  exit 1
fi

NOW=$(date +%s)
EXP=$((NOW + D))

mkdir -p "$NODE_DIR"

cat >"$CFG" <<CFG
listen: 0.0.0.0:${PORT}

tls:
  cert: ${CERT_FILE}
  key: ${KEY_FILE}

auth:
  type: password
  password: ${AUTH_PASS}

masquerade:
  type: proxy
  proxy:
    url: https://www.apple.com
    rewriteHost: true

disableUDP: false
udpIdleTimeout: 60s
speedTest: false
CFG

sanitize_one_line "$TAG" || { echo "❌ bad TAG"; exit 1; }
sanitize_one_line "$AUTH_PASS" || { echo "❌ bad AUTH_PASS"; exit 1; }
sanitize_one_line "$SERVER_ADDR" || { echo "❌ bad SERVER_ADDR"; exit 1; }
sanitize_one_line "$PIN_SHA256" || { echo "❌ bad PIN_SHA256"; exit 1; }

cat >"$META" <<M
TAG=$TAG
PORT=$PORT
AUTH_PASS=$AUTH_PASS
SERVER_ADDR=$SERVER_ADDR
EXPIRE_EPOCH=$EXP
PIN_SHA256=$PIN_SHA256
M

chmod 600 "$CFG" "$META" 2>/dev/null || true

UNIT="/etc/systemd/system/${TAG}.service"
cat >"$UNIT" <<U
[Unit]
Description=Temp HY2 $TAG
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/hy2_run_temp.sh $TAG $CFG
ExecStopPost=/usr/local/sbin/hy2_cleanup_one.sh $TAG
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
  echo "❌ 启动临时 HY2 服务失败，正在回滚..."
  HY2_LOCK_HELD=1 FORCE=1 /usr/local/sbin/hy2_cleanup_one.sh "$TAG" || true
  exit 1
fi

E_STR=$(TZ=Asia/Shanghai date -d "@$EXP" '+%F %T')
PIN_Q="$(urlencode "$PIN_SHA256")"
HY2_URL="hy2://${AUTH_PASS}@${SERVER_ADDR}:${PORT}/?insecure=1&pinSHA256=${PIN_Q}#${TAG}"

echo "✅ 新 HY2 临时节点: $TAG
地址: ${SERVER_ADDR}:${PORT}/udp
密码: ${AUTH_PASS}
有效期: ${D} 秒
到期(北京时间): ${E_STR}
HY2 链接: ${HY2_URL}"
MK
chmod +x /usr/local/sbin/hy2_mktemp.sh

########################################
# 4) GC：按 meta 过期时间清理
########################################
cat >/usr/local/sbin/hy2_gc.sh << 'GC'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
shopt -s nullglob

meta_get() { local file="$1" key="$2"; awk -F= -v k="$key" '$1==k {sub($1"=",""); print; exit}' "$file"; }

LOCK="/run/hy2-temp.lock"
exec 9>"$LOCK"
flock -n 9 || exit 0

HY_BASE="/etc/hysteria"
NODE_DIR="${HY_BASE}/nodes"
NOW=$(date +%s)

for META in "$NODE_DIR"/hy2-temp-*.meta; do
  TAG="$(meta_get "$META" TAG || true)"
  EXPIRE_EPOCH="$(meta_get "$META" EXPIRE_EPOCH || true)"

  [[ -z "${TAG:-}" ]] && continue
  [[ -z "${EXPIRE_EPOCH:-}" || ! "${EXPIRE_EPOCH}" =~ ^[0-9]+$ ]] && continue

  if (( EXPIRE_EPOCH <= NOW )); then
    HY2_LOCK_HELD=1 /usr/local/sbin/hy2_cleanup_one.sh "$TAG" || true
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
# 5) 审计脚本（主 HY2 + 临时 HY2）
########################################
cat >/usr/local/sbin/hy2_audit.sh << 'AUDIT'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
shopt -s nullglob

meta_get() { local file="$1" key="$2"; awk -F= -v k="$key" '$1==k {sub($1"=",""); print; exit}' "$file"; }

MAIN_HY2="${MAIN_HY2:-hy2.service}"
HY_BASE="/etc/hysteria"
NODE_DIR="${HY_BASE}/nodes"
MAIN_CFG="${HY_BASE}/main.yaml"

printf "%-40s %-10s %-6s %-12s %-10s %-20s\n" "NAME" "STATE" "PORT" "LEFT" "NOTE" "EXPIRE(China)"

get_main_port() {
  if [[ -f "$MAIN_CFG" ]]; then
    awk -F: '/^listen:[[:space:]]*/{gsub(/[[:space:]]/,"",$0); print $NF; exit}' "$MAIN_CFG" 2>/dev/null || echo "443"
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
print_main "$MAIN_HY2" "$MAIN_PORT" "hy2-main"

for META in "$NODE_DIR"/hy2-temp-*.meta; do
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

  printf "%-40s %-10s %-6s %-12s %-10s %-20s\n" "$NAME" "$STATE" "$PORT_STR" "$LEFT_STR" "hy2-temp" "$EXPIRE_AT_FMT"
done
AUDIT
chmod +x /usr/local/sbin/hy2_audit.sh

########################################
# 6) 清空全部临时 HY2 节点（强制）
########################################
cat >/usr/local/sbin/hy2_clear_all.sh << 'CLR'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
shopt -s nullglob

meta_get() { local file="$1" key="$2"; awk -F= -v k="$key" '$1==k {sub($1"=",""); print; exit}' "$file"; }

LOCK="/run/hy2-temp.lock"
exec 9>"$LOCK"
flock -w 10 9

HY_BASE="/etc/hysteria"
NODE_DIR="${HY_BASE}/nodes"

echo "== HY2 临时节点批量清理开始 =="

META_FILES=("$NODE_DIR"/hy2-temp-*.meta)
if (( ${#META_FILES[@]} == 0 )); then
  echo "当前没有任何临时 HY2 节点。"
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
  HY2_LOCK_HELD=1 FORCE=1 /usr/local/sbin/hy2_cleanup_one.sh "$TAG" || true
done

systemctl daemon-reload >/dev/null 2>&1 || true
echo "✅ 所有临时 HY2 节点清理流程已执行完毕。"
CLR
chmod +x /usr/local/sbin/hy2_clear_all.sh

echo "✅ HY2 临时节点 + 审计 + GC 脚本部署/覆盖完成（绝对时间 TTL）。"

cat <<USE
============ 使用方法（HY2 临时节点 / 审计） ============

1) 新建一个临时 HY2 节点（例如 600 秒）：
   D=600 hy2_mktemp.sh

   # 可自定义临时端口范围（默认 40000-50050）：
   PORT_START=40000 PORT_END=60000 D=600 hy2_mktemp.sh

2) 查看主 HY2 + 所有临时节点状态（按绝对时间计算剩余）：
   hy2_audit.sh

3) 正常情况下：
   - hy2_run_temp.sh 使用 timeout(剩余秒数) 控制节点寿命
   - 进程退出后 ExecStopPost -> hy2_cleanup_one.sh 清理已过期节点
   - hy2-gc.timer 作为兜底，定时扫描 EXPIRE_EPOCH 过期节点

4) 手动强制清空所有临时节点（无视是否过期）：
   hy2_clear_all.sh

5) 强制干掉某一个未过期节点示例：
   FORCE=1 hy2_cleanup_one.sh hy2-temp-YYYYMMDDHHMMSS-ABCD
========================================================
USE
EOF

  chmod +x /root/hy2_temp_audit_ipv4_all.sh
}

# ------------------ 4. nftables 配额系统（UDP 双向，仅统计 VPS<->用户） ------------------

install_port_quota() {
  echo "🧩 部署 UDP 双向配额系统（nftables，仅统计 VPS<->用户，不包含网站流量）..."
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

nft add rule inet portquota down_out udp sport "$PORT" \
  quota name "pq_quota_$PORT" drop comment "pq-drop-out-$PORT"
nft add rule inet portquota down_out udp sport "$PORT" \
  counter name "pq_out_$PORT" comment "pq-count-out-$PORT"

nft add rule inet portquota up_in udp dport "$PORT" \
  quota name "pq_quota_$PORT" drop comment "pq-drop-in-$PORT"
nft add rule inet portquota up_in udp dport "$PORT" \
  counter name "pq_in_$PORT" comment "pq-count-in-$PORT"

cat >/etc/portquota/pq-"$PORT".meta <<M
PORT=$PORT
LIMIT_BYTES=$BYTES
LIMIT_GIB=$GIB
MODE=quota
PROTO=udp
M

PQ_LOCK_HELD=1 /usr/local/sbin/pq_save.sh
systemctl enable --now nftables >/dev/null 2>&1 || true

echo "✅ 已为端口 $PORT 设置限额 ${GIB}GiB（统计=VPS<->用户 UDP 双向合计；网站流量不计）"
echo "   统计口径："
echo "   - VPS->用户：output 链 udp sport=$PORT"
echo "   - 用户->VPS： input 链 udp dport=$PORT"
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

echo "✅ 已删除端口 $PORT 的配额（UDP 双向统计/限额）"
DEL
  chmod +x /usr/local/sbin/pq_del.sh

  cat >/usr/local/sbin/pq_audit.sh <<'AUDIT'
#!/usr/bin/env bash
# 🔍 实时审计 nft quota（仅统计 VPS<->用户 UDP 双向合计，不包含网站流量）
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
============ 使用方法（UDP 双向配额 / 审计，仅统计 VPS<->用户，建议用于 HY2 端口） ============

1) 为端口添加配额（例如限制 443 端口 总计 500GiB，双向合计）：
   pq_add.sh 443 500

   # 临时 HY2 节点端口（例如 40000）：
   pq_add.sh 40000 50

2) 查看所有端口使用情况（下行/上行/合计）：
   pq_audit.sh

3) 删除某个端口的配额：
   pq_del.sh 40000

统计口径说明：
- 仅统计“用户 <-> VPS”这条 HY2 / QUIC / UDP 连接的流量：
  - VPS -> 用户：hook output，匹配 udp sport = 监听端口
  - 用户 -> VPS： hook input， 匹配 udp dport = 监听端口
- 不统计“VPS <-> 网站”的转发流量：
  因为 VPS 访问网站的连接不会使用服务端监听端口作为本地固定端口

持久化说明（更安全）：
- 每次 add/del 会导出 inet portquota 表到 /etc/nftables.d/portquota.nft
- pq-save.timer 每 5 分钟保存一次快照
- 不覆盖 /etc/nftables.conf，不 flush 全局 ruleset，避免破坏你已有防火墙
===========================================================================================
USE
}

# ------------------ 5. 日志轮转（保留 2 天） ------------------

install_logrotate_rules() {
  echo "🧩 写入 logrotate 规则（保留 2 天，压缩）..."
  cat >/etc/logrotate.d/portquota-hy2 <<'LR'
/var/log/pq-save.log /var/log/hy2-gc.log {
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
  install_hy2_script
  install_hy2_temp_audit
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

2) HY2 主节点：
   bash /root/onekey_hy2_ipv4.sh

3) HY2 临时节点 + 审计 + GC（绝对时间 TTL）：
   bash /root/hy2_temp_audit_ipv4_all.sh

   # 部署后：
   D=600 hy2_mktemp.sh
   PORT_START=40000 PORT_END=60000 D=600 hy2_mktemp.sh

   hy2_audit.sh
   hy2_clear_all.sh

4) UDP 配额（nftables + 5 分钟保存快照）：
   pq_add.sh 443 500
   pq_add.sh 40000 50
   pq_audit.sh
   pq_del.sh 40000

5) 日志轮转（保留最近 2 天）：
   - /var/log/pq-save.log
   - /var/log/hy2-gc.log
   配置文件：/etc/logrotate.d/portquota-hy2

6) systemd journal 自动清理（保留 2 天）：
   systemctl status journal-vacuum.timer

🎯 建议顺序：
   1) update-all && reboot
   2) bash /root/onekey_hy2_ipv4.sh
   3) bash /root/hy2_temp_audit_ipv4_all.sh
      然后 D=xxx hy2_mktemp.sh
   4) 需要限额就 pq_add.sh / pq_audit.sh / pq_del.sh
==================================================
DONE
}

main "$@"
