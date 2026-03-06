#!/usr/bin/env bash
# Debian 12 一键部署脚本（HY2 / 普通 ACME / 自定义伪装目标版）
# - 初始化系统 & 内核
# - HY2 主节点：hy2.liucna.com + 普通 ACME + masquerade
# - HY2 临时账号 + 审计 + GC（绝对时间 TTL，同一 443 端口）
# - nftables UDP 双向配额（仅统计 VPS<->用户）
# - 日志 logrotate：保留最近 2 天
# - systemd journal：自动 vacuum 保留 2 天
#
# 特点：
# - 不用 Cloudflare API / DNS API
# - 不依赖 Hysteria trafficStats API 做核心逻辑
# - 默认不开 Salamander（只保留可选开关）
# - 伪装目标 MASQ_URL 必填，不写死官方示例站点
#
# 运行前准备：
# 1) Cloudflare 里 A 记录：
#    hy2 -> 你的 VPS 公网 IPv4
#    并保持 DNS only（灰云）
# 2) 准备两个环境变量：
#    export ACME_EMAIL='你的邮箱'
#    export MASQ_URL='https://你自己选的伪装站点'
#
# 可选环境变量：
#    export ENABLE_SALAMANDER='0'   # 默认 0
#    export SALAMANDER_PASSWORD='你的混淆密码'
#
# 然后执行：
#    bash this_script.sh

set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

UP_BASE="/usr/local/src/debian12-upstream"
HY_DOMAIN="hy2.liucna.com"
HY_LISTEN=":443"

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
  for c in curl openssl python3 nft timeout ss flock awk sed grep base64 systemctl; do
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
  echo "🧩 写入 /root/onekey_hy2_acme.sh ..."
  cat >/root/onekey_hy2_acme.sh << 'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
umask 077

UP_BASE="/usr/local/src/debian12-upstream"
HY_BASE="/etc/hysteria"
BASE_ENV="${HY_BASE}/base.env"
ACCOUNTS_DB="${HY_BASE}/accounts.db"
CFG_FILE="${HY_BASE}/config.yaml"
SERVICE_FILE="/etc/systemd/system/hy2.service"

HY_DOMAIN="hy2.liucna.com"
HY_LISTEN=":443"

ACME_EMAIL="${ACME_EMAIL:-}"
MASQ_URL="${MASQ_URL:-}"
ENABLE_SALAMANDER="${ENABLE_SALAMANDER:-0}"
SALAMANDER_PASSWORD="${SALAMANDER_PASSWORD:-}"

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
    curl -fsSL "https://get.hy2.sh/" -o "$installer"
    chmod +x "$installer"
  fi

  echo "⚙ 安装 / 更新 Hysteria 2 ..."
  bash "$installer"

  if ! command -v hysteria >/dev/null 2>&1; then
    echo "❌ 未找到 hysteria 可执行文件"; exit 1
  fi
}

yaml_quote() {
  python3 - "$1" <<'PY'
import sys
s = sys.argv[1]
print("'" + s.replace("'", "''") + "'")
PY
}

db_get_field_by_id() { # ID FIELD_INDEX
  local id="$1" idx="$2"
  awk -F'|' -v id="$id" -v idx="$idx" '$1==id {print $idx; exit}' "$ACCOUNTS_DB" 2>/dev/null || true
}

check_debian12

if [[ -z "$ACME_EMAIL" ]]; then
  echo "❌ 缺少 ACME_EMAIL 环境变量"
  echo "   示例：export ACME_EMAIL='you@example.com'"
  exit 1
fi

if [[ -z "$MASQ_URL" ]]; then
  echo "❌ 缺少 MASQ_URL 环境变量"
  echo "   示例：export MASQ_URL='https://你自己选的伪装站点'"
  exit 1
fi

if [[ "$ENABLE_SALAMANDER" == "1" && -z "$SALAMANDER_PASSWORD" ]]; then
  echo "❌ ENABLE_SALAMANDER=1 时必须同时提供 SALAMANDER_PASSWORD"
  exit 1
fi

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

systemctl stop hysteria-server.service 2>/dev/null || true
systemctl disable hysteria-server.service 2>/dev/null || true

echo
echo "=== 3. 写入基础目录 / 认证后端 ==="
mkdir -p "$HY_BASE"
chmod 700 "$HY_BASE" 2>/dev/null || true

cat >"$BASE_ENV" <<B
HY_DOMAIN=$HY_DOMAIN
HY_LISTEN=$HY_LISTEN
ACME_EMAIL=$ACME_EMAIL
MASQ_URL=$MASQ_URL
ENABLE_SALAMANDER=$ENABLE_SALAMANDER
SALAMANDER_PASSWORD=$SALAMANDER_PASSWORD
B
chmod 600 "$BASE_ENV"

cat >/usr/local/sbin/hy2_auth_command.sh <<'AUTH'
#!/usr/bin/env bash
set -Eeuo pipefail

DB="/etc/hysteria/accounts.db"

ADDR="${1:-}"
AUTH_STR="${2:-}"
TX_HINT="${3:-0}"

[[ -f "$DB" ]] || exit 1
[[ -n "$AUTH_STR" ]] || exit 1

NOW=$(date +%s)

while IFS='|' read -r ID TOKEN EXPIRE_EPOCH NOTE TYPE; do
  [[ -z "${ID:-}" ]] && continue
  [[ "${ID:0:1}" == "#" ]] && continue

  if [[ "$TOKEN" == "$AUTH_STR" ]]; then
    if [[ "$EXPIRE_EPOCH" =~ ^[0-9]+$ ]]; then
      if (( EXPIRE_EPOCH == 0 || EXPIRE_EPOCH > NOW )); then
        printf '%s\n' "$ID"
        exit 0
      fi
    fi
    exit 1
  fi
done <"$DB"

exit 1
AUTH
chmod 700 /usr/local/sbin/hy2_auth_command.sh

cat >/usr/local/sbin/hy2_show_link.sh <<'SHOW'
#!/usr/bin/env bash
set -Eeuo pipefail

ID="${1:?need ID}"
BASE="/etc/hysteria/base.env"
DB="/etc/hysteria/accounts.db"

env_get() {
  local key="$1"
  awk -F= -v k="$key" '$1==k {sub($1"=",""); print; exit}' "$BASE"
}

[[ -f "$BASE" && -f "$DB" ]] || { echo "❌ 缺少基础文件"; exit 1; }

DOMAIN="$(env_get HY_DOMAIN)"
ENABLE_SALAMANDER="$(env_get ENABLE_SALAMANDER)"
SALAMANDER_PASSWORD="$(env_get SALAMANDER_PASSWORD)"

TOKEN="$(awk -F'|' -v id="$ID" '$1==id {print $2; exit}' "$DB")"
[[ -n "$TOKEN" ]] || { echo "❌ 未找到账号: $ID"; exit 1; }

URL="hy2://${TOKEN}@${DOMAIN}:443/?sni=${DOMAIN}#${ID}"
if [[ "$ENABLE_SALAMANDER" == "1" ]]; then
  URL="hy2://${TOKEN}@${DOMAIN}:443/?sni=${DOMAIN}&obfs=salamander&obfs-password=${SALAMANDER_PASSWORD}#${ID}"
fi

echo "$URL"
SHOW
chmod 700 /usr/local/sbin/hy2_show_link.sh

echo
echo "=== 4. 初始化主账号（如不存在） ==="
if [[ ! -f "$ACCOUNTS_DB" ]]; then
  MAIN_TOKEN="$(openssl rand -hex 16)"
  printf 'main|%s|0|main|main\n' "$MAIN_TOKEN" >"$ACCOUNTS_DB"
  chmod 600 "$ACCOUNTS_DB"
else
  chmod 600 "$ACCOUNTS_DB"
  if ! awk -F'|' '$1=="main" {found=1} END{exit found?0:1}' "$ACCOUNTS_DB"; then
    MAIN_TOKEN="$(openssl rand -hex 16)"
    printf 'main|%s|0|main|main\n' "$MAIN_TOKEN" >>"$ACCOUNTS_DB"
  fi
fi

echo
echo "=== 5. 写入配置文件 ==="
DOMAIN_Q="$(yaml_quote "$HY_DOMAIN")"
EMAIL_Q="$(yaml_quote "$ACME_EMAIL")"
MASQ_Q="$(yaml_quote "$MASQ_URL")"
SALAMANDER_Q="$(yaml_quote "$SALAMANDER_PASSWORD")"

if [[ -f "$CFG_FILE" ]]; then
  cp -a "$CFG_FILE" "${CFG_FILE}.bak.$(date +%F-%H%M%S)"
fi

{
  echo "listen: ${HY_LISTEN}"
  echo
  echo "acme:"
  echo "  domains:"
  echo "    - ${DOMAIN_Q}"
  echo "  email: ${EMAIL_Q}"
  echo
  echo "auth:"
  echo "  type: command"
  echo "  command: /usr/local/sbin/hy2_auth_command.sh"
  echo
  if [[ "$ENABLE_SALAMANDER" == "1" ]]; then
    echo "obfs:"
    echo "  type: salamander"
    echo "  salamander:"
    echo "    password: ${SALAMANDER_Q}"
    echo
  fi
  echo "masquerade:"
  echo "  type: proxy"
  echo "  proxy:"
  echo "    url: ${MASQ_Q}"
  echo "    rewriteHost: true"
  echo
  echo "speedTest: false"
  echo "disableUDP: false"
  echo "udpIdleTimeout: 60s"
} >"$CFG_FILE"

chmod 600 "$CFG_FILE"

echo
echo "=== 6. 写入 systemd 服务 ==="
HY_BIN="$(command -v hysteria)"
cat >"$SERVICE_FILE" <<SVC
[Unit]
Description=Hysteria 2 Main Service
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$HY_BIN server -c $CFG_FILE
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable hy2.service >/dev/null 2>&1 || true
systemctl restart hy2.service

sleep 5
if ! systemctl is-active --quiet hy2.service; then
  echo "❌ hy2 启动失败，状态与日志如下：" >&2
  systemctl --no-pager --full status hy2.service >&2 || true
  journalctl -u hy2.service --no-pager -n 120 >&2 || true
  exit 1
fi

MAIN_URL="$(/usr/local/sbin/hy2_show_link.sh main)"
if base64 --help 2>/dev/null | grep -q -- "-w"; then
  echo "$MAIN_URL" | base64 -w0 >/root/hy2_subscription_base64.txt
else
  echo "$MAIN_URL" | base64 | tr -d '\n' >/root/hy2_subscription_base64.txt
fi
echo "$MAIN_URL" >/root/hy2_main_url.txt

chmod 600 /root/hy2_subscription_base64.txt /root/hy2_main_url.txt 2>/dev/null || true

echo
echo "================== 主节点信息 =================="
echo "$MAIN_URL"
echo
echo "Base64 订阅："
cat /root/hy2_subscription_base64.txt
echo
echo "保存位置："
echo "  /root/hy2_main_url.txt"
echo "  /root/hy2_subscription_base64.txt"
echo "✅ Hysteria 2 主节点安装完成"
EOF

  chmod +x /root/onekey_hy2_acme.sh
}

# ------------------ 3. HY2 临时账号 + 审计 + GC ------------------

install_hy2_temp_audit() {
  echo "🧩 写入 /root/hy2_temp_user_all.sh 和相关脚本 ..."
  cat >/root/hy2_temp_user_all.sh << 'EOF'
#!/usr/bin/env bash
# HY2 临时账号 + 审计 + GC（同一 443 端口 / 绝对时间 TTL）
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
umask 077

HY_BASE="/etc/hysteria"
BASE_ENV="${HY_BASE}/base.env"
ACCOUNTS_DB="${HY_BASE}/accounts.db"
LOG="/var/log/hy2-gc.log"

[[ -f "$BASE_ENV" && -f "$ACCOUNTS_DB" ]] || {
  echo "❌ 未找到 ${BASE_ENV} 或 ${ACCOUNTS_DB}，请先执行：bash /root/onekey_hy2_acme.sh"
  exit 1
}

########################################
# 0) 小工具
########################################
cat >/usr/local/sbin/hy2_env_get.sh << 'GET'
#!/usr/bin/env bash
set -Eeuo pipefail
KEY="${1:?need KEY}"
awk -F= -v k="$KEY" '$1==k {sub($1"=",""); print; exit}' /etc/hysteria/base.env
GET
chmod +x /usr/local/sbin/hy2_env_get.sh

########################################
# 1) 单账号清理
########################################
cat >/usr/local/sbin/hy2_cleanup_one.sh << 'CLEAN'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

ID="${1:?need ID}"
[[ "$ID" != "main" ]] || { echo "❌ 禁止删除 main"; exit 1; }

LOCK="/run/hy2-accounts.lock"
exec 9>"$LOCK"
flock -w 15 9

DB="/etc/hysteria/accounts.db"
TMP="${DB}.tmp"

[[ -f "$DB" ]] || { echo "❌ accounts.db 不存在"; exit 1; }

awk -F'|' -v id="$ID" 'BEGIN{OFS="|"} $1!=id {print $0}' "$DB" >"$TMP"
mv "$TMP" "$DB"
chmod 600 "$DB" 2>/dev/null || true

echo "$(date '+%F %T %Z') cleanup ${ID}" >> /var/log/hy2-gc.log 2>/dev/null || true
echo "✅ 已清理账号: $ID"
CLEAN
chmod +x /usr/local/sbin/hy2_cleanup_one.sh

########################################
# 2) 创建临时账号：D=秒 hy2_mktemp.sh
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

LOCK="/run/hy2-accounts.lock"
exec 9>"$LOCK"
flock -w 15 9

DB="/etc/hysteria/accounts.db"
SHOW_LINK="/usr/local/sbin/hy2_show_link.sh"

[[ -f "$DB" ]] || { echo "❌ accounts.db 不存在"; exit 1; }
[[ -x "$SHOW_LINK" ]] || { echo "❌ hy2_show_link.sh 不存在"; exit 1; }

ID="${ID:-hy2tmp-$(date +%Y%m%d%H%M%S)-$(openssl rand -hex 2)}"
TOKEN="${TOKEN:-$(openssl rand -hex 16)}"
NOTE="${NOTE:-temp}"

[[ "$ID" != "main" ]] || { echo "❌ ID 不能是 main" >&2; exit 1; }

for v in "$ID" "$TOKEN" "$NOTE"; do
  [[ "$v" != *$'\n'* && "$v" != *$'\r'* && "$v" != *'|'* ]] || { echo "❌ 字段含非法字符"; exit 1; }
done

if awk -F'|' -v id="$ID" '$1==id {found=1} END{exit found?0:1}' "$DB"; then
  echo "❌ 账号已存在: $ID" >&2
  exit 1
fi

NOW=$(date +%s)
EXP=$((NOW + D))

printf '%s|%s|%s|%s|temp\n' "$ID" "$TOKEN" "$EXP" "$NOTE" >>"$DB"
chmod 600 "$DB" 2>/dev/null || true

E_STR=$(TZ=Asia/Shanghai date -d "@$EXP" '+%F %T')
URL="$("$SHOW_LINK" "$ID")"

echo "✅ 新 HY2 临时账号: $ID
域名: $(/usr/local/sbin/hy2_env_get.sh HY_DOMAIN):443
Token: $TOKEN
有效期: ${D} 秒
到期(北京时间): ${E_STR}
链接: ${URL}"
MK
chmod +x /usr/local/sbin/hy2_mktemp.sh

########################################
# 3) GC
########################################
cat >/usr/local/sbin/hy2_gc.sh << 'GC'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

LOCK="/run/hy2-accounts.lock"
exec 9>"$LOCK"
flock -n 9 || exit 0

DB="/etc/hysteria/accounts.db"
TMP="${DB}.tmp"

[[ -f "$DB" ]] || exit 0

NOW=$(date +%s)

awk -F'|' -v now="$NOW" '
BEGIN{OFS="|"}
{
  if ($0 ~ /^#/ || NF < 5) { print $0; next }
  id=$1; token=$2; exp=$3; note=$4; typ=$5
  if (typ=="temp" && exp ~ /^[0-9]+$/ && exp > 0 && exp <= now) {
    next
  }
  print $0
}' "$DB" >"$TMP"

mv "$TMP" "$DB"
chmod 600 "$DB" 2>/dev/null || true
echo "$(date '+%F %T %Z') gc run" >> /var/log/hy2-gc.log 2>/dev/null || true
GC
chmod +x /usr/local/sbin/hy2_gc.sh

cat >/etc/systemd/system/hy2-gc.service << 'GCSVC'
[Unit]
Description=HY2 Temp Account Garbage Collector
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/hy2_gc.sh
GCSVC

cat >/etc/systemd/system/hy2-gc.timer << 'GCTMR'
[Unit]
Description=Run HY2 temp account GC every 15 minutes

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
# 4) 审计
########################################
cat >/usr/local/sbin/hy2_audit.sh << 'AUDIT'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

DB="/etc/hysteria/accounts.db"
SVC="hy2.service"

[[ -f "$DB" ]] || { echo "❌ accounts.db 不存在"; exit 1; }

SVC_STATE="$(systemctl is-active "$SVC" 2>/dev/null || echo unknown)"
echo "服务状态: ${SVC_STATE}"
printf "%-28s %-8s %-10s %-12s %-20s\n" "ID" "TYPE" "STATE" "LEFT" "NOTE"

NOW=$(date +%s)

while IFS='|' read -r ID TOKEN EXPIRE_EPOCH NOTE TYPE; do
  [[ -z "${ID:-}" ]] && continue
  [[ "${ID:0:1}" == "#" ]] && continue

  STATE="ok"
  LEFT="-"

  if [[ "$EXPIRE_EPOCH" =~ ^[0-9]+$ ]] && (( EXPIRE_EPOCH > 0 )); then
    REMAIN=$((EXPIRE_EPOCH - NOW))
    if (( REMAIN <= 0 )); then
      STATE="expired"
      LEFT="expired"
    else
      D=$((REMAIN/86400))
      H=$(((REMAIN%86400)/3600))
      M=$(((REMAIN%3600)/60))
      LEFT=$(printf "%02dd%02dh%02dm" "$D" "$H" "$M")
    fi
  fi

  printf "%-28s %-8s %-10s %-12s %-20s\n" "$ID" "$TYPE" "$STATE" "$LEFT" "$NOTE"
done <"$DB"
AUDIT
chmod +x /usr/local/sbin/hy2_audit.sh

########################################
# 5) 清空全部临时账号
########################################
cat >/usr/local/sbin/hy2_clear_all.sh << 'CLR'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

LOCK="/run/hy2-accounts.lock"
exec 9>"$LOCK"
flock -w 15 9

DB="/etc/hysteria/accounts.db"
TMP="${DB}.tmp"

[[ -f "$DB" ]] || { echo "❌ accounts.db 不存在"; exit 1; }

awk -F'|' '
BEGIN{OFS="|"}
($5 != "temp") { print $0 }
' "$DB" >"$TMP"

mv "$TMP" "$DB"
chmod 600 "$DB" 2>/dev/null || true

echo "✅ 所有临时 HY2 账号已清理。"
CLR
chmod +x /usr/local/sbin/hy2_clear_all.sh

echo "✅ HY2 临时账号 + 审计 + GC 已部署完成。"

cat <<USE
============ 使用方法（HY2 临时账号 / 审计） ============

1) 新建一个临时 HY2 账号（例如 600 秒）：
   D=600 hy2_mktemp.sh

   # 自定义 ID / Token / 备注：
   ID=test01 TOKEN=1234567890abcdef1234567890abcdef NOTE=guest D=600 hy2_mktemp.sh

2) 查看主账号 + 所有临时账号状态：
   hy2_audit.sh

3) 正常情况下：
   - hy2-gc.timer 每 15 分钟自动清理到期账号
   - 即使 GC 还没执行，过期账号也会被认证后端直接拒绝

4) 手动强制清空所有临时账号：
   hy2_clear_all.sh

5) 手动清理某一个临时账号：
   hy2_cleanup_one.sh 账号ID

6) 重新查看某个账号的分享链接：
   hy2_show_link.sh 账号ID
========================================================
USE
EOF

  chmod +x /root/hy2_temp_user_all.sh
}

# ------------------ 4. UDP 端口配额（HY2 推荐主要用于 443） ------------------

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
============ 使用方法（UDP 双向配额 / 审计，HY2 推荐主要用于 443） ============

1) 为 443 端口添加配额（例如总计 500GiB，双向合计）：
   pq_add.sh 443 500

2) 查看所有端口使用情况（下行/上行/合计）：
   pq_audit.sh

3) 删除某个端口的配额：
   pq_del.sh 443
=============================================================================
USE
}

# ------------------ 5. 日志轮转（保留 2 天） ------------------

install_logrotate_rules() {
  echo "🧩 写入 logrotate 规则（保留 2 天，压缩）..."
  cat >/etc/logrotate.d/hy2-tools <<'LR'
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

2) HY2 主节点（普通 ACME / 自定义伪装目标）：
   export ACME_EMAIL='你的邮箱'
   export MASQ_URL='https://你自己选的伪装站点'
   # 可选：
   # export ENABLE_SALAMANDER='0'
   # export SALAMANDER_PASSWORD='你的混淆密码'
   bash /root/onekey_hy2_acme.sh

3) HY2 临时账号 + 审计 + GC（同一 443 端口）：
   bash /root/hy2_temp_user_all.sh

   # 部署后：
   D=600 hy2_mktemp.sh
   ID=test01 TOKEN=1234567890abcdef1234567890abcdef NOTE=guest D=600 hy2_mktemp.sh

   hy2_audit.sh
   hy2_clear_all.sh
   hy2_cleanup_one.sh 账号ID
   hy2_show_link.sh 账号ID

4) UDP 端口配额（nftables + 5 分钟保存快照）：
   pq_add.sh 443 500
   pq_audit.sh
   pq_del.sh 443

5) 日志轮转（保留最近 2 天）：
   - /var/log/pq-save.log
   - /var/log/hy2-gc.log
   配置文件：/etc/logrotate.d/hy2-tools

6) systemd journal 自动清理（保留 2 天）：
   systemctl status journal-vacuum.timer

🎯 建议顺序：
   1) update-all && reboot
   2) export ACME_EMAIL='你的邮箱'
   3) export MASQ_URL='https://你自己选的伪装站点'
   4) bash /root/onekey_hy2_acme.sh
   5) bash /root/hy2_temp_user_all.sh
   6) 需要限额就 pq_add.sh 443 500
==================================================
DONE
}

main "$@"
