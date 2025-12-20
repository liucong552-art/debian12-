#!/usr/bin/env bash
# Debian 12 一键部署（修复版）
# - update-all
# - VLESS Reality 主节点（含 Xray API 正确启用：127.0.0.1:10085）
# - 代码2：单进程 + Xray API 动态临时节点（多端口）+ 审计 + GC + 重启恢复
# - nftables TCP 上行配额系统（可选）

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
  codename="$(grep -E "^VERSION_CODENAME=" /etc/os-release 2>/dev/null | cut -d= -f2 || true)"
  if [[ "$codename" != "bookworm" ]]; then
    echo "❌ 本脚本仅适用于 Debian 12 (bookworm)，当前: ${codename:-未知}"
    exit 1
  fi
}

need_basic_tools() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  # util-linux: flock；coreutils: timeout；iproute2: ss/ip；python3: json patch；openssl/curl 必备
  apt-get install -y curl wget openssl python3 coreutils iproute2 util-linux logrotate nftables >/dev/null 2>&1 || \
    apt-get install -y curl wget openssl python3 coreutils iproute2 util-linux >/dev/null 2>&1 || true
}

download_upstreams() {
  echo "⬇ 下载/更新 上游文件到 ${UP_BASE} ..."
  mkdir -p "$UP_BASE"

  curl -fsSL "${REPO_BASE}/xray-install-release.sh" -o "${UP_BASE}/xray-install-release.sh"
  chmod +x "${UP_BASE}/xray-install-release.sh"

  echo "✅ 上游已更新："
  ls -l "$UP_BASE" || true
}

configure_logrotate_2days() {
  # 可选：保证 /var/log 下不会无限涨
  cat >/etc/logrotate.d/vless-tmp-custom <<'EOF'
/var/log/xray/*.log /var/log/vless-*.log /var/log/pq-*.log {
  daily
  rotate 2
  missingok
  notifempty
  compress
  delaycompress
  copytruncate
}
EOF
}

# ------------------ 1. 系统更新 + 新内核 ------------------

install_update_all() {
  echo "🧩 写入 /usr/local/bin/update-all ..."
  cat >/usr/local/bin/update-all <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

check_debian12() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "❌ 请以 root 身份运行"; exit 1
  fi
  local codename
  codename="$(grep -E "^VERSION_CODENAME=" /etc/os-release 2>/dev/null | cut -d= -f2 || true)"
  if [[ "$codename" != "bookworm" ]]; then
    echo "❌ 本脚本仅适用于 Debian 12 (bookworm)，当前为: ${codename:-未知}"
    exit 1
  fi
}

check_debian12
export DEBIAN_FRONTEND=noninteractive

echo "🚀 开始系统更新 (Debian 12 / bookworm)..."
apt-get update -y
apt-get full-upgrade -y
apt-get --purge autoremove -y
apt-get autoclean -y
apt-get clean -y
echo "✅ 软件包更新完成"

echo "🧱 配置 bookworm-backports 仓库..."
BACKPORTS_FILE=/etc/apt/sources.list.d/backports.list
if [[ -f "$BACKPORTS_FILE" ]]; then
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

# ------------------ 2. 主节点：VLESS Reality（含 API 正确启用） ------------------

install_vless_script() {
  echo "🧩 写入 /root/onekey_reality_ipv4.sh（已修复 conditional / API 配置）..."
  cat >/root/onekey_reality_ipv4.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

REPO_BASE="https://raw.githubusercontent.com/liucong552-art/debian12-/main"
UP_BASE="/usr/local/src/debian12-upstream"

XRAY_CFG="/usr/local/etc/xray/config.json"
ENV_FILE="/usr/local/etc/xray/env.conf"

check_debian12() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "❌ 请以 root 身份运行"; exit 1
  fi
  local codename
  codename="$(grep -E "^VERSION_CODENAME=" /etc/os-release 2>/dev/null | cut -d= -f2 || true)"
  if [[ "$codename" != "bookworm" ]]; then
    echo "❌ 仅支持 Debian 12 (bookworm)，当前: ${codename:-未知}"
    exit 1
  fi
}

install_xray_from_local_or_repo() {
  mkdir -p "$UP_BASE"
  local xray_installer="$UP_BASE/xray-install-release.sh"
  if [[ ! -x "$xray_installer" ]]; then
    echo "⬇ 从仓库获取 Xray 安装脚本..."
    curl -fsSL "$REPO_BASE/xray-install-release.sh" -o "$xray_installer"
    chmod +x "$xray_installer"
  fi
  echo "⚙ 安装 / 更新 Xray-core..."
  "$xray_installer" install --without-geodata
  [[ -x /usr/local/bin/xray ]] || { echo "❌ 未找到 /usr/local/bin/xray"; exit 1; }
}

is_private_ip() {
  local ip="$1"
  [[ "$ip" =~ ^10\. ]] && return 0
  [[ "$ip" =~ ^127\. ]] && return 0
  [[ "$ip" =~ ^192\.168\. ]] && return 0
  [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
  return 1
}

# ✅ 修复点：绝不把函数调用塞进 [[ ... ]] 内部
detect_ipv4_public_first() {
  local ip=""
  ip="$(curl -4fsS --connect-timeout 2 --max-time 6 --retry 2 --retry-delay 1 --retry-all-errors https://api.ipify.org || true)"
  if [[ -n "$ip" ]] && ! is_private_ip "$ip"; then
    echo "$ip"; return 0
  fi
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  if [[ -n "$ip" ]] && ! is_private_ip "$ip"; then
    echo "$ip"; return 0
  fi
  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  if [[ -n "$ip" ]] && ! is_private_ip "$ip"; then
    echo "$ip"; return 0
  fi
  echo ""
}

check_debian12

REALITY_DOMAIN="www.apple.com"
PORT=443
NODE_NAME="VLESS-REALITY-IPv4-APPLE"
API_LISTEN="127.0.0.1:10085"

SERVER_IP="$(detect_ipv4_public_first)"
if [[ -z "$SERVER_IP" ]]; then
  echo "❌ 无法检测 IPv4 公网 IP（NAT 场景请手动在 env.conf 里填写 SERVER_ADDR=域名/公网IP）"
  SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
fi

echo "服务器地址(探测): ${SERVER_IP:-未知}"
echo "伪装域名:         $REALITY_DOMAIN"
echo "端口:             $PORT"
echo "API 监听:         $API_LISTEN"
sleep 1

echo "=== 1) 只开启 fq + bbr（其余 sysctl 保持默认）==="
cat >/etc/sysctl.d/99-bbr.conf <<SYS
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
SYS
modprobe tcp_bbr 2>/dev/null || true
sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1 || true
echo "当前: qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown), cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"

echo "=== 2) 安装/更新 xray ==="
install_xray_from_local_or_repo
systemctl stop xray >/dev/null 2>&1 || true

echo "=== 3) UUID + Reality 密钥 ==="
UUID="$(/usr/local/bin/xray uuid)"
KEY_OUT="$(/usr/local/bin/xray x25519)"

PRIVATE_KEY="$(printf '%s\n' "$KEY_OUT" | awk '/^Private(Key| key):/{print $2; if(NF>=3)print $3}' | head -n1)"
PUBLIC_KEY="$(printf '%s\n' "$KEY_OUT" | awk '/^Public(Key| key):/{print $2; if(NF>=3)print $3} /^Password:/{print $2}' | head -n1)"
if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
  echo "❌ 无法解析 Reality 密钥："
  echo "$KEY_OUT"
  exit 1
fi

SHORT_ID="$(openssl rand -hex 8)"

mkdir -p /usr/local/etc/xray
cat >"$XRAY_CFG" <<CONF
{
  "log": { "loglevel": "warning" },

  "api": {
    "tag": "api",
    "listen": "${API_LISTEN}",
    "services": ["HandlerService","LoggerService","StatsService","RoutingService"]
  },

  "stats": {},

  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true
    }
  },

  "inbounds": [
    {
      "tag": "vless-main",
      "listen": "0.0.0.0",
      "port": ${PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${UUID}", "email": "main@vless", "flow": "xtls-rprx-vision" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${REALITY_DOMAIN}:443",
          "xver": 0,
          "serverNames": [ "${REALITY_DOMAIN}" ],
          "privateKey": "${PRIVATE_KEY}",
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
CONF

systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable xray >/dev/null 2>&1 || true
systemctl restart xray
sleep 1

if ! systemctl is-active xray >/dev/null 2>&1; then
  echo "❌ xray 启动失败："
  systemctl status xray --no-pager -n 120 || true
  exit 1
fi

# API 监听自检
if ! ss -lntp 2>/dev/null | grep -qE "127\.0\.0\.1:10085\b"; then
  echo "❌ 未检测到 API 监听 127.0.0.1:10085，请检查配置是否生效"
  exit 1
fi

# 生成链接文件
SERVER_ADDR_FOR_URL="${SERVER_IP:-}"
VLESS_URL="vless://${UUID}@${SERVER_ADDR_FOR_URL}:${PORT}?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&sni=${REALITY_DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}#${NODE_NAME}"

echo "$VLESS_URL" >/root/vless_reality_vision_url.txt
if base64 --help 2>/dev/null | grep -q -- "-w"; then
  echo "$VLESS_URL" | base64 -w0 >/root/v2ray_subscription_base64.txt
else
  echo "$VLESS_URL" | base64 | tr -d '\n' >/root/v2ray_subscription_base64.txt
fi

# 写 env.conf 供 代码2 使用（注意：NAT/域名场景可手工改 SERVER_ADDR）
mkdir -p /usr/local/etc/xray
cat >"$ENV_FILE" <<ENV
# Xray API 地址（代码2 使用）
API_SERVER="127.0.0.1:10085"

# 对外展示地址（NAT/域名/端口映射场景建议手工填域名）
SERVER_ADDR="${SERVER_IP:-}"

# 临时端口范围（代码2）
PORT_RANGE_START="40000"
PORT_RANGE_END="50050"

# 客户端指纹
CLIENT_FP="chrome"
ENV
chmod 600 "$ENV_FILE"

echo
echo "================== 主节点信息 =================="
echo "$VLESS_URL"
echo
echo "保存位置："
echo "  /root/vless_reality_vision_url.txt"
echo "  /root/v2ray_subscription_base64.txt"
echo "  /usr/local/etc/xray/env.conf"
echo "✅ 主节点部署完成（并已正确启用 API：127.0.0.1:10085）"
EOF

  chmod +x /root/onekey_reality_ipv4.sh
}

# ------------------ 3. 代码2：单进程 + Xray API 临时节点系统 ------------------

install_code2_singleproc_tempnodes() {
  echo "🧩 写入 /root/vless_temp_audit_ipv4_all.sh（代码2：已修复 API/outbound/unbound/source/锁）..."
  cat >/root/vless_temp_audit_ipv4_all.sh <<'EOF'
#!/usr/bin/env bash
# 代码2（最终版）：单进程 Xray + API 动态临时节点（多端口）
# - vless_mktemp.sh：创建临时端口入站（TTL=绝对到期）
# - vless_restore.sh：重启恢复未过期入站
# - vless_gc.sh + timer：到期自动清理
# - vless_audit.sh：审计
# ✅ 修复点：API_SERVER unbound / 必须 source env / API 正确启用 / 并发锁

set -euo pipefail

XRAY_CFG="/usr/local/etc/xray/config.json"
ENV_FILE="/usr/local/etc/xray/env.conf"
STATE_DIR="/usr/local/etc/xray/tmpnodes"
LOCK_FILE="/run/lock/vless-temp.lock"
XRAY_BIN="/usr/local/bin/xray"

need_root() { [[ "$(id -u)" -eq 0 ]] || { echo "❌ 请用 root 执行"; exit 1; }; }

need_tools() {
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y python3 openssl curl coreutils util-linux iproute2 >/dev/null 2>&1 || true
}

ensure_env() {
  mkdir -p "$(dirname "$ENV_FILE")" "$STATE_DIR" /run/lock
  if [[ ! -f "$ENV_FILE" ]]; then
    cat >"$ENV_FILE" <<'E'
API_SERVER="127.0.0.1:10085"
SERVER_ADDR=""
PORT_RANGE_START="40000"
PORT_RANGE_END="50050"
CLIENT_FP="chrome"
E
    chmod 600 "$ENV_FILE"
  fi
}

# 统一 env 加载：必须 source，且兜底，避免 set -u 炸
cat >/usr/local/sbin/vless_load_env.sh <<'E'
#!/usr/bin/env bash
set -euo pipefail
ENV_FILE="/usr/local/etc/xray/env.conf"

# 兜底（避免 unbound）
API_SERVER="${API_SERVER:-127.0.0.1:10085}"
SERVER_ADDR="${SERVER_ADDR:-}"
PORT_RANGE_START="${PORT_RANGE_START:-40000}"
PORT_RANGE_END="${PORT_RANGE_END:-50050}"
CLIENT_FP="${CLIENT_FP:-chrome}"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

API_SERVER="${API_SERVER:-127.0.0.1:10085}"
PORT_RANGE_START="${PORT_RANGE_START:-40000}"
PORT_RANGE_END="${PORT_RANGE_END:-50050}"
CLIENT_FP="${CLIENT_FP:-chrome}"

export API_SERVER SERVER_ADDR PORT_RANGE_START PORT_RANGE_END CLIENT_FP
E
chmod +x /usr/local/sbin/vless_load_env.sh

# 修复 conditional：绝不在 [[ ]] 内部调用函数
cat >/usr/local/sbin/vless_detect_addr.sh <<'E'
#!/usr/bin/env bash
set -euo pipefail

is_private_ip() {
  local ip="$1"
  [[ "$ip" =~ ^10\. ]] && return 0
  [[ "$ip" =~ ^127\. ]] && return 0
  [[ "$ip" =~ ^192\.168\. ]] && return 0
  [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
  return 1
}

detect_ipv4_public_first() {
  local ip=""
  ip="$(curl -4fsS --connect-timeout 2 --max-time 6 --retry 2 --retry-delay 1 --retry-all-errors https://api.ipify.org || true)"
  if [[ -n "$ip" ]] && ! is_private_ip "$ip"; then
    echo "$ip"; return 0
  fi
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  if [[ -n "$ip" ]] && ! is_private_ip "$ip"; then
    echo "$ip"; return 0
  fi
  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  if [[ -n "$ip" ]] && ! is_private_ip "$ip"; then
    echo "$ip"; return 0
  fi
  echo ""
}

detect_ipv4_public_first
E
chmod +x /usr/local/sbin/vless_detect_addr.sh

# 从主配置读取 Reality 参数；从主链接文件提取 pbk/sid（若存在）
cat >/usr/local/sbin/vless_read_reality.sh <<'E'
#!/usr/bin/env bash
set -euo pipefail

MAIN_CFG="/usr/local/etc/xray/config.json"
URL_FILE="/root/vless_reality_vision_url.txt"

[[ -f "$MAIN_CFG" ]] || { echo "ERR: missing $MAIN_CFG" >&2; exit 1; }

python3 - "$MAIN_CFG" "$URL_FILE" <<'PY'
import json,sys,re
cfg=json.load(open(sys.argv[1]))
ibs=cfg.get("inbounds",[])
if not ibs:
    print(""); print(""); print(""); print(""); print(""); raise SystemExit(0)
ib=ibs[0]
rs=ib.get("streamSettings",{}).get("realitySettings",{})
priv=rs.get("privateKey","")
dest=rs.get("dest","")
sns=rs.get("serverNames",[]) or []
sni=sns[0] if sns else ""
sids=rs.get("shortIds",[]) or []
sid=sids[0] if sids else ""

pbk=""
try:
    line=open(sys.argv[2]).read().strip().splitlines()[0]
    m=re.search(r"(?:\?|&)pbk=([^&]+)", line)
    if m: pbk=m.group(1)
except Exception:
    pass

print(priv)
print(dest)
print(sni)
print(sid)
print(pbk)
PY
E
chmod +x /usr/local/sbin/vless_read_reality.sh

# Patch：确保 Xray config 正确启用 API，并删除错误 outbound api
cat >/usr/local/sbin/vless_patch_api.sh <<'E'
#!/usr/bin/env bash
set -euo pipefail
CFG="/usr/local/etc/xray/config.json"
[[ -f "$CFG" ]] || exit 0

python3 - "$CFG" <<'PY'
import json,sys
p=sys.argv[1]
cfg=json.load(open(p))

# 删除错误 outbounds: protocol=api（防 unknown config id: api）
obs=cfg.get("outbounds",[])
cfg["outbounds"]=[o for o in obs if o.get("protocol")!="api" and o.get("tag")!="api"]

api=cfg.get("api") or {}
api.setdefault("tag","api")
api.setdefault("listen","127.0.0.1:10085")
api.setdefault("services",["HandlerService","LoggerService","StatsService","RoutingService"])
cfg["api"]=api

cfg.setdefault("stats",{})
cfg.setdefault("policy",{
  "levels":{"0":{"statsUserUplink":True,"statsUserDownlink":True}},
  "system":{"statsInboundUplink":True,"statsInboundDownlink":True}
})

open(p,"w").write(json.dumps(cfg,ensure_ascii=False,indent=2))
print("patched",p)
PY
E
chmod +x /usr/local/sbin/vless_patch_api.sh

ensure_xray_api_up() {
  /usr/local/sbin/vless_patch_api.sh || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl restart xray >/dev/null 2>&1 || true
  sleep 0.8
  if ! systemctl is-active xray >/dev/null 2>&1; then
    echo "❌ xray 未 active："
    systemctl status xray --no-pager -n 120 || true
    exit 1
  fi
  if ! ss -lntp 2>/dev/null | grep -qE "127\.0\.0\.1:10085\b"; then
    echo "❌ 未检测到 API 监听 127.0.0.1:10085"
    exit 1
  fi
}

# 创建临时节点（动态 inbound）
cat >/usr/local/sbin/vless_mktemp.sh <<'E'
#!/usr/bin/env bash
set -euo pipefail
: "${D:?用法：D=600 vless_mktemp.sh（D=秒）}"

if ! [[ "$D" =~ ^[0-9]+$ ]] || (( D <= 0 )); then
  echo "❌ D 必须为正整数秒" >&2
  exit 1
fi

. /usr/local/sbin/vless_load_env.sh

STATE_DIR="/usr/local/etc/xray/tmpnodes"
LOCK_FILE="/run/lock/vless-temp.lock"
XRAY_BIN="/usr/local/bin/xray"

mkdir -p "$STATE_DIR" /run/lock
exec 9>"$LOCK_FILE"
flock -n 9 || { echo "❌ 另一个 mktemp/gc/restore 正在运行"; exit 1; }

read -r R_PRIV R_DEST R_SNI R_SID R_PBK < <(/usr/local/sbin/vless_read_reality.sh)

if [[ -z "$R_PRIV" || -z "$R_DEST" ]]; then
  echo "❌ 无法从主配置解析 realitySettings.privateKey/dest（请先跑主节点脚本）" >&2
  exit 1
fi
[[ -n "$R_SNI" ]] || R_SNI="${R_DEST%%:*}"

# 对外展示地址：优先 env.conf 里 SERVER_ADDR；否则自动探测公网
if [[ -z "${SERVER_ADDR:-}" ]]; then
  SERVER_ADDR="$(/usr/local/sbin/vless_detect_addr.sh)"
fi
if [[ -z "${SERVER_ADDR:-}" ]]; then
  SERVER_ADDR="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
fi
if [[ -z "${SERVER_ADDR:-}" ]]; then
  echo "❌ 无法确定对外地址，请在 /usr/local/etc/xray/env.conf 填 SERVER_ADDR=域名或公网IP" >&2
  exit 1
fi

START="${PORT_RANGE_START}"
END="${PORT_RANGE_END}"

port_used() {
  local p="$1"
  ss -ltnH 2>/dev/null | awk '{print $4}' | sed 's/.*://g' | grep -qx "$p" && return 0
  # state 里也视为占用
  if ls "$STATE_DIR"/*.meta.json >/dev/null 2>&1; then
    python3 - "$STATE_DIR" "$p" <<'PY' >/dev/null 2>&1
import json,glob,sys
d=sys.argv[1]; p=int(sys.argv[2])
for f in glob.glob(d+"/*.meta.json"):
  try:
    o=json.load(open(f))
    if int(o.get("port",0))==p:
      raise SystemExit(0)
  except: pass
raise SystemExit(1)
PY
    [[ $? -eq 0 ]] && return 0
  fi
  return 1
}

PORT=""
for p in $(seq "$START" "$END"); do
  if ! port_used "$p"; then
    PORT="$p"; break
  fi
done
[[ -n "$PORT" ]] || { echo "❌ 端口耗尽：${START}-${END}" >&2; exit 1; }

UUID="$("$XRAY_BIN" uuid)"
TAG="vless-tmp-${PORT}"
EMAIL="${TAG}@temp"

NOW="$(date +%s)"
EXP="$((NOW + D))"

INB_JSON="${STATE_DIR}/${TAG}.inbound.json"
META_JSON="${STATE_DIR}/${TAG}.meta.json"

cat >"$INB_JSON" <<JSON
{
  "tag": "${TAG}",
  "listen": "0.0.0.0",
  "port": ${PORT},
  "protocol": "vless",
  "settings": {
    "clients": [
      { "id": "${UUID}", "email": "${EMAIL}", "flow": "xtls-rprx-vision" }
    ],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "show": false,
      "dest": "${R_DEST}",
      "xver": 0,
      "serverNames": [ "${R_SNI}" ],
      "privateKey": "${R_PRIV}",
      "shortIds": [ "${R_SID}" ]
    }
  }
}
JSON

cat >"$META_JSON" <<JSON
{
  "tag": "${TAG}",
  "email": "${EMAIL}",
  "uuid": "${UUID}",
  "port": ${PORT},
  "created_epoch": ${NOW},
  "expire_epoch": ${EXP},
  "server_addr": "${SERVER_ADDR}",
  "sni": "${R_SNI}",
  "sid": "${R_SID}",
  "pbk": "${R_PBK}"
}
JSON

# 调用 API 添加 inbound
if ! "$XRAY_BIN" api adi --server="$API_SERVER" "$INB_JSON" >/tmp/vless_adi.log 2>&1; then
  echo "❌ 添加 inbound 失败（xray api adi）"
  sed -n '1,200p' /tmp/vless_adi.log || true
  rm -f "$INB_JSON" "$META_JSON"
  exit 1
fi

# 等待监听出现
for _ in {1..12}; do
  ss -ltnH 2>/dev/null | awk '{print $4}' | sed 's/.*://g' | grep -qx "$PORT" && break
  sleep 0.12
done

E_STR="$(TZ=Asia/Shanghai date -d "@$EXP" '+%F %T')"

PBK_PARAM=""
if [[ -n "${R_PBK:-}" ]]; then
  PBK_PARAM="&pbk=${R_PBK}"
fi
SID_PARAM=""
if [[ -n "${R_SID:-}" ]]; then
  SID_PARAM="&sid=${R_SID}"
fi

VLESS_URL="vless://${UUID}@${SERVER_ADDR}:${PORT}?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&sni=${R_SNI}&fp=${CLIENT_FP}${PBK_PARAM}${SID_PARAM}#${TAG}"

echo "✅ 新临时节点(单进程): ${TAG}
端口: ${PORT} （inbound: ${TAG}）
UUID: ${UUID}
到期(北京时间): ${E_STR}
链接:
${VLESS_URL}"

if [[ -z "${R_PBK:-}" ]]; then
  echo "(未找到 pbk：请确认 /root/vless_reality_vision_url.txt 存在，或手工补 pbk 参数)"
fi
E
chmod +x /usr/local/sbin/vless_mktemp.sh

# 删除一个 inbound（tag 或 port）
cat >/usr/local/sbin/vless_rmi_one.sh <<'E'
#!/usr/bin/env bash
set -euo pipefail
. /usr/local/sbin/vless_load_env.sh

STATE_DIR="/usr/local/etc/xray/tmpnodes"
LOCK_FILE="/run/lock/vless-temp.lock"
XRAY_BIN="/usr/local/bin/xray"

ARG="${1:-}"
[[ -n "$ARG" ]] || { echo "用法：vless_rmi_one.sh <tag|port>" >&2; exit 1; }

if [[ "$ARG" =~ ^[0-9]+$ ]]; then
  TAG="vless-tmp-${ARG}"
else
  TAG="$ARG"
fi

mkdir -p "$STATE_DIR" /run/lock
exec 9>"$LOCK_FILE"
flock -n 9 || { echo "❌ 另一个任务正在运行"; exit 1; }

# 兼容不同版本 rmi 参数：优先 -tag，其次 positional
HELP="$("$XRAY_BIN" help api rmi 2>/dev/null || true)"
if echo "$HELP" | grep -q -- "-tag"; then
  "$XRAY_BIN" api rmi --server="$API_SERVER" -tag="$TAG" >/tmp/vless_rmi.log 2>&1 || true
else
  "$XRAY_BIN" api rmi --server="$API_SERVER" "$TAG" >/tmp/vless_rmi.log 2>&1 || true
fi

rm -f "$STATE_DIR/${TAG}.inbound.json" "$STATE_DIR/${TAG}.meta.json" >/dev/null 2>&1 || true

echo "✅ 已尝试删除：$TAG"
if [[ -s /tmp/vless_rmi.log ]]; then
  sed -n '1,120p' /tmp/vless_rmi.log || true
fi
E
chmod +x /usr/local/sbin/vless_rmi_one.sh

# GC：到期删除
cat >/usr/local/sbin/vless_gc.sh <<'E'
#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

. /usr/local/sbin/vless_load_env.sh

STATE_DIR="/usr/local/etc/xray/tmpnodes"
LOCK_FILE="/run/lock/vless-temp.lock"
XRAY_BIN="/usr/local/bin/xray"

mkdir -p "$STATE_DIR" /run/lock
exec 9>"$LOCK_FILE"
flock 9

NOW="$(date +%s)"

for META in "$STATE_DIR"/*.meta.json; do
  TAG="$(python3 - "$META" <<'PY'
import json,sys
o=json.load(open(sys.argv[1]))
print(o.get("tag",""))
PY
)"
  EXP="$(python3 - "$META" <<'PY'
import json,sys
o=json.load(open(sys.argv[1]))
print(int(o.get("expire_epoch",0)))
PY
)"
  [[ -n "$TAG" ]] || continue
  if (( EXP > 0 && EXP <= NOW )); then
    /usr/local/sbin/vless_rmi_one.sh "$TAG" >/dev/null 2>&1 || true
  fi
done
E
chmod +x /usr/local/sbin/vless_gc.sh

# restore：重启后恢复未过期入站（API 动态入站不会持久化）
cat >/usr/local/sbin/vless_restore.sh <<'E'
#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

. /usr/local/sbin/vless_load_env.sh

STATE_DIR="/usr/local/etc/xray/tmpnodes"
LOCK_FILE="/run/lock/vless-temp.lock"
XRAY_BIN="/usr/local/bin/xray"

mkdir -p "$STATE_DIR" /run/lock
exec 9>"$LOCK_FILE"
flock 9

NOW="$(date +%s)"

lsi_has_tag() {
  local tag="$1"
  local out=""
  out="$("$XRAY_BIN" api lsi --server="$API_SERVER" 2>/dev/null || true)"
  echo "$out" | grep -qE "(\"tag\"[[:space:]]*:[[:space:]]*\"${tag}\")|(\b${tag}\b)"
}

for META in "$STATE_DIR"/*.meta.json; do
  TAG="$(python3 - "$META" <<'PY'
import json,sys
o=json.load(open(sys.argv[1]))
print(o.get("tag",""))
PY
)"
  EXP="$(python3 - "$META" <<'PY'
import json,sys
o=json.load(open(sys.argv[1]))
print(int(o.get("expire_epoch",0)))
PY
)"
  [[ -n "$TAG" ]] || continue

  if (( EXP > 0 && EXP <= NOW )); then
    /usr/local/sbin/vless_rmi_one.sh "$TAG" >/dev/null 2>&1 || true
    continue
  fi

  if lsi_has_tag "$TAG"; then
    continue
  fi

  INB_JSON="${STATE_DIR}/${TAG}.inbound.json"
  if [[ -f "$INB_JSON" ]]; then
    "$XRAY_BIN" api adi --server="$API_SERVER" "$INB_JSON" >/dev/null 2>&1 || true
  fi
done
E
chmod +x /usr/local/sbin/vless_restore.sh

# audit
cat >/usr/local/sbin/vless_audit.sh <<'E'
#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

STATE_DIR="/usr/local/etc/xray/tmpnodes"

echo "==== XRAY 主进程 ===="
systemctl is-active xray && echo "xray.service: active" || echo "xray.service: NOT active"
echo
printf "%-34s %-6s %-6s %-12s %-20s\n" "TAG" "PORT" "STATE" "LEFT" "EXPIRE(China)"

NOW="$(date +%s)"

for META in "$STATE_DIR"/*.meta.json; do
  python3 - "$META" "$NOW" <<'PY'
import json,sys,datetime,subprocess,time
p=sys.argv[1]; now=int(sys.argv[2])
o=json.load(open(p))
tag=o.get("tag","?")
port=o.get("port","?")
exp=int(o.get("expire_epoch",0))
left=exp-now
if left<=0:
  left_s="expired"
else:
  d=left//86400; h=(left%86400)//3600; m=(left%3600)//60
  left_s=f"{d:02d}d{h:02d}h{m:02d}m"
st="unknown"
try:
  cmd=f"ss -ltnH 2>/dev/null | awk '{{print $4}}' | sed 's/.*://g' | grep -qx {port} && echo alive || echo dead"
  st=subprocess.check_output(["bash","-lc",cmd],text=True).strip() or "unknown"
except Exception:
  pass
exp_cn=(datetime.datetime.utcfromtimestamp(exp)+datetime.timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S") if exp>0 else "N/A"
print(f"{tag:<34} {str(port):<6} {st:<6} {left_s:<12} {exp_cn:<20}")
PY
done
E
chmod +x /usr/local/sbin/vless_audit.sh

# clear all
cat >/usr/local/sbin/vless_clear_all.sh <<'E'
#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

STATE_DIR="/usr/local/etc/xray/tmpnodes"

for META in "$STATE_DIR"/*.meta.json; do
  TAG="$(python3 - "$META" <<'PY'
import json,sys
o=json.load(open(sys.argv[1]))
print(o.get("tag",""))
PY
)"
  [[ -n "$TAG" ]] || continue
  /usr/local/sbin/vless_rmi_one.sh "$TAG" >/dev/null 2>&1 || true
done
echo "✅ 已执行清空流程（所有临时入站）"
E
chmod +x /usr/local/sbin/vless_clear_all.sh

# systemd: restore + gc.timer
cat >/etc/systemd/system/vless-restore.service <<'S'
[Unit]
Description=Restore VLESS temp inbounds (single-process)
After=network.target xray.service
Wants=xray.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vless_restore.sh

[Install]
WantedBy=multi-user.target
S

cat >/etc/systemd/system/vless-gc.service <<'S'
[Unit]
Description=GC expired VLESS temp inbounds (single-process)
After=network.target xray.service
Wants=xray.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vless_gc.sh
S

cat >/etc/systemd/system/vless-gc.timer <<'T'
[Unit]
Description=Run VLESS temp GC every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
T

main() {
  need_root
  need_tools
  ensure_env

  [[ -x "$XRAY_BIN" ]] || { echo "❌ 未找到 $XRAY_BIN，请先安装 xray"; exit 1; }
  [[ -f "$XRAY_CFG" ]] || { echo "❌ 未找到 $XRAY_CFG，请先跑主节点脚本 onekey_reality_ipv4.sh"; exit 1; }

  /usr/local/sbin/vless_patch_api.sh || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl restart xray >/dev/null 2>&1 || true
  sleep 0.8

  # API 监听自检
  if ! ss -lntp 2>/dev/null | grep -qE "127\.0\.0\.1:10085\b"; then
    echo "❌ API 未监听 127.0.0.1:10085（请检查 $XRAY_CFG 的 api.listen）"
    exit 1
  fi

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now vless-gc.timer >/dev/null 2>&1 || true
  systemctl enable --now vless-restore.service >/dev/null 2>&1 || true

  echo "✅ 代码2部署完成：单进程 + 多端口临时节点"
  echo
  cat <<'USE'
用法：
- 创建临时节点：
  D=600 vless_mktemp.sh

- 审计：
  vless_audit.sh

- 删除某个临时节点：
  vless_rmi_one.sh 40035
  vless_rmi_one.sh vless-tmp-40035

- 清空全部：
  vless_clear_all.sh

说明：
- 临时节点是“动态 inbound”，不会写入 config.json
- 重启后由 vless-restore.service 自动恢复未过期节点
- 到期由 vless-gc.timer 自动清理
USE
}

main "$@"
EOF

  chmod +x /root/vless_temp_audit_ipv4_all.sh
}

# ------------------ 4. nftables 配额系统（可选，保持你原思路） ------------------

install_port_quota() {
  echo "🧩 部署 TCP 上行配额系统（nftables）..."
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y nftables >/dev/null 2>&1 || true

  mkdir -p /etc/portquota

  nft list table inet portquota >/dev/null 2>&1 || nft add table inet portquota
  nft list chain inet portquota down_out >/dev/null 2>&1 || \
    nft add chain inet portquota down_out '{ type filter hook output priority filter; policy accept; }'

  nft list ruleset > /etc/nftables.conf || true
  systemctl enable --now nftables >/dev/null 2>&1 || true

  cat >/usr/local/sbin/pq_add.sh <<'ADD'
#!/usr/bin/env bash
set -euo pipefail
PORT="${1:-}"; GIB="${2:-}"
[[ -n "$PORT" && -n "$GIB" ]] || { echo "用法: pq_add.sh <端口> <GiB整数>"; exit 1; }
[[ "$GIB" =~ ^[0-9]+$ ]] || { echo "❌ GiB 需为整数"; exit 1; }
BYTES=$((GIB * 1024 * 1024 * 1024))

nft -a list chain inet portquota down_out 2>/dev/null | \
  awk -v p="$PORT" '$0 ~ "tcp sport "p" " {print $NF}' | while read -r h; do
    nft delete rule inet portquota down_out handle "$h" 2>/dev/null || true
  done

nft delete counter inet portquota "pq_down_$PORT" 2>/dev/null || true
nft add counter inet portquota "pq_down_$PORT"

nft add rule inet portquota down_out tcp sport "$PORT" \
  counter name "pq_down_$PORT" quota over "$BYTES" bytes drop comment "pq-quota-$PORT"
nft add rule inet portquota down_out tcp sport "$PORT" \
  counter name "pq_down_$PORT" comment "pq-track-$PORT"

cat >/etc/portquota/pq-"$PORT".meta <<M
PORT=$PORT
LIMIT_BYTES=$BYTES
LIMIT_GIB=$GIB
MODE=quota
M

nft list ruleset > /etc/nftables.conf
systemctl enable --now nftables >/dev/null 2>&1 || true

echo "✅ 已为端口 $PORT 设置限额 ${GIB}GiB（本机 TCP 上行，sport=$PORT）"
ADD
  chmod +x /usr/local/sbin/pq_add.sh

  cat >/usr/local/sbin/pq_del.sh <<'DEL'
#!/usr/bin/env bash
set -euo pipefail
PORT="${1:-}"
[[ -n "$PORT" ]] || { echo "用法: pq_del.sh <端口>"; exit 1; }

nft -a list chain inet portquota down_out 2>/dev/null | \
  awk -v p="$PORT" '$0 ~ "tcp sport "p" " {print $NF}' | while read -r h; do
    nft delete rule inet portquota down_out handle "$h" 2>/dev/null || true
  done

nft delete counter inet portquota "pq_down_$PORT" 2>/dev/null || true
rm -f /etc/portquota/pq-"$PORT".meta

nft list ruleset > /etc/nftables.conf
systemctl enable --now nftables >/dev/null 2>&1 || true

echo "✅ 已删除端口 $PORT 的配额"
DEL
  chmod +x /usr/local/sbin/pq_del.sh

  cat >/usr/local/sbin/pq_audit.sh <<'AUD'
#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

printf "%-8s %-10s %-12s %-12s %-8s\n" "PORT" "STATE" "USED(GiB)" "LIMIT(GiB)" "PERCENT"

for META in /etc/portquota/pq-*.meta; do
  unset PORT LIMIT_BYTES LIMIT_GIB MODE
  # shellcheck disable=SC1090
  . "$META" 2>/dev/null || continue
  [[ -n "${PORT:-}" ]] || continue

  CUR="$(nft list counter inet portquota "pq_down_${PORT}" 2>/dev/null \
    | awk '/bytes/{for(i=1;i<=NF;i++)if($i=="bytes"){print $(i+1);exit}}' || true)"
  CUR="${CUR:-0}"

  USED="$(awk -v b="$CUR" 'BEGIN{printf "%.2f",b/1024/1024/1024}')"
  LIMB="${LIMIT_BYTES:-0}"

  if [[ "$LIMB" =~ ^[0-9]+$ ]] && (( LIMB > 0 )); then
    LIMIT="$(awk -v b="$LIMB" 'BEGIN{printf "%.2f",b/1024/1024/1024}')"
    PCT="$(awk -v u="$CUR" -v l="$LIMB" 'BEGIN{printf "%.1f%%",(u*100.0)/l}')"
    STATE="ok"
    (( CUR >= LIMB )) && STATE="dropped"
  else
    LIMIT="0"
    PCT="N/A"
    STATE="track"
  fi

  printf "%-8s %-10s %-12s %-12s %-8s\n" "$PORT" "$STATE" "$USED" "$LIMIT" "$PCT"
done
AUD
  chmod +x /usr/local/sbin/pq_audit.sh
}

# ------------------ 主流程 ------------------

main() {
  check_debian12
  need_basic_tools
  download_upstreams
  configure_logrotate_2days

  install_update_all
  install_vless_script
  install_code2_singleproc_tempnodes
  install_port_quota

  cat <<'DONE'

==================================================
✅ 所有脚本已生成完毕（Debian 12）

建议顺序：
1) update-all && reboot
2) bash /root/onekey_reality_ipv4.sh
3) bash /root/vless_temp_audit_ipv4_all.sh
4) 创建临时节点：D=600 vless_mktemp.sh

常用命令（代码2）：
- D=600 vless_mktemp.sh
- vless_audit.sh
- vless_rmi_one.sh 40035
- vless_clear_all.sh

配额（可选）：
- pq_add.sh 40035 50
- pq_audit.sh
- pq_del.sh 40035
==================================================
DONE
}

main "$@"
