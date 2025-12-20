#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# huanxin.sh (Debian 12) - 单进程 Xray + Reality + API 动态入站 + 配额系统
# 生成：
#   - /usr/local/bin/update-all
#   - /root/onekey_reality_ipv4.sh
#   - /usr/local/bin/vless_mktemp.sh
#   - /usr/local/bin/vless_rmi_one.sh
#   - /usr/local/bin/vless_audit.sh
#   - /usr/local/bin/vless_clear_all.sh
#   - /usr/local/bin/vless_quota_show.sh
#   - /usr/local/bin/vless_quota_watch.sh
#   - /usr/local/bin/vless_quota_install_timer.sh
#
# 修复：
#   - 避免 `head -n1` 在 pipefail 下触发 exit=141
#   - xray x25519 输出 PublicKey/Password 兼容
#   - xray api adi/rmi/statsquery 参数多风格兼容
# ============================================================

SCRIPT_VER="2025-12-20+quota"

XRAY_BIN="/usr/local/bin/xray"
XRAY_CFG="/usr/local/etc/xray/config.json"
XRAY_LOG_DIR="/var/log/xray"
ENV_FILE="/root/reality.env"
STATE_FILE="/root/.vless_temp_inbounds.jsonl"

DEFAULT_SNI="www.apple.com"
DEFAULT_DEST="www.apple.com:443"
DEFAULT_PORT="443"
DEFAULT_FP="chrome"
DEFAULT_API_LISTEN="127.0.0.1:10085"

export DEBIAN_FRONTEND=noninteractive

log()  { echo -e "$*"; }
ok()   { echo -e "✅ $*"; }
warn() { echo -e "⚠️  $*" >&2; }
die()  { echo -e "❌ $*" >&2; exit 1; }

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "请用 root 执行：sudo -i 后再运行"
}

apt_install() {
  apt-get update -y
  apt-get install -y --no-install-recommends "$@"
}

ensure_deps() {
  # 说明：
  # - jq: 解析 JSON
  # - iproute2: ip/ss
  # - coreutils: numfmt/sed 等（Debian 默认有，但装上更保险）
  # - util-linux: flock（Debian 默认有，但装上更保险）
  apt_install curl ca-certificates unzip jq openssl iproute2 coreutils util-linux
}

detect_public_ip() {
  local ip=""
  ip="$(curl -fsSL https://api.ipify.org 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(curl -fsSL https://ip.sb 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/{print $7; exit}' || true)"
  [[ -n "$ip" ]] || die "无法探测服务器 IP（curl 出网失败？）"
  echo "$ip"
}

install_or_update_xray() {
  ensure_deps
  log "=== 安装/更新 Xray ==="
  # 官方安装脚本（会安装 systemd service）
  bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install -u root
  [[ -x "$XRAY_BIN" ]] || die "Xray 安装失败：找不到 $XRAY_BIN"
  ok "Xray 已安装/更新：$("$XRAY_BIN" version 2>/dev/null | sed -n '1p' || true)"
}

enable_fq_bbr_only() {
  log "=== 仅开启 fq + bbr（其余 sysctl 保持默认）==="
  cat >/etc/sysctl.d/99-huanxin-fq-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl --system >/dev/null 2>&1 || true

  local qdisc cc
  qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
  cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
  ok "当前: qdisc=${qdisc:-?}, cc=${cc:-?}"
}

gen_uuid() {
  "$XRAY_BIN" uuid
}

# 兼容：旧版输出 PublicKey，新版输出 Password（等价 publicKey）
gen_x25519() {
  local out priv pub
  out="$("$XRAY_BIN" x25519 2>/dev/null || true)"
  priv="$(echo "$out" | awk -F': ' '/PrivateKey/{print $2; exit}')"
  pub="$(echo "$out"  | awk -F': ' '/^(PublicKey|Password):/{print $2; exit}')"
  [[ -n "$priv" && -n "$pub" ]] || {
    echo "$out" >&2
    die "x25519 解析失败（没有拿到 PrivateKey/PublicKey(or Password)）"
  }
  echo "$priv|$pub"
}

gen_shortid() {
  openssl rand -hex 8
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  cp -a "$f" "${f}.bak.$(date +%Y%m%d_%H%M%S)"
}

write_main_config() {
  local port="$1" sni="$2" dest="$3" uuid="$4" priv="$5" pub="$6" sid="$7" api_listen="$8"

  mkdir -p "$(dirname "$XRAY_CFG")" "$XRAY_LOG_DIR"
  backup_file "$XRAY_CFG"

  # 关键点：配额系统需要 stats + policy.system.statsInboundUplink/Downlink
  cat >"$XRAY_CFG" <<EOF
{
  "log": {
    "access": "$XRAY_LOG_DIR/access.log",
    "error": "$XRAY_LOG_DIR/error.log",
    "loglevel": "warning"
  },
  "api": {
    "tag": "api",
    "listen": "$api_listen",
    "services": ["HandlerService", "LoggerService", "StatsService"]
  },
  "stats": {},
  "policy": {
    "levels": {
      "0": { "statsUserUplink": true, "statsUserDownlink": true }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true
    }
  },
  "inbounds": [
    {
      "tag": "vless-reality-$port",
      "listen": "0.0.0.0",
      "port": $port,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "$uuid", "flow": "xtls-rprx-vision" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$dest",
          "xver": 0,
          "serverNames": ["$sni"],
          "privateKey": "$priv",
          "shortIds": ["$sid"]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" }
    ]
  }
}
EOF

  umask 077
  cat >"$ENV_FILE" <<EOF
# Generated by huanxin.sh $SCRIPT_VER
SERVER_IP="$(detect_public_ip)"
PORT_MAIN="$port"
SNI="$sni"
DEST="$dest"
FP="$DEFAULT_FP"
API_LISTEN="$api_listen"

UUID="$uuid"
PRIVATE_KEY="$priv"
PUBLIC_KEY="$pub"
SHORT_ID="$sid"
EOF
  chmod 600 "$ENV_FILE"
}

restart_xray() {
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable xray >/dev/null 2>&1 || true
  systemctl restart xray
  sleep 0.5
  systemctl --no-pager --full status xray | sed -n '1,12p' || true
  ok "Xray 已启动"
}

vless_url() {
  local uuid="$1" host="$2" port="$3" sni="$4" fp="$5" pbk="$6" sid="$7" name="$8"
  echo "vless://${uuid}@${host}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=${fp}&pbk=${pbk}&sid=${sid}&type=tcp&headerType=none#${name}"
}

write_bin() {
  local path="$1"
  install -m 0755 /dev/null "$path"
  cat >"$path"
  chmod 0755 "$path"
}

gen_update_all() {
  write_bin /usr/local/bin/update-all <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
echo "🚀 开始系统更新 (Debian 12 / bookworm)..."
apt-get update -y
apt-get upgrade -y
apt-get autoremove -y
apt-get autoclean -y
echo "✅ 软件包更新完成"
echo "🧠 建议：如安装了新内核/ssh 等关键组件，重启一次更稳：reboot"
EOF
}

gen_onekey_reality() {
  write_bin /root/onekey_reality_ipv4.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

XRAY_BIN="/usr/local/bin/xray"
XRAY_CFG="/usr/local/etc/xray/config.json"
ENV_FILE="/root/reality.env"
XRAY_LOG_DIR="/var/log/xray"

DEFAULT_SNI="${SNI:-www.apple.com}"
DEFAULT_DEST="${DEST:-www.apple.com:443}"
DEFAULT_PORT="${PORT:-443}"
DEFAULT_API_LISTEN="${API_LISTEN:-127.0.0.1:10085}"
DEFAULT_FP="${FP:-chrome}"

die(){ echo "❌ $*" >&2; exit 1; }
ok(){ echo "✅ $*"; }

apt_install() { apt-get update -y; apt-get install -y --no-install-recommends "$@"; }
ensure_deps() { apt_install curl ca-certificates unzip jq openssl iproute2 coreutils util-linux; }

detect_public_ip() {
  local ip=""
  ip="$(curl -fsSL https://api.ipify.org 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(curl -fsSL https://ip.sb 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/{print $7; exit}' || true)"
  [[ -n "$ip" ]] || die "无法探测服务器 IP"
  echo "$ip"
}

install_or_update_xray() {
  ensure_deps
  bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install -u root
  [[ -x "$XRAY_BIN" ]] || die "Xray 安装失败：找不到 $XRAY_BIN"
  ok "Xray：$("$XRAY_BIN" version 2>/dev/null | sed -n '1p' || true)"
}

gen_uuid(){ "$XRAY_BIN" uuid; }

gen_x25519() {
  local out priv pub
  out="$("$XRAY_BIN" x25519 2>/dev/null || true)"
  priv="$(echo "$out" | awk -F': ' '/PrivateKey/{print $2; exit}')"
  pub="$(echo "$out" | awk -F': ' '/^(PublicKey|Password):/{print $2; exit}')"
  [[ -n "$priv" && -n "$pub" ]] || { echo "$out" >&2; die "x25519 解析失败"; }
  echo "$priv|$pub"
}

gen_shortid(){ openssl rand -hex 8; }

enable_fq_bbr_only() {
  cat >/etc/sysctl.d/99-huanxin-fq-bbr.conf <<'E'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
E
  sysctl --system >/dev/null 2>&1 || true
  ok "已写入 fq+bbr（/etc/sysctl.d/99-huanxin-fq-bbr.conf）"
}

backup_file(){ [[ -f "$1" ]] && cp -a "$1" "${1}.bak.$(date +%Y%m%d_%H%M%S)" || true; }

write_main_config() {
  local port="$1" sni="$2" dest="$3" uuid="$4" priv="$5" pub="$6" sid="$7" api_listen="$8"

  mkdir -p "$(dirname "$XRAY_CFG")" "$XRAY_LOG_DIR"
  backup_file "$XRAY_CFG"

  cat >"$XRAY_CFG" <<JSON
{
  "log": { "access": "$XRAY_LOG_DIR/access.log", "error": "$XRAY_LOG_DIR/error.log", "loglevel": "warning" },
  "api": { "tag": "api", "listen": "$api_listen", "services": ["HandlerService","LoggerService","StatsService"] },
  "stats": {},
  "policy": {
    "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
    "system": { "statsInboundUplink": true, "statsInboundDownlink": true }
  },
  "inbounds": [
    {
      "tag": "vless-reality-$port",
      "listen": "0.0.0.0",
      "port": $port,
      "protocol": "vless",
      "settings": { "clients": [ { "id": "$uuid", "flow": "xtls-rprx-vision" } ], "decryption": "none" },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$dest",
          "xver": 0,
          "serverNames": ["$sni"],
          "privateKey": "$priv",
          "shortIds": ["$sid"]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"], "routeOnly": true }
    }
  ],
  "outbounds": [ { "protocol":"freedom","tag":"direct" }, { "protocol":"blackhole","tag":"block" } ],
  "routing": { "domainStrategy":"AsIs", "rules":[ { "type":"field", "ip":["geoip:private"], "outboundTag":"block" } ] }
}
JSON

  umask 077
  cat >"$ENV_FILE" <<E
SERVER_IP="$(detect_public_ip)"
PORT_MAIN="$port"
SNI="$sni"
DEST="$dest"
FP="$DEFAULT_FP"
API_LISTEN="$api_listen"
UUID="$uuid"
PRIVATE_KEY="$priv"
PUBLIC_KEY="$pub"
SHORT_ID="$sid"
E
  chmod 600 "$ENV_FILE"
}

restart_xray() {
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable xray >/dev/null 2>&1 || true
  systemctl restart xray
  sleep 0.5
  ok "Xray 已重启"
}

vless_url() {
  local uuid="$1" host="$2" port="$3" sni="$4" fp="$5" pbk="$6" sid="$7" name="$8"
  echo "vless://${uuid}@${host}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=${fp}&pbk=${pbk}&sid=${sid}&type=tcp&headerType=none#${name}"
}

main() {
  enable_fq_bbr_only
  install_or_update_xray

  echo "=== 生成 UUID + Reality 密钥 ==="
  local uuid; uuid="$(gen_uuid)"
  local kp priv pub; kp="$(gen_x25519)"; priv="${kp%%|*}"; pub="${kp##*|}"
  local sid; sid="$(gen_shortid)"

  write_main_config "$DEFAULT_PORT" "$DEFAULT_SNI" "$DEFAULT_DEST" "$uuid" "$priv" "$pub" "$sid" "$DEFAULT_API_LISTEN"
  restart_xray

  # 输出主节点
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  local url; url="$(vless_url "$UUID" "$SERVER_IP" "$PORT_MAIN" "$SNI" "$FP" "$PUBLIC_KEY" "$SHORT_ID" "reality-$PORT_MAIN")"
  echo "$url" | tee /root/vless_main_${PORT_MAIN}.txt >/dev/null
  echo
  ok "主节点已写入：/root/vless_main_${PORT_MAIN}.txt"
  echo "----------------------------------------"
  echo "$url"
  echo "----------------------------------------"
}

main "$@"
EOF
}

gen_temp_tools() {
  # vless_mktemp.sh（支持 Q=配额MB）
  write_bin /usr/local/bin/vless_mktemp.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/root/reality.env"
STATE_FILE="/root/.vless_temp_inbounds.jsonl"
XRAY_BIN="/usr/local/bin/xray"

die(){ echo "❌ $*" >&2; exit 1; }
ok(){ echo "✅ $*"; }
warn(){ echo "⚠️  $*" >&2; }

[[ -f "$ENV_FILE" ]] || die "缺少 $ENV_FILE，请先运行：bash /root/onekey_reality_ipv4.sh"
# shellcheck disable=SC1090
source "$ENV_FILE"

D="${D:-600}"                       # 存活秒数
PORT="${PORT:-}"                    # 可手动指定
NAME="${NAME:-temp}"                # 节点备注
Q="${Q:-0}"                         # 配额（MB，上下行合计；0=不限）
API="${API_LISTEN:-127.0.0.1:10085}"

rand_port() { shuf -i 20000-60000 -n 1; }

port_free() {
  local p="$1"
  ! ss -lnt "( sport = :$p )" 2>/dev/null | grep -q ":$p"
}

xray_adi() {
  local file="$1"
  "$XRAY_BIN" api adi --server="$API" "$file" >/dev/null 2>&1 && return 0
  "$XRAY_BIN" api adi -server="$API" "$file"  >/dev/null 2>&1 && return 0
  "$XRAY_BIN" api adi -s "$API" "$file"       >/dev/null 2>&1 && return 0
  return 1
}

xray_stats_reset_tag() {
  local tag="$1"
  local pattern="inbound>>>${tag}>>>traffic>>>"
  # reset=true 兼容多风格
  "$XRAY_BIN" api statsquery --server="$API" --pattern="$pattern" --reset=true >/dev/null 2>&1 && return 0
  "$XRAY_BIN" api statsquery -server="$API" -pattern="$pattern" -reset=true    >/dev/null 2>&1 && return 0
  "$XRAY_BIN" api statsquery -s "$API" -pattern="$pattern" -reset=true         >/dev/null 2>&1 && return 0
  return 0
}

vless_url() {
  local uuid="$1" host="$2" port="$3" sni="$4" fp="$5" pbk="$6" sid="$7" name="$8"
  echo "vless://${uuid}@${host}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=${fp}&pbk=${pbk}&sid=${sid}&type=tcp&headerType=none#${name}"
}

choose_port() {
  if [[ -n "${PORT}" ]]; then
    [[ "$PORT" =~ ^[0-9]+$ ]] || die "PORT 必须是数字"
    port_free "$PORT" || die "端口 $PORT 已被占用"
    echo "$PORT"
    return 0
  fi

  local p
  for _ in $(seq 1 20); do
    p="$(rand_port)"
    if port_free "$p"; then
      echo "$p"; return 0
    fi
  done
  die "随机挑选端口失败（连续 20 次都被占用？）"
}

main() {
  local port tag tmp expires now quota_bytes
  port="$(choose_port)"
  tag="temp-${port}"
  tmp="/tmp/inbound_${tag}.json"

  [[ "$D" =~ ^[0-9]+$ ]] || die "D 必须是数字"
  [[ "$Q" =~ ^[0-9]+$ ]] || die "Q 必须是数字（MB）"
  quota_bytes=$(( Q * 1024 * 1024 ))

  cat >"$tmp" <<JSON
{
  "tag": "$tag",
  "listen": "0.0.0.0",
  "port": $port,
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
      "dest": "$DEST",
      "xver": 0,
      "serverNames": ["$SNI"],
      "privateKey": "$PRIVATE_KEY",
      "shortIds": ["$SHORT_ID"]
    }
  },
  "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"], "routeOnly": true }
}
JSON

  xray_adi "$tmp" || die "添加入站失败：xray api adi 调用失败（可运行：$XRAY_BIN api adi -h 查看参数）"

  # 重置该 tag 的统计（避免端口复用造成旧数据干扰）
  xray_stats_reset_tag "$tag" || true

  now="$(date +%s)"
  expires="$((now + D))"
  mkdir -p "$(dirname "$STATE_FILE")"
  echo "{\"tag\":\"$tag\",\"port\":$port,\"created\":$now,\"expires\":$expires,\"quotaBytes\":$quota_bytes}" >>"$STATE_FILE"

  local url
  url="$(vless_url "$UUID" "$SERVER_IP" "$port" "$SNI" "${FP:-chrome}" "$PUBLIC_KEY" "$SHORT_ID" "${NAME}-${port}")"
  echo "$url" | tee "/root/vless_${tag}.txt" >/dev/null

  echo
  ok "临时入站已创建：port=$port  duration=${D}s  tag=$tag  quotaMB=${Q}"
  ok "节点已写入：/root/vless_${tag}.txt"
  echo "----------------------------------------"
  echo "$url"
  echo "----------------------------------------"

  if [[ "$D" -gt 0 ]]; then
    nohup bash -c "sleep $D; /usr/local/bin/vless_rmi_one.sh $port >/dev/null 2>&1" >/dev/null 2>&1 &
    ok "已后台定时删除：${D}s 后移除 port=$port"
  fi
}

main "$@"
EOF

  # vless_rmi_one.sh
  write_bin /usr/local/bin/vless_rmi_one.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/root/reality.env"
STATE_FILE="/root/.vless_temp_inbounds.jsonl"
XRAY_BIN="/usr/local/bin/xray"

die(){ echo "❌ $*" >&2; exit 1; }
ok(){ echo "✅ $*"; }

[[ $# -ge 1 ]] || die "用法：vless_rmi_one.sh <port>"
PORT="$1"
[[ "$PORT" =~ ^[0-9]+$ ]] || die "port 必须是数字"

[[ -f "$ENV_FILE" ]] || die "缺少 $ENV_FILE（先跑 /root/onekey_reality_ipv4.sh）"
# shellcheck disable=SC1090
source "$ENV_FILE"

API="${API_LISTEN:-127.0.0.1:10085}"
TAG="temp-${PORT}"

xray_rmi() {
  "$XRAY_BIN" api rmi --server="$API" --tag="$TAG" >/dev/null 2>&1 && return 0
  "$XRAY_BIN" api rmi -server="$API" -tag="$TAG"   >/dev/null 2>&1 && return 0
  "$XRAY_BIN" api rmi -s "$API" "$TAG"             >/dev/null 2>&1 && return 0
  return 1
}

xray_rmi || die "移除失败：tag=$TAG（可运行：$XRAY_BIN api rmi -h 查看参数）"
ok "已移除入站：tag=$TAG"

# 更新状态文件
if [[ -f "$STATE_FILE" ]]; then
  tmp="${STATE_FILE}.tmp"
  grep -v "\"port\":${PORT}" "$STATE_FILE" >"$tmp" || true
  mv -f "$tmp" "$STATE_FILE"
fi
EOF

  # vless_audit.sh
  write_bin /usr/local/bin/vless_audit.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/root/reality.env"
STATE_FILE="/root/.vless_temp_inbounds.jsonl"

die(){ echo "❌ $*" >&2; exit 1; }

[[ -f "$ENV_FILE" ]] || die "缺少 $ENV_FILE（先跑 /root/onekey_reality_ipv4.sh）"
# shellcheck disable=SC1090
source "$ENV_FILE"

echo "=== Reality 主配置 ==="
echo "SERVER_IP=$SERVER_IP"
echo "PORT_MAIN=$PORT_MAIN"
echo "SNI=$SNI"
echo "DEST=$DEST"
echo "API_LISTEN=$API_LISTEN"
echo

echo "=== 临时入站状态（本机记录）==="
if [[ ! -f "$STATE_FILE" ]]; then
  echo "(无记录)"
  exit 0
fi

now="$(date +%s)"
while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  port="$(echo "$line" | jq -r '.port')"
  tag="$(echo "$line" | jq -r '.tag')"
  exp="$(echo "$line" | jq -r '.expires')"
  qbytes="$(echo "$line" | jq -r '.quotaBytes // 0')"
  left="$((exp - now))"
  if [[ "$left" -lt 0 ]]; then left=0; fi
  printf "port=%s  tag=%s  剩余=%ss  quotaBytes=%s\n" "$port" "$tag" "$left" "$qbytes"
done <"$STATE_FILE"
EOF

  # vless_clear_all.sh
  write_bin /usr/local/bin/vless_clear_all.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

STATE_FILE="/root/.vless_temp_inbounds.jsonl"

if [[ ! -f "$STATE_FILE" ]]; then
  echo "✅ 无需清理（没有状态文件）"
  exit 0
fi

ports="$(jq -r '.port' "$STATE_FILE" 2>/dev/null || true)"
if [[ -z "$ports" ]]; then
  rm -f "$STATE_FILE"
  echo "✅ 已清空状态文件"
  exit 0
fi

while read -r p; do
  [[ -n "$p" ]] || continue
  /usr/local/bin/vless_rmi_one.sh "$p" || true
done <<<"$ports"

rm -f "$STATE_FILE"
echo "✅ 已清理完成"
EOF
}

gen_quota_tools() {
  # vless_quota_show.sh
  write_bin /usr/local/bin/vless_quota_show.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/root/reality.env"
STATE_FILE="/root/.vless_temp_inbounds.jsonl"
XRAY_BIN="/usr/local/bin/xray"

die(){ echo "❌ $*" >&2; exit 1; }

[[ -f "$ENV_FILE" ]] || die "缺少 $ENV_FILE（先跑 /root/onekey_reality_ipv4.sh）"
# shellcheck disable=SC1090
source "$ENV_FILE"

API="${API_LISTEN:-127.0.0.1:10085}"

xray_statsquery() {
  local pattern="$1"
  "$XRAY_BIN" api statsquery --server="$API" --pattern="$pattern" 2>/dev/null && return 0
  "$XRAY_BIN" api statsquery -server="$API" -pattern="$pattern"  2>/dev/null && return 0
  "$XRAY_BIN" api statsquery -s "$API" -pattern="$pattern"       2>/dev/null && return 0
  return 1
}

fmt_bytes() {
  local n="$1"
  if command -v numfmt >/dev/null 2>&1; then
    numfmt --to=iec --suffix=B "$n"
  else
    echo "${n}B"
  fi
}

[[ -f "$STATE_FILE" ]] || { echo "(无临时入站记录)"; exit 0; }

now="$(date +%s)"
echo "tag | port | 剩余 | 已用 | 配额 | 状态"
echo "---------------------------------------------------------------"

while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  tag="$(echo "$line" | jq -r '.tag')"
  port="$(echo "$line" | jq -r '.port')"
  exp="$(echo "$line" | jq -r '.expires')"
  qbytes="$(echo "$line" | jq -r '.quotaBytes // 0')"

  left="$((exp - now))"; [[ "$left" -lt 0 ]] && left=0

  used=0
  json="$(xray_statsquery "inbound>>>${tag}>>>traffic>>>" || true)"
  if [[ -n "$json" ]]; then
    up="$(echo "$json" | jq -r --arg t "$tag" '.stat[]? | select(.name|contains("inbound>>>"+$t+">>>traffic>>>uplink")) | .value' | sed -n '1p')"
    down="$(echo "$json" | jq -r --arg t "$tag" '.stat[]? | select(.name|contains("inbound>>>"+$t+">>>traffic>>>downlink")) | .value' | sed -n '1p')"
    up="${up:-0}"; down="${down:-0}"
    used="$((up + down))"
  fi

  status="OK"
  if [[ "$qbytes" -gt 0 && "$used" -ge "$qbytes" ]]; then status="OVER"; fi

  echo "${tag} | ${port} | ${left}s | $(fmt_bytes "$used") | $(fmt_bytes "$qbytes") | ${status}"
done <"$STATE_FILE"
EOF

  # vless_quota_watch.sh（执行一次检查，超限就删）
  write_bin /usr/local/bin/vless_quota_watch.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/root/reality.env"
STATE_FILE="/root/.vless_temp_inbounds.jsonl"
XRAY_BIN="/usr/local/bin/xray"

die(){ echo "❌ $*" >&2; exit 1; }
warn(){ echo "⚠️  $*" >&2; }
ok(){ echo "✅ $*"; }

[[ -f "$ENV_FILE" ]] || die "缺少 $ENV_FILE（先跑 /root/onekey_reality_ipv4.sh）"
# shellcheck disable=SC1090
source "$ENV_FILE"

API="${API_LISTEN:-127.0.0.1:10085}"

xray_statsquery() {
  local pattern="$1"
  "$XRAY_BIN" api statsquery --server="$API" --pattern="$pattern" 2>/dev/null && return 0
  "$XRAY_BIN" api statsquery -server="$API" -pattern="$pattern"  2>/dev/null && return 0
  "$XRAY_BIN" api statsquery -s "$API" -pattern="$pattern"       2>/dev/null && return 0
  return 1
}

lock_and_run() {
  if command -v flock >/dev/null 2>&1; then
    exec 9>"/tmp/vless_quota_watch.lock"
    flock -n 9 || exit 0
    "$@"
  else
    "$@"
  fi
}

run_once() {
  [[ -f "$STATE_FILE" ]] || exit 0

  local now tmp removed_any=0
  now="$(date +%s)"
  tmp="${STATE_FILE}.tmp.$$"
  : >"$tmp"

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue

    tag="$(echo "$line" | jq -r '.tag')"
    port="$(echo "$line" | jq -r '.port')"
    exp="$(echo "$line" | jq -r '.expires')"
    qbytes="$(echo "$line" | jq -r '.quotaBytes // 0')"

    # 到期：直接删（兜底）
    if [[ "$now" -ge "$exp" ]]; then
      /usr/local/bin/vless_rmi_one.sh "$port" >/dev/null 2>&1 || true
      removed_any=1
      continue
    fi

    # 无配额：保留
    if [[ "$qbytes" -le 0 ]]; then
      echo "$line" >>"$tmp"
      continue
    fi

    # 查用量
    used=0
    json="$(xray_statsquery "inbound>>>${tag}>>>traffic>>>" || true)"
    if [[ -n "$json" ]]; then
      up="$(echo "$json" | jq -r --arg t "$tag" '.stat[]? | select(.name|contains("inbound>>>"+$t+">>>traffic>>>uplink")) | .value' | sed -n '1p')"
      down="$(echo "$json" | jq -r --arg t "$tag" '.stat[]? | select(.name|contains("inbound>>>"+$t+">>>traffic>>>downlink")) | .value' | sed -n '1p')"
      up="${up:-0}"; down="${down:-0}"
      used="$((up + down))"
    fi

    if [[ "$used" -ge "$qbytes" ]]; then
      warn "超限：tag=$tag port=$port used=${used} quota=${qbytes} -> 移除入站"
      /usr/local/bin/vless_rmi_one.sh "$port" >/dev/null 2>&1 || true
      removed_any=1
      continue
    fi

    echo "$line" >>"$tmp"
  done <"$STATE_FILE"

  mv -f "$tmp" "$STATE_FILE"
  [[ "$removed_any" -eq 1 ]] && ok "本轮检查：已移除超限/到期入站"
}

lock_and_run run_once
EOF

  # 安装 systemd timer：每 30 秒跑一次 vless_quota_watch.sh
  write_bin /usr/local/bin/vless_quota_install_timer.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

die(){ echo "❌ $*" >&2; exit 1; }
ok(){ echo "✅ $*"; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "请用 root 执行"

cat >/etc/systemd/system/vless-quota-watch.service <<'S'
[Unit]
Description=VLESS quota watcher (remove temp inbounds when over quota)

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vless_quota_watch.sh
S

cat >/etc/systemd/system/vless-quota-watch.timer <<'T'
[Unit]
Description=Run VLESS quota watcher every 30s

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s
Unit=vless-quota-watch.service

[Install]
WantedBy=timers.target
T

systemctl daemon-reload
systemctl enable --now vless-quota-watch.timer
systemctl status --no-pager vless-quota-watch.timer | sed -n '1,12p' || true
ok "已安装并启动配额定时器：vless-quota-watch.timer（每 30 秒检查一次）"
EOF
}

main() {
  need_root

  gen_update_all
  gen_onekey_reality
  gen_temp_tools
  gen_quota_tools

  ok "所有脚本已生成完毕（Debian 12 / 单进程 Xray + API 动态入站 + 配额系统）"
  echo
  echo "建议顺序："
  echo "1) update-all && reboot"
  echo "2) bash /root/onekey_reality_ipv4.sh"
  echo "3) 自检 API：/usr/local/bin/xray api lsi --server=\"127.0.0.1:10085\""
  echo "4) 安装配额定时器（可选但推荐）：vless_quota_install_timer.sh"
  echo "5) 创建临时节点（带配额MB）：D=3600 Q=50 vless_mktemp.sh"
  echo
  echo "常用命令："
  echo "- D=600 Q=0 vless_mktemp.sh           # 不限流量"
  echo "- D=3600 Q=50 vless_mktemp.sh         # 50MB 配额（上下行合计）"
  echo "- vless_quota_show.sh                 # 查看用量/配额"
  echo "- vless_quota_watch.sh                # 手动跑一轮（超限就删）"
  echo "- vless_audit.sh"
  echo "- vless_rmi_one.sh 40035"
  echo "- vless_clear_all.sh"
  echo
  echo "如果你仍然看到 ensure_deps / command not found："
  echo "- 说明 GitHub 上 huanxin.sh 可能被压缩、丢换行或被替换（网页编辑器最常见）。"
  echo "- 请用原样文本覆盖上传（建议 git push）。"
}

main "$@"
