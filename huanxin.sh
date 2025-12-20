#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# huanxin.sh (Debian 12)
# - 单进程 Xray + Reality(VLESS Vision) + API 动态入站 + 配额系统
#
# 生成：
# - /usr/local/bin/update-all
# - /root/onekey_reality_ipv4.sh
# - /usr/local/bin/vless_mktemp.sh
# - /usr/local/bin/vless_rmi_one.sh
# - /usr/local/bin/vless_audit.sh
# - /usr/local/bin/vless_clear_all.sh
# - /usr/local/bin/vless_quota_show.sh
# - /usr/local/bin/vless_quota_watch.sh
# - /usr/local/bin/vless_quota_install_timer.sh
#
# 关键修复：
# - 彻底避免 head -n1 在 pipefail 下触发 exit=141（统一改 sed -n '1p'）
# - xray x25519 输出兼容 PublicKey / Password
# - xray api 参数兼容（--server / -server / -s）
# - mktemp 的 adi 失败时会打印 xray 原始报错，方便你定位
# ============================================================

SCRIPT_VER="2025-12-20+quota-fixed"
export DEBIAN_FRONTEND=noninteractive

XRAY_BIN="/usr/local/bin/xray"
XRAY_CFG="/usr/local/etc/xray/config.json"
XRAY_LOG_DIR="/var/log/xray"

ENV_FILE="/root/reality.env"
STATE_FILE="/root/.vless_temp_inbounds.jsonl"

DEFAULT_SNI="${SNI:-www.apple.com}"
DEFAULT_DEST="${DEST:-www.apple.com:443}"
DEFAULT_PORT_MAIN="${PORT:-443}"
DEFAULT_FP="${FP:-chrome}"
DEFAULT_API_LISTEN="${API_LISTEN:-127.0.0.1:10085}"

trap 'echo -e "\n❌ 出错：exit=$?  行号=${LINENO}  命令：${BASH_COMMAND}\n" >&2' ERR

log()  { echo -e "$*"; }
ok()   { echo -e "✅ $*"; }
warn() { echo -e "⚠️ $*" >&2; }
die()  { echo -e "❌ $*" >&2; exit 1; }

need_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "请用 root 执行：sudo -i 后再运行"; }

apt_install() {
  apt-get update -y
  apt-get install -y --no-install-recommends "$@"
}

ensure_deps() {
  apt_install curl ca-certificates unzip jq openssl iproute2 coreutils util-linux
}

detect_public_ip() {
  local ip=""
  ip="$(curl -4fsSL https://api.ipify.org 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(curl -4fsSL https://ip.sb 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/{print $7; exit}' || true)"
  [[ -n "$ip" ]] || die "无法探测服务器 IPv4（curl 出网失败？）"
  echo "$ip"
}

install_or_update_xray() {
  ensure_deps
  log "=== 安装/更新 Xray ==="
  bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install -u root
  [[ -x "$XRAY_BIN" ]] || die "Xray 安装失败：找不到 $XRAY_BIN"
  ok "Xray：$("$XRAY_BIN" version 2>/dev/null | sed -n '1p' || true)"
}

enable_fq_bbr_only() {
  log "=== 写入 fq + bbr ==="
  cat >/etc/sysctl.d/99-huanxin-fq-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl --system >/dev/null 2>&1 || true
  ok "已写入 fq+bbr（/etc/sysctl.d/99-huanxin-fq-bbr.conf）"
}

gen_uuid() { "$XRAY_BIN" uuid; }

# 兼容：旧版输出 PublicKey，新版输出 Password（等价 publicKey）
gen_x25519() {
  local out priv pub
  out="$("$XRAY_BIN" x25519 2>/dev/null || true)"
  priv="$(echo "$out" | awk -F': ' '/PrivateKey/{print $2; exit}')"
  pub="$(echo "$out" | awk -F': ' '/^(PublicKey|Password):/{print $2; exit}')"
  [[ -n "$priv" && -n "$pub" ]] || { echo "$out" >&2; die "x25519 解析失败"; }
  echo "$priv|$pub"
}

gen_shortid() { openssl rand -hex 8; }

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  cp -a "$f" "${f}.bak.$(date +%Y%m%d_%H%M%S)"
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
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive

XRAY_BIN="/usr/local/bin/xray"
XRAY_CFG="/usr/local/etc/xray/config.json"
XRAY_LOG_DIR="/var/log/xray"
ENV_FILE="/root/reality.env"

DEFAULT_SNI="${SNI:-www.apple.com}"
DEFAULT_DEST="${DEST:-www.apple.com:443}"
DEFAULT_PORT_MAIN="${PORT:-443}"
DEFAULT_FP="${FP:-chrome}"
DEFAULT_API_LISTEN="${API_LISTEN:-127.0.0.1:10085}"

trap 'echo -e "\n❌ 出错：exit=$?  行号=${LINENO}  命令：${BASH_COMMAND}\n" >&2' ERR

die(){ echo "❌ $*" >&2; exit 1; }
ok(){ echo "✅ $*"; }

apt_install() { apt-get update -y; apt-get install -y --no-install-recommends "$@"; }
ensure_deps() { apt_install curl ca-certificates unzip jq openssl iproute2 coreutils util-linux; }

detect_public_ip() {
  local ip=""
  ip="$(curl -4fsSL https://api.ipify.org 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(curl -4fsSL https://ip.sb 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/{print $7; exit}' || true)"
  [[ -n "$ip" ]] || die "无法探测服务器 IPv4"
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

write_env() {
  local server_ip="$1" port_main="$2" uuid="$3" priv="$4" pub="$5" sid="$6" sni="$7" dest="$8" fp="$9" api_listen="${10}"
  cat >"$ENV_FILE" <<E
# generated by onekey_reality_ipv4.sh
SERVER_IP="${server_ip}"
PORT_MAIN="${port_main}"
UUID="${uuid}"
PRIVATE_KEY="${priv}"
PUBLIC_KEY="${pub}"
SHORT_ID="${sid}"
SNI="${sni}"
DEST="${dest}"
FP="${fp}"
API_LISTEN="${api_listen}"
E
  chmod 600 "$ENV_FILE"
}

write_main_config() {
  local api_listen="$1"

  local api_host api_port
  api_host="${api_listen%:*}"
  api_port="${api_listen##*:}"
  [[ "$api_host" != "$api_port" ]] || die "API_LISTEN 格式错误，应为 127.0.0.1:10085"

  mkdir -p "$(dirname "$XRAY_CFG")" "$XRAY_LOG_DIR"
  backup_file "$XRAY_CFG"

  # 重点：为了配额统计，开启 stats + policy.system.statsInboundUplink/Downlink
  cat >"$XRAY_CFG" <<JSON
{
  "log": {
    "loglevel": "warning",
    "access": "${XRAY_LOG_DIR}/access.log",
    "error": "${XRAY_LOG_DIR}/error.log"
  },
  "api": {
    "tag": "api",
    "services": ["HandlerService", "LoggerService", "StatsService"]
  },
  "stats": {},
  "policy": {
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink": false,
      "statsOutboundDownlink": false
    }
  },
  "inbounds": [
    {
      "tag": "api",
      "listen": "${api_host}",
      "port": ${api_port},
      "protocol": "dokodemo-door",
      "settings": { "address": "${api_host}" }
    },
    {
      "tag": "vless-reality-${PORT_MAIN}",
      "listen": "0.0.0.0",
      "port": ${PORT_MAIN},
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${UUID}", "flow": "xtls-rprx-vision", "email": "main" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "${DEST}",
          "serverNames": ["${SNI}"],
          "privateKey": "${PRIVATE_KEY}",
          "shortIds": ["${SHORT_ID}"]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"],
        "routeOnly": true
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": {
    "rules": [
      { "type": "field", "inboundTag": ["api"], "outboundTag": "api" }
    ]
  }
}
JSON

  systemctl enable xray >/dev/null 2>&1 || true
  systemctl restart xray
  sleep 0.6
}

vless_url() {
  local uuid="$1" host="$2" port="$3" sni="$4" fp="$5" pbk="$6" sid="$7" name="$8"
  echo "vless://${uuid}@${host}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=${fp}&pbk=${pbk}&sid=${sid}&type=tcp&headerType=none#${name}"
}

main() {
  enable_fq_bbr_only
  install_or_update_xray

  echo "=== 生成 UUID + Reality 密钥 ==="
  local uuid kp priv pub sid server_ip
  uuid="$(gen_uuid)"
  kp="$(gen_x25519)"; priv="${kp%%|*}"; pub="${kp##*|}"
  sid="$(gen_shortid)"
  server_ip="$(detect_public_ip)"

  write_env "$server_ip" "$DEFAULT_PORT_MAIN" "$uuid" "$priv" "$pub" "$sid" "$DEFAULT_SNI" "$DEFAULT_DEST" "$DEFAULT_FP" "$DEFAULT_API_LISTEN"
  # shellcheck disable=SC1090
  source "$ENV_FILE"

  write_main_config "$API_LISTEN"
  ok "Xray 已重启"

  local url
  url="$(vless_url "$UUID" "$SERVER_IP" "$PORT_MAIN" "$SNI" "$FP" "$PUBLIC_KEY" "$SHORT_ID" "reality-${PORT_MAIN}")"
  echo "$url" | tee "/root/vless_main_${PORT_MAIN}.txt" >/dev/null

  echo
  ok "主节点已写入：/root/vless_main_${PORT_MAIN}.txt"
  echo "----------------------------------------"
  echo "$url"
  echo "----------------------------------------"
  echo
  echo "下一步建议："
  echo "  /usr/local/bin/xray api lsi --server=127.0.0.1:10085"
}

main "$@"
EOF
}

gen_temp_tools() {
  write_bin /usr/local/bin/vless_mktemp.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

ENV_FILE="/root/reality.env"
STATE_FILE="/root/.vless_temp_inbounds.jsonl"
XRAY_BIN="/usr/local/bin/xray"

trap 'echo -e "\n❌ 出错：exit=$?  行号=${LINENO}  命令：${BASH_COMMAND}\n" >&2' ERR

die(){ echo "❌ $*" >&2; exit 1; }
ok(){ echo "✅ $*"; }
warn(){ echo "⚠️ $*" >&2; }

[[ -f "$ENV_FILE" ]] || die "缺少 $ENV_FILE，请先运行：bash /root/onekey_reality_ipv4.sh"
# shellcheck disable=SC1090
source "$ENV_FILE"

D="${D:-600}"         # 存活秒数
PORT="${PORT:-}"      # 可手动指定
NAME="${NAME:-temp}"  # 节点备注
Q="${Q:-0}"           # 配额（MB，上下行合计；0=不限）
API="${API_LISTEN:-127.0.0.1:10085}"

[[ "$D" =~ ^[0-9]+$ ]] || die "D 必须是数字"
[[ "$Q" =~ ^[0-9]+$ ]] || die "Q 必须是数字（MB）"

rand_port(){ shuf -i 20000-60000 -n 1; }
port_free(){ local p="$1"; ! ss -lnt "( sport = :$p )" 2>/dev/null | grep -q ":$p"; }

choose_port() {
  if [[ -n "${PORT}" ]]; then
    [[ "$PORT" =~ ^[0-9]+$ ]] || die "PORT 必须是数字"
    port_free "$PORT" || die "端口 $PORT 已被占用"
    echo "$PORT"; return 0
  fi
  local p
  for _ in $(seq 1 30); do
    p="$(rand_port)"
    if port_free "$p"; then echo "$p"; return 0; fi
  done
  die "随机挑选端口失败（连续 30 次都被占用？）"
}

# 兼容多风格参数：--server / -server / -s
xray_api_try() {
  # usage: xray_api_try <subcmd> <args...>
  local sub="$1"; shift
  local out rc

  out="$("$XRAY_BIN" api "$sub" --server="$API" "$@" 2>&1)" && { echo "$out"; return 0; }
  rc=$?
  out="$("$XRAY_BIN" api "$sub" -server="$API" "$@" 2>&1)" && { echo "$out"; return 0; }
  rc=$?
  out="$("$XRAY_BIN" api "$sub" -s "$API" "$@" 2>&1)" && { echo "$out"; return 0; }
  rc=$?

  echo "$out"
  return "$rc"
}

vless_url() {
  local uuid="$1" host="$2" port="$3" sni="$4" fp="$5" pbk="$6" sid="$7" name="$8"
  echo "vless://${uuid}@${host}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=${fp}&pbk=${pbk}&sid=${sid}&type=tcp&headerType=none#${name}"
}

with_lock() {
  if command -v flock >/dev/null 2>&1; then
    exec 9>"/tmp/vless_mktemp.lock"
    flock -n 9 || die "正在有另一个 mktemp 在运行，请稍后再试"
  fi
  "$@"
}

main() {
  local port tag tmp expires now quota_bytes
  port="$(choose_port)"
  tag="temp-${port}"
  tmp="/tmp/inbound_${tag}.json"
  now="$(date +%s)"
  expires="$((now + D))"
  quota_bytes="$((Q * 1024 * 1024))"

  # 生成动态入站 JSON（必须是合法 inbound 对象）
  cat >"$tmp" <<JSON
{
  "tag": "${tag}",
  "listen": "0.0.0.0",
  "port": ${port},
  "protocol": "vless",
  "settings": {
    "clients": [
      { "id": "${UUID}", "flow": "xtls-rprx-vision", "email": "${tag}" }
    ],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "dest": "${DEST}",
      "serverNames": ["${SNI}"],
      "privateKey": "${PRIVATE_KEY}",
      "shortIds": ["${SHORT_ID}"]
    }
  },
  "sniffing": {
    "enabled": true,
    "destOverride": ["http", "tls", "quic"],
    "routeOnly": true
  }
}
JSON

  # 添加入站（失败就打印 xray 原始报错）
  if ! out="$(xray_api_try adi "$tmp")"; then
    echo "$out" >&2
    die "❌ 添加入站失败：xray api adi 调用失败（建议先自检：$XRAY_BIN api lsi --server=127.0.0.1:10085）"
  fi

  # 记录状态（JSONL）
  with_lock bash -c '
    set -euo pipefail
    line=$(jq -c -n \
      --arg tag "'"$tag"'" \
      --argjson port "'"$port"'" \
      --argjson expires "'"$expires"'" \
      --argjson quotaBytes "'"$quota_bytes"'" \
      "{tag:\$tag, port:\$port, expires:\$expires, quotaBytes:\$quotaBytes}")
    touch "'"$STATE_FILE"'"
    echo "$line" >>"'"$STATE_FILE"'"
  '

  # 重置该 inbound 的统计（不强依赖）
  xray_api_try statsquery --pattern="inbound>>>${tag}>>>traffic>>>" --reset=true >/dev/null 2>&1 || true

  # 输出节点
  local url
  url="$(vless_url "$UUID" "$SERVER_IP" "$port" "$SNI" "${FP:-chrome}" "$PUBLIC_KEY" "$SHORT_ID" "${NAME}-${port}")"
  echo "$url" | tee "/root/vless_${tag}.txt" >/dev/null

  ok "临时入站已创建：port=${port} duration=${D}s tag=${tag} quotaMB=${Q}"
  ok "节点已写入：/root/vless_${tag}.txt"
  echo "----------------------------------------"
  echo "$url"
  echo "----------------------------------------"

  # 到期兜底删除（哪怕你不装 quota timer，也能到点清）
  if [[ "$D" -gt 0 ]]; then
    nohup bash -c "sleep ${D}; /usr/local/bin/vless_rmi_one.sh ${port} >/dev/null 2>&1" >/dev/null 2>&1 &
    ok "已后台定时删除：${D}s 后移除 port=${port}"
  fi
}

main "$@"
EOF

  write_bin /usr/local/bin/vless_rmi_one.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

ENV_FILE="/root/reality.env"
STATE_FILE="/root/.vless_temp_inbounds.jsonl"
XRAY_BIN="/usr/local/bin/xray"

trap 'echo -e "\n❌ 出错：exit=$?  行号=${LINENO}  命令：${BASH_COMMAND}\n" >&2' ERR

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

xray_api_try() {
  local sub="$1"; shift
  local out rc
  out="$("$XRAY_BIN" api "$sub" --server="$API" "$@" 2>&1)" && { echo "$out"; return 0; }
  rc=$?
  out="$("$XRAY_BIN" api "$sub" -server="$API" "$@" 2>&1)" && { echo "$out"; return 0; }
  rc=$?
  out="$("$XRAY_BIN" api "$sub" -s "$API" "$@" 2>&1)" && { echo "$out"; return 0; }
  rc=$?
  echo "$out"
  return "$rc"
}

# rmi 参数不同版本可能是 --tag=xxx 或直接传 tag（这里都试）
if ! xray_api_try rmi --tag="$TAG" >/dev/null; then
  if ! xray_api_try rmi "$TAG" >/dev/null; then
    die "移除失败：tag=$TAG（可运行：$XRAY_BIN api rmi -h 查看参数）"
  fi
fi

ok "已移除入站：tag=$TAG"

# 更新状态文件
if [[ -f "$STATE_FILE" ]]; then
  tmp="${STATE_FILE}.tmp.$$"
  grep -v "\"port\":${PORT}" "$STATE_FILE" >"$tmp" || true
  mv -f "$tmp" "$STATE_FILE"
fi
EOF

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
  left="$((exp - now))"; [[ "$left" -lt 0 ]] && left=0
  printf "port=%s tag=%s 剩余=%ss quotaBytes=%s\n" "$port" "$tag" "$left" "$qbytes"
done <"$STATE_FILE"
EOF

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

xray_api_try() {
  local sub="$1"; shift
  "$XRAY_BIN" api "$sub" --server="$API" "$@" 2>/dev/null && return 0
  "$XRAY_BIN" api "$sub" -server="$API" "$@" 2>/dev/null && return 0
  "$XRAY_BIN" api "$sub" -s "$API" "$@" 2>/dev/null && return 0
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
  json="$(xray_api_try statsquery --pattern="inbound>>>${tag}>>>traffic>>>" && true || true)"
  if [[ -n "${json:-}" ]]; then
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

  write_bin /usr/local/bin/vless_quota_watch.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

ENV_FILE="/root/reality.env"
STATE_FILE="/root/.vless_temp_inbounds.jsonl"
XRAY_BIN="/usr/local/bin/xray"

trap 'echo -e "\n❌ 出错：exit=$?  行号=${LINENO}  命令：${BASH_COMMAND}\n" >&2' ERR

die(){ echo "❌ $*" >&2; exit 1; }
warn(){ echo "⚠️ $*" >&2; }
ok(){ echo "✅ $*"; }

[[ -f "$ENV_FILE" ]] || die "缺少 $ENV_FILE（先跑 /root/onekey_reality_ipv4.sh）"
# shellcheck disable=SC1090
source "$ENV_FILE"
API="${API_LISTEN:-127.0.0.1:10085}"

xray_api_try() {
  local sub="$1"; shift
  "$XRAY_BIN" api "$sub" --server="$API" "$@" 2>/dev/null && return 0
  "$XRAY_BIN" api "$sub" -server="$API" "$@" 2>/dev/null && return 0
  "$XRAY_BIN" api "$sub" -s "$API" "$@" 2>/dev/null && return 0
  return 1
}

lock_and_run() {
  if command -v flock >/dev/null 2>&1; then
    exec 9>"/tmp/vless_quota_watch.lock"
    flock -n 9 || exit 0
  fi
  "$@"
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

    # 到期：兜底删除
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

    used=0
    json="$(xray_api_try statsquery --pattern="inbound>>>${tag}>>>traffic>>>" && true || true)"
    if [[ -n "${json:-}" ]]; then
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
  echo "3) 自检 API：/usr/local/bin/xray api lsi --server=127.0.0.1:10085"
  echo "4) 安装配额定时器（可选但推荐）：vless_quota_install_timer.sh"
  echo "5) 创建临时节点（带配额MB）：D=3600 Q=50 vless_mktemp.sh"
  echo
  echo "常用命令："
  echo "- D=600  Q=0  vless_mktemp.sh     # 不限流量"
  echo "- D=3600 Q=50 vless_mktemp.sh     # 50MB 配额（上下行合计）"
  echo "- vless_quota_show.sh             # 查看用量/配额"
  echo "- vless_quota_watch.sh            # 手动跑一轮（超限就删）"
  echo "- vless_audit.sh"
  echo "- vless_rmi_one.sh 40035"
  echo "- vless_clear_all.sh"
  echo
  echo "⚠️ 如果出现脚本变 1 行/丢换行：请用 git push 上传，不要用网页编辑器粘贴。"
}

main "$@"
