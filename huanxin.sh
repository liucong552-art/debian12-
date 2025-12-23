#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# huanxin_persist.sh (Debian 12)
# - 单进程 Xray + Reality(VLESS Vision)
# - Xray API 动态临时入站（可恢复）
# - 配额：累计用量写磁盘（重启不丢）
# - 到期时间：按北京时间输出（YYYY-MM-DD HH:MM:SS）
#
# 生成/安装：
# - /usr/local/bin/update-all
# - /root/onekey_reality_ipv4.sh
# - /usr/local/bin/vless_mktemp.sh
# - /usr/local/bin/vless_rmi_one.sh
# - /usr/local/bin/vless_audit.sh
# - /usr/local/bin/vless_clear_all.sh
# - /usr/local/bin/vless_restore.sh
# - /usr/local/bin/vless_quota_show.sh
# - /usr/local/bin/vless_quota_watch.sh
# - /usr/local/bin/vless_services_install.sh   (安装/启用：恢复+配额定时器)
#
# systemd：
# - vless-restore.service        (开机恢复临时入站)
# - vless-quota-watch.timer      (每 30 秒检查：到期/超限就删)
# ============================================================

SCRIPT_VER="2025-12-23+persist-quota-cn-exp"
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

check_debian12() {
  local codename
  codename="$(. /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-}")"
  [[ "$codename" == "bookworm" ]] || die "仅支持 Debian 12(bookworm)，当前：${codename:-未知}"
}

apt_install() {
  apt-get update -y
  apt-get install -y --no-install-recommends "$@"
}

ensure_deps() {
  # coreutils: numfmt/shuf ; util-linux: flock ; iproute2: ss ; jq 解析
  apt_install curl ca-certificates unzip jq openssl iproute2 coreutils util-linux
}

write_bin() {
  local path="$1"
  install -m 0755 /dev/null "$path"
  cat >"$path"
  chmod 0755 "$path"
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

gen_update_all() {
  write_bin /usr/local/bin/update-all <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
echo "🚀 开始系统更新 (Debian 12 / bookworm)..."
apt-get update -y
apt-get full-upgrade -y
apt-get --purge autoremove -y
apt-get autoclean -y
apt-get clean -y
echo "✅ 软件包更新完成"
echo "🧠 建议：如更新了内核/openssh/系统关键组件，重启一次更稳：reboot"
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

  # stats + policy.system.statsInboundUplink/Downlink 开启（供配额统计）
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
    { "protocol": "blackhole", "tag": "block" },
    { "protocol": "freedom", "tag": "api" }
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
  sleep 0.8
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
  echo "API 自检（应能列出 inbounds）："
  echo "  /usr/local/bin/xray api lsi --server=${API_LISTEN}"
}

main "$@"
EOF
}

gen_temp_tools() {
  # 临时入站：adi + 写 state（含累计字段）+ 输出北京时间到期
  write_bin /usr/local/bin/vless_mktemp.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

ENV_FILE="/root/reality.env"
STATE_FILE="/root/.vless_temp_inbounds.jsonl"
XRAY_BIN="/usr/local/bin/xray"
LOCK_FILE="/tmp/vless_mktemp.lock"

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

xray_api_try() {
  local sub="$1"; shift
  "$XRAY_BIN" api "$sub" --server="$API" "$@" 2>/dev/null && return 0
  "$XRAY_BIN" api "$sub" -server="$API" "$@" 2>/dev/null && return 0
  "$XRAY_BIN" api "$sub" -s "$API" "$@" 2>/dev/null && return 0
  return 1
}

vless_url() {
  local uuid="$1" host="$2" port="$3" sni="$4" fp="$5" pbk="$6" sid="$7" name="$8"
  echo "vless://${uuid}@${host}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=${fp}&pbk=${pbk}&sid=${sid}&type=tcp&headerType=none#${name}"
}

with_lock() {
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$LOCK_FILE"
    flock -n 9 || die "正在有另一个 mktemp 在运行，请稍后再试"
  fi
  "$@"
}

record_state() {
  local tag="$1" port="$2" expires="$3" quota_bytes="$4" name="$5"
  local line tmp
  line="$(jq -c -n \
    --arg tag "$tag" \
    --argjson port "$port" \
    --argjson expires "$expires" \
    --argjson quotaBytes "$quota_bytes" \
    --arg name "$name" \
    --argjson totalUsedBytes 0 \
    --argjson lastSeenBytes 0 \
    '{tag:$tag, port:$port, expires:$expires, quotaBytes:$quotaBytes, name:$name, totalUsedBytes:$totalUsedBytes, lastSeenBytes:$lastSeenBytes}')"

  mkdir -p "$(dirname "$STATE_FILE")"
  touch "$STATE_FILE"
  tmp="${STATE_FILE}.tmp.$$"
  grep -Fv "\"tag\":\"${tag}\"" "$STATE_FILE" | grep -Fv "\"port\":${port}" >"$tmp" || true
  printf '%s\n' "$line" >>"$tmp"
  mv -f "$tmp" "$STATE_FILE"
}

main() {
  local port tag tmp_json now expires quota_bytes exp_cn exp_tag node_name url
  port="$(choose_port)"
  tag="temp-${port}"
  tmp_json="/tmp/inbound_${tag}.json"

  now="$(date +%s)"
  expires="$((now + D))"
  quota_bytes="$((Q * 1024 * 1024))"

  exp_cn="$(TZ='Asia/Shanghai' date -d "@$expires" '+%Y-%m-%d %H:%M:%S')"
  exp_tag="$(TZ='Asia/Shanghai' date -d "@$expires" '+%Y%m%d%H%M%S')"
  node_name="${NAME}-${port}-exp${exp_tag}"

  # adi 需要 {"inbounds":[{...}]} 结构
  cat >"$tmp_json" <<JSON
{
  "inbounds": [
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
  ]
}
JSON

  xray_api_try adi "$tmp_json" || die "添加临时入站失败（建议自检：xray api lsi --server=$API）"

  record_state "$tag" "$port" "$expires" "$quota_bytes" "$node_name"

  # 初次创建可尝试 reset（失败也不影响）
  xray_api_try statsquery --pattern="inbound>>>${tag}>>>traffic>>>" --reset=true >/dev/null 2>&1 || true

  url="$(vless_url "$UUID" "$SERVER_IP" "$port" "$SNI" "${FP:-chrome}" "$PUBLIC_KEY" "$SHORT_ID" "$node_name")"
  echo "$url" | tee "/root/vless_${tag}.txt" >/dev/null

  echo
  ok "临时入站已创建：tag=${tag}"
  echo "地址：${SERVER_IP}:${port}"
  echo "有效期：${D}s"
  echo "到期时间(北京时间)：${exp_cn}"
  echo "配额：${Q} MB（上下行合计，0=不限）"
  echo "保存：/root/vless_${tag}.txt"
  echo
  echo "------------------- VLESS URL -------------------"
  echo "$url"
  echo "-------------------------------------------------"
  echo

  rm -f "$tmp_json" >/dev/null 2>&1 || true
}

with_lock main "$@"
EOF

  # 移除指定 port 的临时入站 + 状态清理
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
  "$XRAY_BIN" api "$sub" --server="$API" "$@" 2>/dev/null && return 0
  "$XRAY_BIN" api "$sub" -server="$API" "$@" 2>/dev/null && return 0
  "$XRAY_BIN" api "$sub" -s "$API" "$@" 2>/dev/null && return 0
  return 1
}

# rmi 参数兼容：--tag=xxx 或直接传 tag
if ! xray_api_try rmi --tag="$TAG" >/dev/null; then
  xray_api_try rmi "$TAG" >/dev/null || die "移除失败：tag=$TAG（可运行：$XRAY_BIN api rmi -h 查看参数）"
fi

ok "已移除入站：tag=$TAG"

# 原子更新状态文件
if [[ -f "$STATE_FILE" ]]; then
  tmp="${STATE_FILE}.tmp.$$"
  grep -Fv "\"port\":${PORT}" "$STATE_FILE" >"$tmp" || true
  mv -f "$tmp" "$STATE_FILE"
fi
EOF

  # 清空所有临时入站
  write_bin /usr/local/bin/vless_clear_all.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
STATE_FILE="/root/.vless_temp_inbounds.jsonl"

if [[ ! -f "$STATE_FILE" ]]; then
  echo "✅ 无需清理（没有状态文件）"
  exit 0
fi

ports="$(jq -r '.port // empty' "$STATE_FILE" 2>/dev/null || true)"
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

  # 审计：显示主配置 + 临时节点（含北京时间到期时间）
  write_bin /usr/local/bin/vless_audit.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/root/reality.env"
STATE_FILE="/root/.vless_temp_inbounds.jsonl"

die(){ echo "❌ $*" >&2; exit 1; }
to_int(){ local v="${1:-0}"; [[ "$v" =~ ^[0-9]+$ ]] && echo "$v" || echo 0; }
fmt_cn_time(){ TZ='Asia/Shanghai' date -d "@$1" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "N/A"; }

[[ -f "$ENV_FILE" ]] || die "缺少 $ENV_FILE（先跑 /root/onekey_reality_ipv4.sh）"
# shellcheck disable=SC1090
source "$ENV_FILE"

echo "=== Reality 主配置 ==="
echo "SERVER_IP=$SERVER_IP"
echo "PORT_MAIN=$PORT_MAIN"
echo "SNI=$SNI"
echo "DEST=$DEST"
echo "FP=$FP"
echo "API_LISTEN=$API_LISTEN"
echo

echo "=== 临时入站（本机记录）==="
if [[ ! -f "$STATE_FILE" ]]; then
  echo "(无记录)"
  exit 0
fi

now="$(date +%s)"
printf "%-14s %-18s %-10s %-20s %-10s %-10s\n" "PORT" "TAG" "LEFT(s)" "EXPIRE(CN)" "Q(MB)" "USED(MB)"
echo "--------------------------------------------------------------------------------"

while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  port="$(to_int "$(echo "$line" | jq -r '.port // 0' 2>/dev/null || echo 0)")"
  tag="$(echo "$line" | jq -r '.tag // empty' 2>/dev/null || true)"
  exp="$(to_int "$(echo "$line" | jq -r '.expires // 0' 2>/dev/null || echo 0)")"
  qbytes="$(to_int "$(echo "$line" | jq -r '.quotaBytes // 0' 2>/dev/null || echo 0)")"
  usedb="$(to_int "$(echo "$line" | jq -r '.totalUsedBytes // 0' 2>/dev/null || echo 0)")"
  [[ -n "$tag" ]] || continue

  left=$((exp - now)); (( left < 0 )) && left=0
  expcn="$(fmt_cn_time "$exp")"
  qmb=$((qbytes / 1024 / 1024))
  usedmb=$((usedb / 1024 / 1024))

  printf "%-14s %-18s %-10s %-20s %-10s %-10s\n" "$port" "$tag" "$left" "$expcn" "$qmb" "$usedmb"
done <"$STATE_FILE"
EOF
}

gen_restore_tool() {
  # 开机恢复：读取 state，把未过期的入站重新 adi 回来
  write_bin /usr/local/bin/vless_restore.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

ENV_FILE="/root/reality.env"
STATE_FILE="/root/.vless_temp_inbounds.jsonl"
XRAY_BIN="/usr/local/bin/xray"

trap 'echo -e "\n❌ 出错：exit=$? 行号=${LINENO} 命令：${BASH_COMMAND}\n" >&2' ERR
die(){ echo "❌ $*" >&2; exit 1; }
warn(){ echo "⚠️ $*" >&2; }
ok(){ echo "✅ $*"; }

to_int(){ local v="${1:-0}"; [[ "$v" =~ ^[0-9]+$ ]] && echo "$v" || echo 0; }

[[ -f "$ENV_FILE" ]] || { ok "无 $ENV_FILE，跳过恢复"; exit 0; }
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

port_free(){
  local p="$1"
  ! ss -lnt "( sport = :$p )" 2>/dev/null | grep -q ":$p"
}

wait_api_ready() {
  # 最多等 ~10 秒
  for _ in $(seq 1 20); do
    if xray_api_try lsi >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  return 1
}

[[ -s "$STATE_FILE" ]] || { ok "无临时入站记录，无需恢复"; exit 0; }

if ! wait_api_ready; then
  warn "Xray API 不可用（${API}），跳过恢复"
  exit 0
fi

now="$(date +%s)"
tmp="${STATE_FILE}.tmp.$$"
: >"$tmp"

restored=0
expired=0
skipped=0

while IFS= read -r line; do
  [[ -n "$line" ]] || continue

  tag="$(echo "$line" | jq -r '.tag // empty' 2>/dev/null || true)"
  port="$(echo "$line" | jq -r '.port // 0' 2>/dev/null || echo 0)"
  exp="$(echo "$line" | jq -r '.expires // 0' 2>/dev/null || echo 0)"

  [[ -n "$tag" ]] || { echo "$line" >>"$tmp"; continue; }

  port="$(to_int "$port")"
  exp="$(to_int "$exp")"

  # 过期：丢弃记录，并尝试移除（幂等）
  if (( exp > 0 && now >= exp )); then
    expired=$((expired+1))
    xray_api_try rmi --tag="$tag" >/dev/null 2>&1 || xray_api_try rmi "$tag" >/dev/null 2>&1 || true
    continue
  fi

  # 端口异常：保留但不恢复
  if (( port <= 0 )); then
    warn "记录异常（port<=0）：tag=$tag，跳过恢复"
    echo "$line" >>"$tmp"
    skipped=$((skipped+1))
    continue
  fi

  # 端口已被占用：保留记录但跳过恢复
  if ! port_free "$port"; then
    warn "端口已被占用，无法恢复：tag=$tag port=$port（保留记录）"
    echo "$line" >>"$tmp"
    skipped=$((skipped+1))
    continue
  fi

  inbound="/tmp/inbound_restore_${tag}.json"
  cat >"$inbound" <<JSON
{
  "inbounds": [
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
  ]
}
JSON

  if xray_api_try adi "$inbound" >/dev/null 2>&1; then
    restored=$((restored+1))
  else
    warn "恢复失败（保留记录）：tag=$tag port=$port（可手动：xray api lsi --server=$API）"
    skipped=$((skipped+1))
  fi

  rm -f "$inbound" >/dev/null 2>&1 || true
  echo "$line" >>"$tmp"
done <"$STATE_FILE"

mv -f "$tmp" "$STATE_FILE"
ok "恢复完成：restored=$restored expired_removed=$expired skipped=$skipped"
EOF
}

gen_quota_tools() {
  # 展示配额：读取 state 的累计 + 用当前 stats 做“展示用增量计算”（不写回）
  write_bin /usr/local/bin/vless_quota_show.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/root/reality.env"
STATE_FILE="/root/.vless_temp_inbounds.jsonl"
XRAY_BIN="/usr/local/bin/xray"

die(){ echo "❌ $*" >&2; exit 1; }
to_int(){ local v="${1:-0}"; [[ "$v" =~ ^[0-9]+$ ]] && echo "$v" || echo 0; }
fmt_cn_time(){ TZ='Asia/Shanghai' date -d "@$1" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "N/A"; }

fmt_bytes() {
  local n; n="$(to_int "${1:-0}")"
  if command -v numfmt >/dev/null 2>&1; then
    numfmt --to=iec --suffix=B "$n"
  else
    echo "${n}B"
  fi
}

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

[[ -f "$STATE_FILE" ]] || { echo "(无临时入站记录)"; exit 0; }

now="$(date +%s)"
echo "tag | port | 剩余 | 到期(北京时间) | 累计已用 | 配额 | 状态"
echo "--------------------------------------------------------------------------------------------"

while IFS= read -r line; do
  [[ -n "$line" ]] || continue

  tag="$(echo "$line" | jq -r '.tag // empty' 2>/dev/null || true)"
  [[ -n "$tag" ]] || continue

  port="$(to_int "$(echo "$line" | jq -r '.port // 0' 2>/dev/null || echo 0)")"
  exp="$(to_int  "$(echo "$line" | jq -r '.expires // 0' 2>/dev/null || echo 0)")"
  qbytes="$(to_int "$(echo "$line" | jq -r '.quotaBytes // 0' 2>/dev/null || echo 0)")"
  total="$(to_int "$(echo "$line" | jq -r '.totalUsedBytes // 0' 2>/dev/null || echo 0)")"
  last="$(to_int  "$(echo "$line" | jq -r '.lastSeenBytes // 0' 2>/dev/null || echo 0)")"

  left=$((exp - now)); (( left < 0 )) && left=0
  expcn="$(fmt_cn_time "$exp")"

  json="$(xray_api_try statsquery --pattern="inbound>>>${tag}>>>traffic>>>" || true)"
  up=0; down=0
  if [[ -n "${json:-}" ]]; then
    up="$(echo "$json" | jq -r --arg t "$tag" \
      '[.stat[]? | select(.name|contains("inbound>>>"+$t+">>>traffic>>>uplink")) | (.value|tonumber? // 0)] | add // 0' \
      2>/dev/null | sed -n '1p' || true)"
    down="$(echo "$json" | jq -r --arg t "$tag" \
      '[.stat[]? | select(.name|contains("inbound>>>"+$t+">>>traffic>>>downlink")) | (.value|tonumber? // 0)] | add // 0' \
      2>/dev/null | sed -n '1p' || true)"
  fi
  up="$(to_int "$up")"; down="$(to_int "$down")"
  cur=$((up + down))

  # 展示用：重启/重置检测
  if (( cur >= last )); then
    total_now=$(( total + (cur - last) ))
  else
    total_now=$(( total + cur ))
  fi

  status="OK"
  if (( qbytes > 0 && total_now >= qbytes )); then status="OVER"; fi

  echo "${tag} | ${port} | ${left}s | ${expcn} | $(fmt_bytes "$total_now") | $(fmt_bytes "$qbytes") | ${status}"
done <"$STATE_FILE"
EOF

  # watcher：每轮把累计用量写回 state；到期/超限就 rmi
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

to_int(){ local v="${1:-0}"; [[ "$v" =~ ^[0-9]+$ ]] && echo "$v" || echo 0; }

[[ -f "$ENV_FILE" ]] || exit 0
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
  [[ -s "$STATE_FILE" ]] || exit 0

  now="$(date +%s)"
  tmp="${STATE_FILE}.tmp.$$"
  removed_any=0
  : >"$tmp"

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue

    tag="$(echo "$line" | jq -r '.tag // empty' 2>/dev/null || true)"
    [[ -n "$tag" ]] || continue

    port="$(to_int "$(echo "$line" | jq -r '.port // 0' 2>/dev/null || echo 0)")"
    exp="$(to_int  "$(echo "$line" | jq -r '.expires // 0' 2>/dev/null || echo 0)")"
    qbytes="$(to_int "$(echo "$line" | jq -r '.quotaBytes // 0' 2>/dev/null || echo 0)")"
    total="$(to_int "$(echo "$line" | jq -r '.totalUsedBytes // 0' 2>/dev/null || echo 0)")"
    last="$(to_int  "$(echo "$line" | jq -r '.lastSeenBytes // 0' 2>/dev/null || echo 0)")"

    if (( port <= 0 )); then
      echo "$line" >>"$tmp"
      continue
    fi

    # 到期删除
    if (( exp > 0 && now >= exp )); then
      warn "到期：tag=$tag port=$port -> 移除入站"
      /usr/local/bin/vless_rmi_one.sh "$port" >/dev/null 2>&1 || true
      removed_any=1
      continue
    fi

    json="$(xray_api_try statsquery --pattern="inbound>>>${tag}>>>traffic>>>" || true)"
    up=0; down=0
    if [[ -n "${json:-}" ]]; then
      up="$(echo "$json" | jq -r --arg t "$tag" \
        '[.stat[]? | select(.name|contains("inbound>>>"+$t+">>>traffic>>>uplink")) | (.value|tonumber? // 0)] | add // 0' \
        2>/dev/null | sed -n '1p' || true)"
      down="$(echo "$json" | jq -r --arg t "$tag" \
        '[.stat[]? | select(.name|contains("inbound>>>"+$t+">>>traffic>>>downlink")) | (.value|tonumber? // 0)] | add // 0' \
        2>/dev/null | sed -n '1p' || true)"
    fi
    up="$(to_int "$up")"; down="$(to_int "$down")"
    cur=$((up + down))

    # stats 重启/重置检测：cur < last 表示归零过
    if (( cur >= last )); then
      delta=$((cur - last))
    else
      delta=$cur
    fi
    total=$(( total + delta ))
    last=$cur

    # 超限删除（用累计 total 判断）
    if (( qbytes > 0 && total >= qbytes )); then
      warn "超限：tag=$tag port=$port used=${total} quota=${qbytes} -> 移除入站"
      /usr/local/bin/vless_rmi_one.sh "$port" >/dev/null 2>&1 || true
      removed_any=1
      continue
    fi

    # 写回更新后的累计字段
    new_line="$(echo "$line" | jq -c \
      --argjson totalUsedBytes "$total" \
      --argjson lastSeenBytes "$last" \
      '.totalUsedBytes=$totalUsedBytes | .lastSeenBytes=$lastSeenBytes' 2>/dev/null || true)"
    [[ -n "$new_line" ]] || new_line="$line"
    echo "$new_line" >>"$tmp"
  done <"$STATE_FILE"

  mv -f "$tmp" "$STATE_FILE"
  if (( removed_any == 1 )); then
    ok "本轮检查：已移除超限/到期入站"
  fi
}

lock_and_run run_once
EOF

  # 一键安装/启用 systemd（恢复 + watcher timer）
  write_bin /usr/local/bin/vless_services_install.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

die(){ echo "❌ $*" >&2; exit 1; }
ok(){ echo "✅ $*"; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "请用 root 执行"

cat >/etc/systemd/system/vless-restore.service <<'S'
[Unit]
Description=Restore VLESS temp inbounds after reboot
After=network-online.target xray.service
Wants=network-online.target
ConditionPathExists=/root/reality.env

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vless_restore.sh

[Install]
WantedBy=multi-user.target
S

cat >/etc/systemd/system/vless-quota-watch.service <<'SVC'
[Unit]
Description=VLESS quota watcher (remove temp inbounds when over quota/expired)
ConditionPathExists=/root/reality.env

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vless_quota_watch.sh
SVC

cat >/etc/systemd/system/vless-quota-watch.timer <<'TMR'
[Unit]
Description=Run VLESS quota watcher every 30s

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s
Unit=vless-quota-watch.service

[Install]
WantedBy=timers.target
TMR

systemctl daemon-reload
systemctl enable --now vless-restore.service
systemctl enable --now vless-quota-watch.timer

ok "已启用：vless-restore.service（开机恢复临时入站）"
ok "已启用：vless-quota-watch.timer（每30秒检查：到期/超限就删）"
echo
systemctl --no-pager --full status vless-restore.service | sed -n '1,12p' || true
systemctl --no-pager --full status vless-quota-watch.timer | sed -n '1,12p' || true
EOF
}

main() {
  need_root
  check_debian12
  ensure_deps

  gen_update_all
  gen_onekey_reality
  gen_temp_tools
  gen_restore_tool
  gen_quota_tools

  # 默认直接启用服务（有 ConditionPathExists，不会因未配置而报错）
  /usr/local/bin/vless_services_install.sh >/dev/null 2>&1 || true

  ok "脚本已生成完毕（${SCRIPT_VER}）"
  echo
  echo "建议顺序："
  echo "1) update-all && reboot"
  echo "2) bash /root/onekey_reality_ipv4.sh"
  echo "3) 创建临时节点（显示到期北京时间）："
  echo "   D=3600 Q=50 NAME=test vless_mktemp.sh"
  echo
  echo "常用命令："
  echo "- vless_audit.sh            # 查看临时节点列表（含到期北京时间）"
  echo "- vless_quota_show.sh       # 查看配额/累计用量（重启不清零）"
  echo "- vless_clear_all.sh        # 清空全部临时节点"
  echo
  echo "服务状态："
  echo "- systemctl status vless-restore.service"
  echo "- systemctl status vless-quota-watch.timer"
}

main "$@"
