#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# ============================================================
# huanxin.sh (Debian 12) - 单进程 Xray + Reality + API 动态入站
# 生成脚本：
#   - /usr/local/bin/update-all
#   - /root/onekey_reality_ipv4.sh
#   - /usr/local/bin/vless_mktemp.sh
#   - /usr/local/bin/vless_rmi_one.sh
#   - /usr/local/bin/vless_audit.sh
#   - /usr/local/bin/vless_clear_all.sh
#
# 重点改动(2025-12-20-r2)：
#   - 启动完整性自检：防止 GitHub “压缩/丢换行/被污染”导致函数缺失
#   - vless_mktemp.sh：自动探测 xray api adi 参数 + 双格式 JSON 尝试 + 输出真实报错
# ============================================================

SCRIPT_VER="2025-12-20-r2"

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

on_err() {
  local ec=$?
  warn "发生错误：exit=$ec"
  warn "出错行号：${BASH_LINENO[0]:-?}"
  warn "出错命令：${BASH_COMMAND:-?}"
  exit "$ec"
}
trap on_err ERR

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "请用 root 执行：sudo -i 后再运行"
}

cmd_exists() { command -v "$1" >/dev/null 2>&1; }

apt_install() {
  apt-get update -y
  apt-get install -y --no-install-recommends "$@"
}

ensure_deps() {
  apt_install curl ca-certificates unzip jq openssl iproute2 coreutils
}

curl_retry() {
  # curl_retry <url>
  curl -fsSL --retry 5 --retry-delay 1 --retry-all-errors "$1"
}

detect_public_ip() {
  local ip=""
  ip="$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(curl -fsSL --max-time 5 https://ip.sb 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(curl -fsSL --max-time 5 https://ifconfig.me/ip 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/{print $7; exit}' || true)"
  [[ -n "$ip" ]] || die "无法探测服务器 IP（curl 出网失败？DNS/路由问题？）"
  echo "$ip"
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

install_or_update_xray() {
  ensure_deps
  log "=== 安装/更新 Xray（官方脚本）==="
  bash <(curl_retry https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install -u root
  [[ -x "$XRAY_BIN" ]] || die "Xray 安装失败：找不到 $XRAY_BIN"
  ok "Xray 已安装/更新：$("$XRAY_BIN" version | head -n1)"
}

gen_uuid() { "$XRAY_BIN" uuid; }

# 兼容：旧版输出 PublicKey，新版输出 Password（等价 publicKey）
gen_x25519() {
  local out priv pub
  out="$("$XRAY_BIN" x25519 2>/dev/null || true)"
  priv="$(echo "$out" | awk -F': ' '/PrivateKey/{print $2; exit}')"
  pub="$(echo "$out" | awk -F': ' '/^(PublicKey|Password):/{print $2; exit}')"
  [[ -n "$priv" && -n "$pub" ]] || {
    echo "$out" >&2
    die "x25519 解析失败（没有拿到 PrivateKey/PublicKey(or Password)）"
  }
  echo "$priv|$pub"
}

gen_shortid() { openssl rand -hex 8; }

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  cp -a "$f" "${f}.bak.$(date +%Y%m%d_%H%M%S)"
}

port_free() {
  local p="$1"
  ! ss -lnt "( sport = :$p )" 2>/dev/null | grep -q ":$p"
}

write_main_config() {
  local port="$1" sni="$2" dest="$3" uuid="$4" priv="$5" pub="$6" sid="$7" api_listen="$8"

  mkdir -p "$(dirname "$XRAY_CFG")" "$XRAY_LOG_DIR"
  backup_file "$XRAY_CFG"

  # 主端口占用检测：避免写了配置但起不来
  port_free "$port" || die "端口 $port 已被占用（请先释放 443 或改 DEFAULT_PORT）"

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
    "services": ["HandlerService", "LoggerService"]
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
    "domainStrategy": "AsIs",
    "rules": [
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" }
    ]
  }
}
EOF

  # 保存环境（供 mktemp / audit / rmi 使用）
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
  sleep 0.6
  systemctl --no-pager --full status xray | sed -n '1,16p' || true
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
set -Eeuo pipefail
IFS=$'\n\t'
export DEBIAN_FRONTEND=noninteractive

SCRIPT_VER="2025-12-20-r2"

XRAY_BIN="/usr/local/bin/xray"
XRAY_CFG="/usr/local/etc/xray/config.json"
ENV_FILE="/root/reality.env"
XRAY_LOG_DIR="/var/log/xray"

DEFAULT_SNI="${SNI:-www.apple.com}"
DEFAULT_DEST="${DEST:-www.apple.com:443}"
DEFAULT_PORT="${PORT:-443}"
DEFAULT_API_LISTEN="${API_LISTEN:-127.0.0.1:10085}"
DEFAULT_FP="${FP:-chrome}"

log(){ echo -e "$*"; }
ok(){ echo -e "✅ $*"; }
warn(){ echo -e "⚠️  $*" >&2; }
die(){ echo -e "❌ $*" >&2; exit 1; }

on_err() {
  local ec=$?
  warn "发生错误：exit=$ec"
  warn "出错行号：${BASH_LINENO[0]:-?}"
  warn "出错命令：${BASH_COMMAND:-?}"
  exit "$ec"
}
trap on_err ERR

apt_install() { apt-get update -y; apt-get install -y --no-install-recommends "$@"; }
ensure_deps() { apt_install curl ca-certificates unzip jq openssl iproute2 coreutils; }

curl_retry() { curl -fsSL --retry 5 --retry-delay 1 --retry-all-errors "$1"; }

detect_public_ip() {
  local ip=""
  ip="$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(curl -fsSL --max-time 5 https://ip.sb 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(curl -fsSL --max-time 5 https://ifconfig.me/ip 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/{print $7; exit}' || true)"
  [[ -n "$ip" ]] || die "无法探测服务器 IP"
  echo "$ip"
}

install_or_update_xray() {
  ensure_deps
  bash <(curl_retry https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install -u root
  [[ -x "$XRAY_BIN" ]] || die "Xray 安装失败：找不到 $XRAY_BIN"
  ok "Xray：$("$XRAY_BIN" version | head -n1)"
}

enable_fq_bbr_only() {
  cat >/etc/sysctl.d/99-huanxin-fq-bbr.conf <<'E'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
E
  sysctl --system >/dev/null 2>&1 || true
  ok "已写入 fq+bbr（/etc/sysctl.d/99-huanxin-fq-bbr.conf）"
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

backup_file(){ [[ -f "$1" ]] && cp -a "$1" "${1}.bak.$(date +%Y%m%d_%H%M%S)" || true; }

port_free() {
  local p="$1"
  ! ss -lnt "( sport = :$p )" 2>/dev/null | grep -q ":$p"
}

write_main_config() {
  local port="$1" sni="$2" dest="$3" uuid="$4" priv="$5" pub="$6" sid="$7" api_listen="$8"

  mkdir -p "$(dirname "$XRAY_CFG")" "$XRAY_LOG_DIR"
  backup_file "$XRAY_CFG"

  port_free "$port" || die "端口 $port 已被占用（请先释放 443 或改 PORT=xxxx 再运行）"

  cat >"$XRAY_CFG" <<JSON
{
  "log": { "access": "$XRAY_LOG_DIR/access.log", "error": "$XRAY_LOG_DIR/error.log", "loglevel": "warning" },

  "api": { "tag": "api", "listen": "$api_listen", "services": ["HandlerService","LoggerService"] },

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
# Generated by onekey_reality_ipv4.sh $SCRIPT_VER
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
  sleep 0.6
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
  echo "$url" | tee "/root/vless_main_${PORT_MAIN}.txt" >/dev/null
  echo
  ok "主节点已写入：/root/vless_main_${PORT_MAIN}.txt"
  echo "----------------------------------------"
  echo "$url"
  echo "----------------------------------------"

  echo
  echo "下一步（强烈建议先测 API 是否可用）："
  echo "  /usr/local/bin/xray api lsi --server=\"${API_LISTEN}\""
  echo "如果能列出 inbounds，说明 mktemp 动态入站就能工作。"
}

main "$@"
EOF
}

gen_temp_tools() {
  # vless_mktemp.sh
  write_bin /usr/local/bin/vless_mktemp.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ENV_FILE="/root/reality.env"
STATE_FILE="/root/.vless_temp_inbounds.jsonl"
XRAY_BIN="/usr/local/bin/xray"

die(){ echo "❌ $*" >&2; exit 1; }
ok(){ echo "✅ $*"; }
warn(){ echo "⚠️  $*" >&2; }

on_err() {
  local ec=$?
  warn "发生错误：exit=$ec"
  warn "出错行号：${BASH_LINENO[0]:-?}"
  warn "出错命令：${BASH_COMMAND:-?}"
  exit "$ec"
}
trap on_err ERR

[[ -f "$ENV_FILE" ]] || die "缺少 $ENV_FILE，请先运行：bash /root/onekey_reality_ipv4.sh"
# shellcheck disable=SC1090
source "$ENV_FILE"

D="${D:-600}"                  # 存活秒数
PORT="${PORT:-}"               # 可手动指定
NAME="${NAME:-temp}"           # 节点备注
API="${API_LISTEN:-127.0.0.1:10085}"

[[ -x "$XRAY_BIN" ]] || die "找不到 xray：$XRAY_BIN"

rand_port() { shuf -i 20000-60000 -n 1; }

port_free() {
  local p="$1"
  ! ss -lnt "( sport = :$p )" 2>/dev/null | grep -q ":$p"
}

choose_port() {
  if [[ -n "${PORT}" ]]; then
    [[ "$PORT" =~ ^[0-9]+$ ]] || die "PORT 必须是数字"
    port_free "$PORT" || die "端口 $PORT 已被占用"
    echo "$PORT"; return 0
  fi

  local p
  for _ in $(seq 1 40); do
    p="$(rand_port)"
    if port_free "$p"; then echo "$p"; return 0; fi
  done
  die "随机挑选端口失败（连续 40 次都被占用？）"
}

vless_url() {
  local uuid="$1" host="$2" port="$3" sni="$4" fp="$5" pbk="$6" sid="$7" name="$8"
  echo "vless://${uuid}@${host}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=${fp}&pbk=${pbk}&sid=${sid}&type=tcp&headerType=none#${name}"
}

xray_help() {
  # xray_help <subcmd>  (e.g. adi / rmi / lsi)
  "$XRAY_BIN" api "$1" -h 2>&1 || true
}

xray_try() {
  # xray_try <cmd...>  (captures stderr)
  local out
  out="$("$@" 2>&1)" && return 0
  LAST_ERR="$out"
  return 1
}

xray_api_lsi() {
  local h; h="$(xray_help lsi)"
  if echo "$h" | grep -q -- '--server'; then
    xray_try "$XRAY_BIN" api lsi --server="$API" && return 0
  fi
  # 兜底尝试
  xray_try "$XRAY_BIN" api lsi --server "$API" && return 0
  xray_try "$XRAY_BIN" api lsi -server="$API" && return 0
  return 1
}

xray_api_adi_file() {
  # xray_api_adi_file <file>
  local file="$1"
  local h; h="$(xray_help adi)"

  # 优先：如果 help 里包含 --file，就用 --file；否则用位置参数
  if echo "$h" | grep -q -- '--file'; then
    xray_try "$XRAY_BIN" api adi --server="$API" --file="$file" && return 0
    xray_try "$XRAY_BIN" api adi --server "$API" --file "$file" && return 0
    xray_try "$XRAY_BIN" api adi -server="$API" -file="$file" && return 0
    xray_try "$XRAY_BIN" api adi -server "$API" -file "$file" && return 0
  fi

  # 位置参数风格
  xray_try "$XRAY_BIN" api adi --server="$API" "$file" && return 0
  xray_try "$XRAY_BIN" api adi --server "$API" "$file" && return 0
  xray_try "$XRAY_BIN" api adi -server="$API" "$file" && return 0
  xray_try "$XRAY_BIN" api adi -server "$API" "$file" && return 0
  return 1
}

main() {
  # 先测 API 是否可用（能 lsi 就说明 gRPC 端口通）
  if ! xray_api_lsi; then
    warn "Xray API 可能不可用（无法 lsi）。"
    warn "请先在服务器执行："
    warn "  $XRAY_BIN api lsi --server=\"$API\""
    warn "真实错误："
    echo "${LAST_ERR:-<empty>}" >&2
    die "API 不通，无法创建临时入站"
  fi

  local port tag now expires
  port="$(choose_port)"
  tag="temp-${port}"

  local tmpdir; tmpdir="$(mktemp -d)"
  local f_wrap="${tmpdir}/inbounds_wrap.json"
  local f_single="${tmpdir}/inbound_single.json"

  # 1) 生成 “wrap 格式”：{"inbounds":[{...}]} —— 许多版本的 adi 更偏好这个
  cat >"$f_wrap" <<JSON
{
  "inbounds": [
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
  ]
}
JSON

  # 2) 生成 “single 格式”：单个 inbound 对象 —— 老版本可能只接受这个
  cat >"$f_single" <<JSON
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

  # 先尝试 wrap，再尝试 single；失败打印真实报错
  if ! xray_api_adi_file "$f_wrap"; then
    warn "adi(wrap) 失败，尝试 single 格式…"
    local err1="${LAST_ERR:-}"
    if ! xray_api_adi_file "$f_single"; then
      warn "adi(single) 也失败。"
      warn "---- adi(wrap) 错误 ----"
      echo "$err1" >&2
      warn "---- adi(single) 错误 ----"
      echo "${LAST_ERR:-<empty>}" >&2
      die "添加入站失败：xray api adi 调用失败（请执行：$XRAY_BIN api adi -h 查看参数）"
    fi
  fi

  now="$(date +%s)"
  expires="$((now + D))"
  mkdir -p "$(dirname "$STATE_FILE")"
  echo "{\"tag\":\"$tag\",\"port\":$port,\"created\":$now,\"expires\":$expires}" >>"$STATE_FILE"

  local url
  url="$(vless_url "$UUID" "$SERVER_IP" "$port" "$SNI" "${FP:-chrome}" "$PUBLIC_KEY" "$SHORT_ID" "${NAME}-${port}")"
  echo "$url" | tee "/root/vless_${tag}.txt" >/dev/null

  echo
  ok "临时入站已创建：port=$port  duration=${D}s  tag=$tag"
  ok "节点已写入：/root/vless_${tag}.txt"
  echo "----------------------------------------"
  echo "$url"
  echo "----------------------------------------"

  # 到期自动删除
  if [[ "$D" -gt 0 ]]; then
    nohup bash -c "sleep $D; /usr/local/bin/vless_rmi_one.sh $port >/dev/null 2>&1" >/dev/null 2>&1 &
    ok "已后台定时删除：${D}s 后移除 port=$port"
  fi

  rm -rf "$tmpdir" >/dev/null 2>&1 || true
}

main "$@"
EOF

  # vless_rmi_one.sh
  write_bin /usr/local/bin/vless_rmi_one.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ENV_FILE="/root/reality.env"
STATE_FILE="/root/.vless_temp_inbounds.jsonl"
XRAY_BIN="/usr/local/bin/xray"

die(){ echo "❌ $*" >&2; exit 1; }
ok(){ echo "✅ $*"; }
warn(){ echo "⚠️  $*" >&2; }

on_err() {
  local ec=$?
  warn "发生错误：exit=$ec"
  warn "出错行号：${BASH_LINENO[0]:-?}"
  warn "出错命令：${BASH_COMMAND:-?}"
  exit "$ec"
}
trap on_err ERR

[[ $# -ge 1 ]] || die "用法：vless_rmi_one.sh <port>"
PORT="$1"
[[ "$PORT" =~ ^[0-9]+$ ]] || die "port 必须是数字"

[[ -f "$ENV_FILE" ]] || die "缺少 $ENV_FILE（先跑 /root/onekey_reality_ipv4.sh）"
# shellcheck disable=SC1090
source "$ENV_FILE"
API="${API_LISTEN:-127.0.0.1:10085}"

[[ -x "$XRAY_BIN" ]] || die "找不到 xray：$XRAY_BIN"

xray_try() {
  local out
  out="$("$@" 2>&1)" && return 0
  LAST_ERR="$out"
  return 1
}

xray_api_rmi_tag() {
  local tag="$1"
  local h; h="$("$XRAY_BIN" api rmi -h 2>&1 || true)"

  # 常见组合（覆盖新旧风格）
  xray_try "$XRAY_BIN" api rmi --server="$API" --tag="$tag" && return 0
  xray_try "$XRAY_BIN" api rmi --server "$API" --tag "$tag" && return 0
  xray_try "$XRAY_BIN" api rmi --server="$API" "$tag" && return 0
  xray_try "$XRAY_BIN" api rmi --server "$API" "$tag" && return 0
  xray_try "$XRAY_BIN" api rmi -server="$API" -tag="$tag" && return 0
  xray_try "$XRAY_BIN" api rmi -server "$API" -tag "$tag" && return 0
  xray_try "$XRAY_BIN" api rmi -server="$API" "$tag" && return 0
  xray_try "$XRAY_BIN" api rmi -server "$API" "$tag" && return 0

  # 如果帮助里明确出现了 --tag，则再补一次严格参数（防某些版本只认 --tag）
  if echo "$h" | grep -q -- '--tag'; then
    xray_try "$XRAY_BIN" api rmi --server="$API" --tag="$tag" && return 0
  fi

  return 1
}

TAG="temp-${PORT}"

# 尝试移除 temp-PORT；兼容你之前可能用过 tmp-PORT
if xray_api_rmi_tag "$TAG"; then
  ok "已移除入站：tag=$TAG"
else
  warn "移除 tag=$TAG 失败，尝试兼容 tag=tmp-$PORT"
  if xray_api_rmi_tag "tmp-${PORT}"; then
    ok "已移除入站：tag=tmp-${PORT}"
  else
    warn "真实错误："
    echo "${LAST_ERR:-<empty>}" >&2
    die "移除失败：port=$PORT（可运行：$XRAY_BIN api rmi -h 查看参数）"
  fi
fi

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
IFS=$'\n\t'

ENV_FILE="/root/reality.env"
STATE_FILE="/root/.vless_temp_inbounds.jsonl"
XRAY_BIN="/usr/local/bin/xray"

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

echo "=== Xray API 入站列表（快速自检）==="
if [[ -x "$XRAY_BIN" ]]; then
  "$XRAY_BIN" api lsi --server="${API_LISTEN}" 2>/dev/null || echo "(无法读取，可能 API 不通)"
else
  echo "(未安装 xray?)"
fi
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
  left="$((exp - now))"
  if [[ "$left" -lt 0 ]]; then left=0; fi
  printf "port=%s  tag=%s  剩余=%ss\n" "$port" "$tag" "$left"
done <"$STATE_FILE"
EOF

  # vless_clear_all.sh
  write_bin /usr/local/bin/vless_clear_all.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

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

self_check_integrity() {
  # 防止 “脚本被压缩/丢换行/被 HTML 污染” 时出现奇怪的 command not found
  local must_funcs=(
    need_root ensure_deps gen_update_all gen_onekey_reality gen_temp_tools
  )
  local f
  for f in "${must_funcs[@]}"; do
    declare -F "$f" >/dev/null 2>&1 || die "脚本不完整或被压缩污染：缺少函数 $f。请重新上传/重新下载 huanxin.sh（确保保留原始换行）。"
  done
}

main() {
  need_root
  self_check_integrity

  gen_update_all
  gen_onekey_reality
  gen_temp_tools

  ok "所有脚本已生成完毕（Debian 12 / 单进程 Xray + API 动态入站）"
  echo
  echo "建议顺序："
  echo "1) update-all && reboot"
  echo "2) bash /root/onekey_reality_ipv4.sh"
  echo "3) 先自检 API：/usr/local/bin/xray api lsi --server=\"${DEFAULT_API_LISTEN}\""
  echo "4) 创建临时节点：D=600 vless_mktemp.sh   （可选：PORT=40035 NAME=hk D=1200 vless_mktemp.sh）"
  echo
  echo "常用命令："
  echo "- D=600 vless_mktemp.sh"
  echo "- vless_audit.sh"
  echo "- vless_rmi_one.sh 40035"
  echo "- vless_clear_all.sh"
  echo
  echo "如果你仍然看到 ensure_deps / command not found："
  echo "- 说明 GitHub 上 huanxin.sh 可能被压缩、丢换行或被替换（比如复制粘贴进网页编辑器）。"
  echo "- 请用原样文本覆盖上传（建议用 git push 或 raw 文件上传，别用网页编辑器“自动格式化”）。"
}

main "$@"
