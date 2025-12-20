#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# huanxin.sh (Debian 12) - Latest Plan
# - Reality main inbound (VLESS + REALITY)
# - Dynamic temp inbounds via Xray gRPC API (adi/rmi)
# - Fix: Xray 2025.10+ x25519 output (Password replaces PublicKey)
# - Fix: cfg unbound variable (init all vars)
# ============================================================

export DEBIAN_FRONTEND=noninteractive

XRAY_BIN="/usr/local/bin/xray"
XRAY_CFG="/usr/local/etc/xray/config.json"
XRAY_ENV="/usr/local/etc/xray/huanxin_env"
XRAY_LOG_DIR="/var/log/xray"
API_ADDR_DEFAULT="127.0.0.1:10085"

say(){ echo -e "$*"; }
die(){ echo -e "❌ $*" >&2; exit 1; }

need_root(){
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "请用 root 运行"
}

apt_install(){
  apt-get update -y
  apt-get install -y --no-install-recommends \
    ca-certificates curl unzip jq python3 openssl iproute2
}

write_bin(){
  local path="$1"
  shift
  install -m 0755 /dev/null "$path"
  cat >"$path" <<'EOF'
EOF
  # append content from stdin
  cat >>"$path"
}

# -----------------------------
# /usr/local/bin/update-all
# -----------------------------
gen_update_all(){
  write_bin "/usr/local/bin/update-all" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "🚀 开始系统更新 (Debian 12 / bookworm)..."
apt-get update -y
apt-get full-upgrade -y
apt-get autoremove -y
apt-get autoclean -y
echo "✅ 软件包更新完成"
echo "🧠 建议：如安装了新内核/ssh 等关键组件，重启一次更稳：reboot"
EOF
}

# -----------------------------
# /root/onekey_reality_ipv4.sh
# -----------------------------
gen_onekey_reality(){
  write_bin "/root/onekey_reality_ipv4.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

XRAY_BIN="/usr/local/bin/xray"
XRAY_CFG="/usr/local/etc/xray/config.json"
XRAY_ENV="/usr/local/etc/xray/huanxin_env"
XRAY_LOG_DIR="/var/log/xray"

# User overridable
SNI="${SNI:-www.apple.com}"
DEST="${DEST:-www.apple.com:443}"
PORT="${PORT:-443}"
API_ADDR="${API_ADDR:-127.0.0.1:10085}"
FP="${FP:-chrome}"
FLOW="${FLOW:-xtls-rprx-vision}"

say(){ echo -e "$*"; }
die(){ echo -e "❌ $*" >&2; exit 1; }

detect_ip4(){
  # Prefer public detection; fallback to routing source
  local ip=""
  ip="$(curl -4 -fsSL https://api.ipify.org 2>/dev/null || true)"
  if [[ -z "$ip" ]]; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  fi
  echo "$ip"
}

ensure_deps(){
  apt-get update -y
  apt-get install -y --no-install-recommends ca-certificates curl unzip jq python3 openssl iproute2
}

enable_bbr_fq(){
  # keep minimal changes; only fq + bbr
  modprobe tcp_bbr 2>/dev/null || true
  cat >/etc/sysctl.d/99-huanxin-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl --system >/dev/null 2>&1 || true
  local qdisc cc
  qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
  cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
  say "=== 1) 只开启 fq + bbr（其余 sysctl 保持默认）==="
  say "当前: qdisc=${qdisc:-?}, cc=${cc:-?}"
}

install_or_update_xray(){
  say "=== 2) 安装/更新 xray ==="
  bash <(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install
  [[ -x "$XRAY_BIN" ]] || die "xray 安装失败：$XRAY_BIN 不存在"
}

xray_uuid(){
  "$XRAY_BIN" uuid
}

# Compatibility: new versions output PrivateKey/Password/Hash32; old outputs PrivateKey/PublicKey
xray_x25519(){
  local out priv pub hash32
  out="$("$XRAY_BIN" x25519 2>/dev/null | tr -d '\r')"
  priv="$(echo "$out" | awk -F': ' '/^PrivateKey:/{print $2; exit}')"
  pub="$(echo "$out" | awk -F': ' '/^PublicKey:/{print $2; exit}')"
  if [[ -z "$pub" ]]; then
    pub="$(echo "$out" | awk -F': ' '/^Password:/{print $2; exit}')"
  fi
  hash32="$(echo "$out" | awk -F': ' '/^Hash32:/{print $2; exit}')"
  if [[ -z "$priv" || -z "$pub" ]]; then
    say "❌ x25519 生成失败，输出："
    echo "$out"
    return 1
  fi
  echo "$priv|$pub|$hash32"
}

rand_sid(){
  # 8 bytes => 16 hex (common Reality shortId length)
  openssl rand -hex 8
}

write_xray_config(){
  local server_ip="$1"
  local uuid="$2"
  local priv="$3"
  local sid="$4"

  install -d -m 0755 /usr/local/etc/xray
  install -d -m 0755 "$XRAY_LOG_DIR"

  # Xray API can be enabled by ApiObject in newer Xray (tag/listen/services).
  # (no need for extra inbound/outbound/routing for api itself in that mode)
  cat >"$XRAY_CFG" <<EOF
{
  "log": {
    "loglevel": "warning",
    "access": "${XRAY_LOG_DIR}/access.log",
    "error": "${XRAY_LOG_DIR}/error.log"
  },
  "api": {
    "tag": "api",
    "listen": "${API_ADDR%%:*}",
    "services": ["HandlerService", "LoggerService", "StatsService"]
  },
  "inbounds": [
    {
      "tag": "reality-main",
      "listen": "0.0.0.0",
      "port": ${PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${uuid}", "flow": "${FLOW}", "email": "main@reality" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${DEST}",
          "xver": 0,
          "serverNames": ["${SNI}"],
          "privateKey": "${priv}",
          "shortIds": ["${sid}"]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls"] }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ]
}
EOF

  # save env for mktemp scripts
  umask 077
  cat >"$XRAY_ENV" <<EOF
# generated by onekey_reality_ipv4.sh
SERVER_IP="${server_ip}"
PORT="${PORT}"
SNI="${SNI}"
DEST="${DEST}"
FP="${FP}"
FLOW="${FLOW}"
API_ADDR="${API_ADDR}"

# REALITY keys
REALITY_PRIVATE_KEY="${priv}"
REALITY_SHORT_ID="${sid}"
# public key is from xray x25519 output:
# - old: PublicKey
# - new: Password
REALITY_PUBLIC_KEY="__WILL_FILL__"
REALITY_HASH32="__WILL_FILL__"
EOF
}

fill_pubkey_hash32(){
  local pub="$1"
  local hash32="$2"
  # in-place replace placeholders
  sed -i "s|REALITY_PUBLIC_KEY=\"__WILL_FILL__\"|REALITY_PUBLIC_KEY=\"${pub}\"|g" "$XRAY_ENV"
  sed -i "s|REALITY_HASH32=\"__WILL_FILL__\"|REALITY_HASH32=\"${hash32}\"|g" "$XRAY_ENV"
}

restart_xray(){
  systemctl daemon-reload || true
  systemctl enable xray >/dev/null 2>&1 || true
  systemctl restart xray
  sleep 0.6
  systemctl is-active --quiet xray || (journalctl -u xray --no-pager -n 80; die "xray 启动失败")
}

print_node(){
  local uuid="$1"
  # shellcheck disable=SC1090
  source "$XRAY_ENV"
  local name="reality-${SERVER_IP}"
  local link
  link="vless://${uuid}@${SERVER_IP}:${PORT}?encryption=none&flow=${FLOW}&security=reality&sni=${SNI}&fp=${FP}&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#${name}"
  say "=================================================="
  say "✅ Reality 主节点已生成"
  say "服务器地址(探测): ${SERVER_IP}"
  say "伪装域名:         ${SNI}"
  say "端口:             ${PORT}"
  say "API 监听:         ${API_ADDR}"
  say ""
  say "📎 节点链接："
  say "${link}"
  echo "${link}" >/root/node.txt
  say ""
  say "已保存到：/root/node.txt"
  say "=================================================="
}

main(){
  ensure_deps
  local server_ip
  server_ip="$(detect_ip4)"
  [[ -n "$server_ip" ]] || die "无法探测服务器 IPv4（请检查网络）"

  enable_bbr_fq
  install_or_update_xray

  say "=== 3) 生成 UUID + Reality 密钥 ==="
  local uuid keys priv pub hash32 sid
  uuid="$(xray_uuid)"
  keys="$(xray_x25519)" || die "x25519 生成失败（注意：新版本输出字段为 Password/Hash32）"
  priv="${keys%%|*}"
  pub="$(echo "$keys" | awk -F'|' '{print $2}')"
  hash32="$(echo "$keys" | awk -F'|' '{print $3}')"
  sid="$(rand_sid)"

  write_xray_config "$server_ip" "$uuid" "$priv" "$sid"
  fill_pubkey_hash32 "$pub" "$hash32"
  restart_xray
  print_node "$uuid"

  say "✅ 完成。接下来可执行：bash /root/vless_temp_dynamic_inbound.sh 生成临时端口脚本"
}

main "$@"
EOF
}

# -----------------------------
# /root/vless_temp_dynamic_inbound.sh
# Generates:
#   /usr/local/bin/vless_mktemp.sh
#   /usr/local/bin/vless_audit.sh
#   /usr/local/bin/vless_rmi_one.sh
#   /usr/local/bin/vless_clear_all.sh
# -----------------------------
gen_temp_inbound_bundle(){
  write_bin "/root/vless_temp_dynamic_inbound.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

XRAY_BIN="/usr/local/bin/xray"
XRAY_ENV="/usr/local/etc/xray/huanxin_env"
DB_DIR="/root/vless_tmp"
DB_FILE="/root/vless_tmp/db.tsv"

die(){ echo -e "❌ $*" >&2; exit 1; }
say(){ echo -e "$*"; }

[[ -f "$XRAY_ENV" ]] || die "未找到 $XRAY_ENV，请先运行：bash /root/onekey_reality_ipv4.sh"
# shellcheck disable=SC1090
source "$XRAY_ENV"

install -d -m 0755 "$DB_DIR"
touch "$DB_FILE"
chmod 0600 "$DB_FILE" || true

xray_api_try(){
  # usage: xray_api_try <subcmd> [args...]
  local sub="$1"; shift
  # Try both flags: --server and -s (different builds/versions)
  if "$XRAY_BIN" api "$sub" --server="$API_ADDR" "$@" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api "$sub" -s "$API_ADDR" "$@" >/dev/null 2>&1; then return 0; fi
  return 1
}

xray_api_adi_file(){
  local json="$1"
  # common possibilities:
  # 1) xray api adi --server=IP:PORT < file
  # 2) xray api adi --server=IP:PORT stdin: < file
  # 3) xray api adi --server=IP:PORT file
  if "$XRAY_BIN" api adi --server="$API_ADDR" < "$json" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api adi -s "$API_ADDR" < "$json" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api adi --server="$API_ADDR" stdin: < "$json" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api adi -s "$API_ADDR" stdin: < "$json" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api adi --server="$API_ADDR" "$json" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api adi -s "$API_ADDR" "$json" >/dev/null 2>&1; then return 0; fi
  return 1
}

xray_api_rmi_tag(){
  local tag="$1"
  # possibilities:
  # 1) positional
  if "$XRAY_BIN" api rmi --server="$API_ADDR" "$tag" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api rmi -s "$API_ADDR" "$tag" >/dev/null 2>&1; then return 0; fi
  # 2) with --tag
  if "$XRAY_BIN" api rmi --server="$API_ADDR" --tag "$tag" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api rmi -s "$API_ADDR" --tag "$tag" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api rmi --server="$API_ADDR" -tag "$tag" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api rmi -s "$API_ADDR" -tag "$tag" >/dev/null 2>&1; then return 0; fi
  return 1
}

gen_mktemp(){
  install -m 0755 /dev/null /usr/local/bin/vless_mktemp.sh
  cat >/usr/local/bin/vless_mktemp.sh <<'EOM'
#!/usr/bin/env bash
set -euo pipefail

XRAY_BIN="/usr/local/bin/xray"
XRAY_ENV="/usr/local/etc/xray/huanxin_env"
DB_FILE="/root/vless_tmp/db.tsv"

die(){ echo -e "❌ $*" >&2; exit 1; }
say(){ echo -e "$*"; }

[[ -f "$XRAY_ENV" ]] || die "缺少 $XRAY_ENV，请先运行 /root/onekey_reality_ipv4.sh"
# shellcheck disable=SC1090
source "$XRAY_ENV"

D="${D:-600}" # seconds
PORT_MIN="${PORT_MIN:-40000}"
PORT_MAX="${PORT_MAX:-49999}"

pick_port(){
  local p
  for _ in $(seq 1 40); do
    p="$(shuf -i "${PORT_MIN}-${PORT_MAX}" -n 1)"
    if ! ss -lnt | awk '{print $4}' | grep -q ":${p}$"; then
      echo "$p"; return 0
    fi
  done
  return 1
}

xray_api_adi_file(){
  local json="$1"
  if "$XRAY_BIN" api adi --server="$API_ADDR" < "$json" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api adi -s "$API_ADDR" < "$json" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api adi --server="$API_ADDR" stdin: < "$json" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api adi -s "$API_ADDR" stdin: < "$json" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api adi --server="$API_ADDR" "$json" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api adi -s "$API_ADDR" "$json" >/dev/null 2>&1; then return 0; fi
  return 1
}

uuid="$("$XRAY_BIN" uuid)"
port="$(pick_port)" || die "分配端口失败"
tag="vless-tmp-${port}"
exp="$(date -d "+${D} seconds" +%s)"

tmp="$(mktemp)"
cat >"$tmp" <<EOF
{
  "tag": "${tag}",
  "listen": "0.0.0.0",
  "port": ${port},
  "protocol": "vless",
  "settings": {
    "clients": [
      { "id": "${uuid}", "flow": "${FLOW}", "email": "${tag}" }
    ],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "show": false,
      "dest": "${DEST}",
      "xver": 0,
      "serverNames": ["${SNI}"],
      "privateKey": "${REALITY_PRIVATE_KEY}",
      "shortIds": ["${REALITY_SHORT_ID}"]
    }
  },
  "sniffing": { "enabled": true, "destOverride": ["http","tls"] }
}
EOF

xray_api_adi_file "$tmp" || { rm -f "$tmp"; die "调用 xray api adi 失败（请确认 Xray API 已开启且监听 ${API_ADDR}）"; }
rm -f "$tmp"

# record: port uuid exp tag
umask 077
echo -e "${port}\t${uuid}\t${exp}\t${tag}" >>"$DB_FILE"

name="tmp-${port}-$(date +%m%d%H%M)"
link="vless://${uuid}@${SERVER_IP}:${port}?encryption=none&flow=${FLOW}&security=reality&sni=${SNI}&fp=${FP}&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#${name}"

say "✅ 已创建临时端口节点（有效期 ${D}s）"
say "${link}"
EOM
}

gen_rmi_one(){
  install -m 0755 /dev/null /usr/local/bin/vless_rmi_one.sh
  cat >/usr/local/bin/vless_rmi_one.sh <<'EOM'
#!/usr/bin/env bash
set -euo pipefail

XRAY_BIN="/usr/local/bin/xray"
XRAY_ENV="/usr/local/etc/xray/huanxin_env"
DB_FILE="/root/vless_tmp/db.tsv"

die(){ echo -e "❌ $*" >&2; exit 1; }
say(){ echo -e "$*"; }

p="${1:-}"
[[ -n "$p" ]] || die "用法：vless_rmi_one.sh <port>"

[[ -f "$XRAY_ENV" ]] || die "缺少 $XRAY_ENV"
# shellcheck disable=SC1090
source "$XRAY_ENV"

tag="vless-tmp-${p}"

xray_api_rmi_tag(){
  local t="$1"
  if "$XRAY_BIN" api rmi --server="$API_ADDR" "$t" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api rmi -s "$API_ADDR" "$t" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api rmi --server="$API_ADDR" --tag "$t" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api rmi -s "$API_ADDR" --tag "$t" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api rmi --server="$API_ADDR" -tag "$t" >/dev/null 2>&1; then return 0; fi
  if "$XRAY_BIN" api rmi -s "$API_ADDR" -tag "$t" >/dev/null 2>&1; then return 0; fi
  return 1
}

xray_api_rmi_tag "$tag" || die "删除 inbound 失败：${tag}"

# remove from db
if [[ -f "$DB_FILE" ]]; then
  awk -F'\t' -v p="$p" 'BEGIN{OFS="\t"} $1!=p {print $0}' "$DB_FILE" >"${DB_FILE}.tmp" && mv "${DB_FILE}.tmp" "$DB_FILE"
fi

say "✅ 已删除：${tag}"
EOM
}

gen_audit(){
  install -m 0755 /dev/null /usr/local/bin/vless_audit.sh
  cat >/usr/local/bin/vless_audit.sh <<'EOM'
#!/usr/bin/env bash
set -euo pipefail

XRAY_ENV="/usr/local/etc/xray/huanxin_env"
DB_FILE="/root/vless_tmp/db.tsv"

die(){ echo -e "❌ $*" >&2; exit 1; }
say(){ echo -e "$*"; }

[[ -f "$XRAY_ENV" ]] || die "缺少 $XRAY_ENV"
[[ -f "$DB_FILE" ]] || { say "（暂无临时节点记录）"; exit 0; }

now="$(date +%s)"

say "PORT    EXPIRES_IN(s)   TAG"
say "---------------------------------------------"

# show + auto remove expired (soft)
tmp_out="$(mktemp)"
while IFS=$'\t' read -r port uuid exp tag; do
  [[ -n "${port:-}" ]] || continue
  left=$(( exp - now ))
  if (( left <= 0 )); then
    # expired - just mark; user can clear with vless_clear_all or vless_rmi_one
    say "${port}    EXPIRED        ${tag}"
  else
    say "${port}    ${left}            ${tag}"
    echo -e "${port}\t${uuid}\t${exp}\t${tag}" >>"$tmp_out"
  fi
done <"$DB_FILE"

# keep only unexpired in db
mv "$tmp_out" "$DB_FILE"
chmod 0600 "$DB_FILE" || true

say "---------------------------------------------"
say "✅ 审计完成（已从本地记录中清理过期条目；如需同时从 Xray 删除端口，请对 EXPIRED 端口执行：vless_rmi_one.sh <port>）"
EOM
}

gen_clear_all(){
  install -m 0755 /dev/null /usr/local/bin/vless_clear_all.sh
  cat >/usr/local/bin/vless_clear_all.sh <<'EOM'
#!/usr/bin/env bash
set -euo pipefail

XRAY_ENV="/usr/local/etc/xray/huanxin_env"
DB_FILE="/root/vless_tmp/db.tsv"

die(){ echo -e "❌ $*" >&2; exit 1; }
say(){ echo -e "$*"; }

[[ -f "$XRAY_ENV" ]] || die "缺少 $XRAY_ENV"
# shellcheck disable=SC1090
source "$XRAY_ENV"

[[ -f "$DB_FILE" ]] || { say "（暂无临时节点记录）"; exit 0; }

xray_api_rmi_tag(){
  local t="$1"
  if /usr/local/bin/xray api rmi --server="$API_ADDR" "$t" >/dev/null 2>&1; then return 0; fi
  if /usr/local/bin/xray api rmi -s "$API_ADDR" "$t" >/dev/null 2>&1; then return 0; fi
  if /usr/local/bin/xray api rmi --server="$API_ADDR" --tag "$t" >/dev/null 2>&1; then return 0; fi
  if /usr/local/bin/xray api rmi -s "$API_ADDR" --tag "$t" >/dev/null 2>&1; then return 0; fi
  return 1
}

while IFS=$'\t' read -r port uuid exp tag; do
  [[ -n "${tag:-}" ]] || continue
  xray_api_rmi_tag "$tag" >/dev/null 2>&1 || true
done <"$DB_FILE"

: >"$DB_FILE"
chmod 0600 "$DB_FILE" || true
say "✅ 已清空所有临时端口（并尝试从 Xray 移除对应 inbounds）"
EOM
}

gen_mktemp
gen_rmi_one
gen_audit
gen_clear_all

say "✅ 动态端口脚本已生成："
say "- D=600 vless_mktemp.sh"
say "- vless_audit.sh"
say "- vless_rmi_one.sh <port>"
say "- vless_clear_all.sh"
EOF
}

# -----------------------------
# Main: install deps and generate
# -----------------------------
main(){
  need_root
  apt_install

  gen_update_all
  gen_onekey_reality
  gen_temp_inbound_bundle

  say "=================================================="
  say "✅ 所有脚本已生成完毕（Debian 12 / 最新方案：动态端口 + adi/rmi）"
  say ""
  say "建议顺序："
  say "1) update-all && reboot"
  say "2) bash /root/onekey_reality_ipv4.sh"
  say "3) bash /root/vless_temp_dynamic_inbound.sh"
  say "4) 创建临时节点：D=600 vless_mktemp.sh"
  say ""
  say "常用命令："
  say "- D=600 vless_mktemp.sh"
  say "- vless_audit.sh"
  say "- vless_rmi_one.sh 40035"
  say "- vless_clear_all.sh"
  say "=================================================="
}

main "$@"
