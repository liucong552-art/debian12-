#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# huanxin (Debian 12) - 最新方案：
# - 主节点：VLESS+REALITY 443
# - API：127.0.0.1:10085 (HandlerService 必开)
# - 临时节点：从 40000 起自动找空闲端口，动态 adi/rmi inbound
# =========================================================

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "❌ 请用 root 运行"
    exit 1
  fi
}

is_debian_12() {
  [[ -f /etc/os-release ]] || return 1
  . /etc/os-release
  [[ "${ID:-}" == "debian" && "${VERSION_ID:-}" == "12" ]]
}

install_deps() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends \
    curl ca-certificates unzip jq python3 openssl iproute2 systemd
}

write_file() {
  local path="$1"
  shift
  install -D -m 0755 /dev/null "$path" 2>/dev/null || true
  cat >"$path" <<'EOF'
EOF
  # shellcheck disable=SC2124
  local content="$*"
  if [[ -n "$content" ]]; then
    printf "%s" "$content" >"$path"
  fi
}

# Safer heredoc writer
write_heredoc() {
  local path="$1"
  local mode="${2:-0755}"
  shift 2 || true
  install -D -m "$mode" /dev/null "$path" 2>/dev/null || true
  cat >"$path"
  chmod "$mode" "$path" 2>/dev/null || true
}

need_root
if ! is_debian_12; then
  echo "⚠️ 当前脚本按 Debian 12 (bookworm) 设计；非 Debian 12 也可能能跑，但不保证。"
fi

install_deps

UPDIR="/usr/local/src/debian12-upstream"
mkdir -p "$UPDIR"

# 1) update-all
write_heredoc /usr/local/bin/update-all 0755 <<'SH'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "🚀 开始系统更新 (Debian 12 / bookworm)..."
apt-get update -y
apt-get upgrade -y
apt-get autoremove -y

echo "✅ 软件包更新完成"
echo "🧠 建议：如安装了新内核/ssh 等关键组件，重启一次更稳：reboot"
SH

# 2) /root/onekey_reality_ipv4.sh
write_heredoc /root/onekey_reality_ipv4.sh 0755 <<'SH'
#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

XRAY_BIN="/usr/local/bin/xray"
XRAY_ETC="/usr/local/etc/xray"
CFG="${XRAY_ETC}/config.json"

# 可覆盖参数
SERVER_IP="${SERVER_IP:-}"
PORT="${PORT:-443}"
SNI="${SNI:-www.apple.com}"
DEST="${DEST:-www.apple.com:443}"
API_LISTEN="${API_LISTEN:-127.0.0.1}"
API_PORT="${API_PORT:-10085}"

detect_ipv4() {
  local ip=""
  ip="$(curl -4 -fsSL --max-time 5 https://ipv4.icanhazip.com 2>/dev/null | tr -d ' \n\r' || true)"
  [[ -n "$ip" ]] || ip="$(curl -4 -fsSL --max-time 5 https://ifconfig.co/ip 2>/dev/null | tr -d ' \n\r' || true)"
  [[ -n "$ip" ]] || ip="$(curl -4 -fsSL --max-time 5 https://api.ipify.org 2>/dev/null | tr -d ' \n\r' || true)"
  echo "$ip"
}

install_deps() {
  apt-get update -y
  apt-get install -y --no-install-recommends curl ca-certificates unzip jq python3 openssl iproute2
}

enable_bbr_fq() {
  # 只动这两个，不乱改其它 sysctl
  cat >/etc/sysctl.d/99-bbr-fq.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl --system >/dev/null 2>&1 || true
  local qdisc cc
  qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
  cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
  echo "当前: qdisc=${qdisc}, cc=${cc}"
}

install_xray() {
  mkdir -p /usr/local/src
  local ins="/usr/local/src/xray-install-release.sh"
  curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh -o "$ins"
  chmod +x "$ins"

  if [[ -x "$XRAY_BIN" ]]; then
    # 尝试 update（脚本支持的话）
    bash "$ins" update >/dev/null 2>&1 || bash "$ins" install
  else
    bash "$ins" install
  fi
}

gen_uuid() {
  "$XRAY_BIN" uuid
}

gen_x25519() {
  # 输出形如：
  # Private key: ...
  # Public key: ...
  "$XRAY_BIN" x25519
}

rand_short_id() {
  # 8 bytes hex (16 chars)
  openssl rand -hex 8
}

main() {
  install_deps

  if [[ -z "$SERVER_IP" ]]; then
    SERVER_IP="$(detect_ipv4)"
  fi
  if [[ -z "$SERVER_IP" ]]; then
    echo "❌ 无法探测 IPv4，请手动指定：SERVER_IP=1.2.3.4 bash /root/onekey_reality_ipv4.sh"
    exit 1
  fi

  echo "服务器地址(探测): $SERVER_IP"
  echo "伪装域名:         $SNI"
  echo "端口:             $PORT"
  echo "API 监听:         ${API_LISTEN}:${API_PORT}"

  echo "=== 1) 只开启 fq + bbr（其余 sysctl 保持默认）==="
  enable_bbr_fq

  echo "=== 2) 安装/更新 xray ==="
  install_xray

  mkdir -p "$XRAY_ETC"

  echo "=== 3) 生成 UUID + Reality 密钥 ==="
  UUID="$(gen_uuid)"
  KEY_OUT="$(gen_x25519)"
  PRIVATE_KEY="$(echo "$KEY_OUT" | awk -F': ' '/Private key/{print $2}' | tr -d ' \r\n')"
  PUBLIC_KEY="$(echo "$KEY_OUT"  | awk -F': ' '/Public key/{print $2}'  | tr -d ' \r\n')"
  SHORT_ID="$(rand_short_id)"

  if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
    echo "❌ x25519 生成失败，输出："
    echo "$KEY_OUT"
    exit 1
  fi

  # 写入 config.json（包含 api + HandlerService）
  cat >"$CFG" <<JSON
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "api": {
    "tag": "api",
    "services": [
      "HandlerService",
      "LoggerService",
      "StatsService"
    ]
  },
  "inbounds": [
    {
      "tag": "api",
      "listen": "${API_LISTEN}",
      "port": ${API_PORT},
      "protocol": "dokodemo-door",
      "settings": {
        "address": "${API_LISTEN}",
        "port": ${API_PORT},
        "network": "tcp"
      }
    },
    {
      "tag": "vless-reality-443",
      "listen": "0.0.0.0",
      "port": ${PORT},
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "id": "${UUID}",
            "flow": "xtls-rprx-vision",
            "email": "main@reality"
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${DEST}",
          "xver": 0,
          "serverNames": [
            "${SNI}"
          ],
          "privateKey": "${PRIVATE_KEY}",
          "shortIds": [
            "${SHORT_ID}"
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ],
        "routeOnly": true
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" },
    { "protocol": "api", "tag": "api" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "inboundTag": ["api"],
        "outboundTag": "api"
      }
    ]
  }
}
JSON

  # env.conf（给临时节点脚本用）
  cat >"${XRAY_ETC}/env.conf" <<EOF
# generated by onekey_reality_ipv4.sh
API_SERVER=${API_LISTEN}:${API_PORT}
TEMP_PORT_START=40000
TEMP_PORT_END=65000
EOF

  mkdir -p /var/log/xray
  touch /var/log/xray/access.log /var/log/xray/error.log 2>/dev/null || true

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable xray.service >/dev/null 2>&1 || true
  systemctl restart xray.service

  # 生成主节点链接
  URL="vless://${UUID}@${SERVER_IP}:${PORT}?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&sni=${SNI}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}#VLESS-REALITY-IPv4-${SNI}"
  echo "$URL" >/root/vless_reality_vision_url.txt
  echo -n "$URL" | base64 -w0 >/root/v2ray_subscription_base64.txt

  echo
  echo "================== 主节点信息 =================="
  echo "$URL"
  echo
  echo "保存位置："
  echo "  /root/vless_reality_vision_url.txt"
  echo "  /root/v2ray_subscription_base64.txt"
  echo "  /usr/local/etc/xray/env.conf"
  echo "✅ 主节点部署完成（API：${API_LISTEN}:${API_PORT}，已启用 HandlerService）"
}

main "$@"
SH

# 3) /root/vless_temp_dynamic_inbound.sh
write_heredoc /root/vless_temp_dynamic_inbound.sh 0755 <<'SH'
#!/usr/bin/env bash
set -euo pipefail

XRAY_BIN="/usr/local/bin/xray"
XRAY_ETC="/usr/local/etc/xray"
CFG="${XRAY_ETC}/config.json"

DIR="/usr/local/etc/xray/tmpusers"
LOCK="/var/lock/vless-tmpusers.lock"
LOG="/var/log/vless-user.log"

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "❌ 请用 root 运行"
    exit 1
  fi
}

install_deps() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends jq python3 openssl iproute2 systemd
}

check_api_cmds() {
  if ! "$XRAY_BIN" help api 2>/dev/null | grep -qE '\badi\b'; then
    echo "❌ 当前 xray 不支持 api adi（请更新 xray）"
    exit 1
  fi
  if ! "$XRAY_BIN" help api 2>/dev/null | grep -qE '\brmi\b'; then
    echo "❌ 当前 xray 不支持 api rmi（请更新 xray）"
    exit 1
  fi
}

check_main_reality() {
  # 主配置里必须有一个 Reality inbound（mktemp 要克隆它的 streamSettings）
  python3 - <<'PY'
import json
cfg="/usr/local/etc/xray/config.json"
d=json.load(open(cfg,'r',encoding='utf-8'))
ok=False
for ib in d.get("inbounds",[]):
    if not isinstance(ib,dict): 
        continue
    ss=ib.get("streamSettings",{})
    if isinstance(ss,dict) and ss.get("security")=="reality":
        rs=ss.get("realitySettings",{})
        if isinstance(rs,dict) and rs.get("privateKey") and rs.get("dest"):
            ok=True
            break
raise SystemExit(0 if ok else 2)
PY
}

setup_dirs() {
  mkdir -p "$DIR"
  touch "$LOG" 2>/dev/null || true
  chmod 700 "$DIR" 2>/dev/null || true
}

write_env_loader() {
  cat >/usr/local/sbin/vless_load_env.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ENV="/usr/local/etc/xray/env.conf"
if [[ -f "$ENV" ]]; then
  # shellcheck disable=SC1090
  source "$ENV"
fi
export API_SERVER="${API_SERVER:-127.0.0.1:10085}"
export TEMP_PORT_START="${TEMP_PORT_START:-40000}"
export TEMP_PORT_END="${TEMP_PORT_END:-65000}"
EOF
  chmod +x /usr/local/sbin/vless_load_env.sh
}

write_mktemp() {
  cat >/usr/local/sbin/vless_mktemp.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

XRAY_BIN="/usr/local/bin/xray"
CFG_MAIN="/usr/local/etc/xray/config.json"
DIR="/usr/local/etc/xray/tmpusers"
LOCK="/var/lock/vless-tmpusers.lock"
LOG="/var/log/vless-user.log"

# load env
if [[ -x /usr/local/sbin/vless_load_env.sh ]]; then
  /usr/local/sbin/vless_load_env.sh
fi
API_SERVER="${API_SERVER:-127.0.0.1:10085}"
TEMP_PORT_START="${TEMP_PORT_START:-40000}"
TEMP_PORT_END="${TEMP_PORT_END:-65000}"

D="${D:-}"
if ! [[ "$D" =~ ^[0-9]+$ ]] || (( D <= 0 )); then
  echo "❌ 用法：D=600 vless_mktemp.sh（D 为正整数秒）"
  exit 1
fi

mkdir -p "$DIR"
touch "$LOG" 2>/dev/null || true
chmod 700 "$DIR" 2>/dev/null || true

exec 9>"$LOCK"
flock -n 9 || { echo "❌ 另一个实例正在运行，请稍后重试"; exit 1; }

systemctl is-active --quiet xray.service || { echo "❌ xray.service 未运行"; exit 1; }

# xray api 必须支持 adi/rmi
"$XRAY_BIN" help api 2>/dev/null | grep -qE '\badi\b' || { echo "❌ xray 不支持 api adi"; exit 1; }
"$XRAY_BIN" help api 2>/dev/null | grep -qE '\brmi\b' || { echo "❌ xray 不支持 api rmi"; exit 1; }

port_in_use_by_meta() {
  local p="$1"
  awk -F= '/^PORT=/{print $2}' "$DIR"/*.meta 2>/dev/null | grep -qx "$p"
}

port_in_listen() {
  local p="$1"
  ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$"
}

PORT=""
for ((p=TEMP_PORT_START; p<=TEMP_PORT_END; p++)); do
  if port_in_use_by_meta "$p"; then
    continue
  fi
  if port_in_listen "$p"; then
    continue
  fi
  PORT="$p"
  break
done

if [[ -z "$PORT" ]]; then
  echo "❌ 没找到可用端口（范围 ${TEMP_PORT_START}-${TEMP_PORT_END}）"
  exit 1
fi

TAG="vless-tmp-${PORT}"
EMAIL="${TAG}@temp"
UUID="$("$XRAY_BIN" uuid)"
NOW=$(date +%s)
EXP=$((NOW + D))

CFG="$DIR/${TAG}.json"
META="$DIR/${TAG}.meta"

# 生成要 adi 的 inbound：从主配置里找第一个 reality inbound，克隆其 streamSettings
python3 - "$CFG_MAIN" "$PORT" "$TAG" "$UUID" "$EMAIL" >"$CFG" <<'PY'
import json, sys

cfg_main=sys.argv[1]
port=int(sys.argv[2])
tag=sys.argv[3]
uuid=sys.argv[4]
email=sys.argv[5]

cfg=json.load(open(cfg_main,'r',encoding='utf-8'))

tpl=None
for ib in cfg.get("inbounds",[]):
    if not isinstance(ib,dict):
        continue
    ss=ib.get("streamSettings",{})
    if isinstance(ss,dict) and ss.get("security")=="reality":
        rs=ss.get("realitySettings",{})
        if isinstance(rs,dict) and rs.get("privateKey") and rs.get("dest"):
            tpl=ib
            break

if not tpl:
    print("NO_REALITY_INBOUND", file=sys.stderr)
    sys.exit(2)

ss=tpl.get("streamSettings",{})
sniff=tpl.get("sniffing")

new_ib={
  "tag": tag,
  "listen": "0.0.0.0",
  "port": port,
  "protocol": "vless",
  "settings": {
    "decryption": "none",
    "clients": [
      {"id": uuid, "email": email, "flow": "xtls-rprx-vision"}
    ]
  },
  "streamSettings": ss
}

if sniff is not None:
    new_ib["sniffing"]=sniff

print(json.dumps({"inbounds":[new_ib]}, ensure_ascii=False, indent=2))
PY

if grep -q "NO_REALITY_INBOUND" "$CFG" 2>/dev/null; then
  echo "❌ 主配置里没找到 Reality inbound（security=reality 且 realitySettings.privateKey/dest 存在）"
  echo "   请先跑：bash /root/onekey_reality_ipv4.sh"
  exit 1
fi

TMPLOG="$(mktemp /tmp/adi.XXXXXX.log)"
chmod 600 "$TMPLOG" 2>/dev/null || true
trap 'rm -f "$TMPLOG" 2>/dev/null || true' EXIT

# 动态添加 inbound
if ! "$XRAY_BIN" api adi -s "$API_SERVER" "$CFG" >"$TMPLOG" 2>&1; then
  cat "$TMPLOG" >&2
  echo "❌ adi 失败（API_SERVER=$API_SERVER）"
  exit 1
fi

cat >"$META" <<M
TAG=$TAG
EMAIL=$EMAIL
UUID=$UUID
PORT=$PORT
EXPIRE_EPOCH=$EXP
M
chmod 600 "$META" "$CFG" 2>/dev/null || true

# 到期自动删除 inbound（best-effort）
UNIT="vless-expire-$TAG"
systemd-run --quiet --collect --unit "$UNIT" --on-active="${D}s" \
  /usr/local/sbin/vless_rmi_one.sh "$TAG" >/dev/null 2>&1 || true

# 拼链接：从主节点链接文件替换 UUID/端口/备注
MAIN="/root/vless_reality_vision_url.txt"
URL="(未找到 ${MAIN}，请用主节点参数手动拼接；端口=$PORT UUID=$UUID)"
if [[ -f "$MAIN" ]]; then
  BASE="$(sed -n '1p' "$MAIN" || true)"
  if [[ -n "$BASE" ]]; then
    URL="$(echo "$BASE" | sed -E \
      "s#^vless://[^@]+@#vless://${UUID}@#; s#@([^:/]+):[0-9]+\?#@\1:${PORT}?#; s/#.*/#${TAG}/")"
  fi
fi

E_STR=$(TZ=Asia/Shanghai date -d "@$EXP" '+%F %T')
echo "$(date '+%F %T %Z') create $TAG port=$PORT email=$EMAIL exp=$EXP" >>"$LOG" 2>/dev/null || true

echo "✅ 新临时节点: $TAG"
echo "端口: $PORT"
echo "UUID: $UUID"
echo "到期(北京时间): $E_STR"
echo "链接:"
echo "$URL"
EOF
  chmod +x /usr/local/sbin/vless_mktemp.sh
}

write_rmi_one() {
  cat >/usr/local/sbin/vless_rmi_one.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

XRAY_BIN="/usr/local/bin/xray"
DIR="/usr/local/etc/xray/tmpusers"
LOCK="/var/lock/vless-tmpusers.lock"

# load env
if [[ -x /usr/local/sbin/vless_load_env.sh ]]; then
  /usr/local/sbin/vless_load_env.sh
fi
API_SERVER="${API_SERVER:-127.0.0.1:10085}"

KEY="${1:-}"
[[ -n "$KEY" ]] || { echo "用法: vless_rmi_one.sh <端口|tag>"; exit 1; }

TAG="$KEY"
if [[ "$KEY" =~ ^[0-9]+$ ]]; then
  TAG="vless-tmp-${KEY}"
fi

exec 9>"$LOCK"
flock -n 9 || { echo "❌ busy"; exit 1; }

"$XRAY_BIN" api rmi -s "$API_SERVER" "$TAG" >/dev/null 2>&1 || true
rm -f "$DIR/${TAG}.json" "$DIR/${TAG}.meta" 2>/dev/null || true

echo "✅ removed inbound: $TAG"
EOF
  chmod +x /usr/local/sbin/vless_rmi_one.sh
}

write_audit() {
  cat >/usr/local/sbin/vless_audit.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DIR="/usr/local/etc/xray/tmpusers"
shopt -s nullglob

now=$(date +%s)
printf "%-22s %-8s %-12s %-20s\n" "TAG" "PORT" "REMAIN(s)" "EXPIRE(Asia/Shanghai)"
for m in "$DIR"/*.meta; do
  unset TAG PORT EXPIRE_EPOCH UUID EMAIL
  # shellcheck disable=SC1090
  . "$m" 2>/dev/null || continue
  remain=$(( EXPIRE_EPOCH - now ))
  if (( remain < 0 )); then remain=0; fi
  exp_str=$(TZ=Asia/Shanghai date -d "@$EXPIRE_EPOCH" '+%F %T' 2>/dev/null || echo "-")
  printf "%-22s %-8s %-12s %-20s\n" "${TAG:-?}" "${PORT:-?}" "$remain" "$exp_str"
done
EOF
  chmod +x /usr/local/sbin/vless_audit.sh
}

write_clear_all() {
  cat >/usr/local/sbin/vless_clear_all.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DIR="/usr/local/etc/xray/tmpusers"
shopt -s nullglob

n=0
for m in "$DIR"/*.meta; do
  unset TAG
  # shellcheck disable=SC1090
  . "$m" 2>/dev/null || continue
  [[ -n "${TAG:-}" ]] || continue
  /usr/local/sbin/vless_rmi_one.sh "$TAG" >/dev/null 2>&1 || true
  n=$((n+1))
done
echo "✅ cleared $n node(s)"
EOF
  chmod +x /usr/local/sbin/vless_clear_all.sh
}

write_restore_gc() {
  cat >/usr/local/sbin/vless_restore.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

XRAY_BIN="/usr/local/bin/xray"
DIR="/usr/local/etc/xray/tmpusers"

# load env
if [[ -x /usr/local/sbin/vless_load_env.sh ]]; then
  /usr/local/sbin/vless_load_env.sh
fi
API_SERVER="${API_SERVER:-127.0.0.1:10085}"

shopt -s nullglob
now=$(date +%s)

systemctl is-active --quiet xray.service || exit 0

for m in "$DIR"/*.meta; do
  unset TAG EXPIRE_EPOCH
  # shellcheck disable=SC1090
  . "$m" 2>/dev/null || continue
  [[ -n "${TAG:-}" ]] || continue

  if [[ -n "${EXPIRE_EPOCH:-}" && "$EXPIRE_EPOCH" =~ ^[0-9]+$ ]]; then
    if (( EXPIRE_EPOCH <= now )); then
      /usr/local/sbin/vless_rmi_one.sh "$TAG" >/dev/null 2>&1 || true
      continue
    fi
  fi

  cfg="$DIR/${TAG}.json"
  [[ -f "$cfg" ]] || continue
  "$XRAY_BIN" api adi -s "$API_SERVER" "$cfg" >/dev/null 2>&1 || true
done

exit 0
EOF
  chmod +x /usr/local/sbin/vless_restore.sh

  cat >/usr/local/sbin/vless_gc.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DIR="/usr/local/etc/xray/tmpusers"
shopt -s nullglob
now=$(date +%s)

for m in "$DIR"/*.meta; do
  unset TAG EXPIRE_EPOCH
  # shellcheck disable=SC1090
  . "$m" 2>/dev/null || continue
  [[ -n "${TAG:-}" ]] || continue
  [[ -n "${EXPIRE_EPOCH:-}" && "$EXPIRE_EPOCH" =~ ^[0-9]+$ ]] || continue

  if (( EXPIRE_EPOCH <= now )); then
    /usr/local/sbin/vless_rmi_one.sh "$TAG" >/dev/null 2>&1 || true
  fi
done
EOF
  chmod +x /usr/local/sbin/vless_gc.sh
}

write_systemd_units() {
  cat >/etc/systemd/system/vless-restore.service <<'EOF'
[Unit]
Description=Restore Xray temp inbounds (adi) after reboot
After=network-online.target xray.service
Wants=network-online.target xray.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vless_restore.sh

[Install]
WantedBy=multi-user.target
EOF

  cat >/etc/systemd/system/vless-gc.service <<'EOF'
[Unit]
Description=GC expired Xray temp inbounds
After=xray.service
Wants=xray.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vless_gc.sh
EOF

  cat >/etc/systemd/system/vless-gc.timer <<'EOF'
[Unit]
Description=Run vless-gc periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=3min
AccuracySec=30s
Unit=vless-gc.service

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable vless-restore.service >/dev/null 2>&1 || true
  systemctl enable --now vless-gc.timer >/dev/null 2>&1 || true
}

main() {
  need_root
  install_deps

  if [[ ! -x "$XRAY_BIN" ]]; then
    echo "❌ 未检测到 xray：请先执行 bash /root/onekey_reality_ipv4.sh"
    exit 1
  fi

  check_api_cmds

  if [[ ! -f "$CFG" ]]; then
    echo "❌ 未检测到主配置 $CFG：请先执行 bash /root/onekey_reality_ipv4.sh"
    exit 1
  fi

  if ! check_main_reality; then
    echo "❌ 主配置未发现可用 Reality inbound（缺 privateKey/dest）"
    echo "   请先执行：bash /root/onekey_reality_ipv4.sh"
    exit 1
  fi

  setup_dirs
  write_env_loader
  write_mktemp
  write_rmi_one
  write_audit
  write_clear_all
  write_restore_gc
  write_systemd_units

  echo "✅ 动态临时节点系统部署完成（单进程 + 动态 adi/rmi inbound）"
  echo
  echo "用法："
  echo "  创建临时节点（例如 10 分钟）：D=600 vless_mktemp.sh"
  echo "  审计：vless_audit.sh"
  echo "  删除某个端口：vless_rmi_one.sh 40035"
  echo "  清空全部：vless_clear_all.sh"
  echo
  echo "说明："
  echo "  - 端口从 40000 开始顺序寻找可用端口（不写死、不预置 40 个端口）"
  echo "  - 重启后 vless-restore.service 会恢复未过期临时节点"
  echo "  - vless-gc.timer 每隔几分钟清理过期节点"
  echo
  echo "⚠️ 别忘了放行端口范围：至少 40000-65000/TCP（云安全组/防火墙）"
}

main "$@"
SH

# 写入口脚本（兼容你之前习惯的名字）
# 之前你用的是 /root/vless_temp_audit_ipv4_all.sh，这里也顺便生成一个同名入口，指向新方案。
write_heredoc /root/vless_temp_audit_ipv4_all.sh 0755 <<'SH'
#!/usr/bin/env bash
set -euo pipefail
exec bash /root/vless_temp_dynamic_inbound.sh "$@"
SH

echo "=================================================="
echo "✅ 所有脚本已生成完毕（Debian 12 / 最新方案：动态端口 + adi/rmi）"
echo
echo "建议顺序："
echo "1) update-all && reboot"
echo "2) bash /root/onekey_reality_ipv4.sh"
echo "3) bash /root/vless_temp_dynamic_inbound.sh   (或 bash /root/vless_temp_audit_ipv4_all.sh)"
echo "4) 创建临时节点：D=600 vless_mktemp.sh"
echo
echo "常用命令："
echo "- D=600 vless_mktemp.sh"
echo "- vless_audit.sh"
echo "- vless_rmi_one.sh 40035"
echo "- vless_clear_all.sh"
echo "=================================================="
