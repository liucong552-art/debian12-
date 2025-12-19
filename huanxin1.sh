cp /root/onekey_reality_ipv4.sh /root/onekey_reality_ipv4.sh.bak.$(date +%F-%H%M%S) 2>/dev/null || true

cat >/root/onekey_reality_ipv4.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# Debian 12 VLESS Reality (单进程 + 多端口临时用户) 一键脚本
# - 使用新版 Xray API（api.listen 直接监听，不再用 dokodemo-door + protocol: api 出站）
# - 兼容 2025.10+ 的 x25519 输出 (PublicKey / Password)
# - 只生成主节点 + env.conf，其它辅助脚本由 huanxin1.sh 另一个脚本生成

REPO_BASE="https://raw.githubusercontent.com/liucong552-art/debian12-/main"
UP_BASE="/usr/local/src/debian12-upstream"

TEMP_PORT_START=40000
TEMP_PORT_COUNT=40   # 40000-40039

XRAY_BIN="/usr/local/bin/xray"
CFG_DIR="/usr/local/etc/xray"
ENV_CONF="${CFG_DIR}/env.conf"
MAIN_CFG="${CFG_DIR}/config.json"

check_debian12() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "❌ 请以 root 运行本脚本"
    exit 1
  fi
  local codename
  codename=$(grep -E "^VERSION_CODENAME=" /etc/os-release 2>/dev/null | cut -d= -f2 || true)
  if [ "$codename" != "bookworm" ]; then
    echo "❌ 仅适用于 Debian 12 (bookworm)，当前: ${codename:-未知}"
    exit 1
  fi
}

install_xray_if_needed() {
  mkdir -p "$UP_BASE"
  local inst="$UP_BASE/xray-install-release.sh"
  if [ ! -x "$inst" ]; then
    curl -fsSL --connect-timeout 3 --max-time 30 --retry 3 --retry-delay 1 --retry-all-errors \
      "${REPO_BASE}/xray-install-release.sh" -o "$inst"
    chmod +x "$inst"
  fi
  if [ ! -x "$XRAY_BIN" ]; then
    echo "== 安装 Xray =="
    "$inst" install --without-geodata
  else
    echo "== 更新 Xray 到最新稳定版 =="
    "$inst" install --without-geodata
  fi
  if [ ! -x "$XRAY_BIN" ]; then
    echo "❌ Xray 安装失败：未找到 ${XRAY_BIN}"
    exit 1
  fi
}

is_private_ip() {
  local ip="$1"
  case "$ip" in
    10.*) return 0 ;;
    192.168.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
  esac
  return 1
}

detect_ipv4_public_first() {
  local ip=""

  # 1) 优先从外网接口获取
  ip="$(curl -4fsS --connect-timeout 2 --max-time 6 --retry 2 --retry-delay 1 --retry-all-errors https://api.ipify.org || true)"
  if [ -n "$ip" ] && ! is_private_ip "$ip"; then
    echo "$ip"
    return 0
  fi

  # 2) 再尝试根据路由表推断出网 IPv4
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  if [ -n "$ip" ] && ! is_private_ip "$ip"; then
    echo "$ip"
    return 0
  fi

  # 3) 最后尝试 hostname -I
  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  if [ -n "$ip" ] && ! is_private_ip "$ip"; then
    echo "$ip"
    return 0
  fi

  echo ""
}

check_port_free() {
  local port="$1"
  if ss -lntH 2>/dev/null | awk '{print $4}' | grep -Eq "(:|])${port}\$"; then
    echo "❌ 端口 ${port} 已被占用，请先释放或修改 MAIN_PORT/API_PORT"
    ss -lntp 2>/dev/null | grep -E "(:|])${port}\b" || true
    exit 1
  fi
}

enable_bbr() {
  echo "=== 1) 只开启 fq + bbr（其余 sysctl 保持默认）==="
  cat >/etc/sysctl.d/99-bbr.conf <<'SYS'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
SYS
  modprobe tcp_bbr 2>/dev/null || true
  sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1 || true
  echo "当前: qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown), cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
}

generate_reality_keys() {
  echo "=== 3) UUID + Reality 密钥 ==="
  UUID="$("$XRAY_BIN" uuid)"
  if [ -z "$UUID" ]; then
    echo "❌ 生成 UUID 失败"
    exit 1
  fi

  local key_out
  key_out="$("$XRAY_BIN" x25519)"

  PRIVATE_KEY="$(printf '%s\n' "$key_out" | grep -i '^PrivateKey:' | awk '{print $2}' || true)"
  PUBLIC_KEY="$(printf '%s\n' "$key_out" | grep -E '^(PublicKey|Password):' | awk '{print $2}' || true)"

  if [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ]; then
    echo "❌ 解析 Reality 密钥失败，原始输出如下："
    printf '%s\n' "$key_out"
    exit 1
  fi

  SHORT_ID="$(openssl rand -hex 8)"
}

write_env_conf() {
  mkdir -p "$CFG_DIR"
  cat >"$ENV_CONF" <<CONFENV
REALITY_DOMAIN=${REALITY_DOMAIN}
MAIN_PORT=${MAIN_PORT}
API_HOST=${API_HOST}
API_PORT=${API_PORT}
TEMP_PORT_START=${TEMP_PORT_START}
TEMP_PORT_COUNT=${TEMP_PORT_COUNT}
CONFENV
  chmod 600 "$ENV_CONF" 2>/dev/null || true
}

build_config_json() {
  echo "=== 4) 生成 Xray 主配置（单进程 + 多端口 + API）==="

  local tmp_cfg
  tmp_cfg="$(mktemp /tmp/xray-main.XXXXXX.json)"

  # 拼接 40 个临时端口 inbound
  local tmp_inbounds=""
  local i p tag
  for i in $(seq 0 $((TEMP_PORT_COUNT-1))); do
    p=$((TEMP_PORT_START + i))
    tag="vless-tmp-${p}"
    tmp_inbounds+=$(cat <<JSON
    ,
    {
      "tag": "${tag}",
      "listen": "0.0.0.0",
      "port": ${p},
      "protocol": "vless",
      "settings": {
        "clients": [],
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
      }
    }
JSON
)
  done

  cat >"$tmp_cfg" <<CONF
{
  "log": {
    "loglevel": "warning"
  },
  "api": {
    "tag": "${API_TAG}",
    "listen": "${API_HOST}:${API_PORT}",
    "services": [
      "HandlerService",
      "LoggerService",
      "StatsService",
      "RoutingService"
    ]
  },
  "inbounds": [
    {
      "tag": "${MAIN_TAG}",
      "listen": "0.0.0.0",
      "port": ${MAIN_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "email": "main@local",
            "flow": "xtls-rprx-vision"
          }
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
      }
    }${tmp_inbounds}
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    },
    {
      "tag": "block",
      "protocol": "blackhole"
    }
  ]
}
CONF

  mv "$tmp_cfg" "$MAIN_CFG"
}

restart_xray() {
  echo "=== 5) 检查并重启 Xray ==="
  "$XRAY_BIN" run -test -config "$MAIN_CFG"

  systemctl daemon-reload
  systemctl enable xray >/dev/null 2>&1 || true
  systemctl restart xray

  sleep 1
  if ! systemctl is-active --quiet xray.service; then
    echo "❌ xray.service 启动失败："
    systemctl status xray.service --no-pager || true
    journalctl -u xray.service -n 80 --no-pager || true
    exit 1
  fi

  echo "== 监听端口检测 =="
  ss -lntp 2>/dev/null | grep -E "xray|:${MAIN_PORT}\b|:${API_PORT}\b|:${TEMP_PORT_START}\b" || true
}

write_main_url() {
  local node_name="VLESS-REALITY-IPv4-APPLE"
  local url="vless://${UUID}@${SERVER_IP}:${MAIN_PORT}?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&sni=${REALITY_DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}#${node_name}"

  echo "$url" > /root/vless_reality_vision_url.txt
  if base64 --help 2>/dev/null | grep -q -- "-w"; then
    echo "$url" | base64 -w0 > /root/v2ray_subscription_base64.txt
  else
    echo "$url" | base64 | tr -d '\n' > /root/v2ray_subscription_base64.txt
  fi

  echo "✅ 主节点完成：${MAIN_PORT} + 单进程 + ${TEMP_PORT_COUNT} 临时端口(${TEMP_PORT_START}-$((TEMP_PORT_START+TEMP_PORT_COUNT-1))) + API(${API_HOST}:${API_PORT})"
  echo "统一配置文件：${ENV_CONF}"
  echo "主节点链接："
  cat /root/vless_reality_vision_url.txt
}

main() {
  check_debian12

  # 核心变量（可按需手动改）
  REALITY_DOMAIN="www.apple.com"
  MAIN_PORT=443
  MAIN_TAG="vless-main"
  API_HOST="127.0.0.1"
  API_PORT=10085
  API_TAG="api"

  enable_bbr
  install_xray_if_needed

  SERVER_IP="$(detect_ipv4_public_first)"
  if [ -z "$SERVER_IP" ]; then
    echo "❌ 无法自动检测公网 IPv4（可能是内网 / 无法连外网）。"
    echo "   请手动导出你的公网 IPv4 后再运行本脚本，或者改脚本内 SERVER_IP。"
    exit 1
  fi

  check_port_free "$MAIN_PORT"
  check_port_free "$API_PORT"

  generate_reality_keys
  write_env_conf
  build_config_json
  restart_xray
  write_main_url
}

main "$@"
EOF

chmod +x /root/onekey_reality_ipv4.sh
