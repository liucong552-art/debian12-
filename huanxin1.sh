#!/usr/bin/env bash
# 适用：Debian 12 + 已安装 /usr/local/bin/xray
# 作用：为 “临时 VLESS 端口脚本” 准备环境（env.conf / XRAY_BIN / api+stats）

set -euo pipefail

#==== 基本检查 ====
if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行本脚本。"
  exit 1
fi

XRAY_BIN=${XRAY_BIN:-/usr/local/bin/xray}
XRAY_CONF=${XRAY_CONF:-/usr/local/etc/xray/config.json}
XRAY_DIR=/usr/local/etc/xray
ENV_FILE="$XRAY_DIR/env.conf"

mkdir -p "$XRAY_DIR"

echo "== 安装必要工具（jq、iproute2） =="
if ! command -v jq >/dev/null 2>&1; then
  apt-get update
  apt-get install -y jq
fi
if ! command -v ss >/dev/null 2>&1; then
  apt-get update
  apt-get install -y iproute2
fi

#==== 1. env.conf ====
if [ ! -f "$ENV_FILE" ]; then
  echo "== 未检测到 $ENV_FILE，准备创建 =="
  read -rp "请输入 REALITY 域名 (默认 www.apple.com): " REALITY_DOMAIN
  REALITY_DOMAIN=${REALITY_DOMAIN:-www.apple.com}

  read -rp "请输入主端口 (默认 443): " MAIN_PORT
  MAIN_PORT=${MAIN_PORT:-443}

  cat >"$ENV_FILE" <<EOF
REALITY_DOMAIN=${REALITY_DOMAIN}
MAIN_PORT=${MAIN_PORT}
API_HOST=127.0.0.1
API_PORT=10085
TEMP_PORT_START=40000
TEMP_PORT_COUNT=40
EOF
else
  echo "== 检测到已有 $ENV_FILE，保持不动，当前内容如下："
  cat "$ENV_FILE"
fi

#==== 2. vless_load_env.sh ====
echo "== 写入 /usr/local/sbin/vless_load_env.sh =="
cat >/usr/local/sbin/vless_load_env.sh <<'EOF'
#!/usr/bin/env bash
set -a
[ -f /usr/local/etc/xray/env.conf ] && . /usr/local/etc/xray/env.conf
set +a
EOF
chmod +x /usr/local/sbin/vless_load_env.sh

# 让当前会话先加载一次环境变量
. /usr/local/sbin/vless_load_env.sh

API_HOST=${API_HOST:-127.0.0.1}
API_PORT=${API_PORT:-10085}

#==== 3. 检查 Xray 二进制 ====
echo "== 检查 Xray 二进制 =="
if ! "$XRAY_BIN" -version >/dev/null 2>&1; then
  echo "❌ 未在 $XRAY_BIN 找到可用的 xray，可根据实际路径修改 XRAY_BIN 变量后重试。"
  exit 1
fi
"$XRAY_BIN" -version

# 让后续登录的 shell 默认有 XRAY_BIN 变量
echo "== 写入 /etc/profile.d/xray.sh =="
cat >/etc/profile.d/xray.sh <<EOF
export XRAY_BIN=$XRAY_BIN
EOF

#==== 4. 备份 config.json ====
echo "== 备份 Xray 主配置 =="
if [ -f "$XRAY_CONF" ]; then
  backup="${XRAY_CONF}.bak.$(date +%F-%H%M%S)"
  cp "$XRAY_CONF" "$backup"
  echo "已备份现有配置到: $backup"
else
  echo "⚠️ 未找到 $XRAY_CONF，将创建一个最小空壳配置。"
  cat >"$XRAY_CONF" <<'EOF'
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
fi

#==== 5. 校验 JSON ====
echo "== 检查 config.json 是否为纯 JSON（不能带注释） =="
if ! jq empty "$XRAY_CONF" >/dev/null 2>&1; then
  echo "❌ $XRAY_CONF 不是纯 JSON（可能有 // 注释），脚本没法自动修改。"
  echo "请先把配置改成无注释 JSON，再重新运行本脚本。"
  exit 1
fi

#==== 6. 补全 api + stats ====
echo "== 补全 api + stats 配置 =="
tmp="${XRAY_CONF}.new"

jq --arg apihost "$API_HOST" --arg apiport "$API_PORT" '
  .api = (.api // {}) |
  .api.tag = (.api.tag // "api") |
  .api.listen = (.api.listen // ($apihost + ":" + $apiport)) |
  .api.services = ((.api.services // []) + ["HandlerService","LoggerService","StatsService","RoutingService"] | unique) |
  .stats = (.stats // {})
' "$XRAY_CONF" >"$tmp"

mv "$tmp" "$XRAY_CONF"

#==== 7. 重启 Xray ====
echo "== 重启 Xray 服务 =="
systemctl daemon-reload || true
systemctl restart xray

sleep 1

#==== 8. 检查 API 端口监听 ====
echo "=== 检查 ${API_HOST}:${API_PORT} 是否在监听 ==="
if ss -lntp | grep -q ":${API_PORT}"; then
  ss -lntp | grep ":${API_PORT}" || true
else
  echo "⚠️ 看起来 ${API_HOST}:${API_PORT} 没在监听，请用 'journalctl -u xray -e' 看日志。"
fi

#==== 9. 测试 stats 调用（仅做提示，不作为失败条件） ====
echo
echo "=== 测试 xray api stats 调用（失败也不会中断脚本） ==="
if "$XRAY_BIN" api stats -s "${API_HOST}:${API_PORT}" -name '' >/dev/null 2>&1; then
  echo "✅ xray api stats 调用正常。"
else
  echo "⚠️ xray api stats 调用失败，但只要 adu/rmu 可用，你的临时端口脚本仍然可以用。"
fi

echo
echo "✅ Xray 环境预配置完成。"
echo "👉 当前会话如果要立刻用临时 VLESS 脚本，请先执行："
echo "   source /usr/local/sbin/vless_load_env.sh"
echo "然后再运行你一开始发给我的那个脚本。"
