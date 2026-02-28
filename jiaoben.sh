#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$' \n\t'

log(){ echo -e "\n[+] $*\n"; }
die(){ echo -e "\n[x] $*\n" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo -i"

# ====== 你需要通过环境变量传入的参数 ======
# ADMIN_EMAIL：面板管理员邮箱（用于安装时生成管理员）
# NODE_IP：只允许访问 7002 的节点机公网 IP（非常重要）
# PANEL_IP：面板机公网 IP（用于 allow 本机自检）
#
# 可选：
# XBOARD_DIR：默认 /opt/Xboard
# BRIDGE_PORT：默认 7002
# UPSTREAM_PORT：默认自动探测，探测不到则用 7001
# =================================================

ADMIN_EMAIL="${ADMIN_EMAIL:-}"
NODE_IP="${NODE_IP:-}"
PANEL_IP="${PANEL_IP:-}"
XBOARD_DIR="${XBOARD_DIR:-/opt/Xboard}"
BRIDGE_PORT="${BRIDGE_PORT:-7002}"

[ -n "$ADMIN_EMAIL" ] || die "缺少 ADMIN_EMAIL（管理员邮箱）"
[ -n "$NODE_IP" ] || die "缺少 NODE_IP（节点机公网 IP，用于放行 7002）"
[ -n "$PANEL_IP" ] || die "缺少 PANEL_IP（面板机公网 IP，用于本机自检 allow）"

log "Step 1/6: 安装基础依赖（curl/git/unzip/nginx）"
apt-get update -y
apt-get install -y curl ca-certificates git unzip nginx

log "Step 2/6: 安装 Docker + docker compose plugin"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | bash
fi
apt-get install -y docker-compose-plugin >/dev/null 2>&1 || true
systemctl enable --now docker

docker --version
docker compose version || die "docker compose 不可用（请确认 docker-compose-plugin 安装成功）"

log "Step 3/6: 拉取 Xboard（compose 分支）到 $XBOARD_DIR"
mkdir -p "$(dirname "$XBOARD_DIR")"
rm -rf "$XBOARD_DIR"

if git clone -b compose --depth 1 https://github.com/cedar2025/Xboard "$XBOARD_DIR"; then
  log "git clone 成功"
else
  log "git clone 失败，改用 zip 下载兜底"
  ZIP=/tmp/xboard-compose.zip
  curl -fL --retry 5 --retry-delay 2 -o "$ZIP" "https://github.com/cedar2025/Xboard/archive/refs/heads/compose.zip" \
  || curl -fL --retry 5 --retry-delay 2 -o "$ZIP" "https://mirror.ghproxy.com/https://github.com/cedar2025/Xboard/archive/refs/heads/compose.zip"
  unzip -q "$ZIP" -d /opt
  mv /opt/Xboard-compose "$XBOARD_DIR"
fi

cd "$XBOARD_DIR"
ls -la | head -n 5

log "Step 4/6: 安装 Xboard（全新安装，SQLite+Redis；输出会写到 /opt/xboard_install.log）"
docker compose run --rm \
  -e ENABLE_SQLITE=true \
  -e ENABLE_REDIS=true \
  -e ADMIN_ACCOUNT="$ADMIN_EMAIL" \
  web php artisan xboard:install | tee /opt/xboard_install.log

log "Step 5/6: 启动 Xboard"
docker compose up -d
docker compose ps

# ---- 自动探测 Xboard 对外端口（用于 token-bridge upstream）----
# 常见情况是 7001；如果不是，会尝试从 docker port 里解析
UPSTREAM_PORT="${UPSTREAM_PORT:-}"

if [ -z "${UPSTREAM_PORT}" ]; then
  if ss -lntp | grep -q ':7001'; then
    UPSTREAM_PORT="7001"
  else
    WEB_CID="$(docker compose ps -q web 2>/dev/null || true)"
    if [ -n "$WEB_CID" ]; then
      # 依次尝试常见容器端口映射
      for cport in 7001 80 8080; do
        hp="$(docker port "$WEB_CID" "${cport}/tcp" 2>/dev/null | awk -F: 'NR==1{print $2}' || true)"
        if [ -n "$hp" ]; then UPSTREAM_PORT="$hp"; break; fi
      done
    fi
  fi
fi

# 最终兜底
UPSTREAM_PORT="${UPSTREAM_PORT:-7001}"

log "Step 5.1/6: 检查本机面板端口（期望监听：$UPSTREAM_PORT）"
ss -lntp | grep ":${UPSTREAM_PORT}" || true
curl -sS -I "http://127.0.0.1:${UPSTREAM_PORT}" | sed -n '1,10p' || true

log "Step 6/6: 配置 token-bridge（nginx :${BRIDGE_PORT} → 127.0.0.1:${UPSTREAM_PORT}）"
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default || true

cat >/etc/nginx/conf.d/xboard_token_bridge.conf <<NG
server {
  listen 0.0.0.0:${BRIDGE_PORT};
  server_name _;

  # 只允许节点机 + 本机自检
  allow ${NODE_IP};
  allow 127.0.0.1;
  allow ${PANEL_IP};
  deny all;

  location / {
    # token：优先 query token，其次 header Token
    set \$token \$arg_token;
    if (\$token = "") { set \$token \$http_token; }
    if (\$token = "") { return 400; }

    # 如果原请求没带 token=，就把 header Token 注入到 query
    if (\$arg_token = "") { set \$args "\${args}&token=\${token}"; }
    if (\$args ~ "^&")    { set \$args "token=\${token}"; }

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host 127.0.0.1;

    proxy_pass http://127.0.0.1:${UPSTREAM_PORT}\$uri?\$args;
  }
}
NG

nginx -t
systemctl enable --now nginx
systemctl restart nginx

ss -lntp | grep ":${BRIDGE_PORT}" || true

cat <<EOF

==================== ✅ 面板机完成 ====================

1) 面板临时访问（HTTP）：
   http://${PANEL_IP}:${UPSTREAM_PORT}

2) token-bridge（给节点机用）：
   http://${PANEL_IP}:${BRIDGE_PORT}

3) 安装输出（后台路径/管理员信息）：
   /opt/xboard_install.log

【你必须在云防火墙/安全组放行】
- ${BRIDGE_PORT}/tcp：只允许 ${NODE_IP}
- ${UPSTREAM_PORT}/tcp：建议只允许你自己的公网 IP（或后续你再做域名+443反代）

【自检】（拿到面板 ApiKey 后再测，header 必须是 Token:xxx）：
  KEY="你的ApiKey"
  curl -sS -i -H "Token: \$KEY" "http://127.0.0.1:${BRIDGE_PORT}/api/v1/server/UniProxy/user?node_id=1&node_type=vless" | sed -n '1,15p'

========================================================
EOF
