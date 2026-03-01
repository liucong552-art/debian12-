#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$' \n\t'

log(){ echo -e "\n[+] $*\n"; }
die(){ echo -e "\n[x] $*\n" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行"

# ====== 运行时必须传入（你只改这3个）======
ADMIN_EMAIL="${ADMIN_EMAIL:-}"
PANEL_IP="${PANEL_IP:-}"
NODE_IP="${NODE_IP:-}"
# ==========================================
BRIDGE_PORT="${BRIDGE_PORT:-7002}"
UPSTREAM_PORT="${UPSTREAM_PORT:-7001}"
XBOARD_DIR="${XBOARD_DIR:-/opt/Xboard}"

[ -n "$ADMIN_EMAIL" ] || die "缺少 ADMIN_EMAIL（管理员邮箱）"
[ -n "$PANEL_IP" ] || die "缺少 PANEL_IP（面板机公网IP）"
[ -n "$NODE_IP" ] || die "缺少 NODE_IP（节点机公网IP）"

log "1) 安装依赖 + nginx"
apt-get update -y
apt-get install -y curl ca-certificates git unzip nginx

log "2) 安装 Docker + compose plugin"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | bash
fi
apt-get install -y docker-compose-plugin >/dev/null 2>&1 || true
systemctl enable --now docker
docker compose version >/dev/null 2>&1 || die "docker compose 不可用（请确认 docker-compose-plugin）"

log "3) 拉取 Xboard compose 分支"
cd /opt
rm -rf "$XBOARD_DIR"
git clone -b compose --depth 1 https://github.com/cedar2025/Xboard "$XBOARD_DIR"
cd "$XBOARD_DIR"

log "4) 安装 Xboard（全新：SQLite+Redis），写入 /opt/xboard_install.log"
docker compose run --rm \
  -e ENABLE_SQLITE=true \
  -e ENABLE_REDIS=true \
  -e ADMIN_ACCOUNT="$ADMIN_EMAIL" \
  web php artisan xboard:install | tee /opt/xboard_install.log

log "5) 启动 Xboard"
docker compose up -d
docker compose ps

log "6) 检查 7001"
ss -lntp | grep ":${UPSTREAM_PORT}" || true
curl -sS -I "http://127.0.0.1:${UPSTREAM_PORT}" | sed -n '1,10p' || true

log "7) 配 token-bridge：${BRIDGE_PORT} -> 127.0.0.1:${UPSTREAM_PORT}"
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default || true

cat >/etc/nginx/conf.d/xboard_token_bridge.conf <<NG
server {
  listen 0.0.0.0:${BRIDGE_PORT};
  server_name _;

  allow ${NODE_IP};
  allow 127.0.0.1;
  allow ${PANEL_IP};
  deny all;

  location / {
    set \$token \$arg_token;
    if (\$token = "") { set \$token \$http_token; }
    if (\$token = "") { return 400; }

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

面板临时访问：
  http://${PANEL_IP}:${UPSTREAM_PORT}

token-bridge（给节点机用）：
  http://${PANEL_IP}:${BRIDGE_PORT}

安装输出（后台路径/管理员信息）：
  /opt/xboard_install.log

【你必须在云安全组放行】
- ${BRIDGE_PORT}/tcp：只允许 ${NODE_IP}
- ${UPSTREAM_PORT}/tcp：建议只允许你自己的公网IP（或后续做域名+443）

========================================================
EOF
