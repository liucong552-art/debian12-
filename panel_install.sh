#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

log(){ echo -e "\n[+] $*\n"; }
die(){ echo -e "\n[x] $*\n" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行"

[ -n "${ADMIN_EMAIL:-}" ] || die "缺少 ADMIN_EMAIL"
[ -n "${TUNNEL_TOKEN:-}" ] || die "缺少 TUNNEL_TOKEN"

PANEL_DOMAIN="${PANEL_DOMAIN:-panel.liucna.com}"
API_DOMAIN="${API_DOMAIN:-api.liucna.com}"
PANEL_PORT="${PANEL_PORT:-7001}"
BRIDGE_PORT="${BRIDGE_PORT:-7002}"
SSH_PORT="${SSH_PORT:-22}"

case "${TUNNEL_TOKEN}" in
  eyJ*) ;;
  *) die "TUNNEL_TOKEN 看起来不合法（应为 eyJ 开头）" ;;
esac

export DEBIAN_FRONTEND=noninteractive

log "安装基础依赖"
apt-get update -y
apt-get install -y curl ca-certificates git unzip nginx nftables

log "安装 Docker"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | bash
fi
apt-get install -y docker-compose-plugin >/dev/null 2>&1 || true
systemctl enable --now docker

log "准备 Xboard 代码"
rm -rf /opt/Xboard
git clone -b compose --depth 1 https://github.com/cedar2025/Xboard /opt/Xboard
cd /opt/Xboard

docker compose pull || true

log "修复 Redis 挂载目录权限"
mkdir -p /opt/Xboard/.docker/.data/redis
find /opt/Xboard/.docker/.data/redis -mindepth 1 -exec rm -rf {} + || true
chown -R 999:999 /opt/Xboard/.docker/.data/redis
chmod 755 /opt/Xboard/.docker/.data
chmod 755 /opt/Xboard/.docker/.data/redis

log "先启动 Redis"
docker compose up -d redis

log "等待 Redis socket 就绪"
ok=0
for i in $(seq 1 60); do
  if docker compose ps redis | grep -q "Up"; then
    if docker compose exec -T redis sh -lc 'test -S /data/redis.sock || test -S /run/redis-socket/redis.sock || redis-cli ping >/dev/null 2>&1'; then
      ok=1
      break
    fi
  fi
  sleep 2
done

if [ "${ok}" != "1" ]; then
  docker compose logs redis --tail=200 || true
  die "Redis 未成功就绪"
fi

log "执行 Xboard 安装（SQLite + Docker Redis）"
docker compose run --rm \
  -e ENABLE_SQLITE=true \
  -e ENABLE_REDIS=true \
  -e ADMIN_ACCOUNT="${ADMIN_EMAIL}" \
  web php artisan xboard:install | tee /opt/xboard_install.log

log "启动 Xboard 全部服务"
docker compose up -d

ids="$(docker compose ps -q)"
[ -n "${ids}" ] || die "Xboard 容器没有成功启动"
docker update --restart unless-stopped ${ids} >/dev/null

log "写入 Xboard 开机自启 systemd 单元"
cat >/etc/systemd/system/xboard-compose.service <<'EOF2'
[Unit]
Description=Xboard Compose Stack
After=network-online.target docker.service
Wants=network-online.target docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/Xboard
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose stop
ExecReload=/usr/bin/docker compose up -d

[Install]
WantedBy=multi-user.target
EOF2

systemctl daemon-reload
systemctl enable --now xboard-compose

log "写入 token-bridge（127.0.0.1:${BRIDGE_PORT} -> 127.0.0.1:${PANEL_PORT}）"
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default || true

cat >/etc/nginx/conf.d/xboard_token_bridge.conf <<EOF2
server {
  listen 127.0.0.1:${BRIDGE_PORT};
  server_name _;

  location / {
    set \$token \$arg_token;
    if (\$token = "") { set \$token \$http_token; }
    if (\$token = "") { return 400; }

    if (\$arg_token = "") { set \$args "\${args}&token=\${token}"; }
    if (\$args ~ "^&")    { set \$args "token=\${token}"; }

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host 127.0.0.1;

    proxy_pass http://127.0.0.1:${PANEL_PORT}\$uri?\$args;
  }
}
EOF2

nginx -t
systemctl enable --now nginx
systemctl restart nginx

log "安装 cloudflared"
mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" > /etc/apt/sources.list.d/cloudflared.list
apt-get update -y
apt-get install -y cloudflared

log "安装/更新 Tunnel service"
systemctl stop cloudflared >/dev/null 2>&1 || true
cloudflared service uninstall >/dev/null 2>&1 || true
cloudflared service install "${TUNNEL_TOKEN}"
systemctl daemon-reload
systemctl enable --now cloudflared

log "配置 nftables（仅保留 SSH 入站）"
cat >/etc/nftables.conf <<EOF2
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0;
    policy drop;

    iif "lo" accept
    ct state established,related accept

    tcp dport ${SSH_PORT} accept
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept
  }

  chain forward {
    type filter hook forward priority 0;
    policy drop;
  }

  chain output {
    type filter hook output priority 0;
    policy accept;
  }
}
EOF2

systemctl enable --now nftables
nft -f /etc/nftables.conf

log "自检本地服务"
curl -fsS -I "http://127.0.0.1:${PANEL_PORT}" >/dev/null || die "本地 Xboard ${PANEL_PORT} 不通"

bridge_code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${BRIDGE_PORT}/" || true)"
case "${bridge_code}" in
  200|301|302|400|403) ;;
  *) die "本地 bridge ${BRIDGE_PORT} 异常，HTTP=${bridge_code}" ;;
esac

echo
echo "======================================================"
echo "面板域名: https://${PANEL_DOMAIN}"
echo "节点 API 域名: https://${API_DOMAIN}"
echo "本地面板: http://127.0.0.1:${PANEL_PORT}"
echo "本地 bridge: http://127.0.0.1:${BRIDGE_PORT}"
echo "Xboard 目录: /opt/Xboard"
echo "安装日志: /opt/xboard_install.log"
echo "面板状态: cd /opt/Xboard && docker compose ps"
echo "Tunnel 状态: systemctl status cloudflared --no-pager"
echo "======================================================"
