#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

die(){ echo -e "\n[x] $*\n" >&2; exit 1; }
log(){ echo -e "\n[+] $*\n"; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行"

[ -n "${ADMIN_EMAIL:-}" ] || die "缺少 ADMIN_EMAIL"
[ -n "${PANEL_DOMAIN:-}" ] || die "缺少 PANEL_DOMAIN"
[ -n "${API_DOMAIN:-}" ] || die "缺少 API_DOMAIN"
[ -n "${TUNNEL_TOKEN:-}" ] || die "缺少 TUNNEL_TOKEN"

if [ -z "${SSH_PORT:-}" ]; then
  SSH_PORT="22"
fi

case "${TUNNEL_TOKEN}" in
  eyJ*) ;;
  *) die "TUNNEL_TOKEN 看起来不是合法 token（应为 eyJ 开头的长字符串）" ;;
esac

export DEBIAN_FRONTEND=noninteractive

log "安装基础依赖"
apt-get update -y
apt-get install -y curl ca-certificates git unzip nftables

log "安装 Docker"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | bash
fi
apt-get install -y docker-compose-plugin >/dev/null 2>&1 || true
systemctl enable --now docker

log "准备 Xboard 代码"
if [ -d /opt/Xboard/.git ]; then
  cd /opt/Xboard
  git fetch --depth 1 origin compose
  git checkout -f compose
  git reset --hard origin/compose
else
  rm -rf /opt/Xboard
  git clone -b compose --depth 1 https://github.com/cedar2025/Xboard /opt/Xboard
fi

cd /opt/Xboard
docker compose pull || true

if [ ! -f /opt/Xboard/.xboard_installed ]; then
  log "首次初始化 Xboard"
  docker compose run --rm \
    -e ENABLE_SQLITE=true \
    -e ENABLE_REDIS=false \
    -e ADMIN_ACCOUNT="${ADMIN_EMAIL}" \
    web php artisan xboard:install | tee /opt/xboard_install.log
  touch /opt/Xboard/.xboard_installed
else
  log "检测到已初始化，跳过 xboard:install"
fi

log "启动 Xboard"
docker compose up -d

ids="$(docker compose ps -q)"
[ -n "${ids}" ] || die "Xboard 容器没有成功启动"
docker update --restart unless-stopped ${ids} >/dev/null

log "写入 Xboard 开机自启 systemd 单元"
cat > /etc/systemd/system/xboard-compose.service <<'EOF'
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
EOF

systemctl daemon-reload
systemctl enable --now xboard-compose

log "安装 cloudflared"
mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" > /etc/apt/sources.list.d/cloudflared.list
apt-get update -y
apt-get install -y cloudflared

log "检查并写入 cloudflared service"
need_install=1
if [ -f /etc/systemd/system/cloudflared.service ]; then
  if grep -q -- "${TUNNEL_TOKEN}" /etc/systemd/system/cloudflared.service 2>/dev/null; then
    need_install=0
  fi
fi

if [ "${need_install}" = "1" ]; then
  log "安装/更新 Tunnel service"
  systemctl stop cloudflared >/dev/null 2>&1 || true
  cloudflared service uninstall >/dev/null 2>&1 || true
  cloudflared service install "${TUNNEL_TOKEN}"
fi

systemctl daemon-reload
systemctl enable --now cloudflared

log "配置 nftables，仅保留 SSH 入站"
cat > /etc/nftables.conf <<EOF
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
EOF

systemctl enable --now nftables
nft -f /etc/nftables.conf

log "等待本地 7001 可用"
ok=0
for _ in $(seq 1 60); do
  code="$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:7001 || true)"
  if [ "${code}" != "000" ]; then
    ok=1
    break
  fi
  sleep 2
done
[ "${ok}" = "1" ] || die "本地 http://127.0.0.1:7001 仍未就绪"

echo
echo "======================================================"
echo "面板地址: https://${PANEL_DOMAIN}"
echo "节点 API: https://${API_DOMAIN}"
echo "Xboard 目录: /opt/Xboard"
echo "安装日志: /opt/xboard_install.log"
echo "本机检测: curl -I http://127.0.0.1:7001"
echo "面板状态: cd /opt/Xboard && docker compose ps"
echo "Tunnel 状态: systemctl status cloudflared --no-pager"
echo "======================================================"
