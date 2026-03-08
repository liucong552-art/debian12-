ADMIN_EMAIL="你的管理员邮箱" \
PANEL_DOMAIN="panel.liucna.com" \
API_DOMAIN="api.liucna.com" \
TUNNEL_TOKEN="这里填 liucna-panel 这个 tunnel 的 token" \
SSH_PORT="22" \
bash -c '
set -Eeuo pipefail
IFS=$'"'"'\n\t'"'"'

die(){ echo -e "\n[x] $*\n" >&2; exit 1; }
log(){ echo -e "\n[+] $*\n"; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行"
[ -n "${ADMIN_EMAIL:-}" ] || die "缺少 ADMIN_EMAIL"
[ -n "${PANEL_DOMAIN:-}" ] || die "缺少 PANEL_DOMAIN"
[ -n "${API_DOMAIN:-}" ] || die "缺少 API_DOMAIN"
[ -n "${TUNNEL_TOKEN:-}" ] || die "缺少 TUNNEL_TOKEN"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl ca-certificates git unzip nftables

if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | bash
fi
apt-get install -y docker-compose-plugin >/dev/null 2>&1 || true
systemctl enable --now docker

rm -rf /opt/Xboard
git clone -b compose --depth 1 https://github.com/cedar2025/Xboard /opt/Xboard
cd /opt/Xboard

docker compose run --rm \
  -e ENABLE_SQLITE=true \
  -e ENABLE_REDIS=false \
  -e ADMIN_ACCOUNT="$ADMIN_EMAIL" \
  web php artisan xboard:install | tee /opt/xboard_install.log

docker compose up -d

mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared bookworm main" > /etc/apt/sources.list.d/cloudflared.list
apt-get update -y
apt-get install -y cloudflared

cloudflared service uninstall >/dev/null 2>&1 || true
cloudflared service install "$TUNNEL_TOKEN"
systemctl enable --now cloudflared

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

systemctl enable nftables
nft -f /etc/nftables.conf

echo
echo "======================================================"
echo "面板地址: https://${PANEL_DOMAIN}"
echo "节点 API: https://${API_DOMAIN}"
echo "Xboard 目录: /opt/Xboard"
echo "安装日志: /opt/xboard_install.log"
echo "查看面板状态: cd /opt/Xboard && docker compose ps"
echo "查看 Tunnel 状态: systemctl status cloudflared --no-pager"
echo "======================================================"
'
