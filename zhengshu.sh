#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$' \n\t'

DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"

[ "$(id -u)" -eq 0 ] || { echo "[x] 请用 root"; exit 1; }
[ -n "$DOMAIN" ] || { echo "[x] 缺少 DOMAIN"; exit 1; }
[ -n "$EMAIL" ] || { echo "[x] 缺少 EMAIL"; exit 1; }

echo "[1/7] 安装依赖（nginx 已有也没关系）"
apt-get update -y
apt-get install -y nginx curl ca-certificates openssl cron
systemctl enable --now cron

echo "[2/7] 先关闭坏掉的 443 配置（避免缺证书导致 nginx 起不来）"
if [ -f /etc/nginx/conf.d/xboard_https.conf ]; then
  mv -f /etc/nginx/conf.d/xboard_https.conf /etc/nginx/conf.d/xboard_https.conf.off
fi

echo "[3/7] 配 80：acme 验证目录 + 其余跳转 https"
mkdir -p /var/www/acme
cat >/etc/nginx/conf.d/xboard_http.conf <<EOF
server {
  listen 80;
  server_name ${DOMAIN};

  location ^~ /.well-known/acme-challenge/ {
    root /var/www/acme;
    default_type "text/plain";
  }

  location / { return 301 https://\$host\$request_uri; }
}
EOF
nginx -t
systemctl restart nginx

echo "[4/7] 安装 acme.sh"
curl https://get.acme.sh | sh -s email="$EMAIL"
source ~/.bashrc

echo "[5/7] 自检：80 验证路径必须 200（不能 301）"
echo ok >/var/www/acme/.well-known/acme-challenge/ping.txt
curl -sS -i "http://${DOMAIN}/.well-known/acme-challenge/ping.txt" | sed -n '1,5p'

echo "[6/7] 签发证书（webroot）"
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
~/.acme.sh/acme.sh --issue -d "$DOMAIN" -w /var/www/acme --keylength 2048

echo "[7/7] 安装证书 + 写 443 反代到 7001"
mkdir -p /etc/ssl/private /etc/ssl/certs
~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
  --key-file       /etc/ssl/private/${DOMAIN}.key \
  --fullchain-file /etc/ssl/certs/${DOMAIN}.fullchain.pem \
  --reloadcmd "systemctl reload nginx"

cat >/etc/nginx/conf.d/xboard_https.conf <<EOF
server {
  listen 443 ssl http2;
  server_name ${DOMAIN};

  ssl_certificate     /etc/ssl/certs/${DOMAIN}.fullchain.pem;
  ssl_certificate_key /etc/ssl/private/${DOMAIN}.key;

  location / {
    proxy_pass http://127.0.0.1:7001;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
  }
}
EOF

nginx -t
systemctl reload nginx

echo "==== 端口检查 ===="
ss -lntp | egrep ':80|:443|:7001|:7002' || true

echo "==== 访问检查 ===="
curl -I "http://${DOMAIN}" | sed -n '1,5p'
curl -kI "https://${DOMAIN}" | sed -n '1,8p'
