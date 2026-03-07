#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$' \n\t'

DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
BACKEND="${BACKEND:-127.0.0.1:7001}"
ACME_ROOT="${ACME_ROOT:-/var/www/acme}"
NGINX_HTTP_CONF="${NGINX_HTTP_CONF:-/etc/nginx/conf.d/xboard_http.conf}"
NGINX_HTTPS_CONF="${NGINX_HTTPS_CONF:-/etc/nginx/conf.d/xboard_https.conf}"

log()  { echo -e "[+] $*"; }
warn() { echo -e "[!] $*"; }
err()  { echo -e "[x] $*" >&2; exit 1; }

require_root() {
  [ "$(id -u)" -eq 0 ] || err "请用 root 运行"
}

check_args() {
  [ -n "$DOMAIN" ] || err "缺少 DOMAIN"
  [ -n "$EMAIL" ] || err "缺少 EMAIL"
}

install_deps() {
  log "1/8 安装依赖"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y nginx curl ca-certificates openssl cron
  systemctl enable --now cron
}

prepare_dirs() {
  log "2/8 准备 ACME 目录"
  mkdir -p "${ACME_ROOT}/.well-known/acme-challenge"
  chmod 755 "${ACME_ROOT}" "${ACME_ROOT}/.well-known" "${ACME_ROOT}/.well-known/acme-challenge"
}

disable_broken_https_conf() {
  log "3/8 临时关闭旧 443 配置（避免缺证书时 nginx 起不来）"
  if [ -f "$NGINX_HTTPS_CONF" ]; then
    mv -f "$NGINX_HTTPS_CONF" "${NGINX_HTTPS_CONF}.off"
  fi
}

write_http_conf() {
  log "4/8 写入 80 站点：ACME 验证 + 其余跳转 HTTPS"
  cat >"$NGINX_HTTP_CONF" <<EOF
server {
  listen 80;
  listen [::]:80;
  server_name ${DOMAIN};

  location ^~ /.well-known/acme-challenge/ {
    root ${ACME_ROOT};
    default_type text/plain;
    try_files \$uri =404;
  }

  location / {
    return 301 https://\$host\$request_uri;
  }
}
EOF

  nginx -t
  systemctl restart nginx
}

install_acme() {
  log "5/8 安装 acme.sh"
  curl -fsSL https://get.acme.sh | sh -s email="$EMAIL"

  ACME_SH="$HOME/.acme.sh/acme.sh"
  [ -x "$ACME_SH" ] || err "acme.sh 安装失败"
}

self_check_http() {
  log "6/8 自检：80 验证路径必须返回 200"

  local ping_file="${ACME_ROOT}/.well-known/acme-challenge/ping.txt"
  echo "ok" > "$ping_file"

  local body_file http_code
  body_file="$(mktemp)"

  http_code="$(curl -sS -o "$body_file" -w '%{http_code}' "http://${DOMAIN}/.well-known/acme-challenge/ping.txt" || true)"

  echo "---- 自检返回内容 ----"
  cat "$body_file" || true
  echo
  echo "HTTP_CODE=${http_code}"
  echo "---------------------"

  rm -f "$body_file"

  [ "$http_code" = "200" ] || err "ACME 自检失败：必须返回 200。请检查域名解析、80 端口、云防火墙/安全组。"
}

issue_cert() {
  log "7/8 签发证书"
  ACME_SH="$HOME/.acme.sh/acme.sh"

  "$ACME_SH" --set-default-ca --server letsencrypt
  "$ACME_SH" --issue -d "$DOMAIN" -w "$ACME_ROOT" --keylength 2048
}

install_cert_and_https() {
  log "8/8 安装证书并写入 443 反代"

  local key_file="/etc/ssl/private/${DOMAIN}.key"
  local fullchain_file="/etc/ssl/certs/${DOMAIN}.fullchain.pem"

  mkdir -p /etc/ssl/private /etc/ssl/certs

  ACME_SH="$HOME/.acme.sh/acme.sh"
  "$ACME_SH" --install-cert -d "$DOMAIN" \
    --key-file "$key_file" \
    --fullchain-file "$fullchain_file" \
    --reloadcmd "systemctl reload nginx"

  cat >"$NGINX_HTTPS_CONF" <<EOF
server {
  listen 443 ssl http2;
  listen [::]:443 ssl http2;
  server_name ${DOMAIN};

  ssl_certificate     ${fullchain_file};
  ssl_certificate_key ${key_file};

  ssl_session_timeout 1d;
  ssl_session_cache shared:SSL:10m;
  ssl_session_tickets off;

  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_prefer_server_ciphers off;

  location / {
    proxy_pass http://${BACKEND};
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$connection_upgrade;
  }
}

map \$http_upgrade \$connection_upgrade {
  default upgrade;
  ''      close;
}
EOF

  nginx -t
  systemctl reload nginx
}

print_status() {
  echo
  echo "==== 端口检查 ===="
  ss -lntp | egrep ':80|:443|:7001|:7002' || true

  echo
  echo "==== HTTP 检查 ===="
  curl -I "http://${DOMAIN}" | sed -n '1,8p' || true

  echo
  echo "==== HTTPS 检查 ===="
  curl -kI "https://${DOMAIN}" | sed -n '1,12p' || true

  echo
  echo "✅ 完成"
  echo "域名: ${DOMAIN}"
  echo "邮箱: ${EMAIL}"
  echo "后端: ${BACKEND}"
  echo "证书:"
  echo "  /etc/ssl/private/${DOMAIN}.key"
  echo "  /etc/ssl/certs/${DOMAIN}.fullchain.pem"
}

main() {
  require_root
  check_args
  install_deps
  prepare_dirs
  disable_broken_https_conf
  write_http_conf
  install_acme
  self_check_http
  issue_cert
  install_cert_and_https
  print_status
}

main "$@"
