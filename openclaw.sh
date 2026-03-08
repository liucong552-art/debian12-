#!/usr/bin/env bash
set -Eeuo pipefail

# =========================
# 可修改参数
# =========================
DOMAIN="${DOMAIN:-hy2.liucna.com}"
EMAIL="${EMAIL:-admin@liucna.com}"              # certbot 用，改成你常用邮箱更好
OPENCLAW_PORT="${OPENCLAW_PORT:-18789}"
OPENCLAW_CONFIG_DIR="${OPENCLAW_CONFIG_DIR:-/root/.openclaw}"
OPENCLAW_CONFIG_FILE="${OPENCLAW_CONFIG_FILE:-/root/.openclaw/openclaw.json}"
OPENCLAW_SERVICE_NAME="${OPENCLAW_SERVICE_NAME:-openclaw-gateway}"
BASIC_AUTH_USER="${BASIC_AUTH_USER:-admin}"
BASIC_AUTH_PASS="${BASIC_AUTH_PASS:-}"
OPENCLAW_TOKEN="${OPENCLAW_TOKEN:-}"
OPENCLAW_BIN="${OPENCLAW_BIN:-}"

# =========================
# 前置检查
# =========================
if [[ "$(id -u)" -ne 0 ]]; then
  echo "请使用 root 执行"
  exit 1
fi

if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  if [[ "${ID:-}" != "debian" || "${VERSION_ID:-}" != "12" ]]; then
    echo "当前系统不是 Debian 12"
    exit 1
  fi
else
  echo "无法识别系统版本"
  exit 1
fi

if [[ -z "${OPENCLAW_TOKEN}" ]]; then
  OPENCLAW_TOKEN="$(openssl rand -hex 32)"
fi

if [[ -z "${BASIC_AUTH_PASS}" ]]; then
  BASIC_AUTH_PASS="$(openssl rand -base64 24 | tr -d '\n' | tr '/+' 'AB')"
fi

# =========================
# 安装依赖
# =========================
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y \
  curl ca-certificates git jq openssl lsof \
  nginx certbot python3-certbot-nginx apache2-utils

# =========================
# 安装 OpenClaw
# 官方安装器 + 非交互
# =========================
curl -fsSL --proto '=https' --tlsv1.2 https://openclaw.ai/install.sh | bash -s -- --no-onboard

if [[ -z "${OPENCLAW_BIN}" ]]; then
  OPENCLAW_BIN="$(command -v openclaw || true)"
fi

if [[ -z "${OPENCLAW_BIN}" || ! -x "${OPENCLAW_BIN}" ]]; then
  echo "未找到 openclaw 命令，请检查安装日志"
  exit 1
fi

# =========================
# 写 OpenClaw 配置
# 仅监听 loopback，避免直接暴露
# =========================
mkdir -p "${OPENCLAW_CONFIG_DIR}"
chmod 700 "${OPENCLAW_CONFIG_DIR}"

cat > "${OPENCLAW_CONFIG_FILE}" <<EOF
{
  gateway: {
    mode: "local",
    port: ${OPENCLAW_PORT},
    bind: "loopback",
    auth: {
      mode: "token",
      token: "${OPENCLAW_TOKEN}"
    }
  },
  agents: {
    defaults: {
      workspace: "~/.openclaw/workspace"
    }
  }
}
EOF

chmod 600 "${OPENCLAW_CONFIG_FILE}"

# =========================
# systemd 服务
# =========================
cat > "/etc/systemd/system/${OPENCLAW_SERVICE_NAME}.service" <<EOF
[Unit]
Description=OpenClaw Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
Environment=HOME=/root
ExecStart=${OPENCLAW_BIN} gateway --port ${OPENCLAW_PORT}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${OPENCLAW_SERVICE_NAME}"

sleep 3
if ! systemctl is-active --quiet "${OPENCLAW_SERVICE_NAME}"; then
  echo "OpenClaw 服务启动失败"
  journalctl -u "${OPENCLAW_SERVICE_NAME}" -n 100 --no-pager || true
  exit 1
fi

# =========================
# Nginx Basic Auth
# =========================
htpasswd -bc /etc/nginx/.htpasswd "${BASIC_AUTH_USER}" "${BASIC_AUTH_PASS}"

# =========================
# Nginx 站点配置
# 先放 HTTP，等 certbot 自动改 HTTPS
# =========================
cat > /etc/nginx/sites-available/openclaw.conf <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    client_max_body_size 50m;

    location / {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/.htpasswd;

        proxy_pass http://127.0.0.1:${OPENCLAW_PORT};
        proxy_http_version 1.1;

        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_read_timeout 3600;
        proxy_send_timeout 3600;
    }
}
EOF

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/openclaw.conf /etc/nginx/sites-enabled/openclaw.conf

nginx -t
systemctl enable nginx
systemctl restart nginx

# =========================
# 防火墙（如果系统装了 ufw）
# =========================
if command -v ufw >/dev/null 2>&1; then
  ufw allow 80/tcp || true
  ufw allow 443/tcp || true
fi

# =========================
# 申请 HTTPS 证书
# 注意：若 Cloudflare 开了橙云代理，HTTP 验证可能失败
# 建议先切 DNS only 再跑这步
# =========================
certbot --nginx --non-interactive --agree-tos -m "${EMAIL}" -d "${DOMAIN}" --redirect

systemctl reload nginx

# =========================
# 输出结果
# =========================
echo
echo "================ 安装完成 ================"
echo "域名: https://${DOMAIN}/"
echo "OpenClaw 本地地址: http://127.0.0.1:${OPENCLAW_PORT}/"
echo
echo "Nginx Basic Auth 用户名: ${BASIC_AUTH_USER}"
echo "Nginx Basic Auth 密码:   ${BASIC_AUTH_PASS}"
echo
echo "OpenClaw Token:"
echo "${OPENCLAW_TOKEN}"
echo
echo "首次访问建议使用："
echo "https://${DOMAIN}/?token=${OPENCLAW_TOKEN}"
echo
echo "常用命令："
echo "systemctl status ${OPENCLAW_SERVICE_NAME}"
echo "journalctl -u ${OPENCLAW_SERVICE_NAME} -f"
echo "nginx -t && systemctl reload nginx"
