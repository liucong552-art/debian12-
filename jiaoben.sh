#!/usr/bin/env bash
set -euo pipefail

# ====== 可改参数（也可运行时提示输入）======
PANEL_UPSTREAM_DEFAULT="127.0.0.1:7001"
LISTEN_PORT_DEFAULT="7002"
ALLOW_NODE_IP_DEFAULT="14.137.255.86"

need_root() { [ "$(id -u)" -eq 0 ] || { echo "[x] 请用 root 运行"; exit 1; }; }
tcp_check() {
  local host="$1" port="$2"
  timeout 1 bash -c "cat < /dev/null > /dev/tcp/${host}/${port}" >/dev/null 2>&1
}

need_root

echo "== 面板机 token-bridge 安装 =="
read -rp "上游 xboard 地址 (默认 ${PANEL_UPSTREAM_DEFAULT}) : " PANEL_UPSTREAM || true
PANEL_UPSTREAM="${PANEL_UPSTREAM:-$PANEL_UPSTREAM_DEFAULT}"

read -rp "token-bridge 监听端口 (默认 ${LISTEN_PORT_DEFAULT}) : " LISTEN_PORT || true
LISTEN_PORT="${LISTEN_PORT:-$LISTEN_PORT_DEFAULT}"

read -rp "允许访问的节点机 IP (默认 ${ALLOW_NODE_IP_DEFAULT}) : " ALLOW_NODE_IP || true
ALLOW_NODE_IP="${ALLOW_NODE_IP:-$ALLOW_NODE_IP_DEFAULT}"

UP_HOST="${PANEL_UPSTREAM%:*}"
UP_PORT="${PANEL_UPSTREAM#*:}"

echo "[+] 检查上游是否监听：${UP_HOST}:${UP_PORT}"
if ! tcp_check "$UP_HOST" "$UP_PORT"; then
  echo "[x] 检测不到 ${UP_HOST}:${UP_PORT}（xboard 未监听/未映射）。请先保证 xboard 在本机可通过该地址访问。"
  exit 1
fi

echo "[+] 安装 nginx..."
apt-get update -y
apt-get install -y nginx curl ca-certificates

# 删除默认站点，避免 nginx 试图占用 80
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default || true

echo "[+] 写入 /etc/nginx/conf.d/xboard_token_bridge.conf"
cat >/etc/nginx/conf.d/xboard_token_bridge.conf <<NG
server {
  listen 0.0.0.0:${LISTEN_PORT};
  listen [::]:${LISTEN_PORT};
  server_name _;

  # 只允许节点机 + 本机自检（更安全：你也可以删掉 allow 127.0.0.1）
  allow ${ALLOW_NODE_IP};
  allow 127.0.0.1;
  deny all;

  location / {
    # token 优先 query，其次 Token header
    set \$token \$arg_token;
    if (\$token = "") { set \$token \$http_token; }
    if (\$token = "") { return 400; }

    set \$sep "";
    if (\$args != "") { set \$sep "&"; }

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host 127.0.0.1;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

    # 关键：把 token 拼到 query 再转发到上游
    proxy_pass http://${PANEL_UPSTREAM}\$uri?\$args\$sep"token="\$token;
  }
}
NG

nginx -t
systemctl enable --now nginx
systemctl restart nginx

echo
echo "[+] DONE：面板机 token-bridge 已启用"
echo "面板机请放行端口 ${LISTEN_PORT}（只放行 ${ALLOW_NODE_IP} 更安全）"
echo
echo "自检（注意 header 写法必须是 Token:xxx）："
echo "  curl -sS -H 'Token: <ApiKey>' 'http://127.0.0.1:${LISTEN_PORT}/api/v1/server/UniProxy/config?node_id=1&node_type=vless' | jq ."
echo "  curl -sS -H 'Token: <ApiKey>' 'http://127.0.0.1:${LISTEN_PORT}/api/v1/server/UniProxy/user?node_id=1&node_type=vless' | jq ."
