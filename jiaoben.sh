sudo -i
NODE_IP="104.224.158.191" \
PANEL_IP="14.137.255.86" \
UPSTREAM="http://127.0.0.1:7001" \
PORT="7002" \
bash -s <<'SH'
set -Eeuo pipefail
IFS=$' \n\t'

: "${NODE_IP:?missing NODE_IP}"
: "${PANEL_IP:?missing PANEL_IP}"
: "${UPSTREAM:=http://127.0.0.1:7001}"
: "${PORT:=7002}"

log(){ echo "[+] $*"; }
die(){ echo "[x] $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo -i"

log "安装依赖..."
apt-get update -y
apt-get install -y nginx curl ca-certificates

log "删除默认站点（避免 nginx 抢 80）..."
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default || true

log "写入 token-bridge 配置..."
cat >/etc/nginx/conf.d/xboard_token_bridge.conf <<NG
server {
  listen 0.0.0.0:${PORT};
  server_name _;

  # 只允许节点机 + 本机自检（否则面板机本机 curl 会 403）
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
    # 如果原来没有任何 args，会变成 "&token=xxx"，把开头的 & 去掉
    if (\$args ~ "^&")    { set \$args "token=\${token}"; }

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host 127.0.0.1;

    proxy_pass ${UPSTREAM}\$uri?\$args;
  }
}
NG

nginx -t
systemctl enable --now nginx
systemctl restart nginx

log "验证监听端口："
ss -lntp | grep ":${PORT}" || true

cat <<EOF

[+] DONE：token-bridge 已启用
- 面板机请在云防火墙/安全组放行 ${PORT}/tcp：只允许 ${NODE_IP}
- 本机自检（header 必须是 Token:xxx）：

  KEY="你的ApiKey"
  curl -sS -i -H "Token: \$KEY" "http://127.0.0.1:${PORT}/api/v1/server/UniProxy/config?node_id=1&node_type=vless" | sed -n '1,15p'
  curl -sS -i -H "Token: \$KEY" "http://127.0.0.1:${PORT}/api/v1/server/UniProxy/user?node_id=1&node_type=vless"   | sed -n '1,15p'

EOF
SH
