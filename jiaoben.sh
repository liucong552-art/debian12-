#!/usr/bin/env bash
set -euo pipefail

log(){ echo -e "\033[1;32m[+]\033[0m $*"; }
die(){ echo -e "\033[1;31m[x]\033[0m $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行"
export DEBIAN_FRONTEND=noninteractive

# 固定你的节点IP：只允许它访问 7002
ALLOW_IP="14.137.255.86"
XBOARD_UPSTREAM="http://127.0.0.1:7001"

# 1) 确认 xboard 在本机 7001
if ! ss -lntp | grep -qE '127\.0\.0\.1:7001|:7001'; then
  die "检测不到本机 127.0.0.1:7001（xboard 未监听）。请先确保面板容器/服务把 7001 监听在本机。"
fi

log "安装 nginx..."
apt-get update -y
apt-get install -y nginx

# 2) 删除默认站点（避免 listen 80 冲突）
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default || true

# 3) 写 token-bridge：0.0.0.0:7002 -> 127.0.0.1:7001
cat >/etc/nginx/conf.d/xboard_token_bridge.conf <<NG
server {
  listen 0.0.0.0:7002;
  server_name _;

  location / {
    # 只允许节点机访问
    allow ${ALLOW_IP};
    deny all;

    # token：优先 query token，其次 Header Token
    set \$token \$arg_token;
    if (\$token = "") { set \$token \$http_token; }
    if (\$token = "") { return 400; }

    # 如果原请求没带 token=，就把 header Token 注入到 query 里
    if (\$arg_token = "") { set \$args "\${args}&token=\${token}"; }
    # 如果原来没有任何 args，会变成 "&token=xxx"，把开头的 & 去掉
    if (\$args ~ "^&")    { set \$args "token=\${token}"; }

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host 127.0.0.1;

    proxy_pass ${XBOARD_UPSTREAM}\$uri?\$args;
  }
}
NG

nginx -t
systemctl enable --now nginx
systemctl restart nginx

ss -lntp | grep ':7002' >/dev/null || die "7002 未监听，nginx 启动失败"

log "DONE：面板机 token-bridge 已启用"
echo "面板机请放行端口 7002（只放行 ${ALLOW_IP} 更安全）"
echo "自检（在面板机本机跑，Token 用你的 ApiKey）："
echo "  curl -sS -H 'Token: ***' 'http://127.0.0.1:7002/api/v1/server/UniProxy/config?node_id=1&node_type=vless' | jq ."
echo "  curl -sS -H 'Token: ***' 'http://127.0.0.1:7002/api/v1/server/UniProxy/user?node_id=1&node_type=vless' | jq ."
