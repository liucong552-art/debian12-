#!/usr/bin/env bash
set -Eeuo pipefail

ORIGIN_IP="${ORIGIN_IP:?ORIGIN_IP is required}"
ADMIN_ALLOW_CIDR="${ADMIN_ALLOW_CIDR:-0.0.0.0/0}"
SSH_PORT="${SSH_PORT:-22}"

log(){ printf '[edge] %s\n' "$*"; }
fail(){ printf '[edge][ERR] %s\n' "$*" >&2; exit 1; }
need_root(){ [ "$(id -u)" -eq 0 ] || fail 'run as root: sudo -E bash edge_install.sh'; }

install_base(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y nginx libnginx-mod-stream ufw rsyslog logrotate curl ca-certificates
  systemctl enable --now rsyslog
}

configure_nginx(){
  log 'configuring nginx stream proxy for tcp/udp 443'
  rm -f /etc/nginx/sites-enabled/default
  mkdir -p /etc/nginx/stream-conf.d

  if ! grep -q 'include /etc/nginx/stream-conf.d/\*.conf;' /etc/nginx/nginx.conf; then
    cat >>/etc/nginx/nginx.conf <<'EOF'

stream {
    log_format stream_basic '$remote_addr [$time_local] $protocol $status '
                            '$bytes_sent $bytes_received $session_time "$upstream_addr"';
    access_log /var/log/nginx/stream_access.log stream_basic;
    error_log  /var/log/nginx/stream_error.log info;

    include /etc/nginx/stream-conf.d/*.conf;
}
EOF
  fi

  cat >/etc/nginx/stream-conf.d/hiddify_edge.conf <<EOF
upstream hiddify_tcp_443 {
    server ${ORIGIN_IP}:443;
}

upstream hiddify_udp_443 {
    server ${ORIGIN_IP}:443;
}

server {
    listen 443 reuseport so_keepalive=on;
    proxy_connect_timeout 5s;
    proxy_timeout 10m;
    proxy_pass hiddify_tcp_443;
}

server {
    listen 443 udp reuseport;
    proxy_timeout 10m;
    proxy_pass hiddify_udp_443;
}
EOF

  nginx -t
  systemctl enable --now nginx
  systemctl reload nginx
}

configure_sysctl(){
  log 'tuning kernel'
  cat >/etc/sysctl.d/99-hiddify-edge.conf <<'EOF'
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 16384
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.ipv4.ip_local_port_range = 10240 65000
EOF
  sysctl --system >/dev/null
}

configure_firewall(){
  log 'configuring ufw'
  ufw --force disable || true
  yes | ufw reset

  ufw default deny incoming
  ufw default allow outgoing

  ufw allow from "${ADMIN_ALLOW_CIDR}" to any port "${SSH_PORT}" proto tcp comment 'admin-ssh'
  ufw allow 443/tcp comment 'reality-tcp-443'
  ufw allow 443/udp comment 'hy2-udp-443'

  ufw --force enable
  systemctl enable ufw
}

install_helpers(){
  cat >/usr/local/bin/hiddify-edge-selfcheck <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

echo "== nginx test =="
nginx -t || true

echo
echo "== service status =="
systemctl --no-pager --full status nginx | sed -n '1,30p' || true

echo
echo "== listening sockets =="
ss -lntup | egrep '(:443\b|:22\b)' || true

echo
echo "== firewall =="
ufw status numbered || true

echo
echo "== nginx recent logs =="
journalctl -u nginx -n 80 --no-pager || true

echo
echo "== stream access log tail =="
tail -n 50 /var/log/nginx/stream_access.log 2>/dev/null || true

echo
echo "== stream error log tail =="
tail -n 50 /var/log/nginx/stream_error.log 2>/dev/null || true
EOF
  chmod +x /usr/local/bin/hiddify-edge-selfcheck
}

print_next(){
  cat <<EOF

[edge] done
[edge] tcp/443  -> ${ORIGIN_IP}:443
[edge] udp/443  -> ${ORIGIN_IP}:443

[edge] useful commands:
  hiddify-edge-selfcheck
  systemctl status nginx --no-pager
  journalctl -u nginx -n 100 --no-pager
  tail -n 50 /var/log/nginx/stream_access.log
  tail -n 50 /var/log/nginx/stream_error.log
  ufw status numbered

EOF
}

main(){
  need_root
  install_base
  configure_nginx
  configure_sysctl
  configure_firewall
  install_helpers
  print_next
}

main "$@"
