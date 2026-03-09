#!/usr/bin/env bash
set -Eeuo pipefail

PANEL_DOMAIN="${PANEL_DOMAIN:?PANEL_DOMAIN is required}"
SUB_DOMAIN="${SUB_DOMAIN:-sub.example.com}"
EDGE_DOMAIN="${EDGE_DOMAIN:-edge.example.com}"
CF_TUNNEL_TOKEN="${CF_TUNNEL_TOKEN:?CF_TUNNEL_TOKEN is required}"
EDGE_ALLOW_IPS="${EDGE_ALLOW_IPS:?EDGE_ALLOW_IPS is required, comma separated}"
ADMIN_ALLOW_CIDR="${ADMIN_ALLOW_CIDR:-0.0.0.0/0}"
SSH_PORT="${SSH_PORT:-22}"
FORCE_DEBIAN="${FORCE_DEBIAN:-0}"
HIDDIFY_INSTALL_URL="${HIDDIFY_INSTALL_URL:-https://i.hiddify.com/release}"

log(){ printf '[panel] %s\n' "$*"; }
fail(){ printf '[panel][ERR] %s\n' "$*" >&2; exit 1; }
need_root(){ [ "$(id -u)" -eq 0 ] || fail 'run as root: sudo -E bash panel_install.sh'; }

trim(){
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

check_os(){
  . /etc/os-release
  case "${ID:-}" in
    ubuntu)
      [ "${VERSION_ID:-}" = "22.04" ] || fail "Hiddify panel official tested OS is Ubuntu 22.04. current=${ID:-}/${VERSION_ID:-}"
      ;;
    debian)
      [ "$FORCE_DEBIAN" = "1" ] || fail "Debian is not the official tested OS for Hiddify panel. Re-run with FORCE_DEBIAN=1 only if you accept unsupported deployment."
      ;;
    *)
      fail "unsupported OS: ${ID:-unknown}"
      ;;
  esac
}

install_base(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl ca-certificates gnupg jq ufw rsyslog logrotate lsb-release apt-transport-https
  systemctl enable --now rsyslog
}

install_hiddify(){
  if [ -d /opt/hiddify-manager ] || [ -d /opt/hiddify-config ]; then
    log 'Hiddify already exists, skip fresh install'
    return 0
  fi

  log "installing Hiddify from ${HIDDIFY_INSTALL_URL}"
  bash <(curl -fsSL "${HIDDIFY_INSTALL_URL}")
}

install_cloudflared(){
  log 'installing cloudflared'
  mkdir -p /usr/share/keyrings
  curl -fsSL https://pkg.cloudflare.com/cloudflare-public-v2.gpg \
    | tee /usr/share/keyrings/cloudflare-public-v2.gpg >/dev/null

  cat >/etc/apt/sources.list.d/cloudflared.list <<'EOF'
deb [signed-by=/usr/share/keyrings/cloudflare-public-v2.gpg] https://pkg.cloudflare.com/cloudflared any main
EOF

  apt-get update -y
  apt-get install -y cloudflared

  cloudflared service uninstall >/dev/null 2>&1 || true
  cloudflared service install "${CF_TUNNEL_TOKEN}"
  systemctl enable --now cloudflared
}

configure_firewall(){
  log 'configuring ufw'
  mkdir -p /etc/hiddify
  printf '%s\n' "${EDGE_ALLOW_IPS}" | tr ',' '\n' | sed '/^[[:space:]]*$/d' > /etc/hiddify/edge_allow.list

  ufw --force disable || true
  yes | ufw reset

  ufw default deny incoming
  ufw default allow outgoing

  ufw allow from "${ADMIN_ALLOW_CIDR}" to any port "${SSH_PORT}" proto tcp comment 'admin-ssh'

  while IFS= read -r raw; do
    ip="$(trim "$raw")"
    [ -n "$ip" ] || continue
    ufw allow from "$ip" to any port 443 proto tcp comment 'edge-to-origin-443-tcp'
    ufw allow from "$ip" to any port 443 proto udp comment 'edge-to-origin-443-udp'
  done </etc/hiddify/edge_allow.list

  ufw --force enable
  systemctl enable ufw
}

install_helpers(){
  cat >/usr/local/bin/hiddify-menu <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
for p in /opt/hiddify-config/menu.sh /opt/hiddify-manager/menu.sh; do
  if [ -x "$p" ]; then exec bash "$p"; fi
done
echo "menu.sh not found under /opt/hiddify-config or /opt/hiddify-manager" >&2
exit 1
EOF
  chmod +x /usr/local/bin/hiddify-menu

  cat >/usr/local/bin/hiddify-panel-selfcheck <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

echo "== service status =="
systemctl --no-pager --full status cloudflared | sed -n '1,30p' || true

echo
echo "== listening sockets =="
ss -lntup | egrep '(:443\b|:22\b)' || true

echo
echo "== firewall =="
ufw status numbered || true

echo
echo "== local https probe =="
curl -skI https://127.0.0.1/ || true

echo
echo "== cloudflared recent logs =="
journalctl -u cloudflared -n 80 --no-pager || true

echo
echo "== hiddify backup dir =="
ls -lah /opt/hiddify-manager/hiddify-panel/backup 2>/dev/null || true

echo
echo "== hiddify menu path =="
command -v hiddify-menu || true
EOF
  chmod +x /usr/local/bin/hiddify-panel-selfcheck

  cat >/etc/logrotate.d/hiddify-local <<'EOF'
/opt/hiddify-manager/log/*.log
/opt/hiddify-manager/log/*/*.log
/opt/hiddify-manager/log/*/*/*.log
/var/log/cloudflared/*.log
{
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF
}

print_next(){
  cat <<EOF

[panel] done

[panel] Cloudflare Tunnel hostnames should already point to:
  ${PANEL_DOMAIN} -> https://localhost:443
  ${SUB_DOMAIN}   -> https://localhost:443

[panel] origin firewall now allows only:
  SSH from ${ADMIN_ALLOW_CIDR}
  443/tcp from edge IPs in /etc/hiddify/edge_allow.list
  443/udp from edge IPs in /etc/hiddify/edge_allow.list

[panel] useful commands:
  hiddify-menu
  hiddify-panel-selfcheck
  systemctl status cloudflared --no-pager
  journalctl -u cloudflared -n 100 --no-pager
  ufw status numbered

[panel] next in Hiddify panel:
  1) open https://${PANEL_DOMAIN}
  2) keep only HY2 + VLESS Reality
  3) use ${EDGE_DOMAIN} as user traffic domain
  4) use ${SUB_DOMAIN} as sub-link-only domain

EOF
}

main(){
  need_root
  check_os
  install_base
  install_hiddify
  install_cloudflared
  configure_firewall
  install_helpers
  print_next
}

main "$@"
