cat >/root/setup_nat_wg_exit_final.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

# NAT 机（出网机）侧：作为 WG 出口，接收来自 VPS wg-nat 的流量并 MASQUERADE 出网
# 用法：
#   bash /root/setup_nat_wg_exit_final.sh <VPS_IP> '<VPS_WG_PUBLIC_KEY>'
#
# 可覆盖参数：
WG_IF="${WG_IF:-wg-exit}"
WG_PORT="${WG_PORT:-51820}"
WG_ADDR="${WG_ADDR:-10.66.66.2/24}"
VPS_WG_ADDR="${VPS_WG_ADDR:-10.66.66.1/32}"   # VPS 在隧道内的地址
PERSISTENT_KEEPALIVE="${PERSISTENT_KEEPALIVE:-25}"
WAN_IF="${WAN_IF:-}"                           # 不填则自动探测

fail(){ echo "❌ $*" >&2; exit 1; }
need_root(){ [[ ${EUID:-0} -eq 0 ]] || fail "请用 root 运行"; }

need_root

VPS_IP="${1:-}"
VPS_PUB="${2:-}"
[[ -n "$VPS_IP"  ]] || fail "用法: $0 <VPS_IP> '<VPS_WG_PUBLIC_KEY>'"
[[ -n "$VPS_PUB" ]] || fail "用法: $0 <VPS_IP> '<VPS_WG_PUBLIC_KEY>'"

# 清洗 VPS_PUB：去空白/引号/尖括号
VPS_PUB="${VPS_PUB//[[:space:]]/}"
VPS_PUB="${VPS_PUB//\"/}"
VPS_PUB="${VPS_PUB#<}"; VPS_PUB="${VPS_PUB%>}"

if ! [[ "$VPS_PUB" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
  echo "⚠️ 警告：VPS_PUB 看起来不像标准 WG 公钥（仍继续写入）。值：$VPS_PUB" >&2
fi

export DEBIAN_FRONTEND=noninteractive
echo "==> 安装依赖（wireguard-tools / iproute2 / iptables / curl）..."
apt-get update -y >/dev/null
apt-get install -y wireguard-tools iproute2 iptables curl >/dev/null

install -d -m 700 /etc/wireguard

if [[ -z "$WAN_IF" ]]; then
  WAN_IF="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}' || true)"
fi
[[ -n "$WAN_IF" ]] || fail "无法探测外网网卡 WAN_IF；请手动指定：WAN_IF=eth0 bash $0 ..."

echo "==> 开启 IPv4 转发（并持久化）..."
cat >/etc/sysctl.d/99-wg-exit.conf <<EOF
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
sysctl --system >/dev/null 2>&1 || true

echo "==> 生成 NAT 机 WireGuard 密钥（${WG_IF}）..."
umask 077
if [[ ! -f "/etc/wireguard/${WG_IF}.key" ]]; then
  wg genkey | tee "/etc/wireguard/${WG_IF}.key" | wg pubkey >"/etc/wireguard/${WG_IF}.pub"
fi
NAT_PRIV="$(cat "/etc/wireguard/${WG_IF}.key")"
NAT_PUB="$(cat "/etc/wireguard/${WG_IF}.pub")"

echo "==> 写入 wg-quick 配置（${WG_IF}）..."
cat >"/etc/wireguard/${WG_IF}.conf" <<CFG
[Interface]
Address = ${WG_ADDR}
PrivateKey = ${NAT_PRIV}

# 确保能转发 + NAT
PostUp = sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

# 允许 wg -> WAN 转发
PostUp = iptables -C FORWARD -i %i -o ${WAN_IF} -j ACCEPT 2>/dev/null || iptables -A FORWARD -i %i -o ${WAN_IF} -j ACCEPT
PostUp = iptables -C FORWARD -i ${WAN_IF} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i ${WAN_IF} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# 出口 NAT
PostUp = iptables -t nat -C POSTROUTING -o ${WAN_IF} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o ${WAN_IF} -j MASQUERADE

PostDown = iptables -t nat -D POSTROUTING -o ${WAN_IF} -j MASQUERADE 2>/dev/null || true
PostDown = iptables -D FORWARD -i %i -o ${WAN_IF} -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -i ${WAN_IF} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

[Peer]
PublicKey = ${VPS_PUB}
Endpoint = ${VPS_IP}:${WG_PORT}
AllowedIPs = ${VPS_WG_ADDR}
PersistentKeepalive = ${PERSISTENT_KEEPALIVE}
CFG

chmod 600 "/etc/wireguard/${WG_IF}.conf"

systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable "wg-quick@${WG_IF}" >/dev/null 2>&1 || true
systemctl restart "wg-quick@${WG_IF}" >/dev/null 2>&1 || true

if ! systemctl is-active --quiet "wg-quick@${WG_IF}"; then
  echo "❌ wg-quick@${WG_IF} 启动失败，日志如下：" >&2
  systemctl --no-pager --full status "wg-quick@${WG_IF}" >&2 || true
  journalctl -u "wg-quick@${WG_IF}" --no-pager -n 120 >&2 || true
  exit 1
fi

echo
echo "✅ NAT 机 WG-EXIT 部署完成。"
echo "外网网卡: ${WAN_IF}"
echo "==================== NAT 机 WG 公钥 ===================="
echo "${NAT_PUB}"
echo "========================================================="
echo
echo "下一步：回到 VPS 执行：/usr/local/sbin/wg_nat_set_peer.sh '${NAT_PUB}'"
EOF

chmod +x /root/setup_nat_wg_exit_final.sh
bash /root/setup_nat_wg_exit_final.sh 104.224.158.191 'kuZSbsKq0rjLNXsJ9EPBeORJUEEqbEuBwwFX27+aYT8='
