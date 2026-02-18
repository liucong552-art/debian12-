#!/usr/bin/env bash
set -Eeuo pipefail

# 一键安装/修复 netwatch 到 /usr/local/sbin/netwatch.sh，并注册 systemd 服务 netwatch.service
# 用法（在目标机执行）：curl -fsSL <raw-url>/natjiance.sh | sudo bash

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y --no-install-recommends \
  iproute2 iputils-ping util-linux procps \
  ethtool tcpdump conntrack ca-certificates curl

install -d /var/log/netwatch/events /var/log/netwatch/pcap

cat >/usr/local/sbin/netwatch.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

# ===== 可按需改这些 =====
TZ="${TZ:-Asia/Shanghai}"
WG_IF="${WG_IF:-wg-exit}"
ENDPOINT_IP="${ENDPOINT_IP:-104.194.67.106}"
WG_PORT="${WG_PORT:-51820}"
PING_IPS=(${PING_IPS:-"1.1.1.1 8.8.8.8"})

FAIL_N="${FAIL_N:-3}"                 # 连续失败 N 次判定事件
HANDSHAKE_STALE="${HANDSHAKE_STALE:-120}" # wg 最后握手超过多少秒视为异常（keepalive=25s 的话 120s 很宽松）

BASE="/var/log/netwatch"
EVENTS="$BASE/events"
PCAP="$BASE/pcap"
IPMON="$BASE/ipmon.log"

PCAP_ENABLE="${PCAP_ENABLE:-1}"
PCAP_ROTATE_SEC="${PCAP_ROTATE_SEC:-300}" # 5分钟一个 pcap

mkdir -p "$EVENTS" "$PCAP"
touch "$IPMON" "$BASE/netwatch.log"

log(){ echo "[$(TZ="$TZ" date '+%F %T%z')] $*" | tee -a "$BASE/netwatch.log" >/dev/null; }

# 防止多实例
exec 9>/run/netwatch.lock
flock -n 9 || exit 0

DEF_GW=""
DEF_IF="eth0"

detect_default(){
  local line
  line="$(ip route show default 2>/dev/null | head -n1 || true)"
  DEF_GW="$(awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1)}}' <<<"$line")"
  DEF_IF="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1)}}' <<<"$line")"
  [[ -n "${DEF_IF:-}" ]] || DEF_IF="eth0"
}

start_ipmon(){
  pgrep -f "ip -ts monitor link route" >/dev/null 2>&1 && return
  (stdbuf -oL ip -ts monitor link route >>"$IPMON" 2>&1) &
  log "ip monitor started pid=$! -> $IPMON"
}

start_tcpdump(){
  [[ "$PCAP_ENABLE" == "1" ]] || return
  pgrep -f "tcpdump .* $PCAP" >/dev/null 2>&1 && return

  detect_default
  local filter="(udp and port $WG_PORT) or icmp or arp or (udp and (port 67 or port 68))"
  (exec tcpdump -i "$DEF_IF" -n -s 128 -G "$PCAP_ROTATE_SEC" \
      -w "$PCAP/%Y%m%d-%H%M%S.pcap" $filter >/dev/null 2>&1) &
  log "tcpdump ring started pid=$! iface=$DEF_IF -> $PCAP"
}

cleanup_old(){
  # 保留最近 2 天
  find "$EVENTS" -mindepth 1 -mtime +2 -exec rm -rf {} \; >/dev/null 2>&1 || true
  find "$PCAP" -type f -mtime +2 -delete >/dev/null 2>&1 || true
  find "$BASE" -maxdepth 1 -type f -name "*.log" -mtime +2 -delete >/dev/null 2>&1 || true
}

wg_hs_age(){
  local epoch nowsec
  epoch="$(wg show "$WG_IF" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')"
  [[ -n "${epoch:-}" && "$epoch" != "0" ]] || { echo 999999; return; }
  nowsec="$(date +%s)"
  echo $(( nowsec - epoch ))
}

ping1(){ ping -n -c1 -W1 "$1" >/dev/null 2>&1; }

snapshot(){
  detect_default
  local ts dir
  ts="$(TZ="$TZ" date '+%Y%m%d-%H%M%S')"
  dir="$EVENTS/$ts"
  mkdir -p "$dir"

  {
    echo "=== SNAPSHOT $(TZ="$TZ" date '+%F %T%z') ==="
    echo "DEF_IF=$DEF_IF DEF_GW=${DEF_GW:-none}"
    echo "WG_IF=$WG_IF ENDPOINT_IP=$ENDPOINT_IP WG_PORT=$WG_PORT"
    echo "operstate: $(cat /sys/class/net/$DEF_IF/operstate 2>/dev/null || true)"
    echo "wg handshake age(s): $(wg_hs_age 2>/dev/null || echo 999999)"
    echo
    echo "## ip"
    ip -br link || true
    ip -br addr || true
    ip route || true
    ip rule || true
    echo
    echo "## wg"
    wg show "$WG_IF" 2>/dev/null || true
    echo
    echo "## ethtool"
    ethtool "$DEF_IF" 2>/dev/null || true
    echo
    echo "## link stats"
    ip -s link show "$DEF_IF" 2>/dev/null || true
    echo
    echo "## conntrack"
    if command -v conntrack >/dev/null 2>&1; then
      echo "conntrack -C: $(conntrack -C 2>/dev/null || true)"
    fi
    echo "nf_conntrack_count: $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || true)"
    echo "nf_conntrack_max  : $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true)"
    echo
    echo "## sockets"
    ss -s 2>/dev/null || true
    ss -uapn 2>/dev/null | head -n 120 || true
  } >"$dir/snapshot.txt" 2>&1

  TZ="$TZ" journalctl -k --since "10 minutes ago" --no-pager >"$dir/journal-kernel-10m.txt" 2>&1 || true
  TZ="$TZ" journalctl --since "10 minutes ago" --no-pager \
    | egrep -i "eth|link|carrier|dhcp|gateway|route|rename|reset|watchdog|tx timeout|conntrack|table full|oom|wireguard|wg" \
    >"$dir/journal-filter-10m.txt" 2>&1 || true

  tail -n 300 "$IPMON" >"$dir/ip-monitor-tail.txt" 2>&1 || true
  log "SNAPSHOT saved -> $dir"
}

main(){
  detect_default
  start_ipmon
  start_tcpdump
  cleanup_old

  local fail=0 in_event=0 last_cleanup=0
  while true; do
    detect_default

    local ok_net=0 ok_ep=0 hs_age
    for ip in "${PING_IPS[@]}"; do
      if ping1 "$ip"; then ok_net=1; break; fi
    done
    if ping1 "$ENDPOINT_IP"; then ok_ep=1; fi
    hs_age="$(wg_hs_age 2>/dev/null || echo 999999)"

    if [[ "$ok_net" -eq 0 || "$hs_age" -ge "$HANDSHAKE_STALE" ]]; then
      fail=$((fail+1))
    else
      fail=0
      if [[ "$in_event" -eq 1 ]]; then
        log "RECOVERED (net=$ok_net ep=$ok_ep hs_age=$hs_age) -> recovery snapshot"
        snapshot
        in_event=0
      fi
    fi

    if [[ "$fail" -ge "$FAIL_N" && "$in_event" -eq 0 ]]; then
      log "OUTAGE DETECTED (net=$ok_net ep=$ok_ep hs_age=$hs_age) -> snapshot"
      snapshot
      in_event=1
    fi

    local nowsec; nowsec="$(date +%s)"
    if (( nowsec - last_cleanup > 3600 )); then
      cleanup_old
      last_cleanup="$nowsec"
    fi

    sleep 1
  done
}

main
EOF

chmod 755 /usr/local/sbin/netwatch.sh

cat >/etc/systemd/system/netwatch.service <<'EOF'
[Unit]
Description=NetWatch - capture evidence when network outage happens
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/netwatch.sh
Restart=always
RestartSec=2
# 保证它能写日志/抓包
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now netwatch.service

echo
echo "[OK] Installed:"
echo "  - /usr/local/sbin/netwatch.sh"
echo "  - systemd: netwatch.service"
echo "Logs:"
echo "  - /var/log/netwatch/netwatch.log"
echo "  - /var/log/netwatch/events/<timestamp>/..."
echo "  - /var/log/netwatch/pcap/*.pcap (rotate, keep 2 days)"
echo
systemctl --no-pager --full status netwatch.service || true
