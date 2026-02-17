sudo tee /usr/local/sbin/netwatch.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

TZ="Asia/Shanghai"
WG_IF="wg-exit"
WG_PORT="51820"
ENDPOINT_IP="104.194.67.106"
PING_IPS=("1.1.1.1" "8.8.8.8")
FAIL_N=3
HANDSHAKE_STALE=120

BASE="/var/log/netwatch"
EVENTS="$BASE/events"
PCAP="$BASE/pcap"
IPMON="$BASE/ipmon.log"

PCAP_ENABLE=1
PCAP_ROTATE_SEC=300

mkdir -p "$EVENTS" "$PCAP"
touch "$IPMON"

log(){ echo "[$(TZ="$TZ" date '+%F %T%z')] $*" | tee -a "$BASE/netwatch.log" >/dev/null; }
now(){ TZ="$TZ" date '+%F %T%z'; }

exec 9>/run/netwatch.lock
if ! flock -n 9; then
  echo "netwatch already running." >&2
  exit 0
fi

detect_default_iface(){
  local line
  line="$(ip route show default 2>/dev/null | head -n1 || true)"
  DEF_GW="$(awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1)}}' <<<"$line")"
  DEF_IF="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1)}}' <<<"$line")"
  [[ -n "${DEF_IF:-}" ]] || DEF_IF="eth0"
}

start_ip_monitor(){
  if pgrep -f "ip -ts monitor link route" >/dev/null 2>&1; then return; fi
  (stdbuf -oL ip -ts monitor link route >>"$IPMON" 2>&1) &
  log "ip monitor started (pid=$!) -> $IPMON"
}

start_tcpdump_ring(){
  [[ "$PCAP_ENABLE" == "1" ]] || return
  if pgrep -f "tcpdump .* $PCAP" >/dev/null 2>&1; then return; fi

  detect_default_iface
  local filter="(udp and port $WG_PORT) or icmp or arp or (udp and (port 67 or port 68))"

  (exec tcpdump -i "$DEF_IF" -n -s 128 -G "$PCAP_ROTATE_SEC" \
      -w "$PCAP/%Y%m%d-%H%M%S.pcap" $filter >/dev/null 2>&1) &
  log "tcpdump ring started (iface=$DEF_IF, pid=$!) -> $PCAP"
}

cleanup_old(){
  find "$EVENTS" -mindepth 1 -mtime +2 -print -exec rm -rf {} \; >/dev/null 2>&1 || true
  find "$PCAP"   -type f -mtime +2 -delete >/dev/null 2>&1 || true
  find "$BASE"   -maxdepth 1 -type f -name "*.log" -mtime +2 -delete >/dev/null 2>&1 || true
}

wg_handshake_age(){
  local epoch nowsec
  epoch="$(wg show "$WG_IF" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}')"
  [[ -n "${epoch:-}" && "$epoch" != "0" ]] || { echo 999999; return; }
  nowsec="$(date +%s)"
  echo $(( nowsec - epoch ))
}

ping1(){ ping -n -c1 -W1 "$1" >/dev/null 2>&1; }

snapshot(){
  detect_default_iface
  local ts dir
  ts="$(TZ="$TZ" date '+%Y%m%d-%H%M%S')"
  dir="$EVENTS/$ts"
  mkdir -p "$dir"

  {
    echo "=== NETWATCH SNAPSHOT $(now) ==="
    echo "DEF_IF=$DEF_IF  DEF_GW=${DEF_GW:-none}"
    echo "ENDPOINT_IP=$ENDPOINT_IP  WG_IF=$WG_IF  WG_PORT=$WG_PORT"
    echo
    echo "## quick status"
    echo "operstate: $(cat /sys/class/net/$DEF_IF/operstate 2>/dev/null || true)"
    echo "wg handshake age(s): $(wg_handshake_age || true)"
    echo
    echo "## ip addr/link/route/rule"
    ip -br link
    echo
    ip -br addr
    echo
    ip route
    echo
    ip rule
    echo
    echo "## ip neigh (top 80)"
    ip neigh | head -n 80
    echo
    echo "## wg show"
    wg show "$WG_IF" 2>/dev/null || true
    echo
    echo "## socket summary"
    ss -s 2>/dev/null || true
    echo
    echo "## udp sockets (top 80)"
    ss -uapn 2>/dev/null | head -n 80 || true
    echo
    echo "## ethtool"
    ethtool "$DEF_IF" 2>/dev/null || true
    echo
    echo "## link stats"
    ip -s link show "$DEF_IF" 2>/dev/null || true
    echo
    echo "## conntrack usage"
    if command -v conntrack >/dev/null 2>&1; then
      echo "conntrack -C: $(conntrack -C 2>/dev/null || true)"
    fi
    echo "nf_conntrack_count: $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || true)"
    echo "nf_conntrack_max  : $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true)"
    echo
    echo "## firewall (first 120 lines)"
    if command -v nft >/dev/null 2>&1; then
      nft list ruleset 2>/dev/null | head -n 120 || true
    else
      iptables-save 2>/dev/null | head -n 120 || true
    fi
  } >"$dir/snapshot.txt" 2>&1

  TZ="$TZ" journalctl -k --since "10 minutes ago" --no-pager >"$dir/journal-kernel-10m.txt" 2>&1 || true
  TZ="$TZ" journalctl --since "10 minutes ago" --no-pager \
    | egrep -i "eth|link|carrier|dhcp|gateway|route|rename|reset|watchdog|tx timeout|conntrack|table full|oom|wireguard|wg" \
    >"$dir/journal-filter-10m.txt" 2>&1 || true

  tail -n 300 "$IPMON" >"$dir/ip-monitor-tail.txt" 2>&1 || true
  log "SNAPSHOT saved -> $dir"
}

main_loop(){
  detect_default_iface
  start_ip_monitor
  start_tcpdump_ring
  cleanup_old

  local fail=0 in_event=0 last_cleanup=0

  while true; do
    local ok_gw=0 ok_net=0 ok_ep=0 hs_age
    detect_default_iface

    if [[ -n "${DEF_GW:-}" ]]; then
      if ping1 "$DEF_GW"; then ok_gw=1; fi
    else
      ok_gw=1
    fi

    for ip in "${PING_IPS[@]}"; do
      if ping1 "$ip"; then ok_net=1; break; fi
    done

    if ping1 "$ENDPOINT_IP"; then ok_ep=1; fi
    hs_age="$(wg_handshake_age 2>/dev/null || echo 999999)"

    if [[ "$ok_net" -eq 0 || "$hs_age" -ge "$HANDSHAKE_STALE" ]]; then
      fail=$((fail+1))
    else
      fail=0
      if [[ "$in_event" -eq 1 ]]; then
        log "RECOVERED (gw=$ok_gw net=$ok_net ep=$ok_ep hs_age=$hs_age) -> take recovery snapshot"
        snapshot
        in_event=0
      fi
    fi

    if [[ "$fail" -ge "$FAIL_N" && "$in_event" -eq 0 ]]; then
      log "OUTAGE DETECTED (gw=$ok_gw net=$ok_net ep=$ok_ep hs_age=$hs_age) -> take snapshot"
      snapshot
      in_event=1
    fi

    local tnow
    tnow="$(date +%s)"
    if (( tnow - last_cleanup > 3600 )); then
      cleanup_old
      last_cleanup="$tnow"
    fi

    sleep 1
  done
}

main_loop
EOF

sudo chmod +x /usr/local/sbin/netwatch.sh
