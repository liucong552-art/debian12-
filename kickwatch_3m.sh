#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$' \n\t'

die(){ echo "[x] $*" >&2; exit 1; }
log(){ echo -e "\n[+] $*\n"; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行"

# ===== 必填（运行时用环境变量传入）=====
PANEL_HOST="${PANEL_HOST:-}"
API_KEY="${API_KEY:-}"
NODE_ID="${NODE_ID:-}"
# ===== 可选 =====
NODE_TYPE="${NODE_TYPE:-vless}"
PORT="${PORT:-8443}"
BAN_TTL="${BAN_TTL:-3m}"
POLL_SEC="${POLL_SEC:-20}"

[ -n "$PANEL_HOST" ] || die "缺少 PANEL_HOST，例如 https://api.liucna.com"
[ -n "$API_KEY" ]   || die "缺少 API_KEY"
[ -n "$NODE_ID" ]   || die "缺少 NODE_ID"

log "0) 参数确认
- PANEL_HOST=$PANEL_HOST
- NODE_ID=$NODE_ID
- NODE_TYPE=$NODE_TYPE
- PORT=$PORT
- BAN_TTL=$BAN_TTL
- POLL_SEC=$POLL_SEC
"

log "1) 安装依赖"
apt-get update -y
apt-get install -y nftables conntrack jq curl
systemctl enable --now nftables

log "2) 清理旧版本（如果存在）"
systemctl disable --now xrayr-kickwatch 2>/dev/null || true
rm -f /etc/systemd/system/xrayr-kickwatch.service /usr/local/bin/xrayr-kickwatch.sh
nft delete table inet xraykick 2>/dev/null || true

log "3) 配置 nftables（拉黑集合 timeout=$BAN_TTL，仅封端口 $PORT）"
nft add table inet xraykick 2>/dev/null || true
nft "add set inet xraykick blocked4 { type ipv4_addr; flags timeout; timeout ${BAN_TTL}; }" 2>/dev/null || true
nft 'add chain inet xraykick input { type filter hook input priority -150; policy accept; }' 2>/dev/null || true
nft add rule inet xraykick input tcp dport $PORT ip saddr @blocked4 drop 2>/dev/null || true

log "4) 写入 kickwatch 主程序 /usr/local/bin/xrayr-kickwatch.sh"
cat >/usr/local/bin/xrayr-kickwatch.sh <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$' \n\t'

PANEL_HOST="${PANEL_HOST:?missing PANEL_HOST}"
API_KEY="${API_KEY:?missing API_KEY}"
NODE_ID="${NODE_ID:?missing NODE_ID}"
NODE_TYPE="${NODE_TYPE:-vless}"
PORT="${PORT:-8443}"
BAN_TTL="${BAN_TTL:-3m}"
POLL_SEC="${POLL_SEC:-20}"

STATE_DIR="/var/lib/xrayr-kickwatch"
STATE_ALLOWED="$STATE_DIR/allowed_ids.txt"
KICK_DIR="$STATE_DIR/kicked_ips"
XRAY_LOG="/var/log/XrayR/runner.log"

mkdir -p "$STATE_DIR" "$KICK_DIR"
touch "$XRAY_LOG"

fetch_allowed_ids() {
  curl -fsS \
    "${PANEL_HOST}/api/v1/server/UniProxy/user?node_id=${NODE_ID}&node_type=${NODE_TYPE}&token=${API_KEY}" \
    | jq -r '.users[]?.id' | sort -n
}

get_ips_for_uid_v4() {
  local uid="$1"
  tail -n 5000 "$XRAY_LOG" 2>/dev/null \
    | grep "@v2board.user|${uid}" \
    | sed -n 's/.* \([0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+\):[0-9]\+ accepted.*/\1/p' \
    | tail -n 30 \
    | sort -u
}

ban_ip_now_v4() {
  local ip="$1"
  nft add element inet xraykick blocked4 "{ $ip timeout $BAN_TTL; }" 2>/dev/null || \
  nft add element inet xraykick blocked4 "{ $ip timeout $BAN_TTL }" 2>/dev/null || true
  conntrack -D -p tcp -s "$ip" --dport "$PORT" 2>/dev/null || true
}

unban_ip_v4() {
  local ip="$1"
  nft delete element inet xraykick blocked4 "{ $ip; }" 2>/dev/null || \
  nft delete element inet xraykick blocked4 "{ $ip }" 2>/dev/null || true
}

if [ ! -f "$STATE_ALLOWED" ]; then
  fetch_allowed_ids >"$STATE_ALLOWED" || true
fi

echo "[kickwatch] start $(date -Is) node=${NODE_ID}/${NODE_TYPE} port=${PORT} ban=${BAN_TTL} poll=${POLL_SEC}s" >&2

while true; do
  new="$(mktemp)"
  if fetch_allowed_ids >"$new"; then
    removed="$(comm -23 "$STATE_ALLOWED" "$new" || true)"
    added="$(comm -13 "$STATE_ALLOWED" "$new" || true)"

    if [ -n "$removed" ]; then
      while read -r uid; do
        [ -n "$uid" ] || continue
        echo "[kickwatch] user removed: id=$uid, kick now..." >&2
        ips="$(get_ips_for_uid_v4 "$uid" || true)"
        if [ -n "$ips" ]; then
          file="$KICK_DIR/$uid"
          : >"$file"
          while read -r ip; do
            [ -n "$ip" ] || continue
            echo "$ip" >>"$file"
            echo "[kickwatch] ban+kill ip=$ip uid=$uid ttl=$BAN_TTL" >&2
            ban_ip_now_v4 "$ip"
          done <<<"$ips"
        else
          echo "[kickwatch] no recent IPv4 found for uid=$uid" >&2
        fi
      done <<<"$removed"
    fi

    if [ -n "$added" ]; then
      while read -r uid; do
        [ -n "$uid" ] || continue
        file="$KICK_DIR/$uid"
        if [ -f "$file" ]; then
          while read -r ip; do
            [ -n "$ip" ] || continue
            echo "[kickwatch] user added back: id=$uid, unban ip=$ip" >&2
            unban_ip_v4 "$ip"
          done <"$file"
          rm -f "$file"
        fi
      done <<<"$added"
    fi

    mv -f "$new" "$STATE_ALLOWED"
  else
    rm -f "$new"
    echo "[kickwatch] fetch users failed, retry..." >&2
  fi
  sleep "$POLL_SEC"
done
SH
chmod +x /usr/local/bin/xrayr-kickwatch.sh

log "5) 写入 systemd 并启动"
cat >/etc/systemd/system/xrayr-kickwatch.service <<EOF
[Unit]
Description=XrayR Kickwatch (ban ${BAN_TTL} and kill connections)
After=network-online.target xrayr.service
Wants=network-online.target xrayr.service

[Service]
Type=simple
Environment=NODE_TYPE=${NODE_TYPE}
Environment=PORT=${PORT}
Environment=BAN_TTL=${BAN_TTL}
Environment=POLL_SEC=${POLL_SEC}
Environment=PANEL_HOST=${PANEL_HOST}
Environment=API_KEY=${API_KEY}
Environment=NODE_ID=${NODE_ID}
ExecStart=/usr/local/bin/xrayr-kickwatch.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now xrayr-kickwatch

log "6) 状态检查"
systemctl status xrayr-kickwatch --no-pager -l | sed -n '1,25p' || true
echo
echo "[i] 看实时日志：journalctl -u xrayr-kickwatch -f --no-pager"
echo "[i] 看黑名单：nft list set inet xraykick blocked4"
echo "[i] 停用服务：systemctl disable --now xrayr-kickwatch"
