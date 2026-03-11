#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR
shopt -s nullglob

meta_get() { local file="$1" key="$2"; awk -F= -v k="$key" '$1==k {sub($1"=",""); print; exit}' "$file"; }
parse_port_from_listen() {
  local listen="${1:-}"
  if [[ "$listen" =~ ([0-9]+)$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}
udp_port_listening() {
  local port="$1"
  ss -lunH 2>/dev/null | awk '{print $5}' | sed -nE 's/.*:([0-9]+)$/\1/p' | grep -qx "$port"
}
get_counter_bytes() {
  local obj="$1"
  nft list counter inet portquota "$obj" 2>/dev/null \
    | awk '/bytes/{for(i=1;i<=NF;i++) if($i=="bytes"){print $(i+1);exit}}'
}
get_quota_used_bytes() {
  local obj="$1"
  nft list quota inet portquota "$obj" 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i=="used"){print $(i+1); exit}}'
}
fmt_gib() {
  local b="${1:-0}"
  [[ "$b" =~ ^[0-9]+$ ]] || b=0
  awk -v v="$b" 'BEGIN{printf "%.2f", v/1024/1024/1024}'
}
fmt_left() {
  local exp="${1:-}"
  local now
  now=$(date +%s)
  if [[ "$exp" =~ ^[0-9]+$ ]]; then
    local left=$((exp - now))
    if (( left <= 0 )); then
      echo "expired"
    else
      local d=$((left/86400))
      local h=$(((left%86400)/3600))
      local m=$(((left%3600)/60))
      printf "%02dd%02dh%02dm" "$d" "$h" "$m"
    fi
  else
    echo "-"
  fi
}
fmt_expire_cn() {
  local exp="${1:-}"
  if [[ "$exp" =~ ^[0-9]+$ ]] && (( exp > 0 )); then
    TZ='Asia/Shanghai' date -d "@$exp" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "-"
  else
    echo "-"
  fi
}
quota_cells() {
  local port="$1"
  local meta="/etc/portquota/pq-${port}.meta"
  local qstate="none" limit="-" used="-" left="-" pct="-"

  if [[ -f "$meta" ]]; then
    local limit_bytes mode out_b in_b total_b quota_used_b used_b left_b pct_val
    limit_bytes="$(meta_get "$meta" LIMIT_BYTES || true)"
    mode="$(meta_get "$meta" MODE || true)"
    [[ "$limit_bytes" =~ ^[0-9]+$ ]] || limit_bytes=0
    mode="${mode:-quota}"

    if [[ "$mode" != "quota" || "$limit_bytes" == "0" ]]; then
      qstate="track"
    else
      out_b="$(get_counter_bytes "pq_out_${port}" || true)"; [[ "$out_b" =~ ^[0-9]+$ ]] || out_b=0
      in_b="$(get_counter_bytes "pq_in_${port}" || true)";   [[ "$in_b" =~ ^[0-9]+$ ]] || in_b=0
      total_b=$((out_b + in_b))
      quota_used_b="$(get_quota_used_bytes "pq_quota_${port}" || true)"
      if [[ "$quota_used_b" =~ ^[0-9]+$ ]]; then
        used_b="$quota_used_b"
      else
        used_b="$total_b"
      fi
      (( used_b < 0 )) && used_b=0
      if (( used_b > limit_bytes )); then
        used_b="$limit_bytes"
      fi
      left_b=$((limit_bytes - used_b))
      (( left_b < 0 )) && left_b=0
      pct_val="$(awk -v u="$used_b" -v l="$limit_bytes" 'BEGIN{printf "%.1f%%", (l>0 ? (u*100.0/l) : 0)}')"
      limit="$(fmt_gib "$limit_bytes")"
      used="$(fmt_gib "$used_b")"
      left="$(fmt_gib "$left_b")"
      pct="$pct_val"
      if (( left_b == 0 )); then
        qstate="full"
      else
        qstate="ok"
      fi
    fi
  fi

  printf '%s|%s|%s|%s|%s\n' "$qstate" "$limit" "$used" "$left" "$pct"
}

NAME_W=32
STATE_W=8
PORT_W=5
RDY_W=3
Q_W=5
LIMIT_W=7
USED_W=7
LEFT_W=7
USE_W=5
TTL_W=10
EXP_W=19
print_sep() {
  printf '%*s\n' 118 '' | tr ' ' '-'
}
render_row() {
  local name="$1" state="$2" port="$3" ready="$4" qstate="$5" limit="$6" used="$7" leftq="$8" pct="$9" ttl_left="${10}" expire_cn="${11}"
  local first=1 chunk rest
  rest="$name"
  while :; do
    if (( ${#rest} > NAME_W )); then
      chunk="${rest:0:NAME_W}"
      rest="${rest:NAME_W}"
    else
      chunk="$rest"
      rest=""
    fi
    if (( first )); then
      printf "%-${NAME_W}s %-${STATE_W}s %-${PORT_W}s %-${RDY_W}s %-${Q_W}s %-${LIMIT_W}s %-${USED_W}s %-${LEFT_W}s %-${USE_W}s %-${TTL_W}s %-${EXP_W}s\n" \
        "$chunk" "$state" "$port" "$ready" "$qstate" "$limit" "$used" "$leftq" "$pct" "$ttl_left" "$expire_cn"
      first=0
    else
      printf "%-${NAME_W}s\n" "$chunk"
    fi
    [[ -z "$rest" ]] && break
  done
}

TEMP_DIR="/etc/hysteria/temp"
ENV_FILE="/etc/default/hy2-main"
MAIN_PORT="443"
if [[ -r "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  P="$(parse_port_from_listen "${HY_LISTEN:-:443}" || true)"
  [[ "$P" =~ ^[0-9]+$ ]] && MAIN_PORT="$P"
fi

echo
printf '%s\n' '=== HY2 AUDIT ==='
print_sep
render_row "NAME" "STATE" "PORT" "RDY" "Q" "LIMIT" "USED" "LEFT" "USE%" "TTL" "EXPIRE(CN)"
print_sep

if systemctl list-unit-files hy2.service >/dev/null 2>&1; then
  STATE="$(systemctl is-active hy2.service 2>/dev/null || echo unknown)"
  READY="no"
  [[ "$STATE" == "active" ]] && udp_port_listening "$MAIN_PORT" && READY="yes"
  render_row "hy2.service" "$STATE" "$MAIN_PORT" "$READY" "none" "-" "-" "-" "-" "-" "-"
fi

for META in "$TEMP_DIR"/hy2-temp-*.meta; do
  TAG="$(meta_get "$META" TAG || true)"
  PORT="$(meta_get "$META" PORT || true)"
  EXP="$(meta_get "$META" EXPIRE_EPOCH || true)"
  [[ -n "$TAG" && -n "$PORT" ]] || continue

  NAME="${TAG}.service"
  STATE="$(systemctl is-active "${TAG}.service" 2>/dev/null || echo unknown)"
  READY="no"
  [[ "$STATE" == "active" ]] && udp_port_listening "$PORT" && READY="yes"
  IFS='|' read -r QSTATE LIMIT USED LEFT_Q PCT <<< "$(quota_cells "$PORT")"
  render_row "$NAME" "$STATE" "$PORT" "$READY" "$QSTATE" "$LIMIT" "$USED" "$LEFT_Q" "$PCT" "$(fmt_left "$EXP")" "$(fmt_expire_cn "$EXP")"
done
print_sep
