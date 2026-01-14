cat >/usr/local/sbin/vless_mktemp_nat.sh <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "❌ ${BASH_SOURCE[0]}:${LINENO}: ${BASH_COMMAND}" >&2' ERR

# 在 VPS 上生成“走 WG-NAT 出口”的临时 VLESS+Reality 节点（通过 sockopt.mark 触发策略路由）
# 依赖你已经部署好的临时节点框架：
#   /usr/local/sbin/vless_run_temp.sh
#   /usr/local/sbin/vless_cleanup_one.sh
# 且已安装主节点（用于复用 Reality 参数）：/usr/local/etc/xray/config.json
#
# 用法：
#   MARK=2333 D=600 vless_mktemp_nat.sh
#   PORT_START=40000 PORT_END=60000 MARK=2333 D=600 vless_mktemp_nat.sh

fail(){ echo "❌ $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || fail "缺少命令：$1"; }

[[ ${EUID:-0} -eq 0 ]] || fail "请用 root 运行"
umask 077

TAG_PREFIX="${TAG_PREFIX:-vless-temp-nat}"
D="${D:-600}"

WG_IF="${WG_IF:-wg-nat}"
MARK_RAW="${MARK:-2333}"
TABLE_ID="${TABLE_ID:-100}"
HANDSHAKE_MAX="${HANDSHAKE_MAX:-180}"

XRAY_DIR="${XRAY_DIR:-/usr/local/etc/xray}"
MAIN_CFG="${MAIN_CFG:-/usr/local/etc/xray/config.json}"
SUB_FILE="${SUB_FILE:-/root/vless_reality_vision_url.txt}"

RUNNER="${RUNNER:-/usr/local/sbin/vless_run_temp.sh}"
CLEANUP="${CLEANUP:-/usr/local/sbin/vless_cleanup_one.sh}"

need curl; need python3; need openssl; need ss; need systemctl; need timeout

norm_mark(){
  local raw="${1,,}"
  raw="${raw//[[:space:]]/}"
  if [[ "$raw" =~ ^0x[0-9a-f]+$ ]]; then raw="${raw#0x}"; echo "$((16#$raw))"
  elif [[ "$raw" =~ ^[0-9]+$ ]]; then echo "$raw"
  else fail "MARK 格式不合法：$1"
  fi
}
MARK_DEC="$(norm_mark "$MARK_RAW")"

urldecode(){ python3 - "$1" <<'PY'
import urllib.parse,sys
print(urllib.parse.unquote(sys.argv[1]))
PY
}

# 1) NAT 出口健康检查（生成临时节点前）
if [[ -x /usr/local/sbin/wg_nat_healthcheck.sh ]]; then
  echo "==> NAT 出口健康检查（生成临时节点前）..."
  HANDSHAKE_MAX="${HANDSHAKE_MAX}" WG_IF="${WG_IF}" MARK="${MARK_DEC}" TABLE_ID="${TABLE_ID}" \
    /usr/local/sbin/wg_nat_healthcheck.sh \
    || fail "wg-nat 出口不可用（常见原因：NAT 机 wg-exit 未启动/UDP 51820 不通/keepalive 未恢复）"
fi

[[ -x "$RUNNER"  ]] || fail "找不到 RUNNER：$RUNNER（先部署临时节点体系：vless_run_temp.sh 等）"
[[ -x "$CLEANUP" ]] || fail "找不到 CLEANUP：$CLEANUP"
[[ -f "$MAIN_CFG" ]] || fail "找不到主配置：$MAIN_CFG（先装主 VLESS Reality）"

# 2) 从主配置解析 Reality 参数：dest / sni / privateKey
readarray -t R < <(python3 - "$MAIN_CFG" <<'PY'
import json,sys
cfg=json.load(open(sys.argv[1]))
for ib in cfg.get("inbounds",[]):
    ss=(ib.get("streamSettings") or {})
    if ss.get("security")=="reality":
        rs=ss.get("realitySettings") or {}
        dest=rs.get("dest","")
        sns=rs.get("serverNames") or []
        sni=sns[0] if sns else ""
        pk=rs.get("privateKey","")
        print(dest); print(sni); print(pk)
        sys.exit(0)
print(""); print(""); print("")
PY
)
REALITY_DEST="${R[0]:-}"
REALITY_SNI="${R[1]:-}"
REALITY_PRIVATE_KEY="${R[2]:-}"
[[ -n "$REALITY_DEST" && -n "$REALITY_SNI" && -n "$REALITY_PRIVATE_KEY" ]] || fail "解析主配置 Reality 参数失败"

# 3) 获取 PBK：优先 PBK env，否则从订阅文件提取 pbk=
PBK="${PBK:-}"
if [[ -z "$PBK" ]]; then
  [[ -f "$SUB_FILE" ]] || fail "PBK 未传且找不到：$SUB_FILE"
  PBK="$(grep -oE 'pbk=[^&]+' "$SUB_FILE" | head -n1 | cut -d= -f2 || true)"
fi
PBK="$(urldecode "$PBK")"
PBK="${PBK//[[:space:]]/}"
[[ -n "$PBK" ]] || fail "PBK 为空"

# 4) 获取服务器公网 IP（也可手动传 SERVER_ADDR=）
SERVER_ADDR="${SERVER_ADDR:-}"
if [[ -z "$SERVER_ADDR" ]]; then
  SERVER_ADDR="$(curl -4fsS --max-time 5 https://api.ipify.org 2>/dev/null | tr -d ' \r\n' || true)"
fi
[[ -n "$SERVER_ADDR" ]] || fail "获取公网 IP 失败，手动传 SERVER_ADDR=..."

# 5) 选端口（避免冲突）
PORT_START="${PORT_START:-40000}"
PORT_END="${PORT_END:-60000}"
declare -A USED=()
while read -r p; do [[ -n "$p" ]] && USED["$p"]=1; done < <(ss -ltnH | awk '{print $4}' | sed -n 's/.*:\([0-9]\+\)$/\1/p')
for m in "$XRAY_DIR"/vless-temp-*.meta "$XRAY_DIR"/vless-temp-nat-*.meta; do
  [[ -f "$m" ]] || continue
  p="$(awk -F= '$1=="PORT"{print $2; exit}' "$m" || true)"
  [[ -n "${p:-}" ]] && USED["$p"]=1
done
PORT=""
for ((p=PORT_START; p<=PORT_END; p++)); do
  if [[ -z "${USED[$p]+x}" ]]; then PORT="$p"; break; fi
done
[[ -n "$PORT" ]] || fail "端口范围 ${PORT_START}-${PORT_END} 没有可用端口"

# 6) 生成 TAG/UUID/SHORT_ID
install -d -m 755 "$XRAY_DIR"
RAND="$(openssl rand -hex 2)"
TAG="${TAG_PREFIX}-$(date +%Y%m%d%H%M%S)-${RAND}"
UUID="$(cat /proc/sys/kernel/random/uuid)"
SHORT_ID="$(openssl rand -hex 8)"

CFG="${XRAY_DIR}/${TAG}.json"
META="${XRAY_DIR}/${TAG}.meta"

# 7) 写 cfg：nat outbound 用 sockopt.mark
cat >"$CFG" <<JSON
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "${TAG}",
      "listen": "0.0.0.0",
      "port": ${PORT},
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "${UUID}", "flow": "xtls-rprx-vision" }],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${REALITY_DEST}",
          "xver": 0,
          "serverNames": ["${REALITY_SNI}"],
          "privateKey": "${REALITY_PRIVATE_KEY}",
          "shortIds": ["${SHORT_ID}"]
        }
      }
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "nat", "protocol": "freedom", "streamSettings": { "sockopt": { "mark": ${MARK_DEC} } } },
    { "tag": "block", "protocol": "blackhole" }
  ],
  "routing": {
    "rules": [
      { "type": "field", "inboundTag": ["${TAG}"], "outboundTag": "nat" }
    ]
  }
}
JSON

EXPIRE_EPOCH=$(( $(date +%s) + D ))
cat >"$META" <<META
TAG=${TAG}
UUID=${UUID}
SERVER_ADDR=${SERVER_ADDR}
PORT=${PORT}
REALITY_SNI=${REALITY_SNI}
SHORT_ID=${SHORT_ID}
PBK=${PBK}
LANDING=nat
MARK=${MARK_DEC}
TABLE_ID=${TABLE_ID}
EXPIRE_EPOCH=${EXPIRE_EPOCH}
CFG=${CFG}
META

chmod 600 "$CFG" "$META" 2>/dev/null || true

# 8) systemd unit：runner 需要 <TAG> <CFG> 两个参数
UNIT="/etc/systemd/system/${TAG}.service"
cat >"$UNIT" <<UNIT
[Unit]
Description=Xray temp VLESS NAT (${TAG})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${RUNNER} ${TAG} ${CFG}
ExecStopPost=${CLEANUP} ${TAG}
Restart=no
SuccessExitStatus=0 124 143

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "${TAG}.service" >/dev/null 2>&1 || true

if ! systemctl start "${TAG}.service"; then
  echo "==> systemd 启动失败，回滚清理..." >&2
  FORCE=1 "${CLEANUP}" "${TAG}" >/dev/null 2>&1 || true
  fail "systemctl start 失败：${TAG}.service"
fi

systemctl is-active --quiet "${TAG}.service" || {
  FORCE=1 "${CLEANUP}" "${TAG}" >/dev/null 2>&1 || true
  fail "服务未 active：${TAG}.service"
}

LINK="vless://${UUID}@${SERVER_ADDR}:${PORT}?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&sni=${REALITY_SNI}&fp=chrome&pbk=${PBK}&sid=${SHORT_ID}#${TAG}"
echo "✅ NAT 落地临时节点已生成：${TAG}"
echo "到期(北京时间)：$(TZ=Asia/Shanghai date -d "@${EXPIRE_EPOCH}" '+%F %T')"
echo "VLESS 链接：${LINK}"
SH

chmod +x /usr/local/sbin/vless_mktemp_nat.sh
