#!/usr/bin/env bash
# code2: 单进程 Xray + API 动态临时入站（多端口）
# - 修复：api 配置方式、变量兜底、source env、并发锁、重启恢复、到期 GC
set -euo pipefail

XRAY_CFG="/usr/local/etc/xray/config.json"
ENV_FILE="/usr/local/etc/xray/env.conf"
STATE_DIR="/usr/local/etc/xray/tmpnodes"
BIN_XRAY="${BIN_XRAY:-/usr/local/bin/xray}"

need_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "❌ 请用 root 执行"
    exit 1
  fi
}

need_tools() {
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y curl python3 openssl iproute2 util-linux >/dev/null 2>&1 || true
}

ensure_env_file() {
  mkdir -p "$(dirname "$ENV_FILE")" "$STATE_DIR"
  if [[ ! -f "$ENV_FILE" ]]; then
    cat >"$ENV_FILE" <<'EOF'
# 代码2 环境变量（可按需修改）
# Xray API 监听地址（默认本机）
API_SERVER="127.0.0.1:10085"

# 对外给客户端展示的地址（强烈建议：NAT/反代/域名场景手动填域名或公网IP）
# 例如：SERVER_ADDR="hinetiw0k.yooddns.stream"
SERVER_ADDR=""

# 临时端口范围（建议 20 个节点，范围留大一点）
PORT_RANGE_START="40000"
PORT_RANGE_END="50050"

# 默认指纹
CLIENT_FP="chrome"
EOF
    chmod 600 "$ENV_FILE"
  fi
}

# 按官方方式启用 API：不要写 outbounds 里的 protocol:"api"
# 简易模式：api.listen=127.0.0.1:10085（不需要再配 api inbound + routing）
# 参考：Project X API 配置说明 :contentReference[oaicite:1]{index=1}
patch_xray_api_config_if_needed() {
  if [[ ! -f "$XRAY_CFG" ]]; then
    echo "⚠️ 未找到 $XRAY_CFG，跳过 API patch（请先安装/配置 Xray）"
    return 0
  fi

  python3 - "$XRAY_CFG" <<'PY'
import json,sys
p=sys.argv[1]
cfg=json.load(open(p))

# 1) 删除错误的 outbound: protocol=api / tag=api（你遇到的 unknown config id: api 就是它）
obs=cfg.get("outbounds",[])
cfg["outbounds"]=[o for o in obs if o.get("protocol")!="api"]

# 2) 确保 api 对象存在，使用简易模式 listen
api=cfg.get("api") or {}
api.setdefault("tag","api")
api.setdefault("listen","127.0.0.1:10085")
api.setdefault("services",["HandlerService","LoggerService","StatsService","RoutingService"])
cfg["api"]=api

open(p,"w").write(json.dumps(cfg,ensure_ascii=False,indent=2))
print("patched",p)
PY
}

restart_xray_and_check_api() {
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl restart xray >/dev/null 2>&1 || true
  sleep 0.7

  if ! systemctl is-active xray >/dev/null 2>&1; then
    echo "❌ xray 未处于 active，请先修复主服务：systemctl status xray -n 100 --no-pager"
    exit 1
  fi

  # 检查 API 端口监听（默认 127.0.0.1:10085）
  if ! ss -lntp 2>/dev/null | grep -qE '127\.0\.0\.1:10085\b'; then
    echo "❌ 未检测到 127.0.0.1:10085 监听。"
    echo "   说明：Xray API 可能未启用或配置未生效。"
    echo "   你可以：grep -n '\"api\"' -n $XRAY_CFG && systemctl restart xray"
    exit 1
  fi
}

install_scripts() {
  # 统一 env 加载脚本：必须 source，且所有变量有兜底，避免 set -u 炸
  cat >/usr/local/sbin/vless_load_env.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/usr/local/etc/xray/env.conf"

# 兜底默认值（避免 unbound variable）
API_SERVER="${API_SERVER:-127.0.0.1:10085}"
SERVER_ADDR="${SERVER_ADDR:-}"
PORT_RANGE_START="${PORT_RANGE_START:-40000}"
PORT_RANGE_END="${PORT_RANGE_END:-50050}"
CLIENT_FP="${CLIENT_FP:-chrome}"

# 载入 env.conf（必须 source）
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

# 再兜底一次
API_SERVER="${API_SERVER:-127.0.0.1:10085}"
PORT_RANGE_START="${PORT_RANGE_START:-40000}"
PORT_RANGE_END="${PORT_RANGE_END:-50050}"
CLIENT_FP="${CLIENT_FP:-chrome}"

export API_SERVER SERVER_ADDR PORT_RANGE_START PORT_RANGE_END CLIENT_FP
EOF
  chmod +x /usr/local/sbin/vless_load_env.sh

  # 解析主配置的 Reality 参数 + 主节点 URL 的 pbk（公共密钥）
  cat >/usr/local/sbin/vless_read_reality.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

MAIN_CFG="/usr/local/etc/xray/config.json"
URL_FILE="/root/vless_reality_vision_url.txt"

[[ -f "$MAIN_CFG" ]] || { echo "ERR: missing $MAIN_CFG" >&2; exit 1; }

python3 - "$MAIN_CFG" "$URL_FILE" <<'PY'
import json,sys,re
cfg=json.load(open(sys.argv[1]))

# 默认取第一个 inbound
ibs=cfg.get("inbounds",[])
if not ibs:
    raise SystemExit("ERR: no inbounds in main config")

ib=ibs[0]
rs=ib.get("streamSettings",{}).get("realitySettings",{})

priv=rs.get("privateKey","")
dest=rs.get("dest","")
sns=rs.get("serverNames",[]) or []
sni=sns[0] if sns else ""

shorts=rs.get("shortIds",[]) or []
sid=shorts[0] if shorts else ""

pbk=""
url_file=sys.argv[2]
if url_file and url_file != "": 
    try:
        line=open(url_file).read().strip().splitlines()[0]
        m=re.search(r"(?:\?|&)pbk=([^&]+)", line)
        if m: pbk=m.group(1)
    except Exception:
        pass

print(priv)
print(dest)
print(sni)
print(sid)
print(pbk)
PY
EOF
  chmod +x /usr/local/sbin/vless_read_reality.sh

  # 选择公网地址（修复你遇到的 [[ ... && ! func ]] 写法）
  cat >/usr/local/sbin/vless_detect_addr.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

is_private_ip() {
  local ip="$1"
  [[ "$ip" =~ ^10\. ]] && return 0
  [[ "$ip" =~ ^127\. ]] && return 0
  [[ "$ip" =~ ^192\.168\. ]] && return 0
  [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
  return 1
}

detect_ipv4_public_first() {
  local ip=""
  ip="$(curl -4fsS --connect-timeout 2 --max-time 6 --retry 2 --retry-delay 1 --retry-all-errors https://api.ipify.org || true)"
  if [[ -n "$ip" ]] && ! is_private_ip "$ip"; then
    echo "$ip"; return 0
  fi

  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  if [[ -n "$ip" ]] && ! is_private_ip "$ip"; then
    echo "$ip"; return 0
  fi

  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  if [[ -n "$ip" ]] && ! is_private_ip "$ip"; then
    echo "$ip"; return 0
  fi

  echo ""
}
detect_ipv4_public_first
EOF
  chmod +x /usr/local/sbin/vless_detect_addr.sh

  # 创建临时入站（单进程）
  cat >/usr/local/sbin/vless_mktemp.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

: "${D:?用法：D=600 vless_mktemp.sh（D 为秒）}"
if ! [[ "$D" =~ ^[0-9]+$ ]] || (( D <= 0 )); then
  echo "❌ D 必须为正整数秒" >&2
  exit 1
fi

. /usr/local/sbin/vless_load_env.sh

BIN_XRAY="/usr/local/bin/xray"
STATE_DIR="/usr/local/etc/xray/tmpnodes"
mkdir -p "$STATE_DIR" /run/lock

LOCK="/run/lock/vless-temp.lock"
exec 9>"$LOCK"
# 避免并发互相抢端口/写状态
if ! flock -n 9; then
  echo "❌ 另一个 vless_mktemp/gc/restore 正在运行，请稍后再试" >&2
  exit 1
fi

# Reality 参数
read -r R_PRIV R_DEST R_SNI R_SID R_PBK < <(/usr/local/sbin/vless_read_reality.sh)

if [[ -z "$R_PRIV" || -z "$R_DEST" ]]; then
  echo "❌ 无法从主配置解析 realitySettings.privateKey/dest" >&2
  exit 1
fi
[[ -n "$R_SNI" ]] || R_SNI="${R_DEST%%:*}"

# 选择对外地址
if [[ -z "${SERVER_ADDR:-}" ]]; then
  SERVER_ADDR="$(/usr/local/sbin/vless_detect_addr.sh)"
fi
if [[ -z "${SERVER_ADDR:-}" ]]; then
  SERVER_ADDR="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
fi
if [[ -z "${SERVER_ADDR:-}" ]]; then
  echo "❌ 无法确定对外地址，请在 $ENV_FILE 里手动设置 SERVER_ADDR=域名或公网IP" >&2
  exit 1
fi

# 选端口：不监听 + 不在 state_dir 里已占用
START="${PORT_RANGE_START}"
END="${PORT_RANGE_END}"

pick_port() {
  local p
  for p in $(seq "$START" "$END"); do
    if ss -ltnH 2>/dev/null | awk '{print $4}' | sed 's/.*://g' | grep -qx "$p"; then
      continue
    fi
    if ls "$STATE_DIR"/*.meta.json >/dev/null 2>&1; then
      if python3 - "$STATE_DIR" "$p" <<'PY'
import json,glob,sys
d=sys.argv[1]; p=int(sys.argv[2])
for f in glob.glob(d+"/*.meta.json"):
  try:
    o=json.load(open(f))
    if int(o.get("port",0))==p:
      print("used"); raise SystemExit(0)
  except: pass
print("free")
PY
      then :; fi | grep -qx "used"; then
        continue
      fi
    fi
    echo "$p"
    return 0
  done
  echo ""
  return 1
}

PORT="$(pick_port)"
if [[ -z "$PORT" ]]; then
  echo "❌ 端口耗尽：${START}-${END}" >&2
  exit 1
fi

UUID="$("$BIN_XRAY" uuid)"
TAG="vless-tmp-${PORT}"
EMAIL="${TAG}@temp"

NOW="$(date +%s)"
EXP="$((NOW + D))"

INB_JSON="${STATE_DIR}/${TAG}.inbound.json"
META_JSON="${STATE_DIR}/${TAG}.meta.json"

cat >"$INB_JSON" <<JSON
{
  "tag": "${TAG}",
  "listen": "0.0.0.0",
  "port": ${PORT},
  "protocol": "vless",
  "settings": {
    "clients": [
      { "id": "${UUID}", "email": "${EMAIL}", "flow": "xtls-rprx-vision" }
    ],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "show": false,
      "dest": "${R_DEST}",
      "xver": 0,
      "serverNames": [ "${R_SNI}" ],
      "privateKey": "${R_PRIV}",
      "shortIds": [ "${R_SID}" ]
    }
  }
}
JSON

cat >"$META_JSON" <<JSON
{
  "tag": "${TAG}",
  "email": "${EMAIL}",
  "uuid": "${UUID}",
  "port": ${PORT},
  "created_epoch": ${NOW},
  "expire_epoch": ${EXP},
  "server_addr": "${SERVER_ADDR}",
  "sni": "${R_SNI}",
  "sid": "${R_SID}",
  "pbk": "${R_PBK}"
}
JSON

# 添加 inbound（单进程动态）
if ! "$BIN_XRAY" api adi --server="$API_SERVER" "$INB_JSON" >/tmp/adi.log 2>&1; then
  echo "❌ 添加 inbound 失败（xray api adi）"
  sed -n '1,200p' /tmp/adi.log || true
  rm -f "$INB_JSON" "$META_JSON"
  exit 1
fi

# 等待端口出现监听
for _ in {1..10}; do
  if ss -ltnH 2>/dev/null | awk '{print $4}' | sed 's/.*://g' | grep -qx "$PORT"; then
    break
  fi
  sleep 0.15
done

E_STR="$(TZ=Asia/Shanghai date -d "@$EXP" '+%F %T')"

PBK_PARAM=""
if [[ -n "${R_PBK:-}" ]]; then
  PBK_PARAM="&pbk=${R_PBK}"
fi
SID_PARAM=""
if [[ -n "${R_SID:-}" ]]; then
  SID_PARAM="&sid=${R_SID}"
fi

VLESS_URL="vless://${UUID}@${SERVER_ADDR}:${PORT}?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&sni=${R_SNI}&fp=${CLIENT_FP}${PBK_PARAM}${SID_PARAM}#${TAG}"

echo "✅ 新临时节点(单进程): ${TAG}
端口: ${PORT}
UUID: ${UUID}
到期(北京时间): ${E_STR}
链接:
${VLESS_URL}"
EOF
  chmod +x /usr/local/sbin/vless_mktemp.sh

  # 删除一个临时入站（按 tag 或 port）
  cat >/usr/local/sbin/vless_rmi_one.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

. /usr/local/sbin/vless_load_env.sh

BIN_XRAY="/usr/local/bin/xray"
STATE_DIR="/usr/local/etc/xray/tmpnodes"
mkdir -p "$STATE_DIR" /run/lock

ARG="${1:-}"
if [[ -z "$ARG" ]]; then
  echo "用法：vless_rmi_one.sh <tag|port>" >&2
  exit 1
fi

if [[ "$ARG" =~ ^[0-9]+$ ]]; then
  TAG="vless-tmp-${ARG}"
else
  TAG="$ARG"
fi

LOCK="/run/lock/vless-temp.lock"
exec 9>"$LOCK"
flock -n 9 || { echo "❌ 另一个任务正在运行"; exit 1; }

# 兼容不同版本 rmi 参数：优先 -tag
RMI_HELP="$("$BIN_XRAY" help api rmi 2>/dev/null || true)"
if echo "$RMI_HELP" | grep -q -- "-tag"; then
  "$BIN_XRAY" api rmi --server="$API_SERVER" -tag="$TAG" >/tmp/rmi.log 2>&1 || true
else
  "$BIN_XRAY" api rmi --server="$API_SERVER" "$TAG" >/tmp/rmi.log 2>&1 || true
fi

# 清理状态文件
rm -f "${STATE_DIR}/${TAG}.inbound.json" "${STATE_DIR}/${TAG}.meta.json" >/dev/null 2>&1 || true

echo "✅ 已尝试删除：$TAG"
if [[ -s /tmp/rmi.log ]]; then
  # 不强制报错，避免已不存在时影响流程
  sed -n '1,120p' /tmp/rmi.log || true
fi
EOF
  chmod +x /usr/local/sbin/vless_rmi_one.sh

  # 审计
  cat >/usr/local/sbin/vless_audit.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

STATE_DIR="/usr/local/etc/xray/tmpnodes"

echo "==== XRAY 主进程 ===="
systemctl is-active xray && echo "xray.service: active" || echo "xray.service: NOT active"
echo

printf "%-36s %-6s %-8s %-12s %-20s\n" "TAG" "PORT" "STATE" "LEFT" "EXPIRE(China)"

NOW="$(date +%s)"

for META in "$STATE_DIR"/*.meta.json; do
  python3 - "$META" "$NOW" <<'PY'
import json,sys,time
p=sys.argv[1]; now=int(sys.argv[2])
o=json.load(open(p))
tag=o.get("tag","?")
port=o.get("port","?")
exp=int(o.get("expire_epoch",0))
left=exp-now
if left<=0:
  left_s="expired"
else:
  d=left//86400; h=(left%86400)//3600; m=(left%3600)//60
  left_s=f"{d:02d}d{h:02d}h{m:02d}m"
# state from systemctl is not applicable (single process); check listen port
import subprocess
try:
  out=subprocess.check_output(["bash","-lc",f"ss -ltnH 2>/dev/null | awk '{{print $4}}' | sed 's/.*://g' | grep -qx {port} && echo alive || echo dead"],text=True).strip()
  st=out or "unknown"
except Exception:
  st="unknown"

import datetime,os
try:
  exp_str=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(exp))
  # convert to China time (+8)
  exp_cn=datetime.datetime.utcfromtimestamp(exp)+datetime.timedelta(hours=8)
  exp_str=exp_cn.strftime("%Y-%m-%d %H:%M:%S")
except Exception:
  exp_str="N/A"

print(f"{tag:<36} {str(port):<6} {st:<8} {left_s:<12} {exp_str:<20}")
PY
done
EOF
  chmod +x /usr/local/sbin/vless_audit.sh

  # GC：到期删除
  cat >/usr/local/sbin/vless_gc.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

. /usr/local/sbin/vless_load_env.sh

BIN_XRAY="/usr/local/bin/xray"
STATE_DIR="/usr/local/etc/xray/tmpnodes"
mkdir -p "$STATE_DIR" /run/lock

LOCK="/run/lock/vless-temp.lock"
exec 9>"$LOCK"
# GC 不用抢占式失败，等一下更稳
flock 9

NOW="$(date +%s)"

for META in "$STATE_DIR"/*.meta.json; do
  TAG="$(python3 - "$META" <<'PY'
import json,sys
o=json.load(open(sys.argv[1]))
print(o.get("tag",""))
PY
)"
  EXP="$(python3 - "$META" <<'PY'
import json,sys
o=json.load(open(sys.argv[1]))
print(int(o.get("expire_epoch",0)))
PY
)"
  [[ -n "$TAG" ]] || continue
  if (( EXP > 0 && EXP <= NOW )); then
    # 删除 inbound
    RMI_HELP="$("$BIN_XRAY" help api rmi 2>/dev/null || true)"
    if echo "$RMI_HELP" | grep -q -- "-tag"; then
      "$BIN_XRAY" api rmi --server="$API_SERVER" -tag="$TAG" >/dev/null 2>&1 || true
    else
      "$BIN_XRAY" api rmi --server="$API_SERVER" "$TAG" >/dev/null 2>&1 || true
    fi
    rm -f "$STATE_DIR/${TAG}.inbound.json" "$STATE_DIR/${TAG}.meta.json" >/dev/null 2>&1 || true
  fi
done
EOF
  chmod +x /usr/local/sbin/vless_gc.sh

  # clear all
  cat >/usr/local/sbin/vless_clear_all.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

STATE_DIR="/usr/local/etc/xray/tmpnodes"

for META in "$STATE_DIR"/*.meta.json; do
  TAG="$(python3 - "$META" <<'PY'
import json,sys
o=json.load(open(sys.argv[1]))
print(o.get("tag",""))
PY
)"
  [[ -n "$TAG" ]] || continue
  /usr/local/sbin/vless_rmi_one.sh "$TAG" >/dev/null 2>&1 || true
done

echo "✅ 已执行清空流程（所有临时入站）"
EOF
  chmod +x /usr/local/sbin/vless_clear_all.sh

  # restore：重启后把未过期的 inbound 重新加回去（API 动态 inbounds 默认不持久化）
  cat >/usr/local/sbin/vless_restore.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

. /usr/local/sbin/vless_load_env.sh

BIN_XRAY="/usr/local/bin/xray"
STATE_DIR="/usr/local/etc/xray/tmpnodes"
mkdir -p "$STATE_DIR" /run/lock

LOCK="/run/lock/vless-temp.lock"
exec 9>"$LOCK"
flock 9

NOW="$(date +%s)"

list_has_tag() {
  local tag="$1"
  local out
  out="$("$BIN_XRAY" api lsi --server="$API_SERVER" 2>/dev/null || true)"
  echo "$out" | grep -qE "(\"tag\"[[:space:]]*:[[:space:]]*\"${tag}\")|(\b${tag}\b)"
}

for META in "$STATE_DIR"/*.meta.json; do
  TAG="$(python3 - "$META" <<'PY'
import json,sys
o=json.load(open(sys.argv[1]))
print(o.get("tag",""))
PY
)"
  EXP="$(python3 - "$META" <<'PY'
import json,sys
o=json.load(open(sys.argv[1]))
print(int(o.get("expire_epoch",0)))
PY
)"
  [[ -n "$TAG" ]] || continue

  if (( EXP > 0 && EXP <= NOW )); then
    # 过期直接清理
    /usr/local/sbin/vless_rmi_one.sh "$TAG" >/dev/null 2>&1 || true
    continue
  fi

  # 未过期：若不存在则恢复
  if list_has_tag "$TAG"; then
    continue
  fi

  INB_JSON="$STATE_DIR/${TAG}.inbound.json"
  if [[ -f "$INB_JSON" ]]; then
    "$BIN_XRAY" api adi --server="$API_SERVER" "$INB_JSON" >/dev/null 2>&1 || true
  fi
done
EOF
  chmod +x /usr/local/sbin/vless_restore.sh

  # systemd: restore + gc timer
  cat >/etc/systemd/system/vless-restore.service <<'EOF'
[Unit]
Description=Restore VLESS temp inbounds (single-process)
After=network.target xray.service
Wants=xray.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vless_restore.sh
EOF

  cat >/etc/systemd/system/vless-gc.service <<'EOF'
[Unit]
Description=GC expired VLESS temp inbounds (single-process)
After=network.target xray.service
Wants=xray.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vless_gc.sh
EOF

  cat >/etc/systemd/system/vless-gc.timer <<'EOF'
[Unit]
Description=Run VLESS temp GC every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now vless-gc.timer >/dev/null 2>&1 || true
  systemctl enable vless-restore.service >/dev/null 2>&1 || true

  echo "✅ 代码2脚本已部署："
  echo "  - D=600 vless_mktemp.sh"
  echo "  - vless_audit.sh"
  echo "  - vless_rmi_one.sh <tag|port>"
  echo "  - vless_clear_all.sh"
  echo "  - systemd: vless-restore.service + vless-gc.timer"
}

main() {
  need_root
  need_tools
  ensure_env_file
  patch_xray_api_config_if_needed
  restart_xray_and_check_api
  install_scripts
  echo
  echo "✅ 完成。建议你现在立刻执行一次："
  echo "   systemctl start vless-restore.service"
  echo "   vless_audit.sh"
  echo
  echo "📌 重要：如果你是 NAT/域名/端口映射环境，请编辑：$ENV_FILE"
  echo '   设置 SERVER_ADDR="你的域名或公网IP"'
}
main "$@"
