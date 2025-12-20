#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

if [[ "${EUID}" -ne 0 ]]; then
  echo "❌ 请使用 root 运行"
  exit 1
fi

apt-get update -y
apt-get install -y curl ca-certificates unzip jq openssl python3 iproute2

mkdir -p /usr/local/sbin /usr/local/etc/xray /var/log/xray

############################################
# 1) update-all
############################################
cat >/usr/local/sbin/update-all <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "🚀 开始系统更新 (Debian 12 / bookworm)..."
apt-get update -y
apt-get -y full-upgrade
apt-get -y autoremove --purge
apt-get -y autoclean
echo "✅ 软件包更新完成"
echo "🧠 建议：如安装了新内核/ssh 等关键组件，重启一次更稳：reboot"
EOF
chmod +x /usr/local/sbin/update-all

############################################
# 2) /root/onekey_reality_ipv4.sh
############################################
cat >/root/onekey_reality_ipv4.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "❌ 请用 root 运行"
    exit 1
  fi
}

get_public_ipv4() {
  local ip=""
  ip="$(curl -4fsSL https://api.ipify.org 2>/dev/null || true)"
  [[ -n "$ip" ]] || ip="$(curl -4fsSL https://ipv4.icanhazip.com 2>/dev/null | tr -d '\n' || true)"
  echo "$ip"
}

enable_fq_bbr() {
  echo "=== 1) 只开启 fq + bbr（其余 sysctl 保持默认）==="
  mkdir -p /etc/sysctl.d
  cat >/etc/sysctl.d/99-fq-bbr.conf <<'EOT'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOT
  sysctl --system >/dev/null 2>&1 || true

  local qdisc cc
  qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
  cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
  echo "当前: qdisc=${qdisc}, cc=${cc}"
}

install_or_update_xray() {
  echo "=== 2) 安装/更新 xray（官方 install-release.sh）==="
  # 官方安装脚本：XTLS/Xray-install
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
  command -v /usr/local/bin/xray >/dev/null 2>&1 || { echo "❌ xray 安装失败"; exit 1; }
}

gen_uuid() {
  cat /proc/sys/kernel/random/uuid
}

# 兼容旧输出 PublicKey / Public key + 新输出 Password（即旧 publicKey）
gen_x25519() {
  local out priv pub
  out="$(/usr/local/bin/xray x25519 2>/dev/null || true)"

  priv="$(echo "$out" | awk -F': *' '
    {k=tolower($1)}
    k=="privatekey" || k=="private key" {print $2; exit}
  ')"

  pub="$(echo "$out" | awk -F': *' '
    {k=tolower($1)}
    k=="publickey" || k=="public key" || k=="password" {print $2; exit}
  ')"

  if [[ -z "${priv}" || -z "${pub}" ]]; then
    echo "❌ x25519 生成失败，输出："
    echo "$out"
    return 1
  fi

  echo "${priv}|${pub}"
}

main() {
  need_root

  # 可自定义（环境变量覆盖）
  PORT="${PORT:-443}"
  SNI="${SNI:-www.apple.com}"
  DEST="${DEST:-www.apple.com:443}"
  API_SERVER="${API_SERVER:-127.0.0.1:10085}"

  local ip
  ip="$(get_public_ipv4)"
  if [[ -z "$ip" ]]; then
    echo "⚠️ 无法探测公网 IPv4（将继续安装，但输出链接可能不对）"
    ip="YOUR_SERVER_IP"
  fi

  echo "服务器地址(探测): ${ip}"
  echo "伪装域名:         ${SNI}"
  echo "端口:             ${PORT}"
  echo "API 监听:         ${API_SERVER}"

  enable_fq_bbr
  install_or_update_xray

  echo "=== 3) 生成 UUID + Reality 密钥 ==="
  UUID_MAIN="$(gen_uuid)"
  KV="$(gen_x25519)"
  REALITY_PRIVATE_KEY="${KV%%|*}"
  REALITY_PUBLIC_KEY="${KV##*|}"
  REALITY_SHORT_ID="$(openssl rand -hex 8)"

  mkdir -p /usr/local/etc/xray /var/log/xray

  cat >/usr/local/etc/xray/config.json <<EOT
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "api": {
    "tag": "api",
    "listen": "${API_SERVER}",
    "services": ["HandlerService", "LoggerService", "StatsService"]
  },
  "inbounds": [
    {
      "tag": "vless-main",
      "listen": "0.0.0.0",
      "port": ${PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID_MAIN}",
            "flow": "xtls-rprx-vision",
            "email": "main@reality"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${DEST}",
          "xver": 0,
          "serverNames": ["${SNI}"],
          "privateKey": "${REALITY_PRIVATE_KEY}",
          "shortIds": ["${REALITY_SHORT_ID}"]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ]
}
EOT

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable xray >/dev/null 2>&1 || true
  systemctl restart xray

  # 写入 env，供临时节点脚本使用（避免再去 parse 主配置）
  cat >/usr/local/etc/xray/env.conf <<EOT
SERVER_IP="${ip}"
PORT="${PORT}"
SNI="${SNI}"
DEST="${DEST}"
API_SERVER="${API_SERVER}"
FLOW="xtls-rprx-vision"
UUID_MAIN="${UUID_MAIN}"
REALITY_PRIVATE_KEY="${REALITY_PRIVATE_KEY}"
REALITY_PUBLIC_KEY="${REALITY_PUBLIC_KEY}"
REALITY_SHORT_ID="${REALITY_SHORT_ID}"
EOT
  chmod 600 /usr/local/etc/xray/env.conf

  MAIN_URL="vless://${UUID_MAIN}@${ip}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#reality-main"
  echo "${MAIN_URL}" | tee /root/vless_main.txt >/dev/null
  echo -n "${MAIN_URL}" | base64 -w0 > /root/vless_main_sub_base64.txt

  echo "✅ 主节点完成："
  echo "----------------------------------------"
  echo "${MAIN_URL}"
  echo "----------------------------------------"
  echo "文件："
  echo " - /root/vless_main.txt"
  echo " - /root/vless_main_sub_base64.txt"
  echo " - /usr/local/etc/xray/env.conf"
}

main "$@"
EOF
chmod +x /root/onekey_reality_ipv4.sh

############################################
# 3) /root/vless_temp_dynamic_inbound.sh
############################################
cat >/root/vless_temp_dynamic_inbound.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "❌ 请用 root 运行"
    exit 1
  fi
}

install_env_loader() {
  cat >/usr/local/sbin/vless_env.sh <<'EOT'
#!/usr/bin/env bash
set -euo pipefail
ENV_FILE="/usr/local/etc/xray/env.conf"
if [[ ! -f "${ENV_FILE}" ]]; then
  echo "❌ 未找到 ${ENV_FILE}"
  echo "请先执行：bash /root/onekey_reality_ipv4.sh"
  exit 1
fi
# shellcheck disable=SC1090
source "${ENV_FILE}"

: "${SERVER_IP:?}"
: "${SNI:?}"
: "${DEST:?}"
: "${API_SERVER:?}"
: "${FLOW:?}"
: "${REALITY_PRIVATE_KEY:?}"
: "${REALITY_PUBLIC_KEY:?}"
: "${REALITY_SHORT_ID:?}"
EOT
  chmod +x /usr/local/sbin/vless_env.sh
}

install_mktemp() {
  cat >/usr/local/sbin/vless_mktemp.sh <<'EOT'
#!/usr/bin/env bash
set -euo pipefail
# 用法：D=600 vless_mktemp.sh  （D 单位：分钟，默认 600）
# 可选：PORT_START=40000 从指定端口起顺序分配

# shellcheck disable=SC1091
source /usr/local/sbin/vless_env.sh

TMP_DIR="/usr/local/etc/xray/tmpusers"
mkdir -p "${TMP_DIR}"

D_MIN="${D:-600}"
PORT_START="${PORT_START:-40000}"

now_ts() { date +%s; }

port_is_free() {
  local p="$1"
  # ss -ltnH "sport = :PORT" 有输出则占用
  if ss -ltnH "sport = :${p}" 2>/dev/null | grep -q .; then
    return 1
  fi
  return 0
}

alloc_port() {
  local p="${PORT_START}"
  while true; do
    if port_is_free "${p}" && [[ ! -f "${TMP_DIR}/vless-tmp-${p}.meta" ]]; then
      echo "${p}"
      return 0
    fi
    p=$((p+1))
    if (( p > 65535 )); then
      echo "❌ 端口已用尽（>${p}）"
      exit 1
    fi
  done
}

api_adi() {
  local file="$1"
  # 新版常见：xray api adi --server 127.0.0.1:10085 file.json
  if /usr/local/bin/xray api adi --server "${API_SERVER}" "${file}" >/dev/null 2>&1; then return 0; fi
  # 兼容旧写法（若存在）
  if /usr/local/bin/xray api adi -s "${API_SERVER}" -f "${file}" >/dev/null 2>&1; then return 0; fi
  if /usr/local/bin/xray api -s "${API_SERVER}" adi -f "${file}" >/dev/null 2>&1; then return 0; fi
  echo "❌ API 添加入站失败（adi）。请检查：/usr/local/bin/xray help api"
  return 1
}

mk_url() {
  local uuid="$1" host="$2" port="$3" tag="$4"
  echo "vless://${uuid}@${host}:${port}?encryption=none&flow=${FLOW}&security=reality&sni=${SNI}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_SHORT_ID}&type=tcp#${tag}"
}

main() {
  local p tag uuid cfg meta created expire url
  p="$(alloc_port)"
  tag="vless-tmp-${p}"
  uuid="$(cat /proc/sys/kernel/random/uuid)"
  created="$(now_ts)"
  expire="$(( created + D_MIN*60 ))"

  cfg="${TMP_DIR}/${tag}.json"
  meta="${TMP_DIR}/${tag}.meta"

  cat >"${cfg}" <<EOF
{
  "inbounds": [
    {
      "tag": "${tag}",
      "listen": "0.0.0.0",
      "port": ${p},
      "protocol": "vless",
      "settings": {
        "decryption": "none",
        "clients": [
          {
            "id": "${uuid}",
            "flow": "${FLOW}",
            "email": "${tag}"
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${DEST}",
          "xver": 0,
          "serverNames": ["${SNI}"],
          "privateKey": "${REALITY_PRIVATE_KEY}",
          "shortIds": ["${REALITY_SHORT_ID}"]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }
    }
  ]
}
EOF

  api_adi "${cfg}"

  cat >"${meta}" <<EOF
TAG=${tag}
PORT=${p}
UUID=${uuid}
CREATED_TS=${created}
EXPIRE_TS=${expire}
CFG=${cfg}
EOF

  url="$(mk_url "${uuid}" "${SERVER_IP}" "${p}" "${tag}")"

  echo "${url}"
  echo "${url}" >>/root/vless_temp_urls.txt
  base64 -w0 /root/vless_temp_urls.txt > /root/vless_temp_sub_base64.txt

  echo "✅ 已创建临时入站：${tag}（端口 ${p}）"
  echo "⏳ 有效期：${D_MIN} 分钟，到期时间：$(date -d "@${expire}" '+%F %T')"
  echo "📄 订阅（base64聚合）：/root/vless_temp_sub_base64.txt"
}

main "$@"
EOT
  chmod +x /usr/local/sbin/vless_mktemp.sh
}

install_rmi_one() {
  cat >/usr/local/sbin/vless_rmi_one.sh <<'EOT'
#!/usr/bin/env bash
set -euo pipefail
# 用法：vless_rmi_one.sh 40035  或  vless_rmi_one.sh vless-tmp-40035

# shellcheck disable=SC1091
source /usr/local/sbin/vless_env.sh

TMP_DIR="/usr/local/etc/xray/tmpusers"
mkdir -p "${TMP_DIR}"

api_rmi() {
  local tag="$1"
  if /usr/local/bin/xray api rmi --server "${API_SERVER}" "${tag}" >/dev/null 2>&1; then return 0; fi
  if /usr/local/bin/xray api rmi -s "${API_SERVER}" -t "${tag}" >/dev/null 2>&1; then return 0; fi
  if /usr/local/bin/xray api -s "${API_SERVER}" rmi -t "${tag}" >/dev/null 2>&1; then return 0; fi
  return 1
}

main() {
  if [[ $# -lt 1 ]]; then
    echo "用法：vless_rmi_one.sh <port|tag>"
    exit 1
  fi

  local arg="$1" tag
  if [[ "${arg}" =~ ^[0-9]+$ ]]; then
    tag="vless-tmp-${arg}"
  else
    tag="${arg}"
  fi

  local meta="${TMP_DIR}/${tag}.meta"
  local cfg="${TMP_DIR}/${tag}.json"

  set +e
  api_rmi "${tag}"
  set -e

  rm -f "${meta}" "${cfg}"
  echo "✅ 已移除：${tag}"
}

main "$@"
EOT
  chmod +x /usr/local/sbin/vless_rmi_one.sh
}

install_audit() {
  cat >/usr/local/sbin/vless_audit.sh <<'EOT'
#!/usr/bin/env bash
set -euo pipefail
TMP_DIR="/usr/local/etc/xray/tmpusers"
mkdir -p "${TMP_DIR}"

now="$(date +%s)"

printf "%-16s %-8s %-20s %-10s\n" "TAG" "PORT" "EXPIRE" "LEFT(min)"
echo "--------------------------------------------------------------"

shopt -s nullglob
for meta in "${TMP_DIR}"/vless-tmp-*.meta; do
  # shellcheck disable=SC1090
  source "${meta}"
  exp="${EXPIRE_TS:-0}"
  left_sec=$((exp - now))
  left_min=$((left_sec / 60))
  exp_str="$(date -d "@${exp}" '+%F %T' 2>/dev/null || echo "${exp}")"
  printf "%-16s %-8s %-20s %-10s\n" "${TAG:-?}" "${PORT:-?}" "${exp_str}" "${left_min}"
done
EOT
  chmod +x /usr/local/sbin/vless_audit.sh
}

install_clear_all() {
  cat >/usr/local/sbin/vless_clear_all.sh <<'EOT'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /usr/local/sbin/vless_env.sh

TMP_DIR="/usr/local/etc/xray/tmpusers"
mkdir -p "${TMP_DIR}"

api_rmi() {
  local tag="$1"
  /usr/local/bin/xray api rmi --server "${API_SERVER}" "${tag}" >/dev/null 2>&1 && return 0
  /usr/local/bin/xray api rmi -s "${API_SERVER}" -t "${tag}" >/dev/null 2>&1 && return 0
  /usr/local/bin/xray api -s "${API_SERVER}" rmi -t "${tag}" >/dev/null 2>&1 && return 0
  return 1
}

shopt -s nullglob
for meta in "${TMP_DIR}"/vless-tmp-*.meta; do
  # shellcheck disable=SC1090
  source "${meta}"
  tag="${TAG:-}"
  [[ -n "${tag}" ]] || continue
  set +e
  api_rmi "${tag}"
  set -e
  rm -f "${TMP_DIR}/${tag}.meta" "${TMP_DIR}/${tag}.json"
done

echo "✅ 已清空所有临时入站"
EOT
  chmod +x /usr/local/sbin/vless_clear_all.sh
}

install_gc_and_restore() {
  cat >/usr/local/sbin/vless_gc.sh <<'EOT'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /usr/local/sbin/vless_env.sh

TMP_DIR="/usr/local/etc/xray/tmpusers"
mkdir -p "${TMP_DIR}"

api_rmi() {
  local tag="$1"
  /usr/local/bin/xray api rmi --server "${API_SERVER}" "${tag}" >/dev/null 2>&1 && return 0
  /usr/local/bin/xray api rmi -s "${API_SERVER}" -t "${tag}" >/dev/null 2>&1 && return 0
  /usr/local/bin/xray api -s "${API_SERVER}" rmi -t "${tag}" >/dev/null 2>&1 && return 0
  return 1
}

now="$(date +%s)"
shopt -s nullglob
for meta in "${TMP_DIR}"/vless-tmp-*.meta; do
  # shellcheck disable=SC1090
  source "${meta}"
  exp="${EXPIRE_TS:-0}"
  tag="${TAG:-}"
  [[ -n "${tag}" ]] || continue
  if (( exp <= now )); then
    set +e
    api_rmi "${tag}"
    set -e
    rm -f "${TMP_DIR}/${tag}.meta" "${TMP_DIR}/${tag}.json"
  fi
done
EOT
  chmod +x /usr/local/sbin/vless_gc.sh

  cat >/usr/local/sbin/vless_restore.sh <<'EOT'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /usr/local/sbin/vless_env.sh

TMP_DIR="/usr/local/etc/xray/tmpusers"
mkdir -p "${TMP_DIR}"

api_adi() {
  local file="$1"
  /usr/local/bin/xray api adi --server "${API_SERVER}" "${file}" >/dev/null 2>&1 && return 0
  /usr/local/bin/xray api adi -s "${API_SERVER}" -f "${file}" >/dev/null 2>&1 && return 0
  /usr/local/bin/xray api -s "${API_SERVER}" adi -f "${file}" >/dev/null 2>&1 && return 0
  return 1
}

now="$(date +%s)"
shopt -s nullglob
for meta in "${TMP_DIR}"/vless-tmp-*.meta; do
  # shellcheck disable=SC1090
  source "${meta}"
  exp="${EXPIRE_TS:-0}"
  cfg="${CFG:-}"
  if (( exp > now )) && [[ -n "${cfg}" && -f "${cfg}" ]]; then
    # 已存在会失败，忽略即可
    api_adi "${cfg}" || true
  fi
done
EOT
  chmod +x /usr/local/sbin/vless_restore.sh

  cat >/etc/systemd/system/vless-restore.service <<'EOT'
[Unit]
Description=Restore temporary VLESS inbounds (Reality)
After=network-online.target xray.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vless_restore.sh

[Install]
WantedBy=multi-user.target
EOT

  cat >/etc/systemd/system/vless-gc.service <<'EOT'
[Unit]
Description=GC expired temporary VLESS inbounds (Reality)
After=xray.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vless_gc.sh
EOT

  cat >/etc/systemd/system/vless-gc.timer <<'EOT'
[Unit]
Description=Run vless-gc.service periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
Unit=vless-gc.service

[Install]
WantedBy=timers.target
EOT

  systemctl daemon-reload
  systemctl enable --now vless-restore.service >/dev/null 2>&1 || true
  systemctl enable --now vless-gc.timer >/dev/null 2>&1 || true
}

main() {
  need_root
  install_env_loader
  install_mktemp
  install_rmi_one
  install_audit
  install_clear_all
  install_gc_and_restore

  echo "=================================================="
  echo "✅ 已安装临时节点系统（最新方案：动态端口 + adi/rmi）"
  echo ""
  echo "常用命令："
  echo " - D=600 vless_mktemp.sh          # 创建临时节点（默认 600 分钟）"
  echo " - vless_audit.sh                 # 查看临时节点列表"
  echo " - vless_rmi_one.sh 40035         # 删除指定端口节点"
  echo " - vless_clear_all.sh             # 清空所有临时节点"
  echo ""
  echo "订阅聚合（base64）：/root/vless_temp_sub_base64.txt"
  echo "=================================================="
}

main "$@"
EOF
chmod +x /root/vless_temp_dynamic_inbound.sh

############################################
# 4) 兼容入口（可选）
############################################
cat >/root/vless_temp_audit_ipv4_all.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "ℹ️ 该入口已合并到动态端口方案。正在执行：/root/vless_temp_dynamic_inbound.sh"
bash /root/vless_temp_dynamic_inbound.sh
EOF
chmod +x /root/vless_temp_audit_ipv4_all.sh

############################################
# 5) 收尾提示
############################################
cat >/root/README_huanxin.txt <<'EOF'
✅ 所有脚本已生成完毕（Debian 12 / 最新方案：动态端口 + adi/rmi）

建议顺序：
1) update-all && reboot
2) bash /root/onekey_reality_ipv4.sh
3) bash /root/vless_temp_dynamic_inbound.sh
4) 创建临时节点：D=600 vless_mktemp.sh

常用命令：
- D=600 vless_mktemp.sh
- vless_audit.sh
- vless_rmi_one.sh 40035
- vless_clear_all.sh

输出文件：
- /root/vless_main.txt
- /root/vless_main_sub_base64.txt
- /root/vless_temp_sub_base64.txt
EOF

echo "=================================================="
echo "✅ 所有脚本已生成完毕（Debian 12 / 最新方案：动态端口 + adi/rmi）"
echo ""
echo "建议顺序："
echo "1) update-all && reboot"
echo "2) bash /root/onekey_reality_ipv4.sh"
echo "3) bash /root/vless_temp_dynamic_inbound.sh"
echo "4) 创建临时节点：D=600 vless_mktemp.sh"
echo "=================================================="
