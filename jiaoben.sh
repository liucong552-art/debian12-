#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$' \n\t'

log(){ echo -e "\n[+] $*\n"; }
die(){ echo -e "\n[x] $*\n" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo -i"

# ====== 你需要通过环境变量传入的参数 ======
# PANEL_HOST：面板 token-bridge 地址，例如 http://14.137.255.86:7002
# API_KEY：面板 ApiKey（给节点用的）
# NODE_ID：面板里创建的节点 ID
#
# 可选：
# UPDATE_PERIODIC：默认 60（不建议太低）
# =======================================================
PANEL_HOST="${PANEL_HOST:-}"
API_KEY="${API_KEY:-}"
NODE_ID="${NODE_ID:-}"
UPDATE_PERIODIC="${UPDATE_PERIODIC:-60}"

[ -n "$PANEL_HOST" ] || die "缺少 PANEL_HOST，例如 http://14.137.255.86:7002"
[ -n "$API_KEY" ] || die "缺少 API_KEY（面板 ApiKey）"
[ -n "$NODE_ID" ] || die "缺少 NODE_ID（面板创建的节点ID）"

log "Step 1/4: 安装依赖（curl/unzip/ca-certificates）"
apt-get update -y
apt-get install -y curl unzip ca-certificates

log "Step 2/4: 下载并安装 XrayR（二进制 latest）"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) asset="XrayR-linux-64.zip" ;;
  aarch64|arm64) asset="XrayR-linux-arm64.zip" ;;
  armv7l|armv7) asset="XrayR-linux-arm32-v7a.zip" ;;
  *) die "不认识的架构: $arch" ;;
esac

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
curl -fL --retry 5 --retry-delay 2 -o "$tmp/xrayr.zip" \
  "https://github.com/XrayR-project/XrayR/releases/latest/download/${asset}"

unzip -qo "$tmp/xrayr.zip" -d "$tmp/out"
install -m 0755 "$tmp/out/XrayR" /usr/local/bin/XrayR

log "Step 3/4: 写入 /etc/XrayR/config.yml + systemd"
mkdir -p /etc/XrayR

cat >/etc/XrayR/config.yml <<EOF
Log:
  Level: warning

ConnectionConfig:
  Handshake: 4
  ConnIdle: 10
  UplinkOnly: 2
  DownlinkOnly: 4
  BufferSize: 64

Nodes:
  - PanelType: "NewV2board"
    ApiConfig:
      ApiHost: "${PANEL_HOST}"
      ApiKey: "${API_KEY}"
      NodeID: ${NODE_ID}
      NodeType: "V2ray"
      Timeout: 30
      EnableVless: true
      VlessFlow: "xtls-rprx-vision"
    ControllerConfig:
      ListenIP: 0.0.0.0
      SendIP: 0.0.0.0
      UpdatePeriodic: ${UPDATE_PERIODIC}

      # 防 nil/panic & Reality 场景更稳
      DisableLocalREALITYConfig: true
      EnableREALITY: true
      REALITYConfigs:
        Show: false

      CertConfig:
        CertMode: none
EOF

cat >/etc/systemd/system/XrayR.service <<'EOF'
[Unit]
Description=XrayR Service
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/XrayR --config /etc/XrayR/config.yml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now XrayR

log "Step 4/4: 联通性自检（从面板拉 config，解析 server_port 并检查监听）"
echo "[i] 测试面板 token-bridge..."
curl -sS -i -H "Token: ${API_KEY}" \
  "${PANEL_HOST}/api/v1/server/UniProxy/user?node_id=${NODE_ID}&node_type=vless" | sed -n '1,12p' || true

echo "[i] 拉取 node config..."
cfg="$(curl -fsS -H "Token: ${API_KEY}" \
  "${PANEL_HOST}/api/v1/server/UniProxy/config?node_id=${NODE_ID}&node_type=vless" || true)"

if [ -n "$cfg" ]; then
  port="$(echo "$cfg" | sed -n 's/.*"server_port":\([0-9]\+\).*/\1/p' | head -n1 || true)"
  [ -n "$port" ] && echo "[i] 面板下发监听端口 server_port=${port}" || echo "[!] 未解析到 server_port（但不影响 XrayR 运行）"
else
  echo "[!] 拉取 config 失败（可能是面板未放行7002/allow未包含本机IP/ApiKey错误）"
  port=""
fi

echo
systemctl status XrayR --no-pager -l | sed -n '1,18p' || true
journalctl -u XrayR -n 50 --no-pager || true

if [ -n "$port" ]; then
  ss -lntp | grep ":${port}" || echo "[!] 未发现监听 :${port}（请看上面的 XrayR 日志）"
else
  echo "[i] 你也可以手动查看监听端口：ss -lntp | grep XrayR"
  ss -lntp | grep XrayR || true
fi

cat <<EOF

==================== ✅ 节点机完成 ====================

下一步你需要：
1) 在云防火墙/安全组放行 “面板下发的 server_port”（比如 8443/tcp）
2) 在面板确认节点在线
3) 客户端订阅走：域名/443（不要走 7002）

常用排障：
- journalctl -u XrayR -f --no-pager
- ss -lntp | grep XrayR

========================================================
EOF
