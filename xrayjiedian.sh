#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

die(){ echo -e "\n[x] $*\n" >&2; exit 1; }
log(){ echo -e "\n[+] $*\n"; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行"
[ -n "${PANEL_HOST:-}" ] || die "缺少 PANEL_HOST"
[ -n "${NODE_ID:-}" ] || die "缺少 NODE_ID"
[ -n "${API_KEY:-}" ] || die "缺少 API_KEY"
[ -n "${BIN_URL:-}" ] || die "缺少 BIN_URL"

if [ -z "${UPDATE_PERIODIC:-}" ]; then
  UPDATE_PERIODIC="10"
fi

[[ "$PANEL_HOST" =~ ^https?:// ]] || die "PANEL_HOST 必须以 http:// 或 https:// 开头"
[[ "$NODE_ID" =~ ^[0-9]+$ ]] || die "NODE_ID 必须是数字"
[[ "$UPDATE_PERIODIC" =~ ^[0-9]+$ ]] || die "UPDATE_PERIODIC 必须是数字"

export DEBIAN_FRONTEND=noninteractive

log "安装基础依赖"
apt-get update -y
apt-get install -y curl ca-certificates tar unzip

mkdir -p /etc/XrayR /var/log/XrayR /usr/local/bin

log "下载你的自编译 XrayR 二进制"
curl -fL "$BIN_URL" -o /usr/local/bin/xrayr

if [ -n "${BIN_SHA256:-}" ]; then
  echo "${BIN_SHA256}  /usr/local/bin/xrayr" | sha256sum -c -
fi

chmod 755 /usr/local/bin/xrayr
/usr/local/bin/xrayr version || true

log "写入 XrayR 配置"
cat > /etc/XrayR/config.yml <<EOF
Log:
  Level: warning

Nodes:
  - PanelType: "NewV2board"
    ApiConfig:
      ApiHost: "${PANEL_HOST}"
      ApiKey: "${API_KEY}"
      NodeID: ${NODE_ID}
      NodeType: Vless
      Timeout: 30
      EnableVless: true
      VlessFlow: "xtls-rprx-vision"
      SpeedLimit: 0
      DeviceLimit: 0
      RuleListPath:
    ControllerConfig:
      ListenIP: 0.0.0.0
      SendIP: 0.0.0.0
      UpdatePeriodic: ${UPDATE_PERIODIC}
      EnableDNS: false
      DNSType: AsIs
      DisableUploadTraffic: false
      DisableGetRule: false
      DisableIVCheck: false
      DisableSniffing: false
      EnableProxyProtocol: false
      EnableFallback: false
      FallBackConfigs:
        -
          SNI:
          Path:
          Dest: 80
          ProxyProtocolVer: 0
      CertConfig:
        CertMode: none
EOF

chmod 600 /etc/XrayR/config.yml

log "写入 runner（先检查面板 API，再拉起 XrayR）"
cat > /usr/local/bin/xrayr-runner <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

API_HOST="${PANEL_HOST}"
API_KEY="${API_KEY}"
NODE_ID="${NODE_ID}"
LOG="/var/log/XrayR/runner.log"

mkdir -p /var/log/XrayR

health_check() {
  local base code
  base="\${API_HOST%/}/api/v1/server/UniProxy/config?node_id=\${NODE_ID}&node_type=vless"

  code="\$(curl -m 8 -sS -o /dev/null -w "%{http_code}" -H "Token: \${API_KEY}" "\${base}" || echo 000)"
  if [[ "\${code}" == "200" || "\${code}" == "304" ]]; then
    return 0
  fi

  code="\$(curl -m 8 -sS -o /dev/null -w "%{http_code}" "\${base}&token=\${API_KEY}" || echo 000)"
  [[ "\${code}" == "200" || "\${code}" == "304" ]]
}

while true; do
  if ! health_check; then
    echo "[runner] panel api not ready (HTTP != 200/304), retry in 3s" >> "\${LOG}"
    sleep 3
    continue
  fi

  /usr/local/bin/xrayr --config /etc/XrayR/config.yml >> "\${LOG}" 2>&1 || true
  echo "[runner] xrayr exited at \$(date -Is), retry in 3s" >> "\${LOG}"
  sleep 3
done
EOF

chmod 700 /usr/local/bin/xrayr-runner

log "写入 systemd 服务"
cat > /etc/systemd/system/xrayr.service <<EOF
[Unit]
Description=XrayR Service (custom BIN_URL build)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
User=root
WorkingDirectory=/etc/XrayR
ExecStart=/usr/local/bin/xrayr-runner
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xrayr
systemctl restart xrayr

echo
echo "======================================================"
echo "已固定使用 BIN_URL:"
echo "  ${BIN_URL}"
if [ -n "${BIN_SHA256:-}" ]; then
  echo "已校验 SHA256:"
  echo "  ${BIN_SHA256}"
fi
echo "面板 API: ${PANEL_HOST}"
echo "节点 ID: ${NODE_ID}"
echo "查看状态:"
echo "  systemctl status xrayr --no-pager"
echo "  journalctl -u xrayr -n 100 --no-pager"
echo "  tail -n 100 /var/log/XrayR/runner.log"
echo "======================================================"
