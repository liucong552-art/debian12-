#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

log(){ echo -e "\n[+] $*\n"; }
die(){ echo -e "\n[x] $*\n" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行"

PANEL_HOST="${PANEL_HOST:-}"
API_KEY="${API_KEY:-}"
NODE_ID="${NODE_ID:-}"
BIN_URL="${BIN_URL:-}"
UPDATE_PERIODIC="${UPDATE_PERIODIC:-60}"

[ -n "${PANEL_HOST}" ] || die "缺少 PANEL_HOST，例如 https://api.liucna.com"
[ -n "${API_KEY}" ]   || die "缺少 API_KEY"
[ -n "${NODE_ID}" ]   || die "缺少 NODE_ID"
[ -n "${BIN_URL}" ]   || die "缺少 BIN_URL"

export DEBIAN_FRONTEND=noninteractive

log "Step 1/6: 安装基础依赖"
apt-get update -y
apt-get install -y curl ca-certificates jq iproute2 unzip

log "Step 2/6: 下载你自己编译的 XrayR 二进制"
mkdir -p /usr/local/bin
curl -fL --retry 10 --retry-delay 2 -o /usr/local/bin/XrayR "${BIN_URL}"
chmod 0755 /usr/local/bin/XrayR
ln -sf /usr/local/bin/XrayR /usr/local/bin/xrayr
/usr/local/bin/XrayR version >/dev/null 2>&1 || /usr/local/bin/XrayR --version >/dev/null 2>&1 || true

log "Step 3/6: 写入 /etc/XrayR/config.yml"
mkdir -p /etc/XrayR
cat >/etc/XrayR/config.yml <<EOF2
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
      NodeType: Vless
      Timeout: 30
      EnableVless: true
      EnableXTLS: true
      VlessFlow: "xtls-rprx-vision"
    ControllerConfig:
      ListenIP: 0.0.0.0
      SendIP: 0.0.0.0
      UpdatePeriodic: ${UPDATE_PERIODIC}
      EnableDNS: false
      DNSType: AsIs
      DisableLocalREALITYConfig: true
      EnableREALITY: false
      REALITYConfigs:
        Show: false
      CertConfig:
        CertMode: none
EOF2

chmod 600 /etc/XrayR/config.yml

log "Step 4/6: 写入稳定 runner"
install -d /var/log/XrayR
: >/var/log/XrayR/runner.log

cat >/usr/local/bin/xrayr-runner <<'EOF2'
#!/usr/bin/env bash
set -Eeuo pipefail

PANEL_HOST="${PANEL_HOST:-}"
API_KEY="${API_KEY:-}"
NODE_ID="${NODE_ID:-}"

LOG=/var/log/XrayR/runner.log
CFG=/etc/XrayR/config.yml

mkdir -p /var/log/XrayR
echo "[runner] start $(date -Is)" >>"$LOG"

health_check() {
  local base code
  base="${PANEL_HOST%/}/api/v1/server/UniProxy/config?node_id=${NODE_ID}&node_type=vless"

  code="$(curl -m 8 -sS -o /dev/null -w "%{http_code}" "${base}&token=${API_KEY}" || echo 000)"
  [ "$code" = "200" ]
}

while true; do
  if [ -n "${PANEL_HOST}" ] && [ -n "${API_KEY}" ] && [ -n "${NODE_ID}" ]; then
    if ! health_check; then
      echo "[runner] panel api not ready (HTTP != 200), retry in 3s" >>"$LOG"
      sleep 3
      continue
    fi
  fi

  /usr/local/bin/XrayR --config "$CFG" >>"$LOG" 2>&1 || true
  echo "[runner] xrayr exited at $(date -Is), retry in 3s" >>"$LOG"
  sleep 3
done
EOF2
chmod +x /usr/local/bin/xrayr-runner

log "Step 5/6: 写入 systemd"
cat >/etc/systemd/system/xrayr.service <<EOF2
[Unit]
Description=XrayR Service (custom BIN_URL build)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
Environment=PANEL_HOST=${PANEL_HOST}
Environment=API_KEY=${API_KEY}
Environment=NODE_ID=${NODE_ID}
ExecStart=/usr/local/bin/xrayr-runner
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF2

systemctl daemon-reload
systemctl enable --now xrayr
systemctl restart xrayr

log "Step 6/6: 自检"
echo "[i] 拉 config："
cfg="$(curl -fsS "${PANEL_HOST}/api/v1/server/UniProxy/config?node_id=${NODE_ID}&node_type=vless&token=${API_KEY}" || true)"
echo "${cfg}" | jq . || true

port="$(echo "${cfg}" | jq -r '.server_port // empty' 2>/dev/null || true)"
if [ -n "${port}" ] && [ "${port}" != "null" ]; then
  echo "[i] 检查监听端口: ${port}"
  ss -lntp | grep ":${port}" || true
fi

echo "[i] 拉 user："
curl -fsS "${PANEL_HOST}/api/v1/server/UniProxy/user?node_id=${NODE_ID}&node_type=vless&token=${API_KEY}" | jq . || true

echo
echo "======================================================"
echo "PANEL_HOST: ${PANEL_HOST}"
echo "NODE_ID: ${NODE_ID}"
echo "BIN_URL: ${BIN_URL}"
echo "查看状态:"
echo "  systemctl status xrayr --no-pager"
echo "  journalctl -u xrayr -n 100 --no-pager"
echo "  tail -n 100 /var/log/XrayR/runner.log"
echo "======================================================"
