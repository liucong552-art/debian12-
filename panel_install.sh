#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

log(){ echo -e "\n[+] $*\n"; }
die(){ echo -e "\n[x] $*\n" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行"

PANEL_HOST="${PANEL_HOST:-}"
API_KEY="${API_KEY:-}"
NODE_ID="${NODE_ID:-}"

UPDATE_PERIODIC="${UPDATE_PERIODIC:-60}"
GO_VER="${GO_VER:-1.25.3}"
XRAYR_COMMIT="${XRAYR_COMMIT:-dd786ef}"

[ -n "${PANEL_HOST}" ] || die "缺少 PANEL_HOST，例如 https://api.liucna.com"
[ -n "${API_KEY}" ]   || die "缺少 API_KEY"
[ -n "${NODE_ID}" ]   || die "缺少 NODE_ID"

export DEBIAN_FRONTEND=noninteractive

log "Step 1/8: 安装依赖"
apt-get update -y
apt-get install -y git curl ca-certificates jq build-essential iproute2 unzip

log "Step 2/8: 安装 Go ${GO_VER}"
arch="$(uname -m)"
case "${arch}" in
  x86_64|amd64) go_arch="amd64" ;;
  aarch64|arm64) go_arch="arm64" ;;
  *) die "不支持的架构: ${arch}" ;;
esac

if ! command -v go >/dev/null 2>&1 || ! go version | grep -q "go${GO_VER}"; then
  rm -rf /usr/local/go
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  curl -fL --retry 5 --retry-delay 2 -o "$tmp/go.tgz" "https://go.dev/dl/go${GO_VER}.linux-${go_arch}.tar.gz" || \
  curl -fL --retry 5 --retry-delay 2 -o "$tmp/go.tgz" "https://dl.google.com/go/go${GO_VER}.linux-${go_arch}.tar.gz"
  tar -C /usr/local -xzf "$tmp/go.tgz"
fi
export PATH="/usr/local/go/bin:$PATH"
go version

log "Step 3/8: 拉取 XrayR 并 checkout ${XRAYR_COMMIT}"
mkdir -p /usr/local/src
if [ ! -d /usr/local/src/XrayR/.git ]; then
  git clone https://github.com/XrayR-project/XrayR.git /usr/local/src/XrayR
fi
cd /usr/local/src/XrayR
git fetch --all --tags
git checkout -f "${XRAYR_COMMIT}"

log "Step 4/8: 打补丁（复刻原成功方案）"
if grep -q 'log.Panicf("Panel Start failed: %s", err)' panel/panel.go 2>/dev/null; then
  sed -i 's/log\.Panicf("Panel Start failed: %s", err)/log.Errorf("Panel Start warning: %s", err)/' panel/panel.go
fi

if grep -q 'return nil, errors.New("users is null")' api/newV2board/v2board.go 2>/dev/null; then
  sed -i 's/return nil, errors.New("users is null")/return \&[]api.UserInfo{}, nil/' api/newV2board/v2board.go
fi

log "Step 5/8: 编译安装 xrayr（dd786ef + 补丁）"
go build -o XrayR -ldflags "-s -w" .
install -m 0755 XrayR /usr/local/bin/xrayr

log "Step 6/8: 写入 /etc/XrayR/config.yml"
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
EOF

chmod 600 /etc/XrayR/config.yml

log "Step 6.1/8: 写入稳定 runner"
install -d /var/log/XrayR
: >/var/log/XrayR/runner.log

cat >/usr/local/bin/xrayr-runner <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
mkdir -p /var/log/XrayR
LOG=/var/log/XrayR/runner.log
CFG=/etc/XrayR/config.yml

echo "[runner] start $(date -Is)" >>"$LOG"
while true; do
  /usr/local/bin/xrayr --config "$CFG" >>"$LOG" 2>&1 || true
  echo "[runner] xrayr exited at $(date -Is), retry in 3s" >>"$LOG"
  sleep 3
done
EOF
chmod +x /usr/local/bin/xrayr-runner

log "Step 6.2/8: 写入 systemd"
cat >/etc/systemd/system/xrayr.service <<'EOF'
[Unit]
Description=XrayR Service (stable runner)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/bin/xrayr-runner
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

log "Step 7/8: 启动服务"
systemctl daemon-reload
systemctl enable --now xrayr
systemctl restart xrayr

log "Step 8/8: 自检"
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
echo "XRAYR_COMMIT: ${XRAYR_COMMIT}"
echo "查看状态:"
echo "  systemctl status xrayr --no-pager"
echo "  journalctl -u xrayr -n 100 --no-pager"
echo "  tail -n 100 /var/log/XrayR/runner.log"
echo "======================================================"
