#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$' \n\t'
log(){ echo -e "\n[+] $*\n"; }
die(){ echo -e "\n[x] $*\n" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "请用 root 运行"

PANEL_HOST="${PANEL_HOST:-}"   # http://面板IP:7002
API_KEY="${API_KEY:-}"
NODE_ID="${NODE_ID:-}"

UPDATE_PERIODIC="${UPDATE_PERIODIC:-60}"
GO_VER="${GO_VER:-1.26.0}"
XRAYR_COMMIT="${XRAYR_COMMIT:-dd786ef}"

[ -n "$PANEL_HOST" ] || die "缺少 PANEL_HOST，例如 http://面板IP:7002"
[ -n "$API_KEY" ] || die "缺少 API_KEY"
[ -n "$NODE_ID" ] || die "缺少 NODE_ID"

log "1) 依赖"
apt-get update -y
apt-get install -y git curl ca-certificates jq build-essential unzip iproute2

log "2) 安装 Go ${GO_VER}"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) go_arch="amd64" ;;
  aarch64|arm64) go_arch="arm64" ;;
  *) die "不支持架构: $arch" ;;
esac
rm -rf /usr/local/go
curl -fL --retry 5 --retry-delay 2 -o /tmp/go.tgz "https://dl.google.com/go/go${GO_VER}.linux-${go_arch}.tar.gz"
tar -C /usr/local -xzf /tmp/go.tgz
export PATH="/usr/local/go/bin:$PATH"
echo 'export PATH=/usr/local/go/bin:$PATH' >/etc/profile.d/go.sh
. /etc/profile.d/go.sh
go version

log "3) 拉 XrayR 并切 ${XRAYR_COMMIT}"
mkdir -p /usr/local/src
rm -rf /usr/local/src/XrayR
git clone https://github.com/XrayR-project/XrayR.git /usr/local/src/XrayR
cd /usr/local/src/XrayR
git checkout -f "$XRAYR_COMMIT"
git log -1 --oneline

log "4) 补丁（users=null / Panel Start failed 不 panic）"
if grep -q 'log.Panicf("Panel Start failed: %s", err)' panel/panel.go 2>/dev/null; then
  sed -i 's/log\.Panicf("Panel Start failed: %s", err)/log.Errorf("Panel Start warning: %s", err)/' panel/panel.go
fi
if grep -q 'errors.New("users is null")' api/newV2board/v2board.go 2>/dev/null; then
  sed -i 's/return nil, errors.New("users is null")/return \&[]api.UserInfo{}, nil/' api/newV2board/v2board.go
fi

log "5) 依赖下载（自动解决 goproxy GOAWAY）"
export GO111MODULE=on
export GOSUMDB=off

try_download() {
  local proxy="$1"
  log "尝试 GOPROXY=${proxy}"
  export GOPROXY="$proxy"
  go clean -modcache
  timeout 30m go mod download
}

# 优先更稳的 proxy.golang.com.cn，其次 goproxy.cn，最后 direct
if ! try_download "https://proxy.golang.com.cn,https://goproxy.cn,direct"; then
  log "代理下载失败，改用 direct（会慢，但更稳）"
  export GOPROXY="direct"
  export GOSUMDB="off"
  go clean -modcache
  timeout 45m go mod download
fi

log "6) 编译并安装（覆盖 /usr/local/bin/XrayR）"
go build -o XrayR -ldflags "-s -w" .
install -m 0755 XrayR /usr/local/bin/XrayR

log "7) 写配置 + systemd"
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
      NodeType: V2ray
      Timeout: 30
      EnableVless: true
      EnableXTLS: true
      VlessFlow: "xtls-rprx-vision"
    ControllerConfig:
      ListenIP: 0.0.0.0
      SendIP: 0.0.0.0
      UpdatePeriodic: ${UPDATE_PERIODIC}
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
systemctl restart XrayR

log "8) 验收"
journalctl -u XrayR --since "2 minutes ago" --no-pager || true
ss -lntp | grep ':8443' || true

cat <<EOF

==================== ✅ 节点机完成 ====================
- commit：${XRAYR_COMMIT}（修复计量）
- 记得云安全组放行 8443/tcp（或面板下发端口）
========================================================
EOF
