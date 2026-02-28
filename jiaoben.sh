#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$' \n\t'

log(){ echo -e "\n[+] $*\n"; }
die(){ echo -e "\n[x] $*\n" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo -i"

# ====== 必填环境变量 ======
# PANEL_HOST：面板 token-bridge 地址，例如 http://104.224.158.191:7002
# API_KEY：面板 ApiKey
# NODE_ID：面板节点 ID（例如 1）
#
# 可选：
# UPDATE_PERIODIC：默认 60（别太低）
# GO_VER：默认 1.25.3（与我们成功经验一致）
# XRAYR_COMMIT：默认 dd786ef（修复计量 #757 的那次成功 commit）
# =========================
PANEL_HOST="${PANEL_HOST:-}"
API_KEY="${API_KEY:-}"
NODE_ID="${NODE_ID:-}"
UPDATE_PERIODIC="${UPDATE_PERIODIC:-60}"

GO_VER="${GO_VER:-1.25.3}"
XRAYR_COMMIT="${XRAYR_COMMIT:-dd786ef}"

[ -n "$PANEL_HOST" ] || die "缺少 PANEL_HOST，例如 http://104.224.158.191:7002"
[ -n "$API_KEY" ]   || die "缺少 API_KEY（面板 ApiKey）"
[ -n "$NODE_ID" ]   || die "缺少 NODE_ID（面板节点ID）"

log "Step 1/7: 安装依赖（git/curl/jq/build-essential/iproute2/unzip）"
apt-get update -y
apt-get install -y git curl ca-certificates jq build-essential iproute2 unzip

log "Step 2/7: 安装 Go ${GO_VER}"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) go_arch="amd64" ;;
  aarch64|arm64) go_arch="arm64" ;;
  *) die "不支持的架构: $arch" ;;
esac

if ! command -v go >/dev/null 2>&1 || ! go version | grep -q "go${GO_VER}"; then
  rm -rf /usr/local/go
  url1="https://go.dev/dl/go${GO_VER}.linux-${go_arch}.tar.gz"
  url2="https://dl.google.com/go/go${GO_VER}.linux-${go_arch}.tar.gz"
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  curl -fL --retry 5 --retry-delay 2 -o "$tmp/go.tgz" "$url1" || \
    curl -fL --retry 5 --retry-delay 2 -o "$tmp/go.tgz" "$url2"
  tar -C /usr/local -xzf "$tmp/go.tgz"
fi
export PATH="/usr/local/go/bin:$PATH"
go version

log "Step 3/7: 拉取 XrayR 并 checkout ${XRAYR_COMMIT}"
mkdir -p /usr/local/src
if [ ! -d /usr/local/src/XrayR/.git ]; then
  git clone https://github.com/XrayR-project/XrayR.git /usr/local/src/XrayR
fi
cd /usr/local/src/XrayR
git fetch --all --tags
git checkout -f "${XRAYR_COMMIT}"

log "Step 4/7: 打补丁（完全复刻我们成功经验）"
# 4.1 Panel Start failed 不再 panic（避免 users is null / 其他临时错误把进程打崩）
if grep -q 'log.Panicf("Panel Start failed: %s", err)' panel/panel.go 2>/dev/null; then
  sed -i 's/log\.Panicf("Panel Start failed: %s", err)/log.Errorf("Panel Start warning: %s", err)/' panel/panel.go
fi

# 4.2 users is null：返回 *([]api.UserInfo) 的空切片指针（避免被当成 fatal）
# 注意：这里必须是 &[]api.UserInfo{}，否则会出现你之前那种“[] 不能当 *[]”的编译错误
if grep -q 'errors.New("users is null")' api/newV2board/v2board.go 2>/dev/null; then
  sed -i 's/return nil, errors.New("users is null")/return \&[]api.UserInfo{}, nil/' api/newV2board/v2board.go
fi

log "Step 5/7: 编译安装 xrayr（带 #757 计量修复的那版）"
go build -o XrayR -ldflags "-s -w" .
install -m 0755 XrayR /usr/local/bin/xrayr

log "Step 6/7: 写入 /etc/XrayR/config.yml（按我们成功配置）"
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

      # ✅ 避免 nil panic（我们成功经验）
      CertConfig:
        CertMode: none
      REALITYConfigs:
        Show: false
EOF

log "Step 6.1/7: 写入 runner（避免 systemd StartLimit 抽风，和我们成功那次一致）"
install -d /var/log/XrayR
: > /var/log/XrayR/runner.log

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

log "Step 6.2/7: 写入 systemd（StartLimitIntervalSec 必须在 [Unit]）"
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

systemctl daemon-reload
systemctl enable --now xrayr
systemctl restart xrayr

log "Step 7/7: 自检（从面板拉 config/user，并检查本机监听端口）"
echo "[i] 拉 config："
cfg="$(curl -fsS -H "Token: ${API_KEY}" \
  "${PANEL_HOST}/api/v1/server/UniProxy/config?node_id=${NODE_ID}&node_type=vless" || true)"
echo "$cfg" | jq . || true

port="$(echo "$cfg" | jq -r '.server_port // empty' 2>/dev/null || true)"
echo "[i] server_port=${port:-NA}"

echo "[i] 拉 user："
curl -fsS -H "Token: ${API_KEY}" \
  "${PANEL_HOST}/api/v1/server/UniProxy/user?node_id=${NODE_ID}&node_type=vless" | jq . || true

echo
systemctl status xrayr --no-pager -l | sed -n '1,18p' || true
tail -n 120 /var/log/XrayR/runner.log || true

if [ -n "${port:-}" ]; then
  ss -lntp | grep ":${port}" || echo "[!] 未发现监听 :${port}（请看 runner.log）"
fi

cat <<EOF

==================== ✅ 节点机完成（按成功经验修复计量） ====================

- 你现在运行的是：XrayR commit ${XRAYR_COMMIT}（包含 #757 计量修复思路）
- runner 日志：tail -n 200 /var/log/XrayR/runner.log
- systemd：systemctl status xrayr

==========================================================================

EOF
