#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$' \n\t'

log(){ echo -e "\n[+] $*\n"; }
die(){ echo -e "\n[x] $*\n" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo -i"

# ====== 必填环境变量 ======
# PANEL_HOST：面板 token-bridge 地址，例如 http://14.137.255.86:7002
# API_KEY：面板 ApiKey（给节点用）
# NODE_ID：面板节点 ID（例如 1）
# =========================
PANEL_HOST="${PANEL_HOST:-}"
API_KEY="${API_KEY:-}"
NODE_ID="${NODE_ID:-}"
UPDATE_PERIODIC="${UPDATE_PERIODIC:-60}"

# ====== 可选 ======
GO_VER="${GO_VER:-1.25.3}"         # 默认 Go 1.25.3（可改）
XRAYR_COMMIT="${XRAYR_COMMIT:-dd786ef}"  # #757 计量修复 commit
SWAP_GB="${SWAP_GB:-2}"            # 内存小可自动加 swap（0=不加）
# ==================

[ -n "$PANEL_HOST" ] || die "缺少 PANEL_HOST，例如 http://14.137.255.86:7002"
[ -n "$API_KEY" ]   || die "缺少 API_KEY（面板 ApiKey）"
[ -n "$NODE_ID" ]   || die "缺少 NODE_ID（面板节点ID）"

log "Step 0: 停掉旧服务（如果有）"
systemctl stop XrayR 2>/dev/null || true
systemctl disable XrayR 2>/dev/null || true
systemctl stop xrayr 2>/dev/null || true
systemctl disable xrayr 2>/dev/null || true

log "Step 1: 安装依赖（git/curl/jq/build-essential/iproute2/unzip）"
apt-get update -y
apt-get install -y git curl ca-certificates jq build-essential iproute2 unzip

log "Step 1.1:（可选）内存太小就加 swap（避免 go build 被 killed）"
if [ "${SWAP_GB}" != "0" ]; then
  mem_kb="$(awk '/MemTotal/{print $2}' /proc/meminfo)"
  swap_kb="$(awk '/SwapTotal/{print $2}' /proc/meminfo)"
  if [ "${mem_kb:-0}" -lt 1200000 ] && [ "${swap_kb:-0}" -eq 0 ]; then
    log "检测到内存较小且无 swap，创建 ${SWAP_GB}G swapfile..."
    fallocate -l "${SWAP_GB}G" /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=$((SWAP_GB*1024))
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    free -h || true
  fi
fi

log "Step 2: 安装 Go ${GO_VER}"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) go_arch="amd64" ;;
  aarch64|arm64) go_arch="arm64" ;;
  *) die "不支持的架构: $arch" ;;
esac

need_go_install="1"
if command -v go >/dev/null 2>&1; then
  if go version | grep -q "go${GO_VER}"; then
    need_go_install="0"
  fi
fi

if [ "$need_go_install" = "1" ]; then
  rm -rf /usr/local/go
  url1="https://go.dev/dl/go${GO_VER}.linux-${go_arch}.tar.gz"
  url2="https://dl.google.com/go/go${GO_VER}.linux-${go_arch}.tar.gz"
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  log "下载 Go：$url1"
  if ! curl -fL --retry 5 --retry-delay 2 -o "$tmp/go.tgz" "$url1"; then
    log "go.dev 下载失败，改用 dl.google.com"
    curl -fL --retry 5 --retry-delay 2 -o "$tmp/go.tgz" "$url2"
  fi
  tar -C /usr/local -xzf "$tmp/go.tgz"
fi

export PATH="/usr/local/go/bin:$PATH"
go version

log "Step 3: 拉取 XrayR 并 checkout ${XRAYR_COMMIT}（含 #757 计量修复）"
mkdir -p /usr/local/src
if [ ! -d /usr/local/src/XrayR/.git ]; then
  git clone https://github.com/XrayR-project/XrayR.git /usr/local/src/XrayR
fi
cd /usr/local/src/XrayR
git fetch --all --tags
git checkout -f "${XRAYR_COMMIT}"

log "Step 4: 打补丁（稳定性：users is null + Panel Start failed 不 panic）"
# 4.1 Panel Start failed 不再 panic（避免面板偶发异常导致进程崩）
if grep -q 'log.Panicf("Panel Start failed: %s", err)' panel/panel.go 2>/dev/null; then
  sed -i 's/log\.Panicf("Panel Start failed: %s", err)/log.Errorf("Panel Start warning: %s", err)/' panel/panel.go
fi

# 4.2 users is null：返回空切片指针（避免 fatal / 编译错误）
if grep -q 'errors.New("users is null")' api/newV2board/v2board.go 2>/dev/null; then
  sed -i 's/return nil, errors.New("users is null")/return \&[]api.UserInfo{}, nil/' api/newV2board/v2board.go
fi

log "Step 5: 编译安装 XrayR（会下载 go modules，网络不稳可切 GOPROXY）"
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
export GOSUMDB="${GOSUMDB:-sum.golang.org}"

# 先预下载依赖，失败则切换 goproxy.cn 再试一次
if ! go mod download; then
  log "go mod download 失败，切换 GOPROXY=goproxy.cn 并临时关闭 GOSUMDB 再试"
  export GOPROXY="https://goproxy.cn,direct"
  export GOSUMDB="off"
  go clean -modcache || true
  go mod download
fi

go build -o XrayR -ldflags "-s -w" .
install -m 0755 XrayR /usr/local/bin/xrayr

log "Step 6: 写入 /etc/XrayR/config.yml（V2ray 类型 + EnableVless/XTLS）"
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

      # 防 nil panic（你之前踩过）
      CertConfig:
        CertMode: none
      REALITYConfigs:
        Show: false
      DisableLocalREALITYConfig: true
EOF

log "Step 6.1: runner（稳定重启，不触发 StartLimit）"
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

log "Step 6.2: systemd（StartLimitIntervalSec 必须在 [Unit]）"
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

log "Step 7: 自检（拉 config/user + 检查监听端口）"
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
systemctl status xrayr --no-pager -l | sed -n '1,20p' || true
tail -n 120 /var/log/XrayR/runner.log || true

if [ -n "${port:-}" ]; then
  ss -lntp | grep ":${port}" || echo "[!] 未发现监听 :${port}（请看 runner.log）"
fi

cat <<EOF

==================== ✅ 节点机完成（修复 Vision/REALITY 计量） ====================

- 运行版本：XrayR commit ${XRAYR_COMMIT}（#757：禁用 splice copy，修复 usage report） 
- runner 日志：tail -n 200 /var/log/XrayR/runner.log
- systemd：systemctl status xrayr

下一步：
- 云防火墙/安全组放行 server_port（例如 8443/tcp）

===============================================================================

EOF
