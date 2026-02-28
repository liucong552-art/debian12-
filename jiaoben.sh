#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$' \n\t'

log(){ echo -e "\n[+] $*\n"; }
warn(){ echo -e "\n[!] $*\n" >&2; }
die(){ echo -e "\n[x] $*\n" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo -i"

MODE="${MODE:-${1:-auto}}"

# ===== 通用依赖 =====
apt_install(){
  apt-get update -y
  apt-get install -y "$@"
}

# ===== 面板机：token-bridge =====
panel_token_bridge(){
  local UPSTREAM_HOST="${UPSTREAM_HOST:-127.0.0.1}"
  local UPSTREAM_PORT="${UPSTREAM_PORT:-7001}"
  local BRIDGE_PORT="${BRIDGE_PORT:-7002}"
  local NODE_IP="${NODE_IP:-}"
  [ -n "$NODE_IP" ] || read -rp "允许访问 token-bridge 的节点机 IP (例如 14.137.255.86): " NODE_IP

  # 面板机本机“走公网 IP 回环测试”时的来源 IP（避免你再遇到本机 curl 403）
  local PANEL_IP="${PANEL_IP:-$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || true)}"
  [ -n "$PANEL_IP" ] || PANEL_IP="127.0.0.1"

  log "安装 nginx/curl/ca-certificates/jq"
  apt_install nginx curl ca-certificates jq

  # 删默认站点，避免 nginx 抢 80
  rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default || true

  log "检查上游是否监听：${UPSTREAM_HOST}:${UPSTREAM_PORT}"
  if ! curl -fsS "http://${UPSTREAM_HOST}:${UPSTREAM_PORT}/" >/dev/null 2>&1; then
    die "检测不到上游 http://${UPSTREAM_HOST}:${UPSTREAM_PORT}（请先保证 xboard 在本机 7001 可访问）"
  fi

  log "写入 /etc/nginx/conf.d/xboard_token_bridge.conf （${BRIDGE_PORT} -> ${UPSTREAM_HOST}:${UPSTREAM_PORT}）"
  cat >/etc/nginx/conf.d/xboard_token_bridge.conf <<NG
server {
  listen 0.0.0.0:${BRIDGE_PORT};
  server_name _;

  # 只允许：节点机 + 面板机本机（127.0.0.1 + 面板机IP）
  allow ${NODE_IP};
  allow 127.0.0.1;
  allow ${PANEL_IP};
  deny all;

  location / {
    # token：优先 query token，其次 header Token
    set \$token \$arg_token;
    if (\$token = "") { set \$token \$http_token; }
    if (\$token = "") { return 400; }

    # 如果原请求没带 token=，就把 header Token 注入到 query
    if (\$arg_token = "") { set \$args "\${args}&token=\${token}"; }
    if (\$args ~ "^&")    { set \$args "token=\${token}"; }

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host 127.0.0.1;

    proxy_pass http://${UPSTREAM_HOST}:${UPSTREAM_PORT}\$uri?\$args;
  }
}
NG

  nginx -t
  systemctl enable --now nginx
  systemctl restart nginx

  ss -lntp | grep ":${BRIDGE_PORT}" || true

  cat <<EOF

[+] DONE：面板机 token-bridge 已启用
- token-bridge： http://${PANEL_IP}:${BRIDGE_PORT}  （公网用 ${PANEL_IP} / 104.224.158.191 替换）
- 请在安全组放行：${BRIDGE_PORT}/tcp 仅允许 ${NODE_IP}

自检（header 必须是 Token:xxx）：
  KEY="你的ApiKey"
  curl -sS -H "Token: \$KEY" "http://127.0.0.1:${BRIDGE_PORT}/api/v1/server/UniProxy/config?node_id=1&node_type=vless" | jq .
  curl -sS -H "Token: \$KEY" "http://127.0.0.1:${BRIDGE_PORT}/api/v1/server/UniProxy/user?node_id=1&node_type=vless"   | jq .

EOF
}

# ===== 节点机：按成功经验安装 XrayR（修复计量） =====
install_go(){
  local GO_VER="${GO_VER:-1.25.3}"
  local arch go_arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) go_arch="amd64" ;;
    aarch64|arm64) go_arch="arm64" ;;
    *) die "不支持的架构: $arch" ;;
  esac

  if command -v go >/dev/null 2>&1 && go version | grep -q "go${GO_VER}"; then
    return
  fi

  log "安装 Go ${GO_VER}"
  rm -rf /usr/local/go
  local url1="https://go.dev/dl/go${GO_VER}.linux-${go_arch}.tar.gz"
  local url2="https://dl.google.com/go/go${GO_VER}.linux-${go_arch}.tar.gz"
  local tmp
  tmp="$(mktemp -d)"
  curl -fL --retry 5 --retry-delay 2 -o "$tmp/go.tgz" "$url1" || \
    curl -fL --retry 5 --retry-delay 2 -o "$tmp/go.tgz" "$url2"
  tar -C /usr/local -xzf "$tmp/go.tgz"
  rm -rf "$tmp"
}

node_install_xrayr(){
  local PANEL_HOST="${PANEL_HOST:-}"
  local NODE_ID="${NODE_ID:-}"
  local API_KEY="${API_KEY:-}"
  local UPDATE_PERIODIC="${UPDATE_PERIODIC:-60}"
  local XRAYR_COMMIT="${XRAYR_COMMIT:-dd786ef}"

  [ -n "$PANEL_HOST" ] || read -rp "PANEL_HOST (例如 http://104.224.158.191:7002): " PANEL_HOST
  [ -n "$NODE_ID" ] || read -rp "NODE_ID (例如 1): " NODE_ID
  if [ -z "$API_KEY" ]; then
    read -rsp "API_KEY(不回显): " API_KEY; echo
  fi

  log "安装依赖（git/curl/jq/build-essential/iproute2/unzip/ca-certificates）"
  apt_install git curl ca-certificates jq build-essential iproute2 unzip

  install_go
  export PATH="/usr/local/go/bin:$PATH"
  go version

  log "拉取 XrayR 源码并 checkout ${XRAYR_COMMIT}（这是我们成功修复计量的关键）"
  mkdir -p /usr/local/src
  if [ ! -d /usr/local/src/XrayR/.git ]; then
    git clone https://github.com/XrayR-project/XrayR.git /usr/local/src/XrayR
  fi
  cd /usr/local/src/XrayR
  git fetch --all --tags
  git checkout -f "${XRAYR_COMMIT}"

  log "打补丁（完全复刻我们成功经验：不 panic + users is null 返回空切片指针）"
  # 1) Panel Start failed 不 panic
  if grep -q 'log.Panicf("Panel Start failed: %s", err)' panel/panel.go 2>/dev/null; then
    sed -i 's/log\.Panicf("Panel Start failed: %s", err)/log.Errorf("Panel Start warning: %s", err)/' panel/panel.go
  fi
  # 2) users is null -> return &[]api.UserInfo{}, nil   （必须是指针，避免你之前那个编译错误）
  if grep -q 'errors.New("users is null")' api/newV2board/v2board.go 2>/dev/null; then
    sed -i 's/return nil, errors.New("users is null")/return \&[]api.UserInfo{}, nil/' api/newV2board/v2board.go
  fi

  log "编译安装 /usr/local/bin/xrayr"
  go build -o XrayR -ldflags "-s -w" .
  install -m 0755 XrayR /usr/local/bin/xrayr

  log "写入 /etc/XrayR/config.yml（NodeType=Vless + CertConfig/REALITYConfigs 防 nil panic）"
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

      CertConfig:
        CertMode: none
      REALITYConfigs:
        Show: false
EOF

  log "写入 runner + systemd（StartLimitIntervalSec 放在 [Unit]，避免你之前那种无效配置）"
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

  log "自检：从面板拉 config/user（header 必须 Token:xxx）"
  curl -sS -H "Token: ${API_KEY}" \
    "${PANEL_HOST}/api/v1/server/UniProxy/config?node_id=${NODE_ID}&node_type=vless" | jq . || true
  curl -sS -H "Token: ${API_KEY}" \
    "${PANEL_HOST}/api/v1/server/UniProxy/user?node_id=${NODE_ID}&node_type=vless" | jq . || true

  echo
  systemctl status xrayr --no-pager -l | sed -n '1,18p' || true
  tail -n 120 /var/log/XrayR/runner.log || true

  cat <<EOF

==================== ✅ 节点机完成（按成功经验修复计量） ====================

- 关键：源码 checkout ${XRAYR_COMMIT} + Go 编译（不是 release latest）
- runner：tail -n 200 /var/log/XrayR/runner.log
- 服务：systemctl status xrayr

注意：
- UPDATE_PERIODIC 建议 60（不要太低，会放大 users=null/抖动概率）
- 如果你在 Windows 里复制粘贴大量输出到 SSH，会把“Windows PowerShell”文字也发到 Linux 里导致脚本乱掉

EOF
}

auto_mode(){
  # 如果本机有 xboard(7001)，默认当面板机；否则当节点机
  if curl -fsS "http://127.0.0.1:7001/" >/dev/null 2>&1; then
    MODE="panel"
  else
    MODE="node"
  fi
}

case "$MODE" in
  panel) panel_token_bridge ;;
  node) node_install_xrayr ;;
  auto|"") auto_mode; "$0" "$MODE" ;;
  *) die "未知 MODE=$MODE（可用：MODE=panel 或 MODE=node）" ;;
esac
