#!/usr/bin/env bash
set -euo pipefail

LOG=/var/log/xrayr_onekey.log
mkdir -p /var/log
touch "$LOG"
exec > >(tee -a "$LOG") 2>&1

echo "[+] Start: $(date) | log: $LOG"

# ========= 可改默认值 =========
XRAYR_REPO_DEFAULT="https://github.com/XrayR-project/XrayR.git"
# 这里不要再写 dd786ef 这种短 hash 了（容易不可达）
# 默认用 master；你也可以运行时输入成 tag/commit/fullhash
XRAYR_REF_DEFAULT="master"

BRIDGE_LISTEN="127.0.0.1:7002"
PANEL_ORIGIN="http://127.0.0.1:7001"
APIHOST="http://127.0.0.1:7002"

# UpdatePeriodic 别太低（避免面板偶发空返回放大）
UPDATE_PERIODIC_DEFAULT=60

# 监听端口建议 8443
NODE_PORT_DEFAULT=8443

# ========= 工具函数 =========
die(){ echo "[!] $*" >&2; exit 1; }
ok(){ echo "[*] $*"; }

need_root() { [[ "${EUID}" -eq 0 ]] || die "Please run as root"; }

ask() {
  local prompt="$1" default="${2:-}"
  local v
  if [[ -n "$default" ]]; then
    read -r -p "[?] ${prompt} (default: ${default}): " v
    echo "${v:-$default}"
  else
    read -r -p "[?] ${prompt}: " v
    echo "$v"
  fi
}

ask_secret() {
  local prompt="$1"
  local v
  read -r -s -p "[?] ${prompt} (input hidden): " v
  echo
  echo "$v"
}

cmd_exists(){ command -v "$1" >/dev/null 2>&1; }

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends "$@"
}

# ========= 0) 基础依赖 =========
need_root
ok "Basic deps..."
apt_install ca-certificates curl jq perl iproute2 tar cron util-linux git patch

# ========= 1) 交互输入 =========
NODE_ID="$(ask "Enter NodeID (e.g. 1)" "")"
[[ -n "$NODE_ID" ]] || die "NodeID required"

API_KEY="$(ask_secret "Enter ApiKey")"
[[ -n "$API_KEY" ]] || die "ApiKey required"

XRAYR_REPO="$(ask "Enter XrayR repo" "$XRAYR_REPO_DEFAULT")"
XRAYR_REF="$(ask "Enter XrayR ref (branch/tag/full commit hash preferred)" "$XRAYR_REF_DEFAULT")"

UPDATE_PERIODIC="$(ask "Enter UpdatePeriodic seconds" "$UPDATE_PERIODIC_DEFAULT")"
NODE_PORT="$(ask "Enter node listen port" "$NODE_PORT_DEFAULT")"

ok "NodeID=$NODE_ID  ApiKeyLen=${#API_KEY}  Repo=$XRAYR_REPO  Ref=$XRAYR_REF  UpdatePeriodic=$UPDATE_PERIODIC  Port=$NODE_PORT"

# ========= 2) nginx token bridge =========
ok "Installing nginx token-bridge (${BRIDGE_LISTEN} -> ${PANEL_ORIGIN})..."
apt_install nginx

# 删掉默认站点，避免占 80
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default || true

cat >/etc/nginx/conf.d/xboard_token_bridge.conf <<'NG'
server {
  listen 127.0.0.1:7002;
  server_name _;

  location / {
    # token: 优先 query token，其次 Header Token
    set $token $arg_token;
    if ($token = "") { set $token $http_token; }
    if ($token = "") { return 400; }

    # 若原请求没带 token=，把 header token 注入 query
    if ($arg_token = "") { set $args "${args}&token=${token}"; }
    if ($args ~ "^&")    { set $args "token=${token}"; }

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host 127.0.0.1;

    proxy_pass http://127.0.0.1:7001$uri?$args;
  }
}
NG

nginx -t
systemctl enable --now nginx
systemctl reload nginx

ok "nginx listening check:"
ss -lntp | grep ':7002' || die "nginx token-bridge not listening on 7002"

# ========= 3) xboard schedule cron =========
ok "Setup cron for xboard schedule (if container exists)..."
cat >/etc/cron.d/xboard-schedule <<'EOF'
* * * * * root flock -n /tmp/xboard_schedule.lock docker exec xboard-web-1 php artisan schedule:run --no-interaction >>/var/log/xboard_schedule.log 2>&1
EOF
chmod 644 /etc/cron.d/xboard-schedule
touch /var/log/xboard_schedule.log
systemctl enable --now cron || true
ok "xboard schedule cron installed: /etc/cron.d/xboard-schedule"

# ========= 4) Go 安装 =========
ok "Installing Go..."
# 用 go.dev 官方下载（你之前用的 1.25.3 没问题）
GO_VER="1.25.3"
GO_TAR="go${GO_VER}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TAR}"

apt_install curl
rm -rf /usr/local/go
curl -fL "$GO_URL" -o "/tmp/${GO_TAR}"
tar -C /usr/local -xzf "/tmp/${GO_TAR}"
rm -f "/tmp/${GO_TAR}"

export PATH=/usr/local/go/bin:$PATH
cmd_exists go || die "go not found after install"
cmd_exists gofmt || die "gofmt not found after install"
ok "$(go version)"

# ========= 5) build deps =========
ok "Installing build deps..."
apt_install build-essential

# ========= 6) clone XrayR（不再浅克隆） =========
ok "Cloning XrayR..."
rm -rf /usr/local/src/XrayR
git clone "$XRAYR_REPO" /usr/local/src/XrayR
cd /usr/local/src/XrayR
git fetch --all --tags

# ref 既可以是 branch/tag，也可以是 commit/fullhash
if git show-ref --verify --quiet "refs/heads/$XRAYR_REF"; then
  git checkout -q "$XRAYR_REF"
elif git show-ref --verify --quiet "refs/tags/$XRAYR_REF"; then
  git checkout -q "tags/$XRAYR_REF"
elif git cat-file -e "${XRAYR_REF}^{commit}" 2>/dev/null; then
  git checkout -q "$XRAYR_REF"
else
  # 如果是短 hash，尝试补全
  FULL=$(git rev-list --all | grep -i "^${XRAYR_REF}" | head -n 1 || true)
  [[ -n "$FULL" ]] || die "XRAYR_REF=$XRAYR_REF not found in repo history"
  git checkout -q "$FULL"
fi

ok "Checked out: $(git rev-parse --short HEAD)"

# ========= 7) 打补丁（最小、确定、可重复） =========
ok "Patching: panel start panic -> error+return"
# panel/panel.go: log.Panicf("Panel Start failed: %s", err) -> log.Errorf(...); return err
# 注意：不同版本可能略有出入，这里做两步替换：先改 Panicf，再补 return
if grep -q 'Panel Start failed' panel/panel.go; then
  # 先把 Panicf 替换成 Errorf
  perl -pi -e 's/log\.Panicf\("Panel Start failed: %s",\s*err\)/log.Errorf("Panel Start warning: %s", err)/g' panel/panel.go
  # 如果紧跟着没有 return err，就在下一行补一个（只在出现 Start failed 的分支里补）
  # 这里用一个相对安全的方式：在包含 "Panel Start warning" 的行后插入 return err（若已存在则不会重复）
  perl -0777 -pi -e 's/(Panel Start warning: %s", err\)\s*;\s*)(?!return err;)/$1return err;\n/g' panel/panel.go
fi

ok "Patching: newV2board users empty -> &empty, nil"
# api/newV2board/v2board.go: if len(users)==0 { return ..., errors.New("users is null") } -> return &empty, nil
if [[ -f api/newV2board/v2board.go ]]; then
  # 仅替换 len(users)==0 这个 if 块（精准替换，避免把别的 return 搞坏）
  perl -0777 -pi -e '
    s/if\s+len\(users\)\s*==\s*0\s*\{\s*return\s+[^;]*?errors\.New\("users is null"\)\s*\}/if len(users) == 0 {\n\t\tempty := make([]api.UserInfo, 0)\n\t\treturn \&empty, nil\n\t}/s
  ' api/newV2board/v2board.go

  # 兼容有些版本写成 return []api.UserInfo{}, nil 这种（类型不对）
  perl -0777 -pi -e '
    s/if\s+len\(users\)\s*==\s*0\s*\{\s*return\s+\[\]api\.UserInfo\{\}\s*,\s*nil\s*\}/if len(users) == 0 {\n\t\tempty := make([]api.UserInfo, 0)\n\t\treturn \&empty, nil\n\t}/s
  ' api/newV2board/v2board.go
fi

ok "Running gofmt..."
gofmt -w panel/panel.go api/newV2board/v2board.go || true

# ========= 8) 编译 =========
ok "Building XrayR... (may take time, log continues here)"
go build -o XrayR -ldflags "-s -w" .

# ========= 9) 安装二进制 + 目录 =========
ok "Installing binaries..."
install -m 755 XrayR /usr/local/bin/xrayr
mkdir -p /etc/XrayR /var/log/XrayR
touch /var/log/XrayR/runner.log

# ========= 10) 写 config.yml =========
ok "Writing /etc/XrayR/config.yml (Vless + Reality/Vision safe defaults)..."
cat >/etc/XrayR/config.yml <<EOF
Log:
  Level: info
  AccessPath: /var/log/XrayR/access.log
  ErrorPath: /var/log/XrayR/error.log

DnsConfigPath:
RouteConfigPath:
InboundConfigPath:
OutboundConfigPath:

ConnetionConfig:
  Handshake: 4
  ConnIdle: 30
  UplinkOnly: 2
  DownlinkOnly: 4
  BufferSize: 64

Nodes:
  - PanelType: "NewV2board"
    ApiConfig:
      ApiHost: "${APIHOST}"
      ApiKey: "${API_KEY}"
      NodeID: ${NODE_ID}
      NodeType: Vless
      Timeout: 30
      EnableVless: true
      EnableXTLS: true
      VlessFlow: "xtls-rprx-vision"
      SpeedLimit: 0
      DeviceLimit: 0
      RuleListPath:
    ControllerConfig:
      ListenIP: "0.0.0.0"
      SendIP: "0.0.0.0"
      UpdatePeriodic: ${UPDATE_PERIODIC}
      EnableDNS: false
      DNSType: AsIs
      EnableProxyProtocol: false
      EnableFallback: false
      DisableSniffing: true
      FallBackConfigs: []
      EnableREALITY: true
      REALITYConfigs:
        Show: false
        Dest: "www.apple.com:443"
        ProxyProtocolVer: 0
        ServerNames:
          - "www.apple.com"
        PrivateKey: ""
        ShortIds:
          - ""
      CertConfig:
        CertMode: none
        CertDomain: ""
        CertFile: ""
        KeyFile: ""
EOF

# ========= 11) runner + systemd =========
ok "Installing runner + systemd service..."

cat >/usr/local/bin/xrayr-runner <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
LOG=/var/log/XrayR/runner.log
mkdir -p /var/log/XrayR
touch "$LOG"

while true; do
  /usr/local/bin/xrayr -c /etc/XrayR/config.yml >>"$LOG" 2>&1 || true
  echo "[runner] xrayr exited at $(date --iso-8601=seconds), retry in 3s" >>"$LOG"
  sleep 3
done
EOF
chmod +x /usr/local/bin/xrayr-runner

cat >/etc/systemd/system/xrayr.service <<'EOF'
[Unit]
Description=XrayR Service (stable runner)
After=network-online.target
Wants=network-online.target

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

ok "Service status:"
systemctl status xrayr --no-pager -l || true

ok "Listen check (node port):"
ss -lntp | grep -E ":${NODE_PORT}|xrayr" || true

# ========= 12) API 自检 =========
ok "Panel API quick check (via bridge):"
HOST="http://127.0.0.1:7002"
curl -sS -H "Token: ${API_KEY}" \
  "${HOST}/api/v1/server/UniProxy/config?node_id=${NODE_ID}&node_type=vless" | head -c 500; echo
curl -sS -H "Token: ${API_KEY}" \
  "${HOST}/api/v1/server/UniProxy/user?node_id=${NODE_ID}&node_type=vless" | head -c 500; echo

echo
echo "[+] DONE."
echo "    - Logs: $LOG and /var/log/XrayR/runner.log"
echo "    - Config: /etc/XrayR/config.yml"
echo "    - Token bridge: 127.0.0.1:7002 -> 127.0.0.1:7001"
