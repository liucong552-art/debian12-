#!/usr/bin/env bash
set -euo pipefail

### ===== 可调参数（保持和你成功那次一致）=====
XRAYR_REPO="https://github.com/XrayR-project/XrayR.git"
XRAYR_DIR="/usr/local/src/XrayR"
XRAYR_COMMIT="dd786ef"

GO_VERSION="1.25.3"
GO_TGZ="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TGZ}"

# xboard UniProxy 本机端口（你成功那次是 7001 -> 7002 bridge）
XBOARD_UPSTREAM="http://127.0.0.1:7001"
BRIDGE_LISTEN="127.0.0.1:7002"

LOG_DIR="/var/log/XrayR"
RUNNER_LOG="${LOG_DIR}/runner.log"

say(){ echo -e "\033[1;32m[+]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[!]\033[0m $*" >&2; }
die(){ echo -e "\033[1;31m[-]\033[0m $*" >&2; exit 1; }

[ "${EUID}" -eq 0 ] || die "请用 root 运行"

### ===== 交互输入（和你成功那次一样：ApiHost/ApiKey/NodeID）=====
read -r -p "ApiHost (默认 http://${BRIDGE_LISTEN}) : " API_HOST_IN || true
API_HOST="${API_HOST_IN:-http://${BRIDGE_LISTEN}}"

read -r -s -p "ApiKey (不回显): " API_KEY
echo
[ -n "${API_KEY}" ] || die "ApiKey 不能为空"

read -r -p "NodeID (例如 1): " NODE_ID
[[ "${NODE_ID}" =~ ^[0-9]+$ ]] || die "NodeID 必须是数字"

say "安装依赖..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y git curl ca-certificates jq iproute2 build-essential unzip nginx cron util-linux

### ===== nginx token-bridge（7002 -> 7001，注入 token 到 query）=====
say "配置 nginx token-bridge (${BRIDGE_LISTEN} -> ${XBOARD_UPSTREAM})..."
cat >/etc/nginx/conf.d/xboard_token_bridge.conf <<'NG'
server {
  listen 127.0.0.1:7002;
  server_name _;

  location / {
    # 取 token：优先 query token，其次 Header Token
    set $token $arg_token;
    if ($token = "") { set $token $http_token; }
    if ($token = "") { return 400; }

    # 如果原请求没带 token=，就把 header Token 注入到 query 里
    if ($arg_token = "") { set $args "${args}&token=${token}"; }
    # 如果原来没有任何 args，会变成 "&token=xxx"，把开头的 & 去掉
    if ($args ~ "^&")    { set $args "token=${token}"; }

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host 127.0.0.1;

    proxy_pass http://127.0.0.1:7001$uri?$args;
  }
}
NG

# 删掉默认站点，避免 nginx 去抢占 80 端口（你踩过的坑）
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default || true

nginx -t
systemctl enable nginx >/dev/null 2>&1 || true
systemctl restart nginx
ss -lntp | grep ":7002" >/dev/null || die "nginx 7002 未监听，检查 /etc/nginx/conf.d/xboard_token_bridge.conf"

### ===== 安装 Go 1.25.3（和你成功那次一致）=====
say "安装 Go ${GO_VERSION}..."
if ! command -v go >/dev/null 2>&1 || ! go version | grep -q "go${GO_VERSION}"; then
  rm -rf /usr/local/go
  curl -fL "${GO_URL}" -o "/tmp/${GO_TGZ}"
  tar -C /usr/local -xzf "/tmp/${GO_TGZ}"
  rm -f "/tmp/${GO_TGZ}"
fi
export PATH="/usr/local/go/bin:${PATH}"
go version | grep -q "go${GO_VERSION}" || die "Go 安装失败/版本不对"

### ===== 拉取 XrayR + checkout dd786ef（和你成功那次一致）=====
say "拉取 XrayR 并 checkout ${XRAYR_COMMIT}..."
mkdir -p /usr/local/src
if [ ! -d "${XRAYR_DIR}/.git" ]; then
  git clone "${XRAYR_REPO}" "${XRAYR_DIR}"
fi
cd "${XRAYR_DIR}"
git fetch --all --tags
git checkout -f "${XRAYR_COMMIT}"

### ===== 打补丁（和你成功那次一致）=====
say "打补丁：panel 不 panic / users is null 不致命..."

# 1) panel/panel.go：把 log.Panicf("Panel Start failed...") 改成 log.Errorf（避免任何 users=null 直接 panic）
if grep -q 'Panel Start failed' panel/panel.go; then
  sed -i 's/log\.Panicf("Panel Start failed: %s", err)/log.Errorf("Panel Start warning: %s", err)/' panel/panel.go || true
fi

# 2) api/newV2board/v2board.go：users is null -> 返回 “空切片指针”
#    这是你“成功那次”最终用的写法：return &[]api.UserInfo{}, nil
if grep -q 'return nil, errors.New("users is null")' api/newV2board/v2board.go; then
  sed -i 's/return nil, errors.New("users is null")/return \&[]api.UserInfo{}, nil/' api/newV2board/v2board.go
fi

### ===== 编译安装 =====
say "编译安装 xrayr（Go 依赖第一次会久）..."
go build -o XrayR -ldflags "-s -w" .
install -m 755 XrayR /usr/local/bin/xrayr

### ===== 日志目录 + runner =====
say "写入 runner..."
mkdir -p "${LOG_DIR}"
touch "${RUNNER_LOG}"
chmod 600 "${LOG_DIR}"/*.log || true

cat >/usr/local/bin/xrayr-runner <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
LOG_DIR="/var/log/XrayR"
LOG="${LOG_DIR}/runner.log"
mkdir -p "${LOG_DIR}"
touch "${LOG}"
chmod 600 "${LOG_DIR}"/*.log || true

while true; do
  echo "[runner] start $(date -Is)" >> "${LOG}"
  /usr/local/bin/xrayr --config /etc/XrayR/config.yml >> "${LOG}" 2>&1 || true
  echo "[runner] xrayr exited at $(date -Is), retry in 3s" >> "${LOG}"
  sleep 3
done
EOF
chmod +x /usr/local/bin/xrayr-runner

### ===== 生成 /etc/XrayR/config.yml（按你成功那次的字段风格）=====
say "生成 /etc/XrayR/config.yml（ApiKey 不回显）..."
mkdir -p /etc/XrayR
cat >/etc/XrayR/config.yml <<EOF
Log:
  Level: info
  AccessPath: ${LOG_DIR}/access.log
  ErrorPath: ${LOG_DIR}/error.log

DnsConfigPath: ""
RouteConfigPath: ""
OutboundConfigPath: ""

ConnetionConfig:
  Handshake: 4
  ConnIdle: 30
  UplinkOnly: 2
  DownlinkOnly: 4

Nodes:
  - PanelType: "NewV2board"
    ApiConfig:
      ApiHost: "${API_HOST}"
      ApiKey: "${API_KEY}"
      NodeID: ${NODE_ID}
      NodeType: Vless
      Timeout: 5
      EnableVless: true
      EnableXTLS: true
      VlessFlow: "xtls-rprx-vision"
      CertConfig:
        CertMode: none
      EnableREALITY: false
      REALITYConfigs:
        Show: false
        Dest: "www.apple.com:443"
        ProxyProtocolVer: 0
        ServerNames:
          - "www.apple.com"
    ControllerConfig:
      UpdatePeriodic: 60
EOF
chmod 600 /etc/XrayR/config.yml

### ===== systemd =====
say "写入 systemd..."
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

### ===== cron：跑 xboard schedule:run（你成功那次做过，保证封禁/超流量判定生效）=====
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx 'xboard-web-1'; then
  say "配置 cron 跑 xboard schedule:run（容器 xboard-web-1 存在）..."
  cat >/etc/cron.d/xboard-schedule <<'EOF'
* * * * * root flock -n /tmp/xboard_schedule.lock docker exec -i xboard-web-1 php artisan schedule:run --no-interaction >>/var/log/xboard_schedule.log 2>&1
EOF
  chmod 644 /etc/cron.d/xboard-schedule
  touch /var/log/xboard_schedule.log
  systemctl enable --now cron >/dev/null 2>&1 || true
else
  warn "未发现容器 xboard-web-1，跳过 cron（如果你是 xboard 同机部署，确认容器名后再补）"
fi

### ===== 验收（和你成功那次一样的检查口径）=====
say "验收："
systemctl --no-pager -l status xrayr || true
ss -lntp | grep -E ':7002|:8443|xrayr' || true
echo
echo "日志：journalctl -u xrayr -o cat -n 200"
echo "runner：tail -n 200 /var/log/XrayR/runner.log"
echo
echo "接口自检（config/user）："
HOST="http://${BRIDGE_LISTEN}"
echo "  curl -sS -H 'Token: ***' '${HOST}/api/v1/server/UniProxy/config?node_id=${NODE_ID}&node_type=vless' | jq ."
echo "  curl -sS -H 'Token: ***' '${HOST}/api/v1/server/UniProxy/user?node_id=${NODE_ID}&node_type=vless' | jq ."
say "DONE"
