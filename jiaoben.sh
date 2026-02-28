#!/usr/bin/env bash
set -euo pipefail

log() { echo -e "\033[1;32m[+]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[!]\033[0m $*"; }
die() { echo -e "\033[1;31m[x]\033[0m $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行"
export DEBIAN_FRONTEND=noninteractive

# ====== 你的面板域名（上游） ======
PANEL_DOMAIN="${XRAYR_PANEL_DOMAIN:-liucna.com}"
PANEL_SCHEME="${XRAYR_PANEL_SCHEME:-https}"
UPSTREAM="${PANEL_SCHEME}://${PANEL_DOMAIN}"

# --------- 读入参数（支持环境变量免交互） ----------
APIKEY="${XRAYR_APIKEY:-}"
NODEID="${XRAYR_NODEID:-}"

if [ -z "$APIKEY" ]; then
  read -rsp "ApiKey(不回显): " APIKEY; echo
fi
if [ -z "$NODEID" ]; then
  read -rp "NodeID(例如 1): " NODEID
fi
[[ "$NODEID" =~ ^[0-9]+$ ]] || die "NodeID 必须是数字"

# --------- 基础连通性检查（检查域名可达，不再检查本机 7001） ----------
log "检查面板可达：${UPSTREAM} ..."
curl -fsS "${UPSTREAM}/" -o /dev/null || die "访问 ${UPSTREAM} 失败（域名不通/被墙/证书问题）。"

# --------- 安装依赖 ----------
log "安装依赖..."
apt-get update -y
apt-get install -y git curl ca-certificates jq iproute2 build-essential unzip nginx cron util-linux

# --------- nginx token-bridge：7002 -> 面板域名 ----------
log "配置 nginx token-bridge (127.0.0.1:7002 -> ${UPSTREAM})..."
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default || true

cat >/etc/nginx/conf.d/xboard_token_bridge.conf <<NG
server {
  listen 127.0.0.1:7002;
  server_name _;

  location / {
    # token：优先 query token，其次 Header Token
    set \$token \$arg_token;
    if (\$token = "") { set \$token \$http_token; }
    if (\$token = "") { return 400; }

    # 如果原请求没带 token=，就把 header Token 注入到 query 里
    if (\$arg_token = "") { set \$args "\${args}&token=\${token}"; }
    # 如果原来没有任何 args，会变成 "&token=xxx"，把开头的 & 去掉
    if (\$args ~ "^&")    { set \$args "token=\${token}"; }

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host ${PANEL_DOMAIN};
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto ${PANEL_SCHEME};

    # https 上游需要 SNI
    proxy_ssl_server_name on;
    proxy_ssl_name ${PANEL_DOMAIN};

    proxy_pass ${UPSTREAM}\$uri?\$args;
  }
}
NG

nginx -t
systemctl enable --now nginx || true
systemctl restart nginx
ss -lntp | grep ':7002' >/dev/null || die "nginx 7002 未监听，token-bridge 失败"

# --------- 自检：通过 bridge 打面板接口（Header Token -> query token） ----------
log "自检 bridge：请求 UniProxy/config ..."
curl -fsS -H "Token: ${APIKEY}" \
  "http://127.0.0.1:7002/api/v1/server/UniProxy/config?node_id=${NODEID}&node_type=vless" \
  | jq . >/dev/null || die "bridge 自检失败：接口不通/路径不对/ApiKey不对/面板未开启该接口"

# --------- 安装 Go（自动取 go.dev 最新 stable；失败则用 apt golang） ----------
if ! command -v go >/dev/null 2>&1; then
  log "安装 Go（自动选择最新 stable）..."
  GO_VER="$(curl -fsSL 'https://go.dev/dl/?mode=json' | jq -r 'map(select(.stable==true))[0].version' | sed 's/^go//')" || true
  if [ -n "${GO_VER:-}" ] && [ "${GO_VER}" != "null" ]; then
    tgz="go${GO_VER}.linux-amd64.tar.gz"
    curl -fsSL "https://go.dev/dl/${tgz}" -o "/tmp/${tgz}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${tgz}"
    ln -sf /usr/local/go/bin/go /usr/local/bin/go
    ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
  else
    warn "无法从 go.dev 自动取版本，改用 apt 安装 golang-go（可能较旧，但一般能编译）"
    apt-get install -y golang-go
  fi
fi
export PATH=/usr/local/go/bin:$PATH
go version || die "go 不可用"

# --------- 拉取 XrayR 并 checkout 固定 commit ----------
XRAYR_DIR="/usr/local/src/XrayR"
COMMIT="dd786ef"

log "拉取 XrayR 并 checkout ${COMMIT}..."
mkdir -p /usr/local/src
if [ ! -d "${XRAYR_DIR}/.git" ]; then
  git clone https://github.com/XrayR-project/XrayR.git "${XRAYR_DIR}"
fi
cd "${XRAYR_DIR}"
git fetch --all --tags
git reset --hard
git checkout "${COMMIT}"

# --------- 打补丁（panel 不 panic / users is null 不致命） ----------
log "打补丁：panel 不 panic / users is null 不致命..."

if grep -q 'log\.Panicf("Panel Start failed: %s", err)' panel/panel.go; then
  sed -i 's/log\.Panicf("Panel Start failed: %s", err)/log.Errorf("Panel Start warning: %s", err)/' panel/panel.go
fi

if grep -q 'return nil, errors.New("users is null")' api/newV2board/v2board.go; then
  sed -i 's/return nil, errors.New("users is null")/return \&[]api.UserInfo{}, nil/' api/newV2board/v2board.go
fi

# --------- 编译安装 ----------
log "编译安装 xrayr..."
go build -o XrayR -ldflags "-s -w" .
install -m 755 XrayR /usr/local/bin/xrayr

# --------- 准备日志目录 ----------
mkdir -p /var/log/XrayR /etc/XrayR
touch /var/log/XrayR/runner.log /var/log/XrayR/access.log /var/log/XrayR/error.log
chmod 700 /var/log/XrayR
chmod 600 /var/log/XrayR/*.log || true

# --------- 写入 runner ----------
log "写入 runner..."
cat >/usr/local/bin/xrayr-runner <<'RUN'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p /var/log/XrayR
while true; do
  echo "[runner] start $(date --iso-8601=seconds)" >>/var/log/XrayR/runner.log
  /usr/local/bin/xrayr --config /etc/XrayR/config.yml >>/var/log/XrayR/runner.log 2>&1 || true
  echo "[runner] xrayr exited at $(date --iso-8601=seconds), retry in 3s" >>/var/log/XrayR/runner.log
  sleep 3
done
RUN
chmod +x /usr/local/bin/xrayr-runner

# --------- 生成 config.yml（ApiHost 仍然走本地 7002） ----------
log "生成 /etc/XrayR/config.yml ..."
cat >/etc/XrayR/config.yml <<EOF
Log:
  Level: none
  AccessPath: /var/log/XrayR/access.log
  ErrorPath: /var/log/XrayR/error.log

DnsConfigPath: /etc/XrayR/dns.json
RouteConfigPath: /etc/XrayR/route.json
InboundConfigPath: /etc/XrayR/custom_inbound.json
OutboundConfigPath: /etc/XrayR/custom_outbound.json

ConnetionConfig:
  Handshake: 4
  ConnIdle: 30
  UplinkOnly: 2
  DownlinkOnly: 4
  BufferSize: 64

Nodes:
  - PanelType: "NewV2board"
    ApiConfig:
      ApiHost: "http://127.0.0.1:7002"
      ApiKey: "${APIKEY}"
      NodeID: ${NODEID}
      NodeType: Vless
      Timeout: 30
      EnableVless: true
      EnableXTLS: true
      VlessFlow: "xtls-rprx-vision"
    ControllerConfig:
      ListenIP: "0.0.0.0"
      SendIP: "0.0.0.0"
      UpdatePeriodic: 60
      CertConfig:
        CertMode: none
      EnableREALITY: true
      REALITYConfigs:
        Show: false
EOF
chmod 600 /etc/XrayR/config.yml

# --------- systemd ----------
log "写入 systemd..."
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

log "验收："
systemctl status xrayr --no-pager -l || true
ss -lntp | grep ':7002' || true

echo
echo "日志：journalctl -u xrayr -o cat -n 200"
echo "runner：tail -n 200 /var/log/XrayR/runner.log"
echo
echo "接口自检（通过 bridge）："
echo "  curl -sS -H 'Token: ***' 'http://127.0.0.1:7002/api/v1/server/UniProxy/config?node_id=${NODEID}&node_type=vless' | jq ."
echo "  curl -sS -H 'Token: ***' 'http://127.0.0.1:7002/api/v1/server/UniProxy/user?node_id=${NODEID}&node_type=vless' | jq ."
echo
log "DONE"
