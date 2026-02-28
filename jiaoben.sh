#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Xboard(NewV2board) + XrayR(VLESS/XTLS/REALITY) 一键复原脚本
# 复原点：
#  - nginx token-bridge: 127.0.0.1:7002 -> 127.0.0.1:7001 (把 Header Token 注入 query token=)
#  - XrayR: checkout dd786ef 并编译安装
#  - 补丁1：panel 不 panic
#  - 补丁2：users is null -> 返回 &[]api.UserInfo{}, nil（避免 *[]api.UserInfo 类型坑）
#  - config.yml：UpdatePeriodic=60 + CertMode none + REALITY Show false
#  - systemd: runner 循环拉起
#  - cron: 每分钟 docker exec xboard-web-1 php artisan schedule:run
#
# 运行方式（推荐）：
#   bash <(curl -fsSL https://raw.githubusercontent.com/<you>/<repo>/main/jiaoben.sh)
# ============================================================

log() { echo -e "\033[1;32m[+]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[!]\033[0m $*"; }
die() { echo -e "\033[1;31m[x]\033[0m $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行"
export DEBIAN_FRONTEND=noninteractive

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

# --------- 前置检查：xboard 必须在本机 7001 ----------
if ! ss -lntp 2>/dev/null | grep -qE '127\.0\.0\.1:7001|:7001'; then
  die "检测不到本机 127.0.0.1:7001（xboard 未监听）。请先把 xboard/docker 部署好并保证 7001 可访问，再运行本脚本。"
fi

# --------- 安装依赖 ----------
log "安装依赖..."
apt-get update -y
apt-get install -y git curl ca-certificates jq iproute2 build-essential unzip nginx cron util-linux

# --------- nginx token-bridge：7002 -> 7001 ----------
log "配置 nginx token-bridge (127.0.0.1:7002 -> http://127.0.0.1:7001)..."
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default || true

cat >/etc/nginx/conf.d/xboard_token_bridge.conf <<'NG'
server {
  listen 127.0.0.1:7002;
  server_name _;

  location / {
    # token：优先 query token，其次 Header Token
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

nginx -t
systemctl enable --now nginx || true
systemctl restart nginx
ss -lntp | grep ':7002' >/dev/null || die "nginx 7002 未监听，token-bridge 失败"

# --------- 安装 Go（按我们成功那次：go1.25.3） ----------
GO_VER="1.25.3"
if ! command -v go >/dev/null 2>&1; then
  log "安装 Go ${GO_VER}..."
  tgz="go${GO_VER}.linux-amd64.tar.gz"
  curl -fsSL "https://go.dev/dl/${tgz}" -o "/tmp/${tgz}"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "/tmp/${tgz}"
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
fi
export PATH=/usr/local/go/bin:$PATH
go version || die "go 不可用"

# --------- 拉取 XrayR 并 checkout 固定 commit（我们成功那次） ----------
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

# --------- 打补丁（原样复原） ----------
log "打补丁：panel 不 panic / users is null 不致命..."

# 1) panel/panel.go：log.Panicf -> log.Errorf
if grep -q 'log\.Panicf("Panel Start failed: %s", err)' panel/panel.go; then
  sed -i 's/log\.Panicf("Panel Start failed: %s", err)/log.Errorf("Panel Start warning: %s", err)/' panel/panel.go
fi

# 2) api/newV2board/v2board.go：users is null -> 返回 &[]api.UserInfo{}, nil（注意是“指针切片”）
#    这是你之前卡住那条报错的“原样解决法”：
#    cannot use []api.UserInfo{} as *[]api.UserInfo
if grep -q 'return nil, errors.New("users is null")' api/newV2board/v2board.go; then
  # sed 的替换里 & 代表“整段匹配”，所以要写成 \& 才能输出字面量 &
  sed -i 's/return nil, errors.New("users is null")/return \&[]api.UserInfo{}, nil/' api/newV2board/v2board.go
fi

# --------- 编译安装 ----------
log "编译安装 xrayr（Go 依赖第一次会久）..."
go build -o XrayR -ldflags "-s -w" .
install -m 755 XrayR /usr/local/bin/xrayr

# --------- 准备日志目录 ----------
mkdir -p /var/log/XrayR /etc/XrayR
touch /var/log/XrayR/runner.log /var/log/XrayR/access.log /var/log/XrayR/error.log
chmod 700 /var/log/XrayR
chmod 600 /var/log/XrayR/*.log || true

# --------- 写入 runner（稳定循环拉起） ----------
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

# --------- 生成 /etc/XrayR/config.yml（关键：UpdatePeriodic + CertMode + REALITY Show） ----------
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
      # ✅ 这俩就是我们之前避免 nil panic 的关键（原样复原）
      CertConfig:
        CertMode: none
      EnableREALITY: true
      REALITYConfigs:
        Show: false
EOF
chmod 600 /etc/XrayR/config.yml

# --------- systemd（注意 StartLimitIntervalSec 在 [Unit]，避免 Unknown key） ----------
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

# --------- cron：跑 xboard schedule:run（你这次验证过可用的那套） ----------
log "配置 cron 跑 xboard schedule:run（如果容器 xboard-web-1 存在）..."
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx 'xboard-web-1'; then
  cat >/etc/cron.d/xboard-schedule <<'EOF'
* * * * * root flock -n /tmp/xboard_schedule.lock docker exec -i xboard-web-1 php artisan schedule:run --no-interaction >>/var/log/xboard_schedule.log 2>&1
EOF
  chmod 644 /etc/cron.d/xboard-schedule
  touch /var/log/xboard_schedule.log
  systemctl enable --now cron || true
else
  warn "未检测到容器 xboard-web-1，已跳过 cron 配置（不影响 xrayr 启动，但可能影响面板定时任务）"
fi

# --------- 验收输出 ----------
log "验收："
systemctl status xrayr --no-pager -l || true
ss -lntp | grep ':7002' || true

echo
echo "日志：journalctl -u xrayr -o cat -n 200"
echo "runner：tail -n 200 /var/log/XrayR/runner.log"
echo
echo "接口自检（config/user）："
echo "  curl -sS -H 'Token: ***' 'http://127.0.0.1:7002/api/v1/server/UniProxy/config?node_id=${NODEID}&node_type=vless' | jq ."
echo "  curl -sS -H 'Token: ***' 'http://127.0.0.1:7002/api/v1/server/UniProxy/user?node_id=${NODEID}&node_type=vless' | jq ."
echo
log "DONE"
