#!/usr/bin/env bash
set -euo pipefail

# =============== 固定为“成功经验”同款参数 ===============
XRAYR_COMMIT="dd786ef"
GO_VERSION="1.25.3"

# xboard UniProxy 在本机 7001（你现网就是这样）
UPSTREAM="http://127.0.0.1:7001"
# nginx token-bridge 在本机 7002（我们成功就是靠它把 Header Token 注入 query token）
BRIDGE="http://127.0.0.1:7002"

# =============== 工具函数 ===============
log(){ echo -e "\033[1;32m[+]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[!]\033[0m $*" >&2; }
die(){ echo -e "\033[1;31m[x]\033[0m $*" >&2; exit 1; }

need_root(){ [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "请用 root 运行"; }

tty_read(){
  # tty_read VAR "Prompt" [silent=1]
  local var="$1" prompt="$2" silent="${3:-0}"
  if [[ -n "${!var:-}" ]]; then return 0; fi
  [[ -t 0 || -e /dev/tty ]] || die "非交互模式请用环境变量提供：$var"
  if [[ "$silent" == "1" ]]; then
    read -r -s -p "$prompt" "$var" </dev/tty || true
    echo </dev/tty
  else
    read -r -p "$prompt" "$var" </dev/tty || true
  fi
  [[ -n "${!var:-}" ]] || die "$var 不能为空"
}

backup_if_exists(){
  local f="$1"
  if [[ -f "$f" ]]; then
    cp -a "$f" "/root/$(basename "$f").bak.$(date +%F_%H%M%S)"
  fi
}

need_root
export DEBIAN_FRONTEND=noninteractive

# =============== 读入必要参数（和我们成功时一样：ApiKey 不回显） ===============
tty_read XRAYR_APIKEY "ApiKey(不回显): " 1
tty_read XRAYR_NODEID "NodeID(例如 1): " 0

# =============== 安装依赖（同款） ===============
log "安装依赖..."
apt-get update -y
apt-get install -y git curl ca-certificates jq iproute2 build-essential unzip nginx cron util-linux

# =============== nginx token bridge：127.0.0.1:7002 -> 127.0.0.1:7001（同款） ===============
log "配置 nginx token-bridge (7002 -> 7001)..."
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
    if (\$args ~ "^&")    { set \$args "token=\${token}"; }

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host 127.0.0.1;

    proxy_pass ${UPSTREAM}\$uri?\$args;
  }
}
NG

# 去掉默认站点避免占用 80（我们踩过这个坑）
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default || true

nginx -t
systemctl enable --now nginx
systemctl restart nginx

ss -lntp | grep -q '127\.0\.0\.1:7002' || die "nginx 未监听 127.0.0.1:7002"

# =============== 安装 Go 1.25.3（同款） ===============
log "安装 Go ${GO_VERSION}..."
TGZ="go${GO_VERSION}.linux-amd64.tar.gz"
URL="https://go.dev/dl/${TGZ}"
rm -rf /usr/local/go
curl -fsSL "$URL" -o "/tmp/${TGZ}"
tar -C /usr/local -xzf "/tmp/${TGZ}"
export PATH=/usr/local/go/bin:$PATH
go version | grep -q "go${GO_VERSION}" || die "Go 安装失败"

# =============== clone + checkout 固定 commit（同款） ===============
log "拉取 XrayR 并 checkout ${XRAYR_COMMIT}..."
mkdir -p /usr/local/src
if [[ ! -d /usr/local/src/XrayR/.git ]]; then
  git clone https://github.com/XrayR-project/XrayR.git /usr/local/src/XrayR
fi
cd /usr/local/src/XrayR
git fetch --all --tags
git checkout -f "${XRAYR_COMMIT}"

# =============== 打补丁（同款：1) panel 不 panic 2) users is null 返回 *空切片 指针） ===============
log "打补丁：panel 不 panic / users is null 不致命..."
# 1) panel/panel.go：log.Panicf -> log.Errorf（我们就是这么解决一直崩的）
if grep -q 'log.Panicf("Panel Start failed: %s", err)' panel/panel.go; then
  sed -i 's/log\.Panicf("Panel Start failed: %s", err)/log.Errorf("Panel Start warning: %s", err)/' panel/panel.go
fi

# 2) api/newV2board/v2board.go：return nil, errors.New("users is null")
#    -> return &[]api.UserInfo{}, nil
#    这就是你问的那个报错的“原样解决”：因为函数返回类型是 *[]api.UserInfo
if grep -q 'return nil, errors.New("users is null")' api/newV2board/v2board.go; then
  sed -i 's/return nil, errors.New("users is null")/return \&[]api.UserInfo{}, nil/' api/newV2board/v2board.go
fi

# =============== 编译安装（同款） ===============
log "编译安装 xrayr..."
go build -o XrayR -ldflags "-s -w" .
install -m 755 XrayR /usr/local/bin/xrayr

# =============== runner（同款路径 + 同款日志） ===============
log "写入 runner..."
mkdir -p /var/log/XrayR /etc/XrayR
cat >/usr/local/bin/xrayr-runner <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
LOG_DIR=/var/log/XrayR
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/runner.log"
CONFIG=/etc/XrayR/config.yml

while true; do
  /usr/local/bin/xrayr --config "$CONFIG" >>"$LOG_FILE" 2>&1 || true
  echo "[runner] xrayr exited at $(date -Is), retry in 3s" >>"$LOG_FILE"
  sleep 3
done
EOF
chmod 755 /usr/local/bin/xrayr-runner

# =============== config.yml（同款关键字段 + 避免 nil panic 的 CertConfig/REALITYConfigs） ===============
log "生成 /etc/XrayR/config.yml ..."
backup_if_exists /etc/XrayR/config.yml

cat >/etc/XrayR/config.yml <<EOF
Log:
  Level: info
  AccessPath: /var/log/XrayR/access.log
  ErrorPath: /var/log/XrayR/error.log

ApiConfig:
  - PanelType: "NewV2board"
    ApiConfig:
      ApiHost: "${BRIDGE}"
      ApiKey: "${XRAYR_APIKEY}"
      NodeID: ${XRAYR_NODEID}
      NodeType: Vless
      Timeout: 30
      EnableVless: true
      EnableXTLS: true
      VlessFlow: "xtls-rprx-vision"

      # 这些是我们成功经验里“必须有”的字段，避免 nil panic
      CertConfig:
        CertMode: none
      REALITYConfigs:
        Show: false

      # 别太低，避免放大面板偶发问题
      UpdatePeriodic: 60
EOF

# =============== systemd（同款 runner 模式；StartLimit 放 Unit 里避免 Unknown key） ===============
log "写入 systemd..."
cat >/etc/systemd/system/xrayr.service <<'EOF'
[Unit]
Description=XrayR Service (stable runner)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
StartLimitBurst=0

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
: > /var/log/XrayR/runner.log
systemctl restart xrayr
sleep 2

# =============== cron：xboard schedule:run（同款：解决封禁/超流量规则不生效的关键之一） ===============
log "配置 cron 跑 xboard schedule:run（如果容器存在）..."
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx 'xboard-web-1'; then
  cat >/etc/cron.d/xboard-schedule <<'EOF'
* * * * * root flock -n /tmp/xboard_schedule.lock docker exec xboard-web-1 php artisan schedule:run --no-interaction >>/var/log/xboard_schedule.log 2>&1
EOF
  chmod 644 /etc/cron.d/xboard-schedule
  touch /var/log/xboard_schedule.log
  systemctl enable --now cron
else
  warn "未发现 xboard-web-1 容器，跳过 schedule:run（你如果还没装 xboard，等装完再跑一次本脚本即可）"
fi

# =============== 验收输出（同款） ===============
log "验收："
systemctl status xrayr --no-pager -l || true
ss -lntp | grep -E ':7002|:8443|xrayr' || true
tail -n 80 /var/log/XrayR/runner.log || true

log "DONE"
