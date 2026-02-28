#!/usr/bin/env bash
set -euo pipefail

# =========================
#  XrayR Node OneKey (Repro Success)
#  - same method as our success:
#    1) nginx token-bridge on 127.0.0.1:7002 (inject Header Token -> query token=)
#    2) build XrayR from stable commit dd786ef
#    3) patch:
#       - panel/panel.go: log.Panicf -> log.Errorf (avoid crash)
#       - api/newV2board/v2board.go: "users is null" -> return empty slice (no panic / no crash)
#    4) systemd runner: /usr/local/bin/xrayr-runner + /etc/systemd/system/xrayr.service
#    5) config.yml includes CertConfig + REALITYConfigs to avoid nil pitfalls
# =========================

XRAYR_REPO="https://github.com/XrayR-project/XrayR.git"
XRAYR_DIR="/usr/local/src/XrayR"
XRAYR_COMMIT="dd786ef"
GO_VERSION="1.25.3"
GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TARBALL}"

NGINX_LISTEN_IP="127.0.0.1"
NGINX_LISTEN_PORT="7002"

XRAYR_BIN="/usr/local/bin/xrayr"
RUNNER_BIN="/usr/local/bin/xrayr-runner"
CFG_DIR="/etc/XrayR"
CFG_FILE="/etc/XrayR/config.yml"
LOG_DIR="/var/log/XrayR"
RUNNER_LOG="/var/log/XrayR/runner.log"

# 可选环境变量（用于一行命令无交互）：
#   API_ORIGIN="https://panel.example.com"
#   NODE_ID="1"
#   API_KEY="xxxx"              # 不要写进 GitHub，只在运行时 export/临时设置
#   UPDATE_PERIODIC="60"

color() { local c="$1"; shift; printf "\033[%sm%s\033[0m\n" "$c" "$*"; }
info()  { color "36" "[+] $*"; }
warn()  { color "33" "[!] $*"; }
err()   { color "31" "[-] $*"; }
die()   { err "$*"; exit 1; }

need_root() { [ "$(id -u)" -eq 0 ] || die "请用 root 运行"; }

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends "$@"
}

trim_trailing_slash() { echo "$1" | sed 's#/*$##'; }

install_go() {
  if command -v go >/dev/null 2>&1; then
    local gv
    gv="$(go version | awk '{print $3}' || true)"
    info "Go 已存在：${gv}"
    if echo "$gv" | grep -q "go${GO_VERSION}"; then
      info "Go 版本匹配 ${GO_VERSION}，跳过安装"
      return 0
    fi
    warn "Go 版本与预期不一致（期望 ${GO_VERSION}），将按成功经验覆盖安装到 /usr/local/go"
  fi

  info "安装 Go ${GO_VERSION}..."
  rm -rf /usr/local/go
  mkdir -p /usr/local
  curl -fsSL "$GO_URL" -o "/tmp/${GO_TARBALL}"
  tar -C /usr/local -xzf "/tmp/${GO_TARBALL}"
  rm -f "/tmp/${GO_TARBALL}"

  export PATH=/usr/local/go/bin:$PATH
  info "$(go version)"
}

clone_xrayr() {
  info "准备 XrayR 源码..."
  mkdir -p /usr/local/src
  if [ -d "$XRAYR_DIR/.git" ]; then
    info "已存在源码目录，fetch 并强制检出..."
    git -C "$XRAYR_DIR" fetch --all --tags
  else
    info "克隆 XrayR..."
    git clone "$XRAYR_REPO" "$XRAYR_DIR"
  fi

  info "检出稳定 commit：${XRAYR_COMMIT}"
  git -C "$XRAYR_DIR" checkout -f "$XRAYR_COMMIT"
}

apply_patches() {
  info "打补丁：避免 users=null / panic 崩溃（按成功经验）..."

  # 1) panel/panel.go: Panicf -> Errorf（避免直接 panic）
  if grep -q 'log\.Panicf("Panel Start failed: %s", err)' "$XRAYR_DIR/panel/panel.go" 2>/dev/null; then
    sed -i 's/log\.Panicf("Panel Start failed: %s", err)/log.Errorf("Panel Start warning: %s", err)/' \
      "$XRAYR_DIR/panel/panel.go"
    info "已修改 panel/panel.go：Panicf -> Errorf"
  else
    warn "panel/panel.go 未命中预期行（仓库结构可能变化），跳过该项"
  fi

  # 2) api/newV2board/v2board.go: users is null -> return empty slice（关键修复）
  if [ -f "$XRAYR_DIR/api/newV2board/v2board.go" ]; then
    if grep -q 'return nil, errors.New("users is null")' "$XRAYR_DIR/api/newV2board/v2board.go"; then
      sed -i 's/return nil, errors.New("users is null")/return []api.UserInfo{}, nil/' \
        "$XRAYR_DIR/api/newV2board/v2board.go"
      info "已修改 api/newV2board/v2board.go：users is null -> empty slice"
    else
      if grep -q 'users is null' "$XRAYR_DIR/api/newV2board/v2board.go"; then
        warn "发现 users is null 但行式不同，请手动检查 api/newV2board/v2board.go"
      else
        warn "未找到 users is null 判空行（可能已修复/改动），跳过该项"
      fi
    fi
  else
    warn "未找到 api/newV2board/v2board.go（仓库结构变化？），跳过该项"
  fi
}

build_install_xrayr() {
  info "编译安装 xrayr（会下载 Go 依赖，可能一段时间无输出）..."
  export PATH=/usr/local/go/bin:$PATH
  pushd "$XRAYR_DIR" >/dev/null
  go build -o XrayR -ldflags "-s -w" .
  install -m 755 XrayR "$XRAYR_BIN"
  popd >/dev/null
  info "xrayr 已安装到 ${XRAYR_BIN}"
}

setup_dirs() {
  mkdir -p "$CFG_DIR" "$LOG_DIR"
  touch "$RUNNER_LOG"
}

write_nginx_bridge() {
  local upstream="$1"
  upstream="$(trim_trailing_slash "$upstream")"
  [ -n "$upstream" ] || die "API_ORIGIN 不能为空"

  local upstream_host
  upstream_host="$(echo "$upstream" | sed -E 's#^https?://##; s#/.*$##')"
  [ -n "$upstream_host" ] || die "解析 upstream_host 失败：$upstream"

  info "安装并配置 nginx token-bridge：${NGINX_LISTEN_IP}:${NGINX_LISTEN_PORT} -> ${upstream}"
  apt_install nginx ca-certificates curl jq

  # 删除默认站点（避免监听 80 抢占）
  rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default 2>/dev/null || true
  rm -f /etc/nginx/conf.d/default.conf 2>/dev/null || true

  cat >/etc/nginx/conf.d/xboard_token_bridge.conf <<NG
server {
  listen ${NGINX_LISTEN_IP}:${NGINX_LISTEN_PORT};
  server_name _;

  location / {
    # token：优先 query token，其次 Header Token
    set \$token \$arg_token;
    if (\$token = "") { set \$token \$http_token; }
    if (\$token = "") { return 400; }

    # 若原请求没带 token=，把 header Token 注入 query
    if (\$arg_token = "") { set \$args "\${args}&token=\${token}"; }
    # 若原来没有任何 args，会变成 "&token=xxx"，把开头的 & 去掉
    if (\$args ~ "^&")    { set \$args "token=\${token}"; }

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host ${upstream_host};
    proxy_ssl_server_name on;

    proxy_pass ${upstream}\$uri?\$args;
  }
}
NG

  nginx -t
  systemctl enable --now nginx
  systemctl restart nginx

  ss -lntp | grep -q ":${NGINX_LISTEN_PORT}" || die "nginx 未监听 ${NGINX_LISTEN_IP}:${NGINX_LISTEN_PORT}"
  info "nginx 已监听 ${NGINX_LISTEN_IP}:${NGINX_LISTEN_PORT}"
}

write_config() {
  local node_id="$1"
  local api_key="$2"
  local upd="$3"
  upd="${upd:-60}"

  [ -n "$node_id" ] || die "NodeID 不能为空"
  [ -n "$api_key" ] || die "ApiKey 不能为空"

  if [ -f "$CFG_FILE" ]; then
    cp -a "$CFG_FILE" "/root/config.yml.bak.$(date +%F_%H%M%S)" || true
    warn "已备份旧配置到 /root/config.yml.bak.*"
  fi

  info "写入 ${CFG_FILE}（ApiKey 不回显）..."
  cat >"$CFG_FILE" <<EOF
Log:
  Level: info
  AccessPath: "${LOG_DIR}/access.log"
  ErrorPath: "${LOG_DIR}/error.log"

DnsConfigPath:
RouteConfigPath:
InboundConfigPath:
OutboundConfigPath:

Nodes:
  - PanelType: "NewV2board"
    ApiConfig:
      ApiHost: "http://${NGINX_LISTEN_IP}:${NGINX_LISTEN_PORT}"
      ApiKey: "${api_key}"
      NodeID: ${node_id}
      NodeType: Vless
      Timeout: 30
    ControllerConfig:
      ListenIP: 0.0.0.0
      SendIP: 0.0.0.0
      UpdatePeriodic: ${upd}

      EnableVless: true
      EnableXTLS: true
      VlessFlow: "xtls-rprx-vision"

      # 避免 nil 坑（按成功经验）
      CertConfig:
        CertMode: none
      REALITYConfigs:
        Show: false
EOF
}

write_runner_and_service() {
  info "写入 runner：${RUNNER_BIN}"
  cat >"$RUNNER_BIN" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
LOG="/var/log/XrayR/runner.log"
mkdir -p /var/log/XrayR
touch "$LOG"

while true; do
  /usr/local/bin/xrayr --config /etc/XrayR/config.yml >>"$LOG" 2>&1 || true
  echo "[runner] xrayr exited at $(date -Is), retry in 3s" >>"$LOG"
  sleep 3
done
SH
  chmod +x "$RUNNER_BIN"

  info "写入 systemd：/etc/systemd/system/xrayr.service"
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
}

optional_setup_xboard_cron_if_local_panel() {
  if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q '^xboard-web-1$'; then
    info "检测到本机 xboard-web-1，配置 cron 跑 schedule:run（按成功经验）..."
    apt_install cron util-linux

    cat >/etc/cron.d/xboard-schedule <<'EOF'
* * * * * root flock -n /tmp/xboard_schedule.lock docker exec xboard-web-1 php artisan schedule:run --no-interaction >>/var/log/xboard_schedule.log 2>&1
EOF
    chmod 644 /etc/cron.d/xboard-schedule
    touch /var/log/xboard_schedule.log
    systemctl enable --now cron
  else
    info "未检测到本机 xboard-web-1，跳过 schedule:run（面板不在本机则正常）"
  fi
}

smoke_test() {
  local node_id="$1"
  local api_key="$2"
  local host="http://${NGINX_LISTEN_IP}:${NGINX_LISTEN_PORT}"

  info "自检：通过 bridge 拉 config/user..."
  echo "NodeID=${node_id}  ApiKeyLen=${#api_key}"

  echo "== config =="
  curl -sS -H "Token: ${api_key}" -w "\nHTTP:%{http_code}\n" \
    "${host}/api/v1/server/UniProxy/config?node_id=${node_id}&node_type=vless" | head -c 900; echo

  echo "== user(len) =="
  curl -sS -H "Token: ${api_key}" \
    "${host}/api/v1/server/UniProxy/user?node_id=${node_id}&node_type=vless" \
    | jq -r '.users|length' 2>/dev/null || true
}

main() {
  need_root
  info "开始按“成功经验”复原：XrayR + nginx token-bridge + patches + runner"

  info "安装基础依赖..."
  apt_install git curl jq ca-certificates iproute2 build-essential unzip

  # 输入（优先用环境变量）
  local API_ORIGIN="${API_ORIGIN:-}"
  local NODE_ID="${NODE_ID:-}"
  local API_KEY="${API_KEY:-}"
  local UPDATE_PERIODIC="${UPDATE_PERIODIC:-60}"

  if [ -z "$API_ORIGIN" ]; then
    read -rp "面板地址 API_ORIGIN（例如 https://liucna.com 或 http://127.0.0.1:7001）: " API_ORIGIN
  fi
  API_ORIGIN="$(trim_trailing_slash "$API_ORIGIN")"
  [ -n "$API_ORIGIN" ] || die "API_ORIGIN 不能为空"

  if [ -z "$NODE_ID" ]; then
    read -rp "NodeID（例如 1）: " NODE_ID
  fi
  [ -n "$NODE_ID" ] || die "NodeID 不能为空"

  if [ -z "$API_KEY" ]; then
    read -rsp "ApiKey（不回显）: " API_KEY
    echo
  fi
  [ -n "$API_KEY" ] || die "ApiKey 不能为空"

  if [ -z "${UPDATE_PERIODIC:-}" ]; then
    UPDATE_PERIODIC="60"
  fi

  # 1) nginx token-bridge（7002）
  write_nginx_bridge "$API_ORIGIN"

  # 2) go
  install_go

  # 3) clone + patch + build
  clone_xrayr
  apply_patches
  setup_dirs
  build_install_xrayr

  # 4) config.yml（ApiHost 固定走 127.0.0.1:7002）
  write_config "$NODE_ID" "$API_KEY" "$UPDATE_PERIODIC"

  # 5) runner + systemd
  write_runner_and_service

  # 6) 若本机有 xboard-web-1，则补 cron schedule
  optional_setup_xboard_cron_if_local_panel

  # 7) 自检
  smoke_test "$NODE_ID" "$API_KEY"

  echo
  info "完成 ✅"
  echo "常用命令："
  echo "  tail -n 200 ${RUNNER_LOG}"
  echo "  journalctl -u xrayr -o cat -n 200"
  echo "  ss -lntp | grep -E ':8443|xrayr' || true"
  echo "  ss -lntp | grep ':${NGINX_LISTEN_PORT}' || true"
}

main "$@"
