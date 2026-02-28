#!/usr/bin/env bash
set -Eeuo pipefail

# =========================
# jiaoben.sh  (XrayR + Xboard(NewV2board) VLESS/Reality/Vision 一键稳定版)
# - 复原成功经验 + 避坑版
# - 默认 checkout 稳定 tag v25.3.6（dd786ef 远端已不存在会导致失败）
# - 精准修复：users is null -> 返回空列表指针（不再 panic/不再编译炸）
# - 配置兜底：CertConfig/REALITYConfigs 防 nil panic
# - Go 下载“像卡死”：设置 GOPROXY + 心跳输出 + 全程写日志
# =========================

# ---- CRLF 自愈（Windows 记事本保存常见）----
if grep -q $'\r' "${BASH_SOURCE[0]}" 2>/dev/null; then
  sed -i 's/\r$//' "${BASH_SOURCE[0]}" || true
  exec bash "${BASH_SOURCE[0]}" "$@"
fi

LOG_FILE="/var/log/xrayr_onekey.log"
mkdir -p /var/log
touch "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

trap 'echo -e "\n[!] ERROR line=$LINENO cmd=$BASH_COMMAND\n    -> log: $LOG_FILE\n" >&2' ERR

log(){ echo -e "\n[*] $*\n"; }
die(){ echo -e "\n[!] $*\n" >&2; exit 1; }

require_root(){
  [[ "$(id -u)" == "0" ]] || die "请用 root 运行（sudo -i）"
}

need_cmd(){
  command -v "$1" >/dev/null 2>&1
}

apt_install(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y "$@"
}

read_input(){
  local var="$1" prompt="$2" def="${3:-}"
  local val=""
  if [[ -n "${!var:-}" ]]; then return; fi
  if [[ -n "$def" ]]; then
    read -r -p "$prompt [$def]: " val || true
    val="${val:-$def}"
  else
    read -r -p "$prompt: " val || true
  fi
  [[ -n "$val" ]] || die "输入不能为空：$var"
  printf -v "$var" '%s' "$val"
}

read_secret(){
  local var="$1" prompt="$2"
  if [[ -n "${!var:-}" ]]; then return; fi
  local val=""
  read -r -s -p "$prompt: " val || true
  echo
  [[ -n "$val" ]] || die "输入不能为空：$var"
  printf -v "$var" '%s' "$val"
}

pick_go_version_from_gomod(){
  local gomod="$1"
  local toolchain go_line
  toolchain="$(awk '$1=="toolchain"{print $2}' "$gomod" 2>/dev/null | head -n1 || true)"
  if [[ -n "$toolchain" ]]; then
    echo "${toolchain#go}"
    return
  fi
  go_line="$(awk '$1=="go"{print $2}' "$gomod" 2>/dev/null | head -n1 || true)"
  [[ -n "$go_line" ]] || die "无法从 go.mod 解析 Go 版本"
  if [[ "$go_line" =~ ^[0-9]+\.[0-9]+$ ]]; then
    echo "${go_line}.0"
  else
    echo "$go_line"
  fi
}

go_arch(){
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "不支持的架构: $(uname -m)" ;;
  esac
}

install_go(){
  local ver="$1"
  local arch tgz url
  arch="$(go_arch)"
  tgz="go${ver}.linux-${arch}.tar.gz"
  url="https://go.dev/dl/${tgz}"

  if /usr/local/go/bin/go version 2>/dev/null | grep -q "go${ver}"; then
    log "Go 已是 ${ver}"
  else
    log "安装 Go ${ver}（${arch}）..."
    rm -rf /usr/local/go
    curl -fsSL "$url" -o "/tmp/${tgz}"
    tar -C /usr/local -xzf "/tmp/${tgz}"
  fi

  mkdir -p /etc/profile.d
  cat >/etc/profile.d/go.sh <<'EOF'
export PATH=/usr/local/go/bin:$PATH
EOF

  export PATH=/usr/local/go/bin:$PATH
  command -v go >/dev/null || die "Go 安装失败：找不到 go"
  command -v gofmt >/dev/null || die "Go 安装异常：找不到 gofmt"
  go version
}

setup_go_proxy(){
  # 为了避免“go downloading 卡住”，直接给一个强韧组合：
  # - 先走 goproxy.cn（国内常用），不通则走官方 proxy.golang.org
  # - 关闭 sumdb 避免某些网络下校验卡死
  export GOPROXY="${GOPROXY:-https://goproxy.cn,https://proxy.golang.org,direct}"
  export GOSUMDB="${GOSUMDB:-off}"
  export GOFLAGS="${GOFLAGS:--buildvcs=false}"

  # 写入 go env（可选）
  go env -w GOPROXY="$GOPROXY" >/dev/null 2>&1 || true
  go env -w GOSUMDB="$GOSUMDB" >/dev/null 2>&1 || true
  go env -w GOFLAGS="$GOFLAGS" >/dev/null 2>&1 || true

  log "Go env: GOPROXY=$GOPROXY  GOSUMDB=$GOSUMDB  GOFLAGS=$GOFLAGS"
}

run_with_heartbeat(){
  # 让“看起来没输出”的阶段持续打印心跳，避免你以为卡死
  local title="$1"; shift
  log "$title"
  ( while true; do echo "[hb] $(date '+%F %T') $title"; sleep 8; done ) &
  local hb_pid=$!
  set +e
  "$@"
  local rc=$?
  set -e
  kill "$hb_pid" >/dev/null 2>&1 || true
  wait "$hb_pid" >/dev/null 2>&1 || true
  return $rc
}

git_checkout_stable(){
  local repo="$1"
  local tag="$2"
  local dir="/usr/local/src/XrayR"

  mkdir -p /usr/local/src
  if [[ -d "$dir/.git" ]]; then
    log "更新 XrayR 仓库..."
    git -C "$dir" fetch --all --tags -q
  else
    log "克隆 XrayR 仓库..."
    rm -rf "$dir"
    git clone "$repo" "$dir"
    git -C "$dir" fetch --all --tags -q
  fi

  cd "$dir"
  if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    log "checkout tag: $tag"
    git checkout -f "$tag"
  else
    local latest
    latest="$(git tag --sort=-v:refname | head -n1 || true)"
    [[ -n "$latest" ]] || die "仓库里没有 tag？请检查：$repo"
    log "tag $tag 不存在，自动改用最新 tag: $latest"
    git checkout -f "$latest"
  fi
}

patch_users_is_null(){
  local f="api/newV2board/v2board.go"
  [[ -f "$f" ]] || die "找不到文件：$f（仓库结构变了？）"

  if grep -q 'return &empty, nil' "$f"; then
    log "补丁已存在：users is null -> &empty, nil（跳过）"
    return
  fi

  if ! grep -q 'errors.New("users is null")' "$f"; then
    log "未发现 users is null 逻辑（可能上游已修复），跳过补丁"
    return
  fi

  log "应用补丁：users is null -> 返回空切片指针（不报错）"
  # 用 patch 精准改三行，避免误伤导致编译炸（你之前那种 353/444 return values 就是误伤）
  patch -p0 -N "$f" <<'PATCH'
*** api/newV2board/v2board.go
--- api/newV2board/v2board.go
***************
*** 1,1 ****
--- 1,1 ----
PATCH
  # 上面只是占位确保 patch 命令存在；实际用 perl 做“最小范围替换”（严格锚定 users is null 行）

  # 只替换： if len(users) == 0 { return nil, errors.New("users is null") }
  # 为：      if len(users) == 0 { empty := make([]api.UserInfo,0); return &empty, nil }
  perl -pi -e '
    if ($.>=1) {
      s/^\s*return\s+nil,\s*errors\.New\("users is null"\)\s*$/\t\tempty := make([]api.UserInfo, 0)\n\t\treturn \&empty, nil/;
    }
  ' "$f"

  # 额外保险：如果出现 “return []api.UserInfo{}” 这种错误返回，也替换掉
  perl -pi -e '
    if ($.>=1) {
      s/^\s*return\s+\[\]api\.UserInfo\{\},\s*nil\s*$/\t\tempty := make([]api.UserInfo, 0)\n\t\treturn \&empty, nil/;
    }
  ' "$f"

  gofmt -w "$f" || true

  grep -n 'users is null' "$f" || true
  grep -n 'return \&empty, nil' "$f" >/dev/null || die "补丁未生效：$f"
}

write_xrayr_config(){
  local api_host="$1" api_key="$2" node_id="$3" update_periodic="$4"

  mkdir -p /etc/XrayR /var/log/XrayR
  chmod 700 /etc/XrayR
  touch /var/log/XrayR/runner.log /var/log/XrayR/access.log /var/log/XrayR/error.log

  cat >/etc/XrayR/config.yml <<EOF
Log:
  Level: info
  AccessPath: /var/log/XrayR/access.log
  ErrorPath: /var/log/XrayR/error.log

Nodes:
  - PanelType: "NewV2board"
    ApiConfig:
      ApiHost: "${api_host}"
      ApiKey: "${api_key}"
      NodeID: ${node_id}
      NodeType: Vless
      Timeout: 30
      EnableVless: true
      EnableXTLS: true
      VlessFlow: "xtls-rprx-vision"
      # 兜底：避免 nil panic
      CertConfig:
        CertMode: none
      REALITYConfigs:
        Show: false
    ControllerConfig:
      ListenIP: 0.0.0.0
      SendIP: 0.0.0.0
      UpdatePeriodic: ${update_periodic}
      DisableSniffing: true
EOF

  chmod 600 /etc/XrayR/config.yml
}

install_runner_and_systemd(){
  cat >/usr/local/bin/xrayr-runner <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
LOG="/var/log/XrayR/runner.log"
CFG="/etc/XrayR/config.yml"
mkdir -p /var/log/XrayR
touch "$LOG"
while true; do
  echo "[runner] start $(date --iso-8601=seconds)" >>"$LOG"
  /usr/local/bin/xrayr -c "$CFG" >>"$LOG" 2>&1 || true
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
}

setup_xboard_cron_if_present(){
  # 只有在本机确实有 xboard-web-1 容器时才装
  if need_cmd docker && docker ps --format '{{.Names}}' | grep -q '^xboard-web-1$'; then
    log "检测到 xboard-web-1：配置 cron 每分钟跑 schedule:run（用于封禁/超流量等计划任务）"
    apt_install cron util-linux >/dev/null
    cat >/etc/cron.d/xboard-schedule <<'EOF'
* * * * * root flock -n /tmp/xboard_schedule.lock docker exec -i xboard-web-1 php artisan schedule:run --no-interaction >>/var/log/xboard_schedule.log 2>&1
EOF
    chmod 644 /etc/cron.d/xboard-schedule
    touch /var/log/xboard_schedule.log
    systemctl enable --now cron
  else
    log "未检测到 xboard-web-1（跳过 schedule cron）"
  fi
}

main(){
  require_root
  log "[+] Start: $(date) | log: $LOG_FILE"

  if ! need_cmd apt-get; then
    die "此脚本按 Debian/Ubuntu(apt-get) 写的，你的系统不匹配。"
  fi

  log "Basic deps..."
  apt_install ca-certificates curl jq perl iproute2 tar git patch >/dev/null

  # ---- 交互输入（也支持环境变量免交互）----
  XRAYR_NODE_ID="${XRAYR_NODE_ID:-}"
  XRAYR_API_KEY="${XRAYR_API_KEY:-}"
  XRAYR_API_HOST="${XRAYR_API_HOST:-http://127.0.0.1:7001}"
  XRAYR_UPDATE_PERIODIC="${XRAYR_UPDATE_PERIODIC:-60}"
  XRAYR_REPO="${XRAYR_REPO:-https://github.com/XrayR-project/XrayR.git}"
  XRAYR_TAG="${XRAYR_TAG:-v25.3.6}"

  read_input XRAYR_NODE_ID "[?] Enter NodeID (e.g. 1)" "${XRAYR_NODE_ID:-1}"
  read_secret XRAYR_API_KEY "[?] Enter ApiKey (input hidden)"
  read_input XRAYR_API_HOST "[?] Enter ApiHost" "$XRAYR_API_HOST"
  read_input XRAYR_UPDATE_PERIODIC "[?] Enter UpdatePeriodic(seconds)" "$XRAYR_UPDATE_PERIODIC"
  read_input XRAYR_REPO "[?] Enter XrayR repo" "$XRAYR_REPO"
  read_input XRAYR_TAG "[?] Enter XrayR tag" "$XRAYR_TAG"

  log "NodeID=$XRAYR_NODE_ID  ApiKeyLen=${#XRAYR_API_KEY}  ApiHost=$XRAYR_API_HOST  UpdatePeriodic=$XRAYR_UPDATE_PERIODIC"
  setup_xboard_cron_if_present

  # ---- 拉代码 + checkout 稳定 tag ----
  git_checkout_stable "$XRAYR_REPO" "$XRAYR_TAG"

  # ---- 读 go.mod 决定 Go 版本 ----
  local go_ver
  go_ver="$(pick_go_version_from_gomod go.mod)"
  install_go "$go_ver"
  setup_go_proxy

  # ---- 需要编译环境 ----
  log "Installing build deps..."
  apt_install build-essential >/dev/null

  # ---- 精准补丁：users is null ----
  patch_users_is_null

  # ---- 下载模块 + 编译（带心跳，避免你以为卡死）----
  export PATH=/usr/local/go/bin:$PATH
  run_with_heartbeat "go mod download (可能依赖多，会持续输出心跳)" go mod download
  run_with_heartbeat "go build -v (编译安装 xrayr)" go build -v -trimpath -ldflags "-s -w" -o XrayR .

  install -m 755 XrayR /usr/local/bin/xrayr
  /usr/local/bin/xrayr version || true

  # ---- 写配置 + systemd ----
  write_xrayr_config "$XRAYR_API_HOST" "$XRAYR_API_KEY" "$XRAYR_NODE_ID" "$XRAYR_UPDATE_PERIODIC"
  install_runner_and_systemd

  sleep 2
  log "Service status:"
  systemctl status xrayr --no-pager -l || true
  log "Listening:"
  ss -lntp | grep -E 'xrayr|:8443|:9443|:2053|:2083|:2096' || true

  log "DONE ✅
- 配置: /etc/XrayR/config.yml
- runner日志: /var/log/XrayR/runner.log
- 一键日志: $LOG_FILE
- 查看实时日志：tail -f /var/log/XrayR/runner.log
"
}

main "$@"
