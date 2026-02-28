#!/usr/bin/env bash
set -Eeuo pipefail

# =========================
# XrayR Node One-Key Script (stable,坑位修复版 + Go 下载卡住自动修复)
# 适用：Debian 12 / Ubuntu / 常见 Linux
#
# 你卡在：go: downloading ... 不动
# 依据你提供的聊天记录，最常见原因是：GOPROXY/网络不可达导致 go mod download 卡住
# 脚本内置同样思路：
#   1) 先用 goproxy.cn + sum.golang.google.cn
#   2) 仍卡：go clean -modcache 再下
#   3) 仍卡：切到 goproxy.cn + GOSUMDB=off
#   4) 仍卡：切到 proxy.golang.org + sum.golang.org
# 并用“无进度自动杀掉重试”的 watchdog 避免无限卡死
# =========================

# ---- CRLF 自愈：如果 GitHub 文件被提交成 CRLF，bash <(curl ...) 也会中招；这里自动转成 LF 再执行 ----
if grep -q $'\r' "${BASH_SOURCE[0]}" 2>/dev/null; then
  tmp="/tmp/xrayr_jiaoben.$$.sh"
  sed 's/\r$//' "${BASH_SOURCE[0]}" >"${tmp}" || true
  chmod +x "${tmp}" || true
  exec bash "${tmp}" "$@"
fi

log(){ echo -e "\n[+] $*\n"; }
warn(){ echo -e "\n[!] $*\n" >&2; }
die(){ echo -e "\n[x] $*\n" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1; }

require_root(){
  if [ "$(id -u)" -ne 0 ]; then
    die "请先 sudo -i 切到 root 再运行（bash <(curl ...) 场景无法在脚本内可靠自提权）"
  fi
}

os_install_pkgs(){
  log "安装依赖..."
  if need apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y \
      git curl ca-certificates jq unzip tar \
      build-essential pkg-config \
      iproute2 iptables \
      perl
  elif need dnf; then
    dnf install -y \
      git curl ca-certificates jq unzip tar \
      gcc gcc-c++ make pkgconf-pkg-config \
      iproute iptables \
      perl
  elif need yum; then
    yum install -y \
      git curl ca-certificates jq unzip tar \
      gcc gcc-c++ make pkgconfig \
      iproute iptables \
      perl
  else
    die "不支持的发行版：找不到 apt-get / dnf / yum"
  fi
}

go_arch(){
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "不支持的架构: $(uname -m)" ;;
  esac
}

pick_go_version_from_gomod(){
  local gomod="$1"
  local toolchain go_line

  toolchain="$(awk '$1=="toolchain"{print $2}' "$gomod" 2>/dev/null | head -n1 || true)"
  if [[ -n "${toolchain}" ]]; then
    echo "${toolchain#go}"
    return
  fi

  go_line="$(awk '$1=="go"{print $2}' "$gomod" 2>/dev/null | head -n1 || true)"
  [[ -n "${go_line}" ]] || die "无法从 go.mod 解析 Go 版本（缺少 go/toolchain 行）"

  if [[ "${go_line}" =~ ^[0-9]+\.[0-9]+$ ]]; then
    echo "${go_line}.0"
  else
    echo "${go_line}"
  fi
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
    curl -fsSL "${url}" -o "/tmp/${tgz}"
    tar -C /usr/local -xzf "/tmp/${tgz}"
  fi

  mkdir -p /etc/profile.d
  cat >/etc/profile.d/go.sh <<'EOF'
export PATH=/usr/local/go/bin:$PATH
EOF
  export PATH=/usr/local/go/bin:$PATH
  go version
}

backup_if_exists(){
  local f="$1"
  if [[ -f "$f" ]]; then
    cp -a "$f" "${f}.bak.$(date +%F_%H%M%S)" || true
  fi
}

stop_old(){
  systemctl stop xrayr 2>/dev/null || true
  systemctl disable xrayr 2>/dev/null || true
  systemctl reset-failed xrayr 2>/dev/null || true
}

clone_or_update_repo(){
  local dir="$1"
  local repo="${2:-https://github.com/XrayR-project/XrayR}"
  mkdir -p "$(dirname "$dir")"

  if [[ -d "$dir/.git" ]]; then
    log "更新 XrayR 源码..."
    cd "$dir"
    git fetch --all --tags -q
  else
    log "克隆 XrayR 源码..."
    rm -rf "$dir"
    git clone "$repo" "$dir"
    cd "$dir"
    git fetch --all --tags -q
  fi

  # 自动识别默认分支（避免 origin/master / origin/main 不一致导致 reset 失败）
  local def_branch
  def_branch="$(git remote show origin 2>/dev/null | awk '/HEAD branch/ {print $NF}' | tail -n1 || true)"
  if [[ -z "${def_branch}" ]]; then
    def_branch="$(git symbolic-ref -q refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || true)"
  fi
  if [[ -z "${def_branch}" ]]; then
    if git show-ref --verify --quiet refs/remotes/origin/main; then
      def_branch="main"
    elif git show-ref --verify --quiet refs/remotes/origin/master; then
      def_branch="master"
    else
      def_branch="master"
    fi
  fi

  git reset --hard "origin/${def_branch}" -q
}

apply_patches(){
  log "应用稳定性补丁（幂等，可重复执行）..."

  # 1) inboundbuilder.go：CertConfig nil 兜底
  if [[ -f service/controller/inboundbuilder.go ]] && grep -q 'config\.CertConfig\.CertMode != "none"' service/controller/inboundbuilder.go; then
    sed -i 's/nodeInfo\.EnableTLS \&\& config\.CertConfig\.CertMode != "none"/nodeInfo.EnableTLS \&\& config.CertConfig != nil \&\& config.CertConfig.CertMode != "none"/g' \
      service/controller/inboundbuilder.go
  fi

  # 2) inboundbuilder.go：REALITYConfigs nil 兜底
  if [[ -f service/controller/inboundbuilder.go ]] && grep -q 'Show: config\.REALITYConfigs\.Show' service/controller/inboundbuilder.go; then
    sed -i 's/Show: config\.REALITYConfigs\.Show,/Show: (config.REALITYConfigs != nil \&\& config.REALITYConfigs.Show),/g' \
      service/controller/inboundbuilder.go
  fi

  # 3) NewV2board：users is null 不再当作 error（避免启动阶段直接死）
  if [[ -f api/newV2board/v2board.go ]] && grep -q 'errors.New("users is null")' api/newV2board/v2board.go; then
    perl -pi -e 's/return\s+nil,\s*errors\.New\("users is null"\)/return nil, nil/g' api/newV2board/v2board.go
  fi

  # 4) Panel Start：把 panic 改成 warning + continue（避免因为面板偶发异常自杀）
  if [[ -f panel/panel.go ]]; then
    perl -0777 -pi -e 's/log\.Panicf\("Panel Start failed: %s",\s*err\)/log.Errorf("Panel Start warning: %s", err); continue/g' panel/panel.go
    perl -0777 -pi -e 's/logrus\.Panicf\("Panel Start failed: %s",\s*err\)/logrus.Errorf("Panel Start warning: %s", err); continue/g' panel/panel.go
    perl -0777 -pi -e 's/logrus\.Panicf\("Panel Start failed:\s*/logrus.Errorf("Panel Start warning:/g' panel/panel.go
  fi

  # 5) token 兼容：SetHeader("Token", x) 后面补 SetQueryParam("token", x)
  #    可用 XR_DISABLE_TOKEN_QUERY_PATCH=1 关闭（如果你不希望 token 出现在 query/日志里）
  if [[ "${XR_DISABLE_TOKEN_QUERY_PATCH:-0}" != "1" ]]; then
    local files
    files="$(grep -R --line-number 'SetHeader("Token"' panel api 2>/dev/null | cut -d: -f1 | sort -u || true)"
    if [[ -n "${files}" ]]; then
      perl -0777 -pi -e 's/\.SetHeader\("Token",\s*([^)]+?)\)(?!\s*\.SetQueryParam\("token")/.SetHeader("Token", $1).SetQueryParam("token", $1)/g' $files
    fi
  fi
}

run_with_watchdog(){
  # 用于解决 “go mod download 卡住不动”
  # 监控：modcache 体积 or 日志文件大小，如连续 XR_GO_IDLE_KILL 秒无变化 => kill 并返回 124
  local log_file="$1"; shift
  local idle_limit="${XR_GO_IDLE_KILL:-300}"

  local modcache
  modcache="$(go env GOMODCACHE 2>/dev/null || true)"
  if [[ -z "${modcache}" ]]; then
    modcache="${HOME:-/root}/go/pkg/mod"
  fi
  mkdir -p "$(dirname "${log_file}")" || true
  : > "${log_file}"

  ( time "$@" ) \
    > >(tee -a "${log_file}") \
    2> >(tee -a "${log_file}" >&2) &
  local pid=$!

  local last_change last_mod_size last_log_size
  last_change="$(date +%s)"
  last_mod_size="$(du -s "${modcache}" 2>/dev/null | awk '{print $1}' || echo 0)"
  last_log_size="$(stat -c %s "${log_file}" 2>/dev/null || echo 0)"

  while kill -0 "${pid}" 2>/dev/null; do
    sleep 10

    local mod_size log_size now
    mod_size="$(du -s "${modcache}" 2>/dev/null | awk '{print $1}' || echo 0)"
    log_size="$(stat -c %s "${log_file}" 2>/dev/null || echo 0)"
    now="$(date +%s)"

    if [[ "${mod_size}" != "${last_mod_size}" || "${log_size}" != "${last_log_size}" ]]; then
      last_mod_size="${mod_size}"
      last_log_size="${log_size}"
      last_change="${now}"
    fi

    if (( now - last_change > idle_limit )); then
      warn "检测到 ${idle_limit}s 无任何下载/日志增长：判定 go 依赖下载卡住，准备切换代理..."
      kill -TERM "${pid}" 2>/dev/null || true
      sleep 2
      kill -KILL "${pid}" 2>/dev/null || true
      wait "${pid}" || true
      return 124
    fi
  done

  wait "${pid}"
}

go_mod_download_with_fallback(){
  local repo_dir="$1"

  export PATH=/usr/local/go/bin:$PATH
  cd "${repo_dir}"

  local try
  local ok="0"
  local once_cleaned="0"

  # 代理组合（按聊天记录思路优先级）
  local combos=(
    "https://goproxy.cn,direct|sum.golang.google.cn"
    "https://goproxy.cn,direct|off"
    "https://proxy.golang.org,direct|sum.golang.org"
  )

  for try in "${combos[@]}"; do
    local gp gs
    gp="${try%%|*}"
    gs="${try##*|}"

    log "尝试 Go 依赖下载：GOPROXY=${gp}  GOSUMDB=${gs}"
    go env -w GOPROXY="${gp}" >/dev/null 2>&1 || true
    go env -w GOSUMDB="${gs}" >/dev/null 2>&1 || true

    export GOPROXY="${gp}"
    export GOSUMDB="${gs}"

    if run_with_watchdog /root/go_mod_download.log go mod download -x; then
      ok="1"
      break
    fi

    warn "本轮 go mod download 失败/卡住（日志：/root/go_mod_download.log）"

    if [[ "${once_cleaned}" == "0" ]]; then
      warn "按聊天记录思路：执行 go clean -modcache 清一次缓存再重试（只做一次）"
      go clean -modcache || true
      once_cleaned="1"

      if run_with_watchdog /root/go_mod_download.log go mod download -x; then
        ok="1"
        break
      fi
      warn "清缓存后仍失败/卡住，继续切换代理..."
    fi
  done

  [[ "${ok}" == "1" ]] || return 1
  return 0
}

build_and_install(){
  local repo_dir="$1"
  log "编译安装 xrayr（日志会写 /root/go_build.log）..."

  export PATH=/usr/local/go/bin:$PATH
  cd "${repo_dir}"

  ( time go build -v -o XrayR -ldflags "-s -w" . ) |& tee /root/go_build.log

  install -m 755 XrayR /usr/local/bin/xrayr
  /usr/local/bin/xrayr version || true
}

write_config(){
  local api_host="$1" api_key="$2" node_id="$3" update_periodic="$4"

  mkdir -p /etc/XrayR /var/log/XrayR
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

    ControllerConfig:
      ListenIP: 0.0.0.0
      SendIP: 0.0.0.0
      UpdatePeriodic: ${update_periodic}

      DisableLocalREALITYConfig: true

      REALITYConfigs:
        Show: false

      CertConfig:
        CertMode: none
EOF
  chmod 600 /etc/XrayR/config.yml
}

write_runner(){
  log "安装 xrayr-runner（自动重试，不会被 StartLimit 打死）..."
  cat >/usr/local/bin/xrayr-runner <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

CFG="/etc/XrayR/config.yml"
LOG="/var/log/XrayR/runner.log"
mkdir -p /var/log/XrayR

API_HOST="$(awk -F'"' '/ApiHost:/{print $2; exit}' "$CFG")"
API_KEY="$(awk -F'"' '/ApiKey:/{print $2; exit}' "$CFG")"
NODE_ID="$(awk '/NodeID:/{print $2; exit}' "$CFG")"
NODE_TYPE="$(awk '/NodeType:/{print $2; exit}' "$CFG")"
NODE_TYPE_LC="$(echo "${NODE_TYPE}" | tr '[:upper:]' '[:lower:]')"

health_check() {
  local base="${API_HOST%/}/api/v1/server/UniProxy/config?node_id=${NODE_ID}&node_type=${NODE_TYPE_LC}"
  local code
  code="$(curl -m 8 -sS -o /dev/null -w "%{http_code}" -H "Token: ${API_KEY}" "${base}" || echo "000")"
  if [[ "${code}" == "200" ]]; then return 0; fi
  code="$(curl -m 8 -sS -o /dev/null -w "%{http_code}" "${base}&token=${API_KEY}" || echo "000")"
  [[ "${code}" == "200" ]]
}

while true; do
  if ! health_check; then
    echo "[runner] panel api not ready (config HTTP!=200). sleep 3s" >>"${LOG}"
    sleep 3
    continue
  fi

  /usr/local/bin/xrayr --config "${CFG}" >>"${LOG}" 2>&1 || true
  echo "[runner] xrayr exited at $(date -Is), retry in 3s" >>"${LOG}"
  sleep 3
done
EOF
  chmod +x /usr/local/bin/xrayr-runner
}

write_systemd(){
  log "写入 systemd service..."
  cat >/etc/systemd/system/xrayr.service <<'EOF'
[Unit]
Description=XrayR Service (stable runner)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
User=root
WorkingDirectory=/etc/XrayR
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

open_firewall(){
  local port="$1"
  log "放行 ${port}/tcp（兼容 ufw/firewalld/iptables）..."

  if need ufw; then ufw allow "${port}/tcp" 2>/dev/null || true; fi
  if need firewall-cmd; then
    firewall-cmd --permanent --add-port="${port}/tcp" 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
  fi
  iptables -C INPUT -p tcp --dport "${port}" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "${port}" -j ACCEPT 2>/dev/null || true
}

fetch_server_port(){
  local host="$1" key="$2" node_id="$3"
  local url="${host%/}/api/v1/server/UniProxy/config?node_id=${node_id}&node_type=vless"
  local body http port

  body="$(mktemp)"
  http="$(curl -sS -m 10 -H "Token: ${key}" -o "${body}" -w "%{http_code}" "${url}" || echo "000")"
  if [[ "${http}" != "200" ]]; then
    http="$(curl -sS -m 10 -o "${body}" -w "%{http_code}" "${url}&token=${key}" || echo "000")"
  fi
  if [[ "${http}" == "200" ]]; then
    port="$(jq -r '.server_port // empty' <"${body}" 2>/dev/null || true)"
    rm -f "${body}"
    if [[ "${port}" =~ ^[0-9]+$ ]]; then
      echo "${port}"
      return 0
    fi
  fi
  rm -f "${body}"
  echo ""
}

post_check(){
  log "服务状态："
  systemctl status xrayr --no-pager -l || true

  log "最近 120 行 journal："
  journalctl -u xrayr -o cat -n 120 || true

  log "runner.log（最近 120 行）："
  tail -n 120 /var/log/XrayR/runner.log 2>/dev/null || true
}

main(){
  require_root
  os_install_pkgs
  stop_old

  log "请输入面板信息（ApiKey 不回显）..."
  read -rp "ApiHost（例如 https://panel.example.com 或 http://127.0.0.1:7002）: " API_HOST
  read -rsp "ApiKey（不回显）: " API_KEY; echo
  read -rp "NodeID（例如 1）: " NODE_ID
  read -rp "UpdatePeriodic（建议 30~60，默认 30；不要填 5）: " UPD || true

  [[ "${API_HOST}" =~ ^https?:// ]] || die "ApiHost 必须以 http:// 或 https:// 开头"
  [[ -n "${API_KEY}" ]] || die "ApiKey 不能为空"
  [[ "${NODE_ID}" =~ ^[0-9]+$ ]] || die "NodeID 必须是数字"

  if [[ -z "${UPD:-}" ]]; then UPD="30"; fi
  if ! [[ "${UPD}" =~ ^[0-9]+$ ]]; then die "UpdatePeriodic 必须是数字"; fi
  if (( UPD < 10 )) && [[ "${ALLOW_FAST_UPDATE:-0}" != "1" ]]; then
    warn "UpdatePeriodic=${UPD} 太小（会放大 users is null/启动崩溃概率），已自动改为 30。"
    UPD="30"
  fi

  # ===== 拉源码 / 安装 Go / 打补丁 / go mod 下载（自动修复卡住）/ 编译 =====
  local xr_dir="/usr/local/src/XrayR"
  local repo_url="${XR_REPO_URL:-https://github.com/XrayR-project/XrayR}"

  clone_or_update_repo "${xr_dir}" "${repo_url}"

  local go_ver
  go_ver="$(pick_go_version_from_gomod "${xr_dir}/go.mod")"
  install_go "${go_ver}"

  apply_patches

  log "开始下载 Go 依赖（如果你之前卡在 go: downloading，这一步会自动切代理）"
  if ! go_mod_download_with_fallback "${xr_dir}"; then
    warn "依赖下载仍失败/卡住。你可以把 /root/go_mod_download.log 发我，我继续按日志定位。"
    warn "也可手动尝试："
    echo "  export GOPROXY=https://goproxy.cn,direct; export GOSUMDB=off"
    echo "  cd ${xr_dir}; go clean -modcache; go mod download -x"
    exit 1
  fi

  build_and_install "${xr_dir}"

  # ===== 写配置 / runner / systemd =====
  backup_if_exists /etc/XrayR/config.yml
  write_config "${API_HOST}" "${API_KEY}" "${NODE_ID}" "${UPD}"
  write_runner
  write_systemd

  # ===== 自动拿 server_port 并放行（拿不到就提示你去面板确认）=====
  local port
  port="$(fetch_server_port "${API_HOST}" "${API_KEY}" "${NODE_ID}")"
  if [[ -n "${port}" ]]; then
    open_firewall "${port}"
    log "已从面板读取 server_port=${port} 并放行防火墙 ✅"
  else
    warn "没能从面板 UniProxy/config 读取 server_port（可能 ApiHost/ApiKey/NodeID 填错，或面板不通）。"
    warn "请你到面板确认该节点端口（你常用 8443），并手动放行：ufw allow 8443/tcp 或 iptables 放行。"
  fi

  log "完成 ✅"
  post_check

  log "监听检查（若未监听，多数是面板没下发端口/配置或仍在重试拉取）"
  ss -lntp 2>/dev/null | grep -E "xrayr|:${port}\b" || true
}

main "$@"
