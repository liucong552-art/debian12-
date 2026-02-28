#!/usr/bin/env bash
set -Eeuo pipefail

log(){ echo -e "\n[+] $*\n"; }
warn(){ echo -e "\n[!] $*\n" >&2; }
die(){ echo -e "\n[x] $*\n" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1; }

require_root(){ [ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo -i"; }

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
  [[ -n "${go_line}" ]] || die "无法从 go.mod 解析 Go 版本"

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

pick_port(){
  local p
  for p in 8443 2053 2083 2096 9443 30443; do
    if ! ss -lntp 2>/dev/null | grep -qE ":${p}\b"; then
      echo "$p"; return
    fi
  done
  die "找不到可用端口（8443/2053/2083/2096/9443/30443 都被占用）"
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
    git reset --hard origin/master -q
  else
    log "克隆 XrayR 源码..."
    rm -rf "$dir"
    git clone "$repo" "$dir"
    cd "$dir"
    git fetch --all --tags -q
    git reset --hard origin/master -q
  fi
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

  # 3) NewV2board：users is null 不再致命
  if [[ -f api/newV2board/v2board.go ]] && grep -q 'errors.New("users is null")' api/newV2board/v2board.go; then
    perl -pi -e 's/return\s+nil,\s*errors\.New\("users is null"\)/return nil, nil/g' api/newV2board/v2board.go
  fi

  # 4) Panel Start：panic -> warning + continue
  if [[ -f panel/panel.go ]]; then
    perl -0777 -pi -e 's/log\.Panicf\("Panel Start failed: %s",\s*err\)/log.Errorf("Panel Start warning: %s", err); continue/g' panel/panel.go
    perl -0777 -pi -e 's/logrus\.Panicf\("Panel Start failed: %s",\s*err\)/logrus.Errorf("Panel Start warning: %s", err); continue/g' panel/panel.go
    perl -0777 -pi -e 's/logrus\.Panicf\("Panel Start failed:\s*/logrus.Errorf("Panel Start warning:/g' panel/panel.go
  fi

  # 5) token 兼容（可选）：Header(Token) 后面补 Query(token)
  #    如不想打这个补丁：运行前 export XR_DISABLE_TOKEN_QUERY_PATCH=1
  if [[ "${XR_DISABLE_TOKEN_QUERY_PATCH:-0}" != "1" ]]; then
    local files
    files="$(grep -R --line-number 'SetHeader("Token"' panel api 2>/dev/null | cut -d: -f1 | sort -u || true)"
    if [[ -n "${files}" ]]; then
      perl -0777 -pi -e 's/\.SetHeader\("Token",\s*([^)]+?)\)(?!\s*\.SetQueryParam\("token")/.SetHeader("Token", $1).SetQueryParam("token", $1)/g' $files
    fi
  fi
}

build_and_install(){
  log "编译安装 xrayr..."
  export PATH=/usr/local/go/bin:$PATH
  go env -w GO111MODULE=on >/dev/null 2>&1 || true
  go build -o XrayR -ldflags "-s -w" .
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
  log "安装 xrayr-runner（自动重试，避免 systemd StartLimit 把服务打死）..."
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
    echo "[runner] panel api not ready (HTTP!=200). sleep 3s" >>"${LOG}"
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
  log "放行 ${port}/tcp..."
  if need ufw; then ufw allow "${port}/tcp" 2>/dev/null || true; fi
  if need firewall-cmd; then
    firewall-cmd --permanent --add-port="${port}/tcp" 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
  fi
  iptables -C INPUT -p tcp --dport "${port}" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "${port}" -j ACCEPT 2>/dev/null || true
}

post_check(){
  log "服务状态："
  systemctl status xrayr --no-pager -l || true

  log "最近 120 行 journald："
  journalctl -u xrayr -o cat -n 120 || true

  log "runner.log（最近 120 行）："
  tail -n 120 /var/log/XrayR/runner.log 2>/dev/null || true
}

main(){
  require_root
  os_install_pkgs
  stop_old

  # ---- 支持环境变量（方便你自动化），不提供则交互输入 ----
  local API_HOST="${API_HOST:-}"
  local API_KEY="${API_KEY:-}"
  local NODE_ID="${NODE_ID:-}"
  local UPD="${UPD:-}"

  log "请输入面板信息（ApiKey 不回显；也可用环境变量 API_HOST/API_KEY/NODE_ID/UPD）"
  if [[ -z "${API_HOST}" ]]; then
    read -rp "ApiHost（例如 https://panel.example.com 或 http://127.0.0.1:7001）: " API_HOST
  fi
  if [[ -z "${API_KEY}" ]]; then
    read -rsp "ApiKey（不回显）: " API_KEY; echo
  fi
  if [[ -z "${NODE_ID}" ]]; then
    read -rp "NodeID（例如 1）: " NODE_ID
  fi
  if [[ -z "${UPD}" ]]; then
    read -rp "UpdatePeriodic（建议 10~60，默认 10；不要填 5）: " UPD || true
  fi

  [[ "${API_HOST}" =~ ^https?:// ]] || die "ApiHost 必须以 http:// 或 https:// 开头"
  [[ -n "${API_KEY}" ]] || die "ApiKey 不能为空"
  [[ "${NODE_ID}" =~ ^[0-9]+$ ]] || die "NodeID 必须是数字"

  if [[ -z "${UPD:-}" ]]; then UPD="10"; fi
  [[ "${UPD}" =~ ^[0-9]+$ ]] || die "UpdatePeriodic 必须是数字"
  if (( UPD < 10 )) && [[ "${ALLOW_FAST_UPDATE:-0}" != "1" ]]; then
    warn "UpdatePeriodic=${UPD} 太小（你之前踩过 5 秒会放大 users=null/崩溃概率），已自动改为 10。"
    UPD="10"
  fi

  local port
  port="$(pick_port)"

  local xr_dir="/usr/local/src/XrayR"
  local repo_url="${XR_REPO_URL:-https://github.com/XrayR-project/XrayR}"

  clone_or_update_repo "${xr_dir}" "${repo_url}"

  local go_ver
  go_ver="$(pick_go_version_from_gomod "${xr_dir}/go.mod")"
  install_go "${go_ver}"

  apply_patches
  build_and_install

  backup_if_exists /etc/XrayR/config.yml
  write_config "${API_HOST}" "${API_KEY}" "${NODE_ID}" "${UPD}"
  write_runner
  write_systemd
  open_firewall "${port}"

  log "完成 ✅"
  echo "------------------------------------------------------------"
  echo "[重要] 请到面板把该节点的端口设置为：${port}"
  echo "      （面板下发端口；本机只是放行并承载服务）"
  echo
  echo "[查看日志]"
  echo "  journalctl -u xrayr -o cat -n 200"
  echo "  tail -n 200 /var/log/XrayR/runner.log"
  echo "------------------------------------------------------------"
  post_check
  ss -lntp 2>/dev/null | grep -E ":${port}\b|xrayr" || true
}

main "$@"
