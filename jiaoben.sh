#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$' \n\t'

trap 'echo "[x] Error at line $LINENO: $BASH_COMMAND" >&2' ERR

log(){ echo "[+] $*"; }
die(){ echo "[x] $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo -i"

# ===== 交互输入（默认按你的两机方案）=====
read -rp "ApiHost (默认 http://104.224.158.191:7002): " APIHOST
APIHOST="${APIHOST:-http://104.224.158.191:7002}"

read -rsp "ApiKey(不回显): " APIKEY; echo
[ -n "${APIKEY}" ] || die "ApiKey 不能为空"

read -rp "NodeID(例如 1): " NODEID
[ -n "${NODEID}" ] || die "NodeID 不能为空"

NODETYPE="Vless"
PORT="8443"

log "安装依赖..."
apt-get update -y
apt-get install -y git curl ca-certificates jq iproute2 build-essential unzip cron util-linux

# ===== 自检：节点机必须能从面板机 7002 拉到 config/user =====
log "自检面板接口（必须 200 且 users 非空）..."
code1="$(curl -sS -o /tmp/cfg.json -w "%{http_code}" -H "Token: ${APIKEY}" \
  "${APIHOST}/api/v1/server/UniProxy/config?node_id=${NODEID}&node_type=vless")" || true
[ "$code1" = "200" ] || { cat /tmp/cfg.json 2>/dev/null || true; die "config 接口不是 200（得到 $code1）"; }

code2="$(curl -sS -o /tmp/usr.json -w "%{http_code}" -H "Token: ${APIKEY}" \
  "${APIHOST}/api/v1/server/UniProxy/user?node_id=${NODEID}&node_type=vless")" || true
[ "$code2" = "200" ] || { cat /tmp/usr.json 2>/dev/null || true; die "user 接口不是 200（得到 $code2）"; }

ul="$(jq -r '.users|length' /tmp/usr.json 2>/dev/null || echo 0)"
[ "${ul}" != "0" ] || die "user 接口返回 users=0（面板还没把用户路由到该节点/或没订阅）"

log "OK：config/user 都正常（users_len=${ul}）"

# ===== 安装 Go（按我们成功经验：Go 1.25.3）=====
if ! command -v go >/dev/null 2>&1; then
  log "安装 Go 1.25.3..."
  curl -fsSL -o /tmp/go1.25.3.linux-amd64.tar.gz https://go.dev/dl/go1.25.3.linux-amd64.tar.gz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go1.25.3.linux-amd64.tar.gz
fi
export PATH=/usr/local/go/bin:$PATH
go version || die "go 不可用"

# ===== 拉取 XrayR（按我们成功经验：checkout dd786ef）=====
log "拉取 XrayR 并 checkout dd786ef..."
mkdir -p /usr/local/src
if [ ! -d /usr/local/src/XrayR/.git ]; then
  git clone https://github.com/XrayR-project/XrayR.git /usr/local/src/XrayR
fi
cd /usr/local/src/XrayR
git fetch --all -p
git checkout -f dd786ef

# ===== 补丁 1：panel 不 panic（完全按我们之前做法）=====
log "打补丁：panel 不 panic..."
perl -pi -e 's/log\.Panicf\("Panel Start failed: %s", err\)/log.Errorf("Panel Start warning: %s", err)/g' panel/panel.go

# ===== 补丁 2：users is null 不致命（返回 *[]api.UserInfo 空指针，避免你那次编译报错）=====
# ✅ 一模一样的修复：return &[]api.UserInfo{}, nil
log "打补丁：users is null 不致命..."
if grep -q 'return nil, errors.New("users is null")' api/newV2board/v2board.go; then
  sed -i 's/return nil, errors.New("users is null")/return \&[]api.UserInfo{}, nil/' api/newV2board/v2board.go
fi

# ===== 编译安装 =====
log "编译安装 xrayr（第一次拉 Go 依赖会久）..."
go build -o XrayR -ldflags "-s -w" .
install -m 755 XrayR /usr/local/bin/xrayr

# ===== 写入 runner（同一套路）=====
log "写入 runner..."
cat >/usr/local/bin/xrayr-runner <<'RUN'
#!/usr/bin/env bash
set -Eeuo pipefail
LOG=/var/log/XrayR/runner.log
mkdir -p /var/log/XrayR
while true; do
  echo "[runner] start $(date --iso-8601=seconds)" >>"$LOG"
  /usr/local/bin/xrayr --config /etc/XrayR/config.yml >>"$LOG" 2>&1 || true
  echo "[runner] xrayr exited at $(date --iso-8601=seconds), retry in 3s" >>"$LOG"
  sleep 3
done
RUN
chmod +x /usr/local/bin/xrayr-runner

# ===== 写入 config.yml（同一套路 + 避坑项 CertConfig/REALITYConfigs）=====
log "生成 /etc/XrayR/config.yml ..."
mkdir -p /etc/XrayR /var/log/XrayR
cat >/etc/XrayR/dns.json <<'J'
{}
J
cat >/etc/XrayR/route.json <<'J'
{}
J
cat >/etc/XrayR/custom_inbound.json <<'J'
{}
J
cat >/etc/XrayR/custom_outbound.json <<'J'
{}
J

cat >/etc/XrayR/config.yml <<EOF
Log:
  Level: info
  AccessPath: /var/log/XrayR/access.log
  ErrorPath: /var/log/XrayR/error.log

DnsConfigPath: /etc/XrayR/dns.json
RouteConfigPath: /etc/XrayR/route.json
InboundConfigPath: /etc/XrayR/custom_inbound.json
OutboundConfigPath: /etc/XrayR/custom_outbound.json

Nodes:
  - PanelType: "NewV2board"
    ApiHost: "${APIHOST}"
    ApiKey: "${APIKEY}"
    NodeID: ${NODEID}
    NodeType: ${NODETYPE}
    Timeout: 30
    EnableVless: true
    EnableXTLS: true
    VlessFlow: "xtls-rprx-vision"

    # ✅ 避坑：nil panic
    CertConfig:
      CertMode: none
    REALITYConfigs:
      Show: false

    ControllerConfig:
      ListenIP: "0.0.0.0"
      SendIP: "0.0.0.0"
      UpdatePeriodic: 60
EOF
chmod 600 /etc/XrayR/config.yml

# ===== systemd（同一套路）=====
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

# ===== 提示放行端口 =====
log "提示：请确保节点机放行 TCP ${PORT}（给客户端连）"
log "验收："
ss -lntp | grep -E ":${PORT}|xrayr" || true
tail -n 120 /var/log/XrayR/runner.log || true

log "DONE"
echo "日志：journalctl -u xrayr -o cat -n 200"
echo "runner：tail -n 200 /var/log/XrayR/runner.log"
