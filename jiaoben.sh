#!/usr/bin/env bash
set -Eeuo pipefail

############################################
# XrayR NewV2board(VLESS/REALITY/Vision) one-key
# - Debian 12
# - token-bridge nginx: 127.0.0.1:7002 -> 127.0.0.1:7001
# - patches:
#   1) Panel Start panic -> error + return (avoid crash loop)
#   2) users empty -> return &[]api.UserInfo{}, nil (avoid "users is null" fatal)
#   3) NodeInfo returns -> ensure "return x" becomes "return x, nil" for (*api.NodeInfo, error)
# - config.yml补齐 CertConfig/REALITYConfigs 避免 nil panic
############################################

LOG="/var/log/xrayr_onekey.log"
mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

echo "[+] Start: $(date) | log: $LOG"

# -------- helpers --------
die(){ echo "[!] $*" >&2; exit 1; }
need_root(){ [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Please run as root"; }

# 自动去 CRLF（即使你是 Windows 编辑上传，也不会炸）
strip_crlf_self() {
  # 仅处理可读脚本文件
  if [[ -f "${BASH_SOURCE[0]}" && -w "${BASH_SOURCE[0]}" ]]; then
    sed -i 's/\r$//' "${BASH_SOURCE[0]}" || true
  fi
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends "$@"
}

# -------- begin --------
need_root
strip_crlf_self

# ====== configurable vars (can override by env) ======
# xboard api host（容器在本机，用 127.0.0.1:7001）
PANEL_HOST="${PANEL_HOST:-http://127.0.0.1:7001}"

# nginx token bridge listen
BRIDGE_LISTEN_IP="${BRIDGE_LISTEN_IP:-127.0.0.1}"
BRIDGE_PORT="${BRIDGE_PORT:-7002}"

# XrayR listen port（面板下发也会是 8443，脚本不强绑）
DEFAULT_NODE_PORT="${DEFAULT_NODE_PORT:-8443}"

# Update periodic (avoid users=null storm)
UPDATE_PERIODIC="${UPDATE_PERIODIC:-60}"

# XrayR git
XRAYR_REPO="${XRAYR_REPO:-https://github.com/XrayR-project/XrayR.git}"
XRAYR_COMMIT="${XRAYR_COMMIT:-dd786ef}"

# Node config
NODE_ID="${NODE_ID:-}"
API_KEY="${API_KEY:-}"

echo "[*] Basic deps..."
apt_install ca-certificates curl jq perl iproute2 tar cron util-linux git patch

# ====== Ask for NODE_ID / API_KEY if not provided ======
if [[ -z "${NODE_ID}" ]]; then
  read -r -p "[?] Enter NodeID (e.g. 1): " NODE_ID
fi
if [[ -z "${API_KEY}" ]]; then
  read -r -s -p "[?] Enter ApiKey (input hidden): " API_KEY
  echo
fi
[[ -n "$NODE_ID" ]] || die "NODE_ID is empty"
[[ -n "$API_KEY" ]] || die "API_KEY is empty"
echo "[*] NodeID=$NODE_ID  ApiKeyLen=${#API_KEY}"

# ====== nginx token-bridge ======
echo "[*] Installing nginx token-bridge (${BRIDGE_LISTEN_IP}:${BRIDGE_PORT} -> ${PANEL_HOST})..."
apt_install nginx

# 删除默认站点（避免占用 80）
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default || true

cat >/etc/nginx/conf.d/xboard_token_bridge.conf <<NG
server {
  listen ${BRIDGE_LISTEN_IP}:${BRIDGE_PORT};
  server_name _;

  location / {
    # token: query token first, then header Token
    set \$token \$arg_token;
    if (\$token = "") { set \$token \$http_token; }
    if (\$token = "") { return 400; }

    # inject token into query if missing
    if (\$arg_token = "") { set \$args "\${args}&token=\${token}"; }
    if (\$args ~ "^&")    { set \$args "token=\${token}"; }

    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host 127.0.0.1;

    proxy_pass ${PANEL_HOST}\$uri?\$args;
  }
}
NG

nginx -t
systemctl enable --now nginx || true
systemctl restart nginx
echo "[*] nginx listening check:"
ss -lntp | grep ":${BRIDGE_PORT}" || die "nginx not listening on ${BRIDGE_LISTEN_IP}:${BRIDGE_PORT}"

# ====== cron: xboard schedule run (if container exists) ======
echo "[*] Setup cron for xboard schedule (if container exists)..."
systemctl enable --now cron || true
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q '^xboard-web-1$'; then
  cat >/etc/cron.d/xboard-schedule <<'EOF'
* * * * * root flock -n /tmp/xboard_schedule.lock docker exec xboard-web-1 php artisan schedule:run --no-interaction >>/var/log/xboard_schedule.log 2>&1
EOF
  chmod 644 /etc/cron.d/xboard-schedule
  touch /var/log/xboard_schedule.log
  echo "[*] xboard schedule cron installed: /etc/cron.d/xboard-schedule"
else
  echo "[!] docker/xboard-web-1 not found, skip schedule cron (you can add later)."
fi

# ====== install Go ======
echo "[*] Installing Go..."
apt_install curl
GO_TARBALL_URL="${GO_TARBALL_URL:-https://go.dev/dl/go1.25.3.linux-amd64.tar.gz}"
if [[ ! -x /usr/local/go/bin/go ]]; then
  rm -rf /usr/local/go
  curl -fsSL "$GO_TARBALL_URL" -o /tmp/go.tgz
  tar -C /usr/local -xzf /tmp/go.tgz
fi
export PATH=/usr/local/go/bin:$PATH
command -v go >/dev/null || die "go not found"
command -v gofmt >/dev/null || die "gofmt not found"
go version

# goproxy fallback（避免某些环境拉依赖慢/卡）
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
export GOSUMDB="${GOSUMDB:-sum.golang.org}"
export GO111MODULE=on

# ====== build-essential (compile deps) ======
echo "[*] Installing build deps..."
apt_install build-essential

# ====== clone + checkout ======
echo "[*] Cloning XrayR..."
rm -rf /usr/local/src/XrayR
git clone --depth 1 "$XRAYR_REPO" /usr/local/src/XrayR
cd /usr/local/src/XrayR
git fetch --depth 1 origin "$XRAYR_COMMIT"
git checkout "$XRAYR_COMMIT"
echo "[*] Checked out: $(git rev-parse --short HEAD)"

# ====== Patch 1: Panel Start panic -> error + return ======
echo "[*] Patch 1/3: Panel Start panic -> error+return"
# 把 log.Panicf("Panel Start failed: %s", err) 改为 log.Errorf + return
# 兼容不同空格/缩进
perl -pi -e '
  if (/log\.Panicf\("Panel Start failed: %s",\s*err\)/) {
    s/log\.Panicf\("Panel Start failed: %s",\s*err\)/log.Errorf("Panel Start warning: %s", err)\n\t\t\t\treturn/;
  }
' panel/panel.go || true

# ====== Patch 2: users empty -> &[]api.UserInfo{}, nil ======
echo "[*] Patch 2/3: newV2board users empty -> &empty, nil"
# 目标块（你已看到在 234-238 行附近）：
# if len(users) == 0 { return nil, errors.New("users is null") }
# 替换为：
# if len(users) == 0 { empty := []api.UserInfo{}; return &empty, nil }
perl -0777 -pi -e '
  s/if\s+len\(users\)\s*==\s*0\s*\{\s*return\s+nil,\s*errors\.New\("users is null"\)\s*\}/if len(users) == 0 {\n\t\tempty := []api.UserInfo{}\n\t\treturn \&empty, nil\n\t}/s;
  s/if\s+len\(users\)\s*==\s*0\s*\{\s*return\s+\[\]api\.UserInfo\{\},\s*nil\s*\}/if len(users) == 0 {\n\t\tempty := []api.UserInfo{}\n\t\treturn \&empty, nil\n\t}/s;
' api/newV2board/v2board.go

# ====== Patch 3: NodeInfo "return x" -> "return x, nil" (only for (*api.NodeInfo, error) funcs) ======
echo "[*] Patch 3/3: fix NodeInfo not-enough-return-values"
python3 - <<'PY'
import re, pathlib, sys
p = pathlib.Path("api/newV2board/v2board.go")
s = p.read_text(encoding="utf-8")

# 找到所有返回签名为 (*api.NodeInfo, error) 的函数块，并把其中：
#   return <expr>
# 且 <expr> 不含逗号、不为 nil
# 替换成：
#   return <expr>, nil
def fix_block(m):
    head = m.group(1)
    body = m.group(2)
    # 只修 "return xxx"（无逗号）且非 "return nil"
    body2 = re.sub(r'(\n[ \t]*return[ \t]+)(?!nil\b)([^,\n]+?)([ \t]*\n)',
                   r'\1\2, nil\3', body)
    return head + body2 + "\n}"

pattern = re.compile(r'(func[ \t]+[^{]*\(\*api\.NodeInfo,[ \t]*error\)[ \t]*\{\n)(.*?\n)\}', re.S)
s2 = pattern.sub(fix_block, s)

if s2 == s:
    # 没匹配到也不算失败，但给个提示
    print("[WARN] No (*api.NodeInfo, error) func blocks matched; skip NodeInfo return patch")
else:
    p.write_text(s2, encoding="utf-8")
    print("[OK] Patched NodeInfo return statements")
PY

# gofmt
gofmt -w api/newV2board/v2board.go panel/panel.go || true

# ====== Build ======
echo "[*] Building XrayR (deps download may take time)..."
go build -o XrayR -ldflags "-s -w" .
install -m 755 XrayR /usr/local/bin/xrayr

# ====== Install runner + systemd ======
echo "[*] Installing runner + systemd..."
mkdir -p /etc/XrayR /var/log/XrayR
touch /var/log/XrayR/runner.log

cat >/usr/local/bin/xrayr-runner <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
LOG="/var/log/XrayR/runner.log"
BIN="/usr/local/bin/xrayr"
CFG="/etc/XrayR/config.yml"

mkdir -p "$(dirname "$LOG")"
touch "$LOG"

while true; do
  ts="$(date -Is)"
  echo "[runner] start $ts" >>"$LOG" || true
  "$BIN" --config "$CFG" >>"$LOG" 2>&1 || true
  ts2="$(date -Is)"
  echo "[runner] xrayr exited at $ts2, retry in 3s" >>"$LOG" || true
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

# ====== Write config.yml ======
echo "[*] Writing /etc/XrayR/config.yml"
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
  ConnIdle: 60
  UplinkOnly: 2
  DownlinkOnly: 4
  BufferSize: 64

Nodes:
  - PanelType: "NewV2board"
    ApiConfig:
      ApiHost: "http://${BRIDGE_LISTEN_IP}:${BRIDGE_PORT}"
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
      DisableCustomConfig: false

    ControllerConfig:
      ListenIP: "0.0.0.0"
      SendIP: "0.0.0.0"
      UpdatePeriodic: ${UPDATE_PERIODIC}

      # 避免 nil panic
      CertConfig:
        CertMode: none
      REALITYConfigs:
        Show: false
EOF

# ====== start service ======
echo "[*] Start xrayr.service..."
systemctl daemon-reload
systemctl enable --now xrayr

sleep 2
echo "[*] Status:"
systemctl status xrayr --no-pager -l || true
echo "[*] Listening ports:"
ss -lntp | grep -E ":${DEFAULT_NODE_PORT}|xrayr|${BRIDGE_PORT}" || true

# ====== quick api sanity ======
echo "[*] Quick API sanity via bridge (should be HTTP 200):"
curl -sS -H "Token: ${API_KEY}" -w "\nHTTP:%{http_code}\n" \
  "http://${BRIDGE_LISTEN_IP}:${BRIDGE_PORT}/api/v1/server/UniProxy/config?node_id=${NODE_ID}&node_type=vless" | head -c 600; echo

curl -sS -H "Token: ${API_KEY}" -w "\nHTTP:%{http_code}\n" \
  "http://${BRIDGE_LISTEN_IP}:${BRIDGE_PORT}/api/v1/server/UniProxy/user?node_id=${NODE_ID}&node_type=vless" | head -c 600; echo

echo "[+] Done."
echo "    Logs:"
echo "      tail -n 200 /var/log/XrayR/runner.log"
echo "      journalctl -u xrayr -n 200 --no-pager"
