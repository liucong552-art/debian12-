==================================================
使用方法（你已经成功部署完所有脚本）

你当前是 root（不需要 sudo）
直接按以下顺序运行：

1) 先在全新 Debian 12 VPS 上执行新版一键脚本：
   bash <(curl -fsSL https://raw.githubusercontent.com/liucong552-art/debian12-/main/hy2.sh)

2) 系统更新 + 新内核：
   update-all
   reboot

3) 重启回来后，先编辑 HY2 主配置文件：
   nano /etc/default/hy2-main

   最少改成这样（按你自己的信息填写）：

   HY_DOMAIN=hy2.liucna.com
   HY_LISTEN=:443
   ACME_EMAIL=你的邮箱
   MASQ_URL=https://www.apple.com/
   ENABLE_SALAMANDER=0
   SALAMANDER_PASSWORD=
   NODE_NAME=HY2-MAIN
   TEMP_PORT_START=40000
   TEMP_PORT_END=50050

   说明：
   - HY_DOMAIN：客户端真正连接你 VPS 的域名
   - 以后 VPS 换 IP，只要改 HY_DOMAIN 的 DNS 解析，客户端原链接不用重新发
   - ACME_EMAIL：用于申请正式证书
   - MASQ_URL：伪装目标网站
   - ENABLE_SALAMANDER：默认写 0，不开启混淆
   - 只有在明确确认当前网络专门封锁 QUIC / HTTP/3 但 UDP 还活着时，才建议改成 1
   - TEMP_PORT_START / TEMP_PORT_END：临时节点默认高端口范围
   - Cloudflare 里的 HY_DOMAIN 必须保持 DNS only（灰云）
   - 证书申请需要 TCP 80 可达

4) HY2 主节点（443 + 正式证书 + masquerade）：
   bash /root/onekey_hy2_main_tls.sh

   执行完成后会生成：
   /root/hy2_main_url.txt
   /root/hy2_main_subscription_base64.txt

5) HY2 临时高端口系统（只需部署一次）：
   bash /root/hy2_temp_port_all.sh

   临时节点命令（全部都是 HY2 临时订阅）：

   # 短测：直接写秒
   D=120 hy2_mktemp.sh                       # 创建 120 秒临时节点

   # 按小时写（推荐这种，方便以后改）：
   D=$((10*3600)) hy2_mktemp.sh              # 创建 10 小时临时节点
   # 想改成 5 小时：
   D=$((5*3600)) hy2_mktemp.sh               # 创建 5 小时临时节点

   # 按天写：
   D=$((10*24*3600)) hy2_mktemp.sh           # 创建 10 天临时节点
   # 想改成 3 天：
   D=$((3*24*3600)) hy2_mktemp.sh            # 创建 3 天临时节点

   # 临时端口范围默认读取 /etc/default/hy2-main 里的：
   # TEMP_PORT_START / TEMP_PORT_END
   # 也可以临时覆盖：
   PORT_START=40000 PORT_END=60000 D=600 hy2_mktemp.sh

   hy2_audit.sh                              # 查看主节点 + 全部临时节点
   hy2_clear_all.sh                          # 清空所有临时节点
   FORCE=1 hy2_cleanup_one.sh hy2-temp-20260307123456-abcd
         # 干掉某个指定临时节点（无视是否到期）

6) UDP 配额系统（nftables，双向合计，对应 HY2 端口）：
   pq_add.sh 443 500                         # 限制主节点 443 端口总计 500GiB
   pq_add.sh 40000 50                        # 限制临时 HY2 端口 40000 总计 50GiB
   pq_audit.sh                               # 查看所有端口使用情况
   pq_del.sh 40000                           # 删除端口 40000 的配额

说明：
- 配额系统统计的是 VPS <-> 用户 这条 HY2 UDP 连接的双向总流量
- 统计口径：
  - VPS -> 用户：output 链，udp sport=监听端口
  - 用户 -> VPS：input  链，udp dport=监听端口
- 不统计 VPS 去访问网站那部分转发流量
- D 最终必须是“秒”，写成 $((天*24*3600)) / $((小时*3600)) 只是方便你自己按天/小时换算
- 主节点订阅统一使用 HY_DOMAIN:443
- 临时节点订阅统一使用 HY_DOMAIN:临时端口
- 以后 VPS 换 IP，只改 HY_DOMAIN 的 DNS 解析，原有客户端链接不用重新发
- 主节点和临时节点统一复用同一张正式证书
- 因为临时节点是高端口，所以伪装度会低于主 443 节点，但换来的是每个临时端口都能独立限额
- 临时节点链接现在不再依赖 insecure=1 / pinSHA256，兼容性会比旧版更好

建议顺序：
   1) 先执行一键脚本
   2) update-all && reboot
   3) 编辑 /etc/default/hy2-main
   4) 跑主节点：bash /root/onekey_hy2_main_tls.sh
   5) 临时节点：先跑 bash /root/hy2_temp_port_all.sh
      再用 D=xxx hy2_mktemp.sh
   6) 需要限额就用：pq_add.sh / pq_audit.sh / pq_del.sh
==================================================
