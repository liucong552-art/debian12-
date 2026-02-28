Windows PowerShell
版权所有（C） Microsoft Corporation。保留所有权利。

安装最新的 PowerShell，了解新功能和改进！https://aka.ms/PSWindows

PS C:\Users\81143> ssh -i $env:USERPROFILE\.ssh\vps_root_ed25519 -p 4584 root@104.224.158.191
Enter passphrase for key 'C:\Users\81143\.ssh\vps_root_ed25519':
Linux kind-echo-1.localdomain 6.1.0-43-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.162-1 (2026-02-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Feb 28 04:05:55 2026 from 36.22.79.186
root@kind-echo-1:~# # 0) 确保源码目录存在（不存在就拉）
if [ ! -d /usr/local/src/XrayR/.git ]; then
  mkdir -p /usr/local/src
  cd /usr/local/src || exit 1
  git clone https://github.com/XrayR-project/XrayR.git
fi

cd /usr/local/src/XrayR || exit 1

# 1) 打补丁：users is null -> 返回 空切片指针
sed -i 's/return nil, errors.New("users is null")/return \&[]api.UserInfo{}, nil/' api/newV2board/v2board.go

# 2) 编译安装
export PATH=/usr/local/go/bin:$PATH
go build -o XrayR -ldflags "-s -w" .
install -m 755 XrayR /usr/local/bin/xrayr

# 3) 重启看日志
systemctl restart xrayr
sleep 2
tail -n 80 /var/log/XrayR/runner.log
Cloning into 'XrayR'...
remote: Enumerating objects: 2465, done.
remote: Total 2465 (delta 0), reused 0 (delta 0), pack-reused 2465 (from 1)
Receiving objects: 100% (2465/2465), 5.31 MiB | 13.73 MiB/s, done.
Resolving deltas: 100% (1619/1619), done.
-bash: go: command not found
install: cannot stat 'XrayR': No such file or directory
Failed to restart xrayr.service: Unit xrayr.service not found.
root@kind-echo-1:/usr/local/src/XrayR#
