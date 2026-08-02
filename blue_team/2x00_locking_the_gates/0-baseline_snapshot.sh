#!/bin/bash

set -euo pipefail

[ "$EUID" -ne 0 ] && echo "Error: Run with sudo" && exit 1

echo "Hostname: $(hostname)"
echo "OS: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
echo "Running services: $(systemctl list-units --type=service --state=running --no-legend | wc -l)"
echo "Open ports: $(ss -tuln | tail -n +2 | wc -l)"
echo "SUID binaries: $(find / -xdev -perm -4000 2>/dev/null | wc -l)"
echo "SGID binaries: $(find / -xdev -perm -2000 2>/dev/null | wc -l)"
echo "World-writable files: $(find / -xdev -type f -perm -2 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | wc -l)"

echo "Kernel: $(uname -r) | Uptime: $(uptime -p)"
systemctl list-units --type=service --state=running --no-legend --no-pager
ss -tuln
find / -xdev -perm -4000 2>/dev/null
find / -xdev -perm -2000 2>/dev/null
find / -xdev -type f -perm -2 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null
for p in kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict net.ipv4.ip_forward net.ipv4.tcp_syncookies; do
    val=$(sysctl -n "$p" 2>/dev/null) && echo "$p = $val"
done
grep -Ei '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)' /etc/ssh/sshd_config 2>/dev/null
awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd
getent group sudo 2>/dev/null || getent group wheel 2>/dev/null
