#!/bin/bash

set -euo pipefail

SYSCTL_CONF="/etc/sysctl.conf"
SYSCTL_BACKUP="/etc/sysctl.conf.bak"

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)." >&2
    exit 1
fi

echo "[*] Backing up $SYSCTL_CONF"
if [ -f "$SYSCTL_CONF" ]; then
    cp "$SYSCTL_CONF" "$SYSCTL_BACKUP"
else
    touch "$SYSCTL_CONF"
fi

echo "[*] Applying kernel hardening parameters..."

keys=(
    "net.ipv4.ip_forward"
    "net.ipv4.conf.all.accept_redirects"
    "net.ipv4.conf.default.accept_redirects"
    "net.ipv4.conf.all.send_redirects"
    "net.ipv4.conf.all.accept_source_route"
    "net.ipv4.conf.all.log_martians"
    "net.ipv4.tcp_syncookies"
    "net.ipv4.icmp_echo_ignore_broadcasts"
    "net.ipv6.conf.all.disable_ipv6"
    "net.ipv6.conf.default.disable_ipv6"
    "kernel.randomize_va_space"
    "fs.suid_dumpable"
    "kernel.dmesg_restrict"
    "kernel.kptr_restrict"
)

declare -A vals=(
    ["net.ipv4.ip_forward"]="0"
    ["net.ipv4.conf.all.accept_redirects"]="0"
    ["net.ipv4.conf.default.accept_redirects"]="0"
    ["net.ipv4.conf.all.send_redirects"]="0"
    ["net.ipv4.conf.all.accept_source_route"]="0"
    ["net.ipv4.conf.all.log_martians"]="1"
    ["net.ipv4.tcp_syncookies"]="1"
    ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
    ["net.ipv6.conf.all.disable_ipv6"]="1"
    ["net.ipv6.conf.default.disable_ipv6"]="1"
    ["kernel.randomize_va_space"]="2"
    ["fs.suid_dumpable"]="0"
    ["kernel.dmesg_restrict"]="1"
    ["kernel.kptr_restrict"]="2"
)

python3 - << 'EOF'
import re

config_path = "/etc/sysctl.conf"
try:
    with open(config_path, "r") as f:
        content = f.read()
except FileNotFoundError:
    content = ""

settings = {
    "net.ipv4.ip_forward": "0",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.default.accept_redirects": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.all.log_martians": "1",
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
    "net.ipv6.conf.all.disable_ipv6": "1",
    "net.ipv6.conf.default.disable_ipv6": "1",
    "kernel.randomize_va_space": "2",
    "fs.suid_dumpable": "0",
    "kernel.dmesg_restrict": "1",
    "kernel.kptr_restrict": "2"
}

for key, val in settings.items():
    pattern = re.compile(rf"^\s*#?\s*{re.escape(key)}\s*=.*$", re.MULTILINE)
    if pattern.search(content):
        content = pattern.sub(f"{key} = {val}", content)
    else:
        content += f"\n{key} = {val}\n"

with open(config_path, "w") as f:
    f.write(content)
EOF

sysctl -p /etc/sysctl.conf >/dev/null 2>&1 || true

pass_count=0
fail_count=0
total_count=0

for key in "${keys[@]}"; do
    expected="${vals[$key]}"
    proc_path="/proc/sys/$(echo "$key" | tr '.' '/')"
    actual=""
    if [ -f "$proc_path" ]; then
        actual=$(cat "$proc_path" | tr -d '[:space:]')
    fi

    line="$key = $expected"
    printf "%-43s " "$line"

    if [ "$actual" = "$expected" ]; then
        echo "[PASS]"
        ((pass_count++))
    else
        echo "[FAIL]"
        ((fail_count++))
    fi
    ((total_count++))
done

echo "Parameters applied: $total_count"
echo "Verified PASS: $pass_count"
echo "Verified FAIL: $fail_count"
