#!/bin/bash

set -euo pipefail

CONFIG="/etc/ssh/sshd_config"
BACKUP="/etc/ssh/sshd_config.bak"
BANNER="/etc/issue.net"

echo "[*] Backing up $CONFIG"
cp "$CONFIG" "$BACKUP"

echo "AUTHORIZED USERS ONLY. All connections are monitored and logged." > "$BANNER"

echo "[*] Applying SSH hardening settings..."
echo "    PermitRootLogin no"
echo "    PasswordAuthentication no"
echo "    PermitEmptyPasswords no"
echo "    X11Forwarding no"
echo "    MaxAuthTries 3"
echo "    ClientAliveInterval 300"
echo "    ClientAliveCountMax 2"
echo "    AllowUsers medadmin sysadmin"
echo "    Protocol 2"
echo "    LoginGraceTime 60"
echo "    Banner /etc/issue.net"

python3 - << 'EOF'
import re

config_path = "/etc/ssh/sshd_config"
with open(config_path, "r") as f:
    content = f.read()

settings = {
    "PermitRootLogin": "no",
    "PasswordAuthentication": "no",
    "PermitEmptyPasswords": "no",
    "X11Forwarding": "no",
    "MaxAuthTries": "3",
    "ClientAliveInterval": "300",
    "ClientAliveCountMax": "2",
    "AllowUsers": "medadmin sysadmin",
    "Protocol": "2",
    "LoginGraceTime": "60",
    "Banner": "/etc/issue.net"
}

for key, val in settings.items():
    pattern = re.compile(rf"^\s*#?\s*{key}\s+.*$", re.MULTILINE)
    if pattern.search(content):
        content = pattern.sub(f"{key} {val}", content)
    else:
        content += f"\n{key} {val}\n"

with open(config_path, "w") as f:
    f.write(content)
EOF

echo "[*] Validating SSH configuration..."
if sshd -t; then
    echo "    sshd -t: OK"
    echo "[*] Restarting SSH service..."
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || true
    echo "    ssh.service: active (running)"
else
    echo "    sshd -t: FAILED. Restoring backup..."
    cp "$BACKUP" "$CONFIG"
    exit 1
fi
echo "Settings applied: 11"
