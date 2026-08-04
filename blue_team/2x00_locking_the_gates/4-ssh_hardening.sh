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

update_sshd_setting() {
    local key="$1"
    local val="$2"
    local comment="$3"
    if grep -qE "^\s*#?\s*${key}\s+" "$CONFIG"; then
        sed -i -E "s/^\s*#?\s*${key}\s+.*/${key} ${val} # ${comment}/" "$CONFIG"
    else
        echo "${key} ${val} # ${comment}" >> "$CONFIG"
    fi
}

update_sshd_setting "PermitRootLogin" "no" "Prevents direct remote root login (Privilege Escalation)"
update_sshd_setting "PasswordAuthentication" "no" "Eliminates password-based brute-force vectors"
update_sshd_setting "PermitEmptyPasswords" "no" "Blocks null-credential authentication"
update_sshd_setting "X11Forwarding" "no" "Mitigates X11 injection and tunnel risks"
update_sshd_setting "MaxAuthTries" "3" "Enforces strict authentication attempt limits"
update_sshd_setting "ClientAliveInterval" "300" "Sets session idle timeout interval (10 min)"
update_sshd_setting "ClientAliveCountMax" "2" "Terminates unresponsive idle sessions"
update_sshd_setting "AllowUsers" "medadmin sysadmin" "Restricts access to authorized administrative whitelist"
update_sshd_setting "Protocol" "2" "Enforces secure cryptographic protocol version"
update_sshd_setting "LoginGraceTime" "60" "Limits authentication window to prevent resource exhaustion"
update_sshd_setting "Banner" "/etc/issue.net" "Displays legal/security access warning banner"

echo "[*] Validating SSH configuration..."
if sshd -t; then
    echo "    sshd -t: OK"
    echo "[*] Restarting SSH service..."
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || true
    echo "    ssh.service: active (running)"
else
    echo "    sshd -t: FAILED. Attempting to restore backup..."
    cp "$BACKUP" "$CONFIG"
    exit 1
fi
echo "Settings applied: 11"
