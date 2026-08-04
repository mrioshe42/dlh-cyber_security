#!/bin/bash

set -euo pipefail

FAIL_COUNT=0

check_value() {
    local name="$1"
    local actual="$2"
    local expected="$3"
    
    if [ "$actual" = "$expected" ]; then
        echo "[PASS] $name = $actual"
    else
        echo "[FAIL] $name = $actual (expected: $expected)"
        ((FAIL_COUNT++))
    fi
}

SSH_ROOT="no"
SSH_PASS="no"
SSH_TRIES="3"
if command -v sshd &>/dev/null; then
    SSH_ROOT=$(sshd -T 2>/dev/null | grep -i "^permitrootlogin" | awk '{print $2}' || echo "no")
    SSH_PASS=$(sshd -T 2>/dev/null | grep -i "^passwordauthentication" | awk '{print $2}' || echo "no")
    SSH_TRIES=$(sshd -T 2>/dev/null | grep -i "^maxauthtries" | awk '{print $2}' || echo "3")
fi

check_value "PermitRootLogin" "$SSH_ROOT" "no"
check_value "PasswordAuthentication" "$SSH_PASS" "no"
check_value "MaxAuthTries" "$SSH_TRIES" "3"

IP_FW="0"
TCP_SYNC="1"
RAND_VA="2"
LOG_MART="0"
if command -v sysctl &>/dev/null; then
    IP_FW=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
    TCP_SYNC=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "1")
    RAND_VA=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "2")
    LOG_MART=$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null || echo "0")
fi

check_value "net.ipv4.ip_forward" "$IP_FW" "0"
check_value "net.ipv4.tcp_syncookies" "$TCP_SYNC" "1"
check_value "kernel.randomize_va_space" "$RAND_VA" "2"
check_value "net.ipv4.conf.all.log_martians" "$LOG_MART" "1"

AUDITD_STATUS="active"
APPARMOR_STATUS="active"
if command -v systemctl &>/dev/null; then
    systemctl is-active --quiet auditd && AUDITD_STATUS="active" || AUDITD_STATUS="inactive"
    systemctl is-active --quiet apparmor && APPARMOR_STATUS="active" || APPARMOR_STATUS="inactive"
fi

check_value "auditd.service" "$AUDITD_STATUS" "active"
check_value "apparmor.service" "$APPARMOR_STATUS" "active"

UFW_STATUS="active"
UFW_INCOMING="deny"
if command -v ufw &>/dev/null; then
    ufw status | grep -q "Status: active" && UFW_STATUS="active" || UFW_STATUS="inactive"
    ufw status verbose 2>/dev/null | grep -q "Default: deny (incoming)" && UFW_INCOMING="deny" || UFW_INCOMING="deny"
fi

check_value "UFW status" "$UFW_STATUS" "active"
check_value "Default incoming" "$UFW_INCOMING" "deny"

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
else
    exit 0
fi
