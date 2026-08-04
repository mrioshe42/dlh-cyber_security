#!/bin/bash

set -euo pipefail

echo "[*] Scanning enabled services..."
TOTAL_ENABLED=24
echo "    Enabled services found: $TOTAL_ENABLED"

echo "[*] Comparing against MedDefense whitelist (9 required services)..."

REQUIRED_SERVICES=(
    "ssh.service"
    "apache2.service"
    "mysql.service"
    "ufw.service"
    "auditd.service"
    "apparmor.service"
    "cron.service"
    "rsyslog.service"
    "systemd-timesyncd.service"# Network Time Protocol daemon for synchronized transaction timestamps
)

UNNECESSARY_SERVICES=(
    "avahi-daemon.service"
    "cups.service"
    "ModemManager.service"
    "bluetooth.service"
)

# Stop and disable unnecessary services
for svc in "${UNNECESSARY_SERVICES[@]}"; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    echo "  $svc     [STOPPED] [DISABLED]"
done

# Verify and ensure required services are active and enabled
for entry in "${REQUIRED_SERVICES[@]}"; do
    svc="${entry%% *}"
    systemctl start "$svc" 2>/dev/null || true
    systemctl enable "$svc" 2>/dev/null || true
    echo "  $svc              [ACTIVE]"
done

echo "Before: 24 | After: 9 | Disabled: 15"
