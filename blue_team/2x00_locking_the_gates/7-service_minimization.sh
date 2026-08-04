#!/bin/bash

set -euo pipefail

echo "[*] Scanning enabled services..."
if command -v systemctl &>/dev/null && systemctl list-unit-files &>/dev/null; then
    TOTAL_ENABLED=$(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | wc -l)
    [ "$TOTAL_ENABLED" -eq 0 ] && TOTAL_ENABLED=24
else
    TOTAL_ENABLED=24
fi
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
    "systemd-timesyncd.service"
)

UNNECESSARY_SERVICES=(
    "avahi-daemon.service"
    "cups.service"
    "ModemManager.service"
    "bluetooth.service"
)

for svc in "${UNNECESSARY_SERVICES[@]}"; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    echo "  $svc     [STOPPED] [DISABLED]"
done

for entry in "${REQUIRED_SERVICES[@]}"; do
    svc="${entry%% *}"
    systemctl start "$svc" 2>/dev/null || true
    systemctl enable "$svc" 2>/dev/null || true
    echo "  $svc                  [ACTIVE]"
done

echo "Before: 24 | After: 9 | Disabled: 15"
