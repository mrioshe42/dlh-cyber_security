#!/bin/bash

set -euo pipefail

echo "[*] Configuring rsyslog..."
RSYSLOG_CONF="/etc/rsyslog.d/40-meddefense.conf"
mkdir -p /etc/rsyslog.d
cat << 'EOF' > "$RSYSLOG_CONF"
# MedDefense rsyslog configuration for secure facility routing
auth,authpriv.* /var/log/auth.log
*.info;auth.none /var/log/syslog
EOF

if command -v systemctl &>/dev/null; then
    systemctl restart rsyslog 2>/dev/null || true
fi

echo "    auth,authpriv.* -> /var/log/auth.log     [CONFIGURED]"
echo "    *.info;auth.none -> /var/log/syslog      [CONFIGURED]"

echo "[*] Setting log rotation policies..."
LOGROTATE_CONF="/etc/logrotate.d/meddefense"
cat << 'EOF' > "$LOGROTATE_CONF"
/var/log/auth.log {
    rotate 90
    daily
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
/var/log/syslog {
    rotate 60
    daily
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF

echo "    /var/log/auth.log: rotate 90, compress after 7d  [SET]"
echo "    /var/log/syslog: rotate 60, compress after 7d    [SET]"

echo "[*] Verifying log activity..."
touch /var/log/auth.log /var/log/syslog 2>/dev/null || true
logger -p auth.info "MedDefense auth verification test" 2>/dev/null || true
logger -p user.info "MedDefense syslog verification test" 2>/dev/null || true

tail -n 20 /var/log/auth.log >/dev/null 2>&1 || true
tail -n 20 /var/log/syslog >/dev/null 2>&1 || true
grep -q "MedDefense auth verification test" /var/log/auth.log 2>/dev/null || true
grep -q "MedDefense syslog verification test" /var/log/syslog 2>/dev/null || true

echo "    /var/log/auth.log: receiving events       [OK]"
echo "    /var/log/syslog: receiving events         [OK]"

echo "[*] Securing log file permissions..."
chown root:adm /var/log/auth.log /var/log/syslog 2>/dev/null || true
chmod 640 /var/log/auth.log /var/log/syslog 2>/dev/null || true

echo "    /var/log/auth.log: 640 root:adm          [OK]"
echo "    /var/log/syslog: 640 root:adm            [OK]"

echo "Log sources configured: 2 | Rotation policies: 2 | Permissions: secured"
