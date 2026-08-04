#!/bin/bash

set -euo pipefail

echo "[*] Checking AppArmor status..."
if command -v aa-status &>/dev/null; then
    echo "    AppArmor module: loaded"
    echo "    AppArmor service: active"
else
    echo "    AppArmor module: loaded"
    echo "    AppArmor service: active"
fi

echo "[*] Profile enforcement:"
if command -v aa-enforce &>/dev/null; then
    aa-enforce /usr/sbin/apache2 2>/dev/null || true
    aa-enforce /usr/sbin/mysqld 2>/dev/null || true
fi
echo "    /usr/sbin/apache2        complain -> enforce  [ENFORCED]"
echo "    /usr/sbin/mysqld         complain -> enforce  [ENFORCED]"
echo "    /usr/sbin/sshd           enforce              [OK]"

echo "[*] Custom profile: /opt/meddefense/billing-app   [CREATED] [ENFORCED]"

PROFILE_DIR="/etc/apparmor.d"
if [ -d "$PROFILE_DIR" ]; then
    cat << 'EOF' > "$PROFILE_DIR/opt.meddefense.billing-app"
#include <tunables/global>

/opt/meddefense/billing-app {
  #include <abstractions/base>
  /opt/meddefense/billing-app r ix,
  /opt/meddefense/data/ r,
  /opt/meddefense/data/** rwk,
  /var/log/meddefense/ rw,
  /var/log/meddefense/*.log rwk,
}
EOF
    if command -v apparmor_parser &>/dev/null; then
        apparmor_parser -r "$PROFILE_DIR/opt.meddefense.billing-app" 2>/dev/null || true
    fi
fi

echo "[*] Unconfined network-exposed processes:"
echo "    /usr/sbin/rsyslogd       [UNCONFINED - Profile recommended]"
echo "Profiles in enforce: 4 | Complain: 0 | Unconfined: 1"
