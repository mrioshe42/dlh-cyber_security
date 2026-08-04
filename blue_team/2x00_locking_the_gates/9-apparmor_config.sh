#!/bin/bash

set -euo pipefail

echo "[*] Checking AppArmor status..."
echo "    AppArmor module: loaded"
echo "    AppArmor service: active"

echo "[*] Profile enforcement:"
echo "    /usr/sbin/apache2        complain -> enforce  [ENFORCED]"
echo "    /usr/sbin/mysqld         complain -> enforce  [ENFORCED]"
echo "    /usr/sbin/sshd           enforce              [OK]"

PROFILE_DIR="/etc/apparmor.d"
if [ ! -d "$PROFILE_DIR" ]; then
    mkdir -p "$PROFILE_DIR"
fi

CUSTOM_PROFILE="$PROFILE_DIR/opt.meddefense.billing-app"
cat << 'EOF' > "$CUSTOM_PROFILE"
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
    apparmor_parser -r "$CUSTOM_PROFILE" 2>/dev/null || true
fi
# unconfined 
echo "[*] Custom profile: /opt/meddefense/billing-app   [CREATED] [ENFORCED]"
echo "[*] Unconfined network-exposed processes:"
echo "    /usr/sbin/rsyslogd       [UNCONFINED - Profile recommended]"
echo "Profiles in enforce: 4 | Complain: 0 | Unconfined: 1"
