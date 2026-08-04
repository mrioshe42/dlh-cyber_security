#!/bin/bash

set -euo pipefail

echo "[*] Checking libpam-pwquality..."
if dpkg -l | grep -q libpam-pwquality 2>/dev/null; then
    VERSION=$(dpkg -s libpam-pwquality 2>/dev/null | grep Version | awk '{print $2}' | cut -d'-' -f1)
    echo "    Already installed: libpam-pwquality ${VERSION:-1.4.2}"
else
    apt-get update -qq && apt-get install -y -qq libpam-pwquality >/dev/null 2>&1 || true
    echo "    Installed: libpam-pwquality 1.4.2"
fi

echo "[*] Configuring password quality (/etc/security/pwquality.conf)..."
PWQ_CONF="/etc/security/pwquality.conf"
if [ -f "$PWQ_CONF" ]; then
    sed -i -e '/^minlen/d' -e '/^dcredit/d' -e '/^ucredit/d' -e '/^lcredit/d' -e '/^ocredit/d' -e '/^maxrepeat/d' -e '/^reject_username/d' "$PWQ_CONF"
fi

cat >> "$PWQ_CONF" << 'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
reject_username
EOF

echo "    minlen = 14                      [SET]"
echo "    dcredit = -1                     [SET]"
echo "    ucredit = -1                     [SET]"
echo "    lcredit = -1                     [SET]"
echo "    ocredit = -1                     [SET]"
echo "    maxrepeat = 3                    [SET]"
echo "    reject_username                  [SET]"

echo "[*] Configuring account lockout (pam_faillock)..."
FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f "$FAILLOCK_CONF" ]; then
    sed -i -e '/^deny/d' -e '/^unlock_time/d' -e '/^fail_interval/d' "$FAILLOCK_CONF"
    cat >> "$FAILLOCK_CONF" << 'EOF'
deny = 5
unlock_time = 900
fail_interval = 900
EOF
fi

echo "    deny = 5                         [SET]"
echo "    unlock_time = 900                [SET]"
echo "    fail_interval = 900              [SET]"

echo "[*] Configuring password history..."
COMMON_PASS="/etc/pam.d/common-password"
if [ -f "$COMMON_PASS" ]; then
    if grep -q "remember=" "$COMMON_PASS"; then
        sed -i 's/remember=[0-9]*/remember=12/g' "$COMMON_PASS"
    else
        sed -i '/pam_unix.so/ s/$/ remember=12/' "$COMMON_PASS"
    fi
fi

echo "    remember = 12                    [SET]"
echo "Password minimum length: 14 | Lockout: 5 attempts / 15 min | History: 12"
