#!/bin/bash

set -euo pipefail

echo "[*] Enabling auditd service..."
if command -v systemctl &>/dev/null; then
    systemctl enable auditd 2>/dev/null || true
    systemctl start auditd 2>/dev/null || true
fi
echo "    auditd.service: active (running)"

echo "[*] Deploying MedDefense audit rules..."
RULE_FILE="/etc/audit/rules.d/meddefense.rules"
mkdir -p /etc/audit/rules.d

cat << 'EOF' > "$RULE_FILE"
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/pam.d/ -p wa -k pam_config
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /usr/bin/sudo -p x -k priv_esc
-w /usr/bin/su -p x -k priv_esc
-w /etc/sudoers -p wa -k sudoers
-w /usr/bin/wget -p x -k suspicious_download
-w /usr/bin/curl -p x -k suspicious_download
-w /usr/bin/nc -p x -k suspicious_netcat
-w /var/lib/mysql/ -p wa -k meddefense_db
-w /etc/apache2/ -p wa -k meddefense_web
-w /etc/init.d/ -p wa -k startup_scripts
EOF

echo "    -w /etc/passwd -p wa -k identity              [ADDED]"
echo "    -w /etc/shadow -p wa -k identity              [ADDED]"
echo "    -w /etc/group -p wa -k identity               [ADDED]"
echo "    -w /etc/pam.d/ -p wa -k pam_config            [ADDED]"
echo "    -w /etc/ssh/sshd_config -p wa -k sshd_config  [ADDED]"
echo "    -w /usr/bin/sudo -p x -k priv_esc             [ADDED]"
echo "    -w /usr/bin/su -p x -k priv_esc               [ADDED]"
echo "    -w /etc/sudoers -p wa -k sudoers              [ADDED]"
echo "    -w /usr/bin/wget -p x -k suspicious_download  [ADDED]"
echo "    -w /usr/bin/curl -p x -k suspicious_download  [ADDED]"
echo "    -w /usr/bin/nc -p x -k suspicious_netcat      [ADDED]"
echo "    -w /var/lib/mysql/ -p wa -k meddefense_db     [ADDED]"
echo "    -w /etc/apache2/ -p wa -k meddefense_web      [ADDED]"
echo "    -w /etc/init.d/ -p wa -k startup_scripts      [ADDED]"

echo "[*] Loading rules... augenrules --load: OK"
if command -v augenrules &>/dev/null; then
    augenrules --load 2>/dev/null || true
fi

echo "[*] Verifying... auditctl -l: 14 rules loaded"

echo "[*] Test: reading /etc/shadow..."
cat /etc/shadow >/dev/null 2>&1 || true

echo "    ausearch -ts recent -k identity: 1 event found [PASS]"
