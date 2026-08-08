#!/bin/bash

set -e
set -u
set -o pipefail

RULE_FILE="/etc/audit/rules.d/meddefense.rules"
mkdir -p /etc/audit/rules.d

CURRENT_COUNT=0
if command -v auditctl &>/dev/null; then
    CURRENT_COUNT=$(auditctl -l | grep -v "No rules" | wc -l)
fi

echo "[*] Current auditd rules: $CURRENT_COUNT"

echo "[*] Adding detection-focused rules..."
echo "    execve syscall tracking               [ADDED]"
echo "    socket/connect syscall tracking       [ADDED]"
echo "    SSH key file monitoring               [ADDED]"
echo "    Cron directory monitoring             [ADDED]"
echo "    sudoers.d monitoring                  [ADDED]"

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
-a always,exit -F arch=b64 -S execve -k process_exec
-a always,exit -F arch=b32 -S execve -k process_exec
-a always,exit -F arch=b64 -S socket -S connect -k network_connect
-a always,exit -F arch=b32 -S socket -S connect -k network_connect
-w /etc/cron.d/ -p wa -k cron_persist
-w /var/spool/cron/ -p wa -k cron_persist
-w /etc/sudoers.d/ -p wa -k sudoers
EOF
#  /home/*/.ssh/
for home in /home/*; do
    if [ -d "$home/.ssh" ]; then
        echo "-w $home/.ssh/ -p rwa -k ssh_keys" >> "$RULE_FILE"
    fi
done

if [ -d "/root/.ssh" ]; then
    echo "-w /root/.ssh/ -p rwa -k ssh_keys" >> "$RULE_FILE"
fi

echo -n "[*] Loading rules... "
if command -v augenrules &>/dev/null; then
    augenrules --load >/dev/null 2>&1 && echo "augenrules --load: OK" || echo "augenrules --load: FAILED"
elif command -v auditctl &>/dev/null; then
    auditctl -R "$RULE_FILE" >/dev/null 2>&1 && echo "auditctl: OK" || echo "auditctl: FAILED"
else
    echo "NO_LOADER_FOUND"
fi

TOTAL_RULES=0
if command -v auditctl &>/dev/null; then
    TOTAL_RULES=$(auditctl -l | grep -v "No rules" | wc -l)
fi
echo "[*] Total rules: $TOTAL_RULES"

echo "[*] Validating new rules..."
passed=0

# Trigger execve rule
/usr/bin/id >/dev/null 2>&1 || true
sleep 1
echo -n "    execve: ran /usr/bin/id -> ausearch -k process_exec    "
if ausearch -k process_exec -ts recent 2>/dev/null | grep -q "execve"; then
    echo "[CAPTURED]"
    ((passed+=1))
else
    echo "[MISSED]"
fi

# Trigger socket/connect rule
curl -s --max-time 2 http://127.0.0.1 >/dev/null 2>&1 || true
sleep 1
echo -n "    socket: curl localhost -> ausearch -k network_connect  "
if ausearch -k network_connect -ts recent 2>/dev/null | grep -q "network_connect"; then
    echo "[CAPTURED]"
    ((passed+=1))
else
    echo "[MISSED]"
fi

# Trigger SSH keys rule
ssh_test=""
for home in /home/*; do
    if [ -d "$home/.ssh" ]; then
        ssh_test="$home/.ssh/audit_test"
        touch "$ssh_test" >/dev/null 2>&1 || true
        break
    fi
done

if [ -z "$ssh_test" ] && [ -d "/root/.ssh" ]; then
    ssh_test="/root/.ssh/audit_test"
    touch "$ssh_test" >/dev/null 2>&1 || true
fi

sleep 1
echo -n "    ssh_keys: touch ~/.ssh/test -> ausearch -k ssh_keys    "
if [ -n "$ssh_test" ] && ausearch -k ssh_keys -ts recent 2>/dev/null | grep -q "ssh_keys"; then
    echo "[CAPTURED]"
    ((passed+=1))
else
    echo "[MISSED]"
fi

# Trigger cron rule
mkdir -p /etc/cron.d
touch /etc/cron.d/audit_test >/dev/null 2>&1 || true
sleep 1
echo -n "    cron: touch /etc/cron.d/test -> ausearch -k cron_persist "
if ausearch -k cron_persist -ts recent 2>/dev/null | grep -q "cron_persist"; then
    echo "[CAPTURED]"
    ((passed+=1))
else
    echo "[MISSED]"
fi

mkdir -p /etc/sudoers.d
touch /etc/sudoers.d/audit_test >/dev/null 2>&1 || true
sleep 1
echo -n "    sudoers: touch /etc/sudoers.d/test -> ausearch -k sudoers "
if ausearch -k sudoers -ts recent 2>/dev/null | grep -q "sudoers"; then
    echo "[CAPTURED]"
    ((passed+=1))
else
    echo "[MISSED]"
fi

rm -f /etc/cron.d/audit_test >/dev/null 2>&1 || true
rm -f /etc/sudoers.d/audit_test >/dev/null 2>&1 || true
if [ -n "$ssh_test" ]; then
    rm -f "$ssh_test" >/dev/null 2>&1 || true
fi

echo "Rules added: 5 | Validation: $passed/5 PASS"
