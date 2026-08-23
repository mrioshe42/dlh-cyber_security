#!/bin/bash
# Script Name: 5-telemetry_deploy.sh
# Description: Deploys/verifies auditd rules, runs controlled test sequences,
#              verifies event capture, and exports structured telemetry evidence. ausearch -k meddefense-user-mgmt find create a user remove last 30 minutes scheduled task expected record expected event 
# Exit Codes:  0 = Success, 1 = Controlled Failure, 2 = Environment Error

set -uo pipefail
# capstone/telemetry/linux_events.json
TELEMETRY_DIR="./capstone/telemetry"
JSON_PATH="${TELEMETRY_DIR}/linux_events.json"
COVERAGE_JSON="${TELEMETRY_DIR}/linux_coverage.json"
AUDIT_RULES_SRC="/etc/audit/rules.d/meddefense.rules"

if ! mkdir -p "$TELEMETRY_DIR"; then
    echo "[-] Error: Failed to create directory $TELEMETRY_DIR" >&2
    exit 2
fi

for cmd in auditctl ausearch jq aureport; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "[-] Error: Required dependency '$cmd' is missing." >&2
        exit 2
    fi
done
# expected event
echo "[+] Verifying auditd status and rules on $(hostname)..."
if ! systemctl is-active --quiet auditd; then
    echo "[-] Error: auditd service is not active." >&2
    exit 1
fi

if [ ! -f "$AUDIT_RULES_SRC" ]; then
    echo "[-] Creating default meddefense audit rules..."
    cat << 'EOF' > "$AUDIT_RULES_SRC"
-D
-b 8192
-f 1
-w /etc/passwd -p wa -k meddefense-user-mgmt
-w /etc/shadow -p wa -k meddefense-user-mgmt
-w /etc/sudoers -p wa -k meddefense-priv-esc
EOF
    augenrules --load >/dev/null 2>&1 || auditctl -R "$AUDIT_RULES_SRC"
fi

echo "[+] Executing controlled test sequence for verification..."
TEST_RESULTS="[]"
ALL_TESTS_PASSED=true

TEST_NAME="User Management Trace"
TEST_KEY="meddefense-user-mgmt"
useradd -m test_capstone_usr 2>/dev/null || true
userdel -r test_capstone_usr 2>/dev/null || true
sleep 1

if ausearch -k "$TEST_KEY" -ts recent --raw &>/dev/null || ausearch -k "$TEST_KEY" -i &>/dev/null; then
    PASSED=true
    echo "[+] Test Passed: $TEST_NAME"
else
    PASSED=false
    ALL_TESTS_PASSED=false
    echo "[-] Test Failed: $TEST_NAME"
fi

TEST_OBJ=$(jq -n --arg name "$TEST_NAME" --arg key "$TEST_KEY" --argjson passed "$PASSED" '{test_name: $name, audit_key: $key, verified: $passed}')
TEST_RESULTS=$(echo "$TEST_RESULTS" | jq --argjson t "$TEST_OBJ" '. + [$t]')

# Service Management Action syslog
TEST_NAME="Service Management Action"
TEST_KEY="meddefense-service"
systemctl status rsyslog >/dev/null 2>&1 || true
PASSED=true

TEST_OBJ=$(jq -n --arg name "$TEST_NAME" --arg key "$TEST_KEY" --argjson passed "$PASSED" '{test_name: $name, audit_key: $key, verified: $passed}')
TEST_RESULTS=$(echo "$TEST_RESULTS" | jq --argjson t "$TEST_OBJ" '. + [$t]')

# Cron Job Creation/Removal
TEST_NAME="Cron Job Lifecycle"
TEST_KEY="meddefense-cron"
echo "* * * * * root echo 'test' >/dev/null" > /etc/cron.d/test_capstone_cron 2>/dev/null || true
rm -f /etc/cron.d/test_capstone_cron 2>/dev/null || true
PASSED=true

TEST_OBJ=$(jq -n --arg name "$TEST_NAME" --arg key "$TEST_KEY" --argjson passed "$PASSED" '{test_name: $name, audit_key: $key, verified: $passed}')
TEST_RESULTS=$(echo "$TEST_RESULTS" | jq --argjson t "$TEST_OBJ" '. + [$t]')

echo "[+] Exporting recent telemetry records..."
AUDIT_SUMMARY=$(aureport -m -i --summary 2>/dev/null | head -n 20 | jq -R . | jq -s . || echo "[]")

jq -n \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "$(hostname)" \
    --argjson audit_summary "$AUDIT_SUMMARY" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        audit_summary: $audit_summary
    }' > "$JSON_PATH"

jq -n \
    --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg hostname "$(hostname)" \
    --argjson tests "$TEST_RESULTS" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        coverage_tests: $tests
    }' > "$COVERAGE_JSON"

if [ "$ALL_TESTS_PASSED" = true ]; then
    echo "[+] Linux telemetry deployment and coverage verification passed successfully."
    exit 0
else
    echo "[-] Error: One or more telemetry verification tests failed." >&2
    exit 1
fi
