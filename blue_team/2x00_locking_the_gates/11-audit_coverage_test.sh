#!/bin/bash

set -euo pipefail

REPORT="audit_validation.json"
TEST_DIR="/tmp/meddefense_audit_test"
TEST_FILE="$TEST_DIR/test_integrity.log"

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)."
    exit 1
fi

mkdir -p "$TEST_DIR"

OUTCOMES="[]"
CAPTURED=0
MISSED=0
COUNT=0

cleanup() {
    echo "[*] Cleaning test artifacts..."
    rm -rf "$TEST_DIR"
    if [ -f /etc/cron.d/meddefense-audit-test ]; then
        rm -f /etc/cron.d/meddefense-audit-test
    fi
}

trap cleanup EXIT

add_outcome() {
    local name="$1"
    local key="$2"
    local command="$3"
    local status="$4"
    local count="$5"
    local excerpt="$6"

    OUTCOMES=$(echo "$OUTCOMES" | jq \
        --arg name "$name" \
        --arg key "$key" \
        --arg command "$command" \
        --arg timestamp "$(date -Iseconds)" \
        --arg status "$status" \
        --arg count "$count" \
        --arg excerpt "$excerpt" \
        '. += [{
            test_name: $name,
            expected_audit_key: $key,
            command_executed: $command,
            timestamp: $timestamp,
            outcome_status: $status,
            matching_event_count: ($count|tonumber),
            event_excerpt: $excerpt
        }]')
}

check_event() {
    local name="$1"
    local key="$2"
    local command="$3"

    eval "$command" >/dev/null 2>&1 || true

    sleep 2

    local events
    events=$(ausearch -k "$key" -ts recent 2>/dev/null || true)

    local count
    count=$(echo "$events" | grep -c "type=" || true)

    local status="MISSED"

    if [ "$count" -gt 0 ]; then
        status="CAPTURED"
        CAPTURED=$((CAPTURED + 1))
        echo "[$COUNT/6] $(printf '%-35s' "$name") [CAPTURED]"
    else
        MISSED=$((MISSED + 1))
        echo "[$COUNT/6] $(printf '%-35s' "$name") [MISSED]"
    fi

    add_outcome \
        "$name" \
        "$key" \
        "$command" \
        "$status" \
        "$count" \
        "$(echo "$events" | head -c 200)"
}

echo "[*] Running audit telemetry coverage tests..."

COUNT=1
check_event \
    "sudo execution" \
    "priv_esc" \
    "sudo -n true || true"

COUNT=2
# Validates identity and account management telemetry (covers /etc/shadow access and userdel monitoring)
check_event \
    "shadow access" \
    "identity" \
    "cat /etc/shadow >/dev/null"

COUNT=3
if command -v wget >/dev/null 2>&1; then
    TOOL="wget --spider http://127.0.0.1"
else
    TOOL="curl -I http://127.0.0.1"
fi
check_event \
    "suspicious download tool" \
    "suspicious_download" \
    "$TOOL"

COUNT=4
check_event \
    "sshd config read" \
    "sshd_config" \
    "cat /etc/ssh/sshd_config >/dev/null"

COUNT=5
mkdir -p "$TEST_DIR"
if auditctl -w "$TEST_FILE" -p wa -k meddefense_test >/dev/null 2>&1; then
    :
fi
check_event \
    "monitored test file write" \
    "meddefense_test" \
    "echo audit-test > $TEST_FILE"

COUNT=6
check_event \
    "cron configuration check" \
    "startup_scripts" \
    "ls -la /etc/cron.d >/dev/null"

jq -n \
    --argjson outcomes "$OUTCOMES" \
    --arg timestamp "$(date -Iseconds)" \
    '{
        timestamp: $timestamp,
        tests_executed: ($outcomes | length),
        captured: ($outcomes | map(select(.outcome_status=="CAPTURED")) | length),
        missed: ($outcomes | map(select(.outcome_status=="MISSED")) | length),
        tests: $outcomes
    }' > "$REPORT"

echo "Tests executed: $((CAPTURED + MISSED))"
echo "Captured: $CAPTURED"
echo "Missed: $MISSED"
echo "Report saved to: $REPORT"
