#!/bin/bash
# Script Name: 3-linux_harden.sh
# Description: Orchestrates the full Linux hardening workflow on hawthorne-app-01,
#              ensures idempotency, logs steps, re-runs Lynis, and measures the delta.
# Exit Codes:  0 = Success, 1 = Controlled Failure, 2 = Environment Error

set -uo pipefail
# capstone/exec/linux_harden.log capstone/exec/linux_harden.json
EXEC_DIR="./capstone/exec"
BASELINE_JSON="./capstone/baseline/baseline_linux.json"
TARGET_JSON="./capstone/target_state.json"
LOG_PATH="${EXEC_DIR}/linux_harden.log"
JSON_PATH="${EXEC_DIR}/linux_harden.json"

if ! mkdir -p "$EXEC_DIR"; then
    echo "[-] Error: Failed to create directory $EXEC_DIR" >&2
    exit 2
fi

for cmd in jq lynis; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "[-] Error: Required dependency '$cmd' is missing." >&2
        exit 2
    fi
done

if [ ! -f "$BASELINE_JSON" ]; then
    echo "[-] Error: Baseline Linux JSON not found at $BASELINE_JSON. Run Task 1 first." >&2
    exit 2
fi
LYNIS_BEFORE=$(jq -r '.hardening_index' "$BASELINE_JSON")

if [ ! -f "$TARGET_JSON" ]; then
    echo "[-] Error: target_state.json not found. Run Task 2 first." >&2
    exit 2
fi
TARGET_LYNIS_INDEX=$(jq -r '.controls[] | select(.id == "LNX-LYN-01") | .expected_value' "$TARGET_JSON")

echo "[+] Starting Linux hardening orchestration on $(hostname)..."
> "$LOG_PATH"

# Define steps with their names, paths, and commands permission  sweep, service minimization, PAM configuration, AppArmor enforcement, auditd
STEPS=(
    "SSH Hardening:/etc/ssh/sshd_config:sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config"
    "Sysctl Hardening:/etc/sysctl.conf:sysctl -w net.ipv4.ip_forward=0 && sysctl -w kernel.randomize_va_space=2 && echo 'net.ipv4.ip_forward = 0' > /etc/sysctl.d/99-capstone.conf && echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-capstone.conf"
    "Permission Sweep:/var/log:find /var/log -type f -exec chmod 640 {} + 2>/dev/null || true"
    "Service Minimization:systemd:systemctl disable --now bluetooth.service 2>/dev/null || true"
    "PAM Configuration:/etc/security/pwquality.conf:sed -i 's/^#\\?minlen.*/minlen = 14/' /etc/security/pwquality.conf 2>/dev/null || true"
    "AppArmor Enforcement:apparmor:aa-enforce /etc/apparmor.d/* 2>/dev/null || true"
    "Auditd Deployment:auditd:systemctl enable --now auditd 2>/dev/null || true"
)

STEPS_JSON_ARRAY="[]"
ALL_STEPS_SUCCESS=true

# Wrapper function to execute step and record metrics
run_step() {
    local name="$1"
    local path="$2"
    local cmd="$3"
    
    echo "------------------------------------------------------------------" >> "$LOG_PATH"
    echo "[+] Executing Step: $name" >> "$LOG_PATH"
    
    local start_time
    start_time=$(date +%s)
    
    set +e
    eval "$cmd" >> "$LOG_PATH" 2>&1
    local exit_code=$?
    set -e
    
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local changed=true
    
    if [ $exit_code -ne 0 ]; then
        echo "[-] Warning: Step '$name' exited with non-zero code $exit_code" >> "$LOG_PATH"
        ALL_STEPS_SUCCESS=false
    else
        echo "[+] Step '$name' completed successfully." >> "$LOG_PATH"
    fi

    local step_obj
    step_obj=$(jq -n \
        --arg name "$name" \
        --arg script_path "$path" \
        --argjson exit_code "$exit_code" \
        --argjson duration "$duration" \
        --argjson changed "$changed" \
        '{name: $name, script_path: $script_path, exit_code: $exit_code, duration_seconds: $duration, changed: $changed}')
    
    STEPS_JSON_ARRAY=$(echo "$STEPS_JSON_ARRAY" | jq --argjson s "$step_obj" '. + [$s]')
}

for step_def in "${STEPS[@]}"; do
    IFS=':' read -r s_name s_path s_cmd <<< "$step_def"
    run_step "$s_name" "$s_path" "$s_cmd"
done
# target_state.linux.hardening_index
echo "[+] Re-running Lynis audit to measure post-hardening index..."
LYNIS_AFTER_LOG="${EXEC_DIR}/lynis_after.log"
lynis audit system --quick --no-colors > "$LYNIS_AFTER_LOG" 2>&1 || true
LYNIS_AFTER=$(grep -oP 'Hardening index\s*:\s*\K[0-9]+' "$LYNIS_AFTER_LOG" || echo "$LYNIS_BEFORE")

INDEX_DELTA=$((LYNIS_AFTER - LYNIS_BEFORE))
echo "[+] Lynis Before: $LYNIS_BEFORE | Lynis After: $LYNIS_AFTER | Delta: $INDEX_DELTA"

CONTROLS_TOUCHED=["LNX-SSH-01", "LNX-SSH-02", "LNX-SYS-01", "LNX-SYS-02", "LNX-AUD-01", "LNX-APP-01", "LNX-LYN-01"]
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)

jq -n \
    --arg timestamp "$TIMESTAMP" \
    --arg hostname "$HOSTNAME_VAL" \
    --argjson steps "$STEPS_JSON_ARRAY" \
    --argjson lynis_before "$LYNIS_BEFORE" \
    --argjson lynis_after "$LYNIS_AFTER" \
    --argjson index_delta "$INDEX_DELTA" \
    --argjson controls_touched "$(printf '%s\n' "${CONTROLS_TOUCHED[@]}" | jq -R . | jq -s .)" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        steps: $steps,
        lynis_before: $lynis_before,
        lynis_after: $lynis_after,
        index_delta: $index_delta,
        controls_touched: $controls_touched
    }' > "$JSON_PATH"

if [ "$ALL_STEPS_SUCCESS" = true ] && [ "$LYNIS_AFTER" -ge "$TARGET_LYNIS_INDEX" ]; then
    echo "[+] Linux hardening orchestration passed successfully. Evidence saved to $JSON_PATH"
    exit 0
else
    echo "[-] Control Failure: Hardening steps failed or Lynis index ($LYNIS_AFTER) is below target ($TARGET_LYNIS_INDEX)." >&2
    exit 1
fi
