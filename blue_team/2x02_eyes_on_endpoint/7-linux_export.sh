#!/bin/bash

# name: 7-linux_export.sh
# purpose: Export security-relevant Linux logs (auth.log, audit.log, syslog) to structured JSON with normalized fields.
# author: Massimo Rios

set -e
set -u
set -o pipefail

AUTH_LOG="/var/log/auth.log"
AUDIT_LOG="/var/log/audit/audit.log"
SYSLOG="/var/log/syslog"

OUTPUT_JSON="linux_events_export.json"
TEMP=$(mktemp)

# Default time window: last 24 hours
START="${1:-24 hours ago}"
END="${2:-now}"

START_EPOCH=$(date -d "$START" +%s)
END_EPOCH=$(date -d "$END" +%s)
YEAR=$(date +%Y)

auth_count=0
ssh_count=0
sudo_count=0
su_count=0
pam_count=0

audit_count=0
execve_count=0
file_count=0
network_count=0
audit_other=0

syslog_count=0
service_count=0
error_count=0
syslog_other=0

# Convert normal Linux log timestamp to ISO 8601 UTC
to_iso() {
    local stamp="$1"
    local month_day="${stamp% *}"
    local time_part="${stamp##* }"
    date -d "$month_day $YEAR $time_part +0200" -u "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo ""
}

# Check if timestamp is inside selected time window
in_window() {
    local iso="$1"
    [ -z "$iso" ] && return 1
    local event_epoch
    event_epoch=$(date -d "$iso" +%s)
    [ "$event_epoch" -ge "$START_EPOCH" ] && [ "$event_epoch" -le "$END_EPOCH" ]
}

add_event() {
    jq -nc \
        --arg timestamp "$1" \
        --arg hostname "$2" \
        --arg source_type "$3" \
        --arg event_category "$4" \
        --arg user "$5" \
        --arg source_ip "$6" \
        --arg command "$7" \
        --arg path "$8" \
        --arg destination "$9" \
        --arg raw_message "${10}" \
        '{
            timestamp: $timestamp,
            hostname: $hostname,
            platform: "Linux",
            source_type: $source_type,
            event_category: $event_category,
            user: $user,
            source_ip: $source_ip,
            command: $command,
            path: $path,
            destination: $destination,
            raw_message: $raw_message
        }' >> "$TEMP"
}

# auth.log
echo -n "[*] Parsing auth.log..."

if [ -f "$AUTH_LOG" ]; then
    while IFS= read -r line; do
        stamp=$(echo "$line" | cut -c1-15)
        iso=$(to_iso "$stamp")

        in_window "$iso" || continue
        host=$(echo "$line" | awk '{print $4}')

        if echo "$line" | grep -q "sshd.*Accepted"; then
            user=$(echo "$line" | sed -n 's/.*Accepted .* for \([^ ]*\) from .*/\1/p')
            ip=$(echo "$line" | sed -n 's/.* from \([^ ]*\) port .*/\1/p')
            add_event "$iso" "$host" "auth" "ssh_login_success" "$user" "$ip" "" "" "" "$line"
            ssh_count=$((ssh_count + 1))
            auth_count=$((auth_count + 1))
        elif echo "$line" | grep -q "sshd.*Failed password"; then
            user=$(echo "$line" | sed -n 's/.*Failed password for \(invalid user \)\?\([^ ]*\) from .*/\2/p')
            ip=$(echo "$line" | sed -n 's/.* from \([^ ]*\) port .*/\1/p')
            add_event "$iso" "$host" "auth" "ssh_login_failure" "$user" "$ip" "" "" "" "$line"
            ssh_count=$((ssh_count + 1))
            auth_count=$((auth_count + 1))
        elif echo "$line" | grep -q "sudo:"; then
            user=$(echo "$line" | sed -n 's/.*sudo:[ ]*\([^ :]*\)[ ]*: .*/\1/p')
            command=$(echo "$line" | sed -n 's/.*COMMAND=\(.*\)/\1/p')
            add_event "$iso" "$host" "auth" "sudo" "$user" "" "$command" "" "" "$line"
            sudo_count=$((sudo_count + 1))
            auth_count=$((auth_count + 1))
        elif echo "$line" | grep -q "su:"; then
            user=$(echo "$line" | sed -n 's/.*session opened for user \([^ ]*\).*/\1/p')
            add_event "$iso" "$host" "auth" "su" "$user" "" "" "" "" "$line"
            su_count=$((su_count + 1))
            auth_count=$((auth_count + 1))
        elif echo "$line" | grep -qi "pam_"; then
            add_event "$iso" "$host" "auth" "PAM" "" "" "" "" "" "$line"
            pam_count=$((pam_count + 1))
            auth_count=$((auth_count + 1))
        fi
    done < "$AUTH_LOG"
fi

echo " $auth_count events"
echo "    SSH logins: $ssh_count | sudo: $sudo_count | su: $su_count | PAM: $pam_count"

# audit.log using ausearch
echo -n "[*] Parsing audit.log..."

if [ -f "$AUDIT_LOG" ]; then
    while IFS= read -r line; do
        audit_epoch=$(echo "$line" | sed -n 's/.*msg=audit(\([0-9]*\).*/\1/p')
        [ -z "$audit_epoch" ] && continue

        if [ "$audit_epoch" -lt "$START_EPOCH" ] || [ "$audit_epoch" -gt "$END_EPOCH" ]; then
            continue
        fi

        iso=$(date -u -d "@$audit_epoch" "+%Y-%m-%dT%H:%M:%SZ")
        host=$(hostname)

        if [[ "$line" == *"type=EXECVE"* ]]; then
    command=""
    if [[ "$line" =~ a[0-9]+=\"([^\"]*)\" ]]; then
        command="${BASH_REMATCH[1]}"
    fi
    add_event "$iso" "$host" "auditd" "execve" "" "" "$command" "" "" "$line"
    execve_count=$((execve_count + 1))
elif [[ "$line" == *"type=PATH"* ]]; then
    path=""
    if [[ "$line" =~ name=\"([^\"]*)\" ]]; then
        path="${BASH_REMATCH[1]}"
    fi
    add_event "$iso" "$host" "auditd" "file_access" "" "" "" "$path" "" "$line"
    file_count=$((file_count + 1))
elif [[ "$line" == *"type=SOCKADDR"* || "$line" == *"network_connect"* ]]; then
    destination=""
    if [[ "$line" =~ saddr=([^\ ]*) ]]; then
        destination="${BASH_REMATCH[1]}"
    fi
    add_event "$iso" "$host" "auditd" "network" "" "" "" "" "$destination" "$line"
    network_count=$((network_count + 1))
else
    add_event "$iso" "$host" "auditd" "other" "" "" "" "" "" "$line"
    audit_other=$((audit_other + 1))
fi

        audit_count=$((audit_count + 1))
    done < <(ausearch --raw -ts recent 2>/dev/null || true)
fi

echo " $audit_count events"
echo "    execve: $execve_count | file_access: $file_count | network: $network_count | other: $audit_other"

# syslog
echo -n "[*] Parsing syslog..."

if [ -f "$SYSLOG" ]; then
    while IFS= read -r line; do
        stamp=$(echo "$line" | cut -c1-15)
        iso=$(to_iso "$stamp")

        in_window "$iso" || continue
        host=$(echo "$line" | awk '{print $4}')

        if echo "$line" | grep -Eqi "Started |Stopped |Starting |Stopping "; then
            category="service"
            service_count=$((service_count + 1))
        elif echo "$line" | grep -Eqi "error|failed|failure|critical"; then
            category="error"
            error_count=$((error_count + 1))
        else
            category="other"
            syslog_other=$((syslog_other + 1))
        fi

        add_event "$iso" "$host" "syslog" "$category" "" "" "" "" "" "$line"
        syslog_count=$((syslog_count + 1))
    done < "$SYSLOG"
fi

echo " $syslog_count events"
echo "    service: $service_count | error: $error_count | other: $syslog_other"

if [ -s "$TEMP" ]; then
    jq -s '.' "$TEMP" > "$OUTPUT_JSON"
else
    cat << 'EOF' > "$OUTPUT_JSON"
[]
EOF
fi

rm -f "$TEMP"

total=$((auth_count + audit_count + syslog_count))
start_iso=$(date -u -d "@$START_EPOCH" "+%Y-%m-%dT%H:%M:%SZ")
end_iso=$(date -u -d "@$END_EPOCH" "+%Y-%m-%dT%H:%M:%SZ")

echo "Total events: $total"
echo "Time range: $start_iso to $end_iso"
echo "Output: $OUTPUT_JSON"
