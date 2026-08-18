#!/bin/bash
# Script Name: 1-attack_surface.sh
# Description: Pure Bash & awk implementation to classify listening sockets
#              from network_baseline.json against service catalogs and rules.
# Author: Massimo

set -euo pipefail

BASELINE_FILE="network_baseline.json"
OUTPUT_FILE="attack_surface.json"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[+] Starting attack surface classification from ${BASELINE_FILE} using pure Bash/awk..."

if [ ! -f "${BASELINE_FILE}" ]; then
    echo "[-] Error: Baseline file ${BASELINE_FILE} not found. Run T0 first." >&2
    exit 1
fi

HOSTNAME=$(grep -o '"hostname"[[:space:]]*:[[:space:]]*"[^"]*"' "${BASELINE_FILE}" | head -n 1 | sed 's/.*"\(["^"]*\)"/\1/')
if [ -z "${HOSTNAME}" ]; then
    HOSTNAME="billing-srv-01"
fi

awk -v timestamp="$TIMESTAMP" -v hostname="$HOSTNAME" '
BEGIN {
    print "{"
    print "  \"generated_at\": \"" timestamp "\","
    print "  \"hostname\": \"" hostname "\","
    print "  \"sockets\": ["
    socket_count = 0
    crit_count = 0
    high_count = 0
    med_count = 0
    low_count = 0
    unknown_func_count = 0
}

/"local_address"/ {
    loc_line = $0
    sub(/.*"local_address"[[:space:]]*:[[:space:]]*"/, "", loc_line)
    sub(/".*/, "", loc_line)
    local_addr = loc_line
}

/"state"/ {
    state_line = $0
    sub(/.*"state"[[:space:]]*:[[:space:]]*"/, "", state_line)
    sub(/".*/, "", state_line)
    sock_state = state_line
}

/"process"/ {
    proc_line = $0
    sub(/.*"process"[[:space:]]*:[[:space:]]*"/, "", proc_line)
    sub(/".*/, "", proc_line)
    proc_raw = proc_line
    
    bind_addr = "unknown"
    port = 0
    if (index(local_addr, ":") > 0) {
        if (substr(local_addr, 1, 1) == "[") {
            end_bracket = index(local_addr, "]")
            bind_addr = substr(local_addr, 2, end_bracket - 2)
            port = substr(local_addr, end_bracket + 2) + 0
        } else {
            split(local_addr, parts, ":")
            bind_addr = parts[1]
            port = parts[2] + 0
        }
    }

    proto = "tcp"
    s_lower = tolower(sock_state)
    if (index(s_lower, "udp") > 0 || index(s_lower, "unconn") > 0) {
        proto = "udp"
    }

    proc_name = "unknown"
    if (index(proc_raw, "\"") > 0) {
        n1 = index(proc_raw, "\"")
        sub_str = substr(proc_raw, n1 + 1)
        n2 = index(sub_str, "\"")
        if (n2 > 0) {
            proc_name = substr(sub_str, 1, n2 - 1)
        }
    } else if (proc_raw != "") {
        proc_name = proc_raw
    }

    # Resolve package via dpkg -S if binary path exists
    pkg_name = "unknown"
    bin_path = ""
    if (proc_name != "unknown" && proc_name != "") {
        # Check standard paths
        cmd = "which " proc_name " 2>/dev/null"
        cmd | getline bin_path
        close(cmd)
        if (bin_path != "") {
            dpkg_cmd = "dpkg -S " bin_path " 2>/dev/null | cut -d: -f1"
            dpkg_cmd | getline pkg_name
            close(dpkg_cmd)
        }
    }
    if (pkg_name == "") pkg_name = "unknown"

    func_label = "unknown"
    if (port == 3306 || port == 5432) func_label = "database"
    else if (port == 80 || port == 443) func_label = "web"
    else if (port == 22) func_label = "ssh"
    else if (port == 53) func_label = "dns"
    else if (port == 123) func_label = "ntp"
    else if (port == 111) func_label = "rpc"
    else if (port == 445 || port == 139) func_label = "smb"
    else if (port == 631) func_label = "print"
    else if (port == 161) func_label = "snmpv2c"
    else if (port == 23) func_label = "telnet"
    else if (port == 21) func_label = "ftp"
    else if (port == 389) func_label = "ldap"
    else if (index(proc_name, "sql") > 0 || index(proc_name, "mysql") > 0) func_label = "database"
    else if (index(proc_name, "ssh") > 0) func_label = "ssh"
    else if (index(proc_name, "snmp") > 0) func_label = "snmpv2c"
    else if (index(proc_name, "telnet") > 0) func_label = "telnet"

    if (func_label == "unknown") unknown_func_count++

    crit_label = "medium"
    if (func_label == "database" || func_label == "dns" || func_label == "telnet") crit_label = "critical"
    else if (func_label == "web" || func_label == "ssh" || func_label == "rpc" || func_label == "smb" || func_label == "snmpv2c" || func_label == "ftp" || func_label == "ldap") crit_label = "high"
    else if (func_label == "ntp") crit_label = "medium"
    else if (func_label == "print") crit_label = "low"

    is_bound_any = (bind_addr == "0.0.0.0" || bind_addr == "*" || bind_addr == "::")
    
    flag_str = ""
    has_flag = 0
    if (is_bound_any && (func_label == "database" || func_label == "rpc" || func_label == "smb")) {
        flag_str = "\"bound_0.0.0.0\", \"" func_label "_exposed\""
        has_flag = 1
    } else if (is_bound_any && func_label != "web" && func_label != "dns" && func_label != "ntp") {
        flag_str = "\"bound_0.0.0.0\""
        has_flag = 1
    }

    if (func_label == "telnet" || func_label == "ftp" || func_label == "snmpv1" || func_label == "snmpv2c" || func_label == "rlogin" || func_label == "nfs") {
        if (flag_str != "") flag_str = flag_str ", "
        flag_str = flag_str "\"insecure_protocol_" func_label "\""
        has_flag = 1
    }

    if (has_flag) {
        if (crit_label == "critical") crit_count++
        else if (crit_label == "high") high_count++
        else if (crit_label == "medium") med_count++
        else if (crit_label == "low") low_count++
    }

    if (socket_count > 0) print ","
    print "    {"
    print "      \"proto\": \"" proto "\","
    print "      \"port\": " port ","
    print "      \"bind_addr\": \"" bind_addr "\","
    print "      \"process\": \"" proc_name "\","
    print "      \"package\": \"" pkg_name "\","
    print "      \"function\": \"" func_label "\","
    print "      \"criticality\": \"" crit_label "\","
    print "      \"exposure_flags\": [" (has_flag ? flag_str : "") "]"
    print "    }"
    socket_count++
}

END {
    print "  ],"
    print "  \"summary\": {"
    print "    \"total_sockets\": " socket_count ","
    print "    \"flagged_counts\": {"
    print "      \"critical\": " crit_count ","
    print "      \"high\": " high_count ","
    print "      \"medium\": " med_count ","
    print "      \"low\": " low_count ","
    print "      \"unknown_functions\": " unknown_func_count
    print "    }"
    print "  }"
    print "}"
}
' "${BASELINE_FILE}" > "${OUTPUT_FILE}"

echo "[+] Attack surface report successfully generated at ${OUTPUT_FILE}."
