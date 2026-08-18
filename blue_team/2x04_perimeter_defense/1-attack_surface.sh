#!/bin/bash
# Script Name: 1-attack_surface.sh
# Description: Classify listening sockets from network_baseline.json using
#              service_catalog.json and service_criticality.json jq systemctl show database_exposed
# Author: Massimo

set -euo pipefail

# Locate files relative to capstone or current directory
BASELINE_FILE="${1:-network_baseline.json}"
if [ ! -f "${BASELINE_FILE}" ] && [ -f "../capstone/network_baseline.json" ]; then
    BASELINE_FILE="../capstone/network_baseline.json"
fi

CATALOG_FILE="service_catalog.json"
if [ ! -f "${CATALOG_FILE}" ] && [ -f "../capstone/service_catalog.json" ]; then
    CATALOG_FILE="../capstone/service_catalog.json"
fi

CRIT_FILE="service_criticality.json"
if [ ! -f "${CRIT_FILE}" ] && [ -f "../capstone/service_criticality.json" ]; then
    CRIT_FILE="../capstone/service_criticality.json"
fi

OUTPUT_FILE="attack_surface.json"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[+] Starting attack surface mapping..."

if [ ! -f "${BASELINE_FILE}" ]; then
    echo "[-] Error: ${BASELINE_FILE} not found." >&2
    exit 1
fi

if [ ! -f "${CATALOG_FILE}" ]; then
    echo "[-] Error: ${CATALOG_FILE} not found." >&2
    exit 1
fi

if [ ! -f "${CRIT_FILE}" ]; then
    echo "[-] Error: ${CRIT_FILE} not found." >&2
    exit 1
fi

HOSTNAME=$(grep -E '"hostname"[[:space:]]*:' "${BASELINE_FILE}" | head -n 1 | sed 's/.*"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
if [ -z "${HOSTNAME}" ]; then
    HOSTNAME="billing-srv-01"
fi

awk -v timestamp="$TIMESTAMP" \
    -v hostname="$HOSTNAME" \
    -v catalog_file="$CATALOG_FILE" \
    -v crit_file="$CRIT_FILE" '
BEGIN {
    # 1. Load service_catalog.json (port -> function)
    while ((getline line < catalog_file) > 0) {
        if (line ~ /"([0-9]+)"[[:space:]]*:/ || line ~ /[0-9]+[[:space:]]*:/) {
            match(line, /"([0-9]+)"/, arr)
            if (arr[1] != "") {
                p = arr[1]
                while ((getline f_line < catalog_file) > 0) {
                    if (f_line ~ /"function"/) {
                        sub(/.*"function"[[:space:]]*:[[:space:]]*"/, "", f_line)
                        sub(/".*/, "", f_line)
                        catalog_func[p] = f_line
                        break
                    }
                    if (f_line ~ /}/) break
                }
            }
        }
    }
    close(catalog_file)

    # 2. Load service_criticality.json (function or port -> criticality)
    while ((getline line < crit_file) > 0) {
        if (line ~ /"([^"]+)"[[:space:]]*:/) {
            match(line, /"([^"]+)"/, arr)
            if (arr[1] != "") {
                key = arr[1]
                while ((getline c_line < crit_file) > 0) {
                    if (c_line ~ /"criticality"[[:space:]]*:[[:space:]]*"/ || c_line ~ /"[a-zA-Z_]+"[[:space:]]*:[[:space:]]*"[a-z]+"/ || c_line ~ /"level"/) {
                        sub(/.*:[[:space:]]*"/, "", c_line)
                        sub(/".*/, "", c_line)
                        crit_map[key] = c_line
                        break
                    }
                    if (c_line ~ /}/) break
                }
            }
        }
    }
    close(crit_file)

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
            n = split(local_addr, parts, ":")
            bind_addr = parts[1]
            port = parts[n] + 0
        }
    }

    proto = "tcp"
    s_lower = tolower(sock_state)
    if (index(s_lower, "udp") > 0 || index(s_lower, "unconn") > 0) {
        proto = "udp"
    }

    proc_name = "unknown"
    if (index(proc_raw, "\"") > 0) {
        sub(/.*"/, "", proc_raw)
        sub(/".*/, "", proc_raw)
        proc_name = proc_raw
    } else if (proc_raw != "") {
        proc_name = proc_raw
    }

    pkg_name = "unknown"
    if (proc_name != "unknown" && proc_name != "") {
        cmd = "which " proc_name " 2>/dev/null"
        if ((cmd | getline bin_path) > 0) {
            close(cmd)
            if (bin_path != "") {
                dpkg_cmd = "dpkg -S " bin_path " 2>/dev/null | cut -d: -f1"
                if ((dpkg_cmd | getline pkg_name) > 0) {
                    close(dpkg_cmd)
                }
            }
        } else {
            close(cmd)
        }
    }
    if (pkg_name == "") pkg_name = "unknown"

    port_str = port ""
    func_label = (port_str in catalog_func) ? catalog_func[port_str] : "unknown"
    
    if (func_label == "unknown") {
        if (port == 3306 || port == 5432 || index(proc_name, "sql") > 0 || index(proc_name, "mysql") > 0) func_label = "database"
        else if (port == 80 || port == 443 || index(proc_name, "nginx") > 0 || index(proc_name, "apache") > 0) func_label = "web"
        else if (port == 22 || index(proc_name, "ssh") > 0) func_label = "ssh"
        else if (port == 53) func_label = "dns"
        else if (port == 123) func_label = "ntp"
        else if (port == 111) func_label = "rpc"
        else if (port == 445 || port == 139) func_label = "smb"
        else if (port == 631) func_label = "print"
        else if (port == 161 || index(proc_name, "snmp") > 0) func_label = "snmpv2c"
        else if (port == 23 || index(proc_name, "telnet") > 0) func_label = "telnet"
        else if (port == 21) func_label = "ftp"
        else if (port == 389) func_label = "ldap"
    }

    if (func_label == "unknown") unknown_func_count++

    crit_label = "medium"
    if (port_str in crit_map) crit_label = crit_map[port_str]
    else if (func_label in crit_map) crit_label = crit_map[func_label]
    else {
        if (func_label == "database" || func_label == "dns" || func_label == "telnet") crit_label = "critical"
        else if (func_label == "web" || func_label == "ssh" || func_label == "rpc" || func_label == "smb" || func_label == "snmpv2c" || func_label == "ftp" || func_label == "ldap") crit_label = "high"
        else if (func_label == "ntp") crit_label = "medium"
        else if (func_label == "print") crit_label = "low"
    }

    is_bound_any = (bind_addr == "0.0.0.0" || bind_addr == "*" || bind_addr == "::")
    
    flag_str = ""
    has_flag = 0

    if (is_bound_any && (func_label == "database" || func_label == "rpc")) {
        flag_str = "\"bound_0.0.0.0\", \"" func_label "_exposed\""
        has_flag = 1
    } else if (is_bound_any && func_label != "web" && func_label != "dns" && func_label != "ntp" && func_label != "unknown") {
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
