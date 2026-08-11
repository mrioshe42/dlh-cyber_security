#!/bin/bash
# name: 0-vuln_inventory.sh
# purpose: Generates a structured vulnerability inventory JSON instantly using local feed data, CVE-related information is extracted from a local feed file, USN advisories are not fetched from the internet, and the script is designed to run without internet access.
#          ubuntu-advantage 
# author: Massimo Rios

set -euo pipefail

OUTPUT_FILE="vulnerability_inventory.json"
FEED_FILE="cve_feed.json"

if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed." >&2
    exit 1
fi

if [ ! -f "$FEED_FILE" ]; then
    echo "{}" > "$FEED_FILE"
fi

INSTALLED_PKGS=$(mktemp)
UPGRADABLE_PKGS=$(mktemp)
JSON_ENTRIES=$(mktemp)
FEED_KEYS=$(mktemp)

trap 'rm -f "$INSTALLED_PKGS" "$UPGRADABLE_PKGS" "$JSON_ENTRIES" "$FEED_KEYS"' EXIT

dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n' | grep "installed" > "$INSTALLED_PKGS"
# apt-get changelog
apt list --upgradable 2>/dev/null | tail -n +2 > "$UPGRADABLE_PKGS" || true

jq -r 'keys[]' "$FEED_FILE" > "$FEED_KEYS" 2>/dev/null || true

echo "[" > "$JSON_ENTRIES"
FIRST=1

while IFS= read -r line; do
    pkg_full=$(echo "$line" | awk '{print $1}')
    pkg_name=$(echo "$pkg_full" | cut -d'/' -f1)
    candidate_version=$(echo "$line" | awk '{print $2}')
    
    [ -z "$pkg_name" ] || [ -z "$candidate_version" ] && continue

    installed_version=$(awk -v pkg="$pkg_name" '$1 == pkg {print $2}' "$INSTALLED_PKGS")
    [ -z "$installed_version" ] && continue

    source_pocket="unknown"
    policy_output=$(apt-cache policy "$pkg_name")
    while IFS= read -r p_line; do
        if [[ "$p_line" =~ ([a-z-]+-(security|updates|backports)) ]]; then
            source_pocket="${BASH_REMATCH[1]}"
            break
        fi
    done <<< "$policy_output"

    max_cvss=0.0
    in_cisa_kev=false
    resolved_cves=()

    if grep -qFx "$pkg_name" "$FEED_KEYS"; then
        cve_entries_json=$(jq -c --arg pkg "$pkg_name" '.[$pkg].cves // []' "$FEED_FILE")
        
        while read -r cve_obj; do
            [ -z "$cve_obj" ] && continue
            cve_id=$(echo "$cve_obj" | jq -r '.cve_id')
            cvss=$(echo "$cve_obj" | jq -r '.cvss // 0.0')
            kev=$(echo "$cve_obj" | jq -r '.in_cisa_kev // false')

            if [[ ! " ${resolved_cves[*]} " =~ " ${cve_id} " ]]; then
                resolved_cves+=("$cve_id")
            fi

            if awk "BEGIN {print ($cvss > $max_cvss)}" 2>/dev/null | grep -q "1"; then
                max_cvss=$cvss
            fi
            if [ "$kev" = "true" ]; then
                in_cisa_kev=true
            fi
        done < <(echo "$cve_entries_json" | jq -c '.[]')
    fi

    cves_json="[]"
    if [ ${#resolved_cves[@]} -gt 0 ]; then
        cves_json=$(jq -nc '$ARGS.positional' --args "${resolved_cves[@]}")
    fi

    if awk "BEGIN {print ($max_cvss >= 9.0)}" 2>/dev/null | grep -q "1"; then
        severity="critical"
    elif awk "BEGIN {print ($max_cvss >= 7.0 && $max_cvss < 9.0)}" 2>/dev/null | grep -q "1"; then
        severity="high"
    elif awk "BEGIN {print ($max_cvss >= 4.0 && $max_cvss < 7.0)}" 2>/dev/null | grep -q "1"; then
        severity="medium"
    elif awk "BEGIN {print ($max_cvss > 0.0 && $max_cvss < 4.0)}" 2>/dev/null | grep -q "1"; then
        severity="low"
    else
        severity="none"
    fi

    pkg_json=$(jq -nc \
        --arg pkg "$pkg_name" \
        --arg inst "$installed_version" \
        --arg cand "$candidate_version" \
        --arg pocket "$source_pocket" \
        --argjson cves "$cves_json" \
        --argjson cvss "$max_cvss" \
        --arg sev "$severity" \
        --argjson kev "$in_cisa_kev" \
        '{
            package: $pkg,
            installed_version: $inst,
            candidate_version: $cand,
            source_pocket: $pocket,
            cves: $cves,
            max_cvss: $cvss,
            severity: $sev,
            in_cisa_kev: $kev
        }')

    if [ $FIRST -eq 0 ]; then
        echo "," >> "$JSON_ENTRIES"
    fi
    echo "$pkg_json" >> "$JSON_ENTRIES"
    FIRST=0

done < "$UPGRADABLE_PKGS"

echo "]" >> "$JSON_ENTRIES"
jq -n --argjson pkgs "$(cat "$JSON_ENTRIES")" '{packages: $pkgs}' > "$OUTPUT_FILE"

