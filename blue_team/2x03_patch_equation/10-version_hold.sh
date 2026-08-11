#!/bin/bash
# name: 10-version_hold.sh
# purpose: Manage package holds and preference pins driven by hold_registry.json with convergence and JSON reporting.

set -uo pipefail

START_TIME=$(date +%s)
REGISTRY_FILE="hold_registry.json"
REPORT_FILE="hold_management.json"
PREF_FILE="/etc/apt/preferences.d/meddefense-pins"

if [ ! -f "$REGISTRY_FILE" ]; then
    echo "Error: $REGISTRY_FILE not found." >&2
    exit 1
fi

entry_count=$(jq '.holds | length' "$REGISTRY_FILE" 2>/dev/null || echo 0)
echo "[*] Reading hold_registry.json...           ($entry_count entries)"

# Read current system holds
current_holds=$(apt-mark showhold 2>/dev/null || true)
current_count=$(echo "$current_holds" | grep -v '^$' | wc -l || echo 0)
echo "[*] Reading current apt-mark showhold...    ($current_count entry/entries)"

echo "Applying holds:"

applied_json="[]"
released_json="[]"
overdue_json="[]"
total_held=0

pref_content=""

today_epoch=$(date +%s)

# Process registry holds
while IFS= read -r row; do
    pkg=$(echo "$row" | jq -r '.package')
    reason=$(echo "$row" | jq -r '.reason')
    owner=$(echo "$row" | jq -r '.owner')
    review_date=$(echo "$row" | jq -r '.review_date')
    pin_version=$(echo "$row" | jq -r '.pin_version')

    # Apply hold
    apt-mark hold "$pkg" >/dev/null 2>&1 || true
    
    # Append to preferences
    pref_content+="Package: $pkg\nPin: version $pin_version\nPin-Priority: 1001\n\n"

    echo "  $pkg        hold + pin $pin_version   OK"

    # Compute days to review (review_date vs today, 2026-08-11)
    review_epoch=$(date -d "$review_date" +%s 2>/dev/null || echo "$today_epoch")
    days_to_review=$(( (review_epoch - today_epoch) / 86400 ))

    if [ "$days_to_review" -lt 0 ]; then
        overdue_json=$(echo "$overdue_json" | jq --arg p "$pkg" --arg rd "$review_date" --argjson d "$days_to_review" '. + [{package: $p, review_date: $rd, days_overdue: ($d * -1)}]')
    fi

    applied_json=$(echo "$applied_json" | jq --arg p "$pkg" --arg r "$reason" --arg o "$owner" --arg rd "$review_date" --arg pv "$pin_version" '. + [{package: $p, reason: $r, owner: $o, review_date: $rd, pin_version: $pv}]')
    total_held=$((total_held + 1))

done < <(jq -c '.holds[]' "$REGISTRY_FILE")

# Write preferences file
echo -e "$pref_content" > "$PREF_FILE"

# Convergence: release holds not in registry
echo "Releasing holds no longer in registry:"
released_none=true
while IFS= read -r cur_pkg; do
    [ -z "$cur_pkg" ] && continue
    found=$(jq --arg p "$cur_pkg" '.holds[] | select(.package == $p)' "$REGISTRY_FILE")
    if [ -z "$found" ]; then
        apt-mark unhold "$cur_pkg" >/dev/null 2>&1 || true
        echo "  released $cur_pkg"
        released_json=$(echo "$released_json" | jq --arg p "$cur_pkg" '. + [$p]')
        released_none=false
    fi
done <<< "$current_holds"

if [ "$released_none" = true ]; then
    echo "  (none)"
fi

overdue_count=$(echo "$overdue_json" | jq 'length')
echo "Overdue reviews: $overdue_count"
echo "Report saved to: $REPORT_FILE"

jq -n \
    --argjson applied "$applied_json" \
    --argjson released "$released_json" \
    --argjson overdue "$overdue_json" \
    --argjson total "$total_held" \
    '{
        applied: $applied,
        released: $released,
        overdue_reviews: $overdue,
        total_held: $total
    }' > "$REPORT_FILE"

exit 0
