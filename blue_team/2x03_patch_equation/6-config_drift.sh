#!/bin/bash
# name: 6-config_drift.sh
# purpose: Fast detection of configuration drift post-patching.

set -uo pipefail

PRE_STATE="pre_patch_state.json"
PATCH_LOG="patch_execution_log.json"
REPORT_FILE="config_drift.json"

TMP_HASHES="/tmp/check_hashes_$$.txt"
TMP_RESULTS="/tmp/hash_results_$$.txt"
TMP_JSON="/tmp/drift_entries_$$.ndjson"


cleanup() { rm -f "$TMP_HASHES" "$TMP_RESULTS" "$TMP_JSON"; }
trap cleanup EXIT
> "$TMP_JSON"

echo "[*] Loading baseline configuration file hashes..."

# Extract paths and hashes into standard sha256sum format: "hash  /path/to/file"
jq -r '
  .conffile_hashes // .conffiles // .config_hashes // {} |
  if type == "object" then
    to_entries[] | "\(.value | if type == "object" then (.hash // .sha256 // .value) else . end)  \(.key)"
  elif type == "array" then
    .[] | "\(.hash // .sha256)  \(.path // .file // .filepath)"
  else empty end
' "$PRE_STATE" 2>/dev/null > "$TMP_HASHES"

total_tracked=$(wc -l < "$TMP_HASHES")
if [ "$total_tracked" -eq 0 ]; then
    echo "[!] No tracked configuration files found in baseline."
fi

# Extract upgraded packages list for cross-referencing
upgraded_pkgs=$(jq -r '.. | objects | select(.name? or .package? or .upgraded?) | (.name // .package // .upgraded)' "$PATCH_LOG" 2>/dev/null | sort -u || true)

echo "[*] Bulk verifying $total_tracked files..."

# Bulk check using native sha256sum
sha256sum -c "$TMP_HASHES" > "$TMP_RESULTS" 2>/dev/null || true

unchanged_count=$(grep -c ": OK$" "$TMP_RESULTS" || true)
modified_count=0
missing_count=0
expected_drift_count=0
unexpected_drift_count=0

grep ": OK$" "$TMP_RESULTS" | sed 's/: OK$//' | jq -R -c '{path: ., classification: "unchanged", expected: true}' >> "$TMP_JSON"

while IFS= read -r line; do
    if [[ "$line" == *": FAILED open or read" ]]; then
        filepath="${line%: FAILED open or read}"
        classification="missing"
        missing_count=$((missing_count + 1))
    elif [[ "$line" == *": FAILED" ]]; then
        filepath="${line%: FAILED}"
        # Check if file actually exists on disk; if not, it's missing rather than modified
        if [ ! -f "$filepath" ]; then
            classification="missing"
            missing_count=$((missing_count + 1))
        else
            classification="modified"
            modified_count=$((modified_count + 1))
        fi
    else
        continue
    fi

    # Lookup owning package
    if command -v dpkg-query >/dev/null 2>&1; then
        owning_pkg=$(dpkg-query -S "$filepath" 2>/dev/null | cut -d: -f1 | head -n1 || echo "unknown")
    elif command -v rpm >/dev/null 2>&1; then
        owning_pkg=$(rpm -qf "$filepath" 2>/dev/null | head -n1 || echo "unknown")
    else
        owning_pkg="unknown"
    fi

    # Classify expected vs unexpected
    expected=false
    if [ "$owning_pkg" != "unknown" ] && echo "$upgraded_pkgs" | grep -qx "$owning_pkg"; then
        expected=true
        expected_drift_count=$((expected_drift_count + 1))
    else
        unexpected_drift_count=$((unexpected_drift_count + 1))
    fi

    # Capture Unified Diff for modifications
    diff_output=""
    if [ "$classification" == "modified" ]; then
        backup_file=""
        for candidate in "${filepath}.dpkg-old" "${filepath}.dpkg-dist" "${filepath}.ucf-old" "${filepath}.rpmsave" "${filepath}.bak"; do
            if [ -f "$candidate" ]; then backup_file="$candidate"; break; fi
        done
        if [ -n "$backup_file" ]; then
            diff_output=$(diff -u "$backup_file" "$filepath" 2>/dev/null | head -n 40 || true)
        fi
    fi

    # Write drift entry
    jq -n -c \
        --arg path "$filepath" \
        --arg owning_package "$owning_pkg" \
        --arg classification "$classification" \
        --arg diff "$diff_output" \
        --argjson expected "$expected" \
        '{path: $path, owning_package: $owning_package, classification: $classification, expected: $expected, diff: $diff}' >> "$TMP_JSON"

done < <(grep -v ": OK$" "$TMP_RESULTS" || true)

jq \
    --argjson total "$total_tracked" \
    --argjson unchanged "$unchanged_count" \
    --argjson modified "$modified_count" \
    --argjson missing "$missing_count" \
    --argjson expected_drift "$expected_drift_count" \
    --argjson unexpected_drift "$unexpected_drift_count" \
    '{
        summary: {
            total_tracked: $total, unchanged: $unchanged, modified: $modified,
            missing: $missing, expected_drift: $expected_drift, unexpected_drift: $unexpected_drift
        },
        files: .
    }' <(jq -s '.' "$TMP_JSON") > "$REPORT_FILE"

echo "[*] Configuration drift check complete."
echo "    Total Tracked:    $total_tracked"
echo "    Unchanged:        $unchanged_count"
echo "    Modified:         $modified_count"
echo "    Missing:          $missing_count"
echo "    Unexpected Drift: $unexpected_drift_count"

if [ "$unexpected_drift_count" -gt 0 ]; then
    echo "VERDICT: FAIL (Unexpected configuration drift detected)" >&2
    exit 1
else
    echo "VERDICT: PASS (No unexpected configuration drift)"
    exit 0
fi
