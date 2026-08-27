#!/bin/bash
# Task 0: Evidence Pack Inventory Script
# Walks the primary evidence pack, safely handles empty files, mixed encodings,
# missing timestamps, permission restrictions, and validates final JSON output.

set -euo pipefail

PACK_ROOT="${1:-$HOME/evidence_pack_primary}"
MANIFEST_FILE="source_inventory.json"

if [ ! -d "$PACK_ROOT" ]; then
    echo "Error: Evidence pack root directory '$PACK_ROOT' does not exist." >&2
    exit 1
fi

echo "Scanning evidence pack at: $PACK_ROOT"

win_count=0
win_bytes=0
linux_count=0
linux_bytes=0
net_count=0
net_bytes=0

TEMP_MANIFEST=$(mktemp)
trap 'rm -f "$TEMP_MANIFEST"' EXIT

extract_timestamps() {
    local filepath="$1"
    local ftype="$2"
    local first_ts="null"
    local last_ts="null"

    if [ ! -s "$filepath" ]; then
        echo "null|null"
        return
    fi

    case "$ftype" in
        "windows_json"|"network_json")
            first_ts=$(jq -r '(.["@timestamp"] // .TimeCreated // .system.timestamp // .timestamp // empty) | strings' "$filepath" 2>/dev/null | head -n 1 || echo "")
            last_ts=$(jq -r '(.["@timestamp"] // .TimeCreated // .system.timestamp // .timestamp // empty) | strings' "$filepath" 2>/dev/null | tail -n 1 || echo "")
            ;;
        "linux_text")
            local first_line last_line
            first_line=$(iconv -f utf-8 -t utf-8//IGNORE "$filepath" 2>/dev/null | grep -m 1 '^[A-Z][a-z][a-z] [ 0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]' || true)
            last_line=$(iconv -f utf-8 -t utf-8//IGNORE "$filepath" 2>/dev/null | grep '^[A-Z][a-z][a-z] [ 0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]' | tail -n 1 || true)
            if [ -n "$first_line" ]; then 
                first_ts=$(echo "$first_line" | awk '{print $1, $2, $3}')
            fi
            if [ -n "$last_line" ]; then 
                last_ts=$(echo "$last_line" | awk '{print $1, $2, $3}')
            fi
            ;;
        "network_csv")
            first_ts=$(awk -F',' 'NR==2 {print $1; exit}' "$filepath" 2>/dev/null || echo "")
            last_ts=$(awk -F',' 'END {print $1}' "$filepath" 2>/dev/null || echo "")
            ;;
    esac

    [ -z "$first_ts" ] || [ "$first_ts" = "null" ] && first_ts="null"
    [ -z "$last_ts" ] || [ "$last_ts" = "null" ] && last_ts="null"

    echo "$first_ts|$last_ts"
}

get_record_count() {
    local filepath="$1"
    local ftype="$2"
    
    if [ ! -s "$filepath" ]; then
        echo 0
        return
    fi

    case "$ftype" in
        "windows_json"|"network_json"|"linux_text")
            wc -l < "$filepath" 2>/dev/null || echo 0
            ;;
        "network_csv")
            local total
            total=$(wc -l < "$filepath" 2>/dev/null || echo 0)
            echo $((total > 0 ? total - 1 : 0))
            ;;
    esac
}

for category in windows linux network; do
    target_dir="$PACK_ROOT/$category"
    if [ ! -d "$target_dir" ]; then
        continue
    fi

    while IFS= read -r -d '' file; do
        if [ ! -r "$file" ]; then
            echo "Warning: File $file is not readable. Skipping." >&2
            continue
        fi

        rel_path="${file#$PACK_ROOT/}"
        size_bytes=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo 0)
        sha256=$(sha256sum "$file" 2>/dev/null | awk '{print $1}' || echo "UNREADABLE")
        
        case "$category" in
            windows)
                source_type="windows_json"
                win_count=$((win_count + 1))
                win_bytes=$((win_bytes + size_bytes))
                ;;
            linux)
                source_type="linux_text"
                linux_count=$((linux_count + 1))
                linux_bytes=$((linux_bytes + size_bytes))
                ;;
            network)
                if [[ "$file" == *.csv ]]; then
                    source_type="network_csv"
                else
                    source_type="network_json"
                fi
                net_count=$((net_count + 1))
                net_bytes=$((net_bytes + size_bytes))
                ;;
        esac

        record_count=$(get_record_count "$file" "$source_type")
        ts_pipe=$(extract_timestamps "$file" "$source_type")
        first_time="${ts_pipe%%|*}"
        last_time="${ts_pipe##*|}"

        jq -n \
            --arg path "$rel_path" \
            --arg type "$source_type" \
            --argjson size "$size_bytes" \
            --arg sha "$sha256" \
            --argjson count "$record_count" \
            --arg first "$first_time" \
            --arg last "$last_time" \
            '{path: $path, source_type: $type, size_bytes: $size, sha256: $sha, record_count: $count, first_event_time: $first, last_event_time: $last}' >> "$TEMP_MANIFEST"

    done < <(find "$target_dir" -maxdepth 1 -type f -print0 | sort -z)
done

jq -s '.' "$TEMP_MANIFEST" > "$MANIFEST_FILE"

if ! jq empty "$MANIFEST_FILE" 2>/dev/null; then
    echo "Error: Generated manifest is not valid JSON." >&2
    exit 1
fi

total_files=$((win_count + linux_count + net_count))
total_bytes=$((win_bytes + linux_bytes + net_bytes))

win_mb=$(awk "BEGIN {print $win_bytes / 1024 / 1024}")
linux_mb=$(awk "BEGIN {print $linux_bytes / 1024 / 1024}")
net_mb=$(awk "BEGIN {print $net_bytes / 1024 / 1024}")
total_mb=$(awk "BEGIN {print $total_bytes / 1024 / 1024}")

printf "windows : %d files  |  %.1f MB\n" "$win_count" "$win_mb"
printf "linux   : %d files  |  %.1f MB\n" "$linux_count" "$linux_mb"
printf "network : %d files  |   %.1f MB\n" "$net_count" "$net_mb"
printf "total   : %d files  |  %.1f MB\n" "$total_files" "$total_mb"
echo "manifest written to $MANIFEST_FILE"
