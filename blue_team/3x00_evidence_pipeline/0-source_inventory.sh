#!/bin/bash
# Task 0: Evidence Pack Inventory Script

set -euo pipefail

PACK_ROOT="${1:-$HOME/evidence_pack_primary}"
MANIFEST_FILE="source_inventory.json"

if [ ! -d "$PACK_ROOT" ]; then
    echo "Error: Evidence pack root directory '$PACK_ROOT' does not exist." >&2
    exit 1
fi

echo "Scanning evidence pack at: $PACK_ROOT"

win_count=0; win_bytes=0
linux_count=0; linux_bytes=0
net_count=0; net_bytes=0

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
        "windows_json")
            first_ts=$(jq -r '(.["timestamp_raw"]? // .["@timestamp"]? // .TimeCreated? // .system?.timestamp? // .timestamp?) | select(type == "string")' "$filepath" 2>/dev/null | head -n 1 || true)
            last_ts=$(jq -r '(.["timestamp_raw"]? // .["@timestamp"]? // .TimeCreated? // .system?.timestamp? // .timestamp?) | select(type == "string")' "$filepath" 2>/dev/null | tail -n 1 || true)
            ;;
        "network_json")
            first_ts=$(jq -r '(.["start_time"]? // .["timestamp"]? // .["@timestamp"]?) | select(type == "string")' "$filepath" 2>/dev/null | head -n 1 || true)
            last_ts=$(jq -r '(.["end_time"]? // .["timestamp"]? // .["@timestamp"]?) | select(type == "string")' "$filepath" 2>/dev/null | tail -n 1 || true)
            ;;
        "linux_text")
            if grep -q "audit(" "$filepath" 2>/dev/null; then
                first_ts=$(grep -oE 'audit\([0-9]+\.[0-9]+' "$filepath" 2>/dev/null | head -n 1 | tr -d 'audit(' || true)
                last_ts=$(grep -oE 'audit\([0-9]+\.[0-9]+' "$filepath" 2>/dev/null | tail -n 1 | tr -d 'audit(' || true)
            else
                local regex='^[A-Z][a-z]{2} [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2}'
                first_ts=$(grep -E -m 1 "$regex" "$filepath" 2>/dev/null | awk '{print $1, $2, $3}' || true)
                last_ts=$(grep -E "$regex" "$filepath" 2>/dev/null | tail -n 1 | awk '{print $1, $2, $3}' || true)
            fi
            ;;
        "network_csv")
            first_ts=$(awk -F',' 'NR==2 {print $1; exit}' "$filepath" 2>/dev/null || true)
            last_ts=$(awk -F',' 'END {if (NR>1) print $1}' "$filepath" 2>/dev/null || true)
            ;;
    esac

    [ -z "$first_ts" ] && first_ts="null"
    [ -z "$last_ts" ] && last_ts="null"

    echo "$first_ts|$last_ts"
}

get_record_count() {
    local filepath="$1"
    local ftype="$2"
    local count=0
    
    if [ ! -s "$filepath" ]; then
        echo 0
        return
    fi

    case "$ftype" in
        "windows_json"|"network_json")
            count=$(jq -r 'select(type == "object") | 1' "$filepath" 2>/dev/null | grep -c '^' || true)
            ;;
        "network_csv")
            local lines
            lines=$(grep -v '^[[:space:]]*$' "$filepath" 2>/dev/null | grep -c '^' || true)
            count=$((lines > 0 ? lines - 1 : 0))
            ;;
        "linux_text")
            if grep -q "audit(" "$filepath" 2>/dev/null; then
                count=$(grep -c "audit(" "$filepath" 2>/dev/null || true)
            else
                count=$(grep -E -c '^[A-Z][a-z]{2} [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2}' "$filepath" 2>/dev/null || true)
            fi
            ;;
    esac
    
    count="${count//[!0-9]/}"
    echo "${count:-0}"
}

for category in windows linux network; do
    target_dir="$PACK_ROOT/$category"
    if [ ! -d "$target_dir" ]; then
        continue
    fi

    while IFS= read -r -d '' file; do
        [ -f "$file" ] || continue
        [ -r "$file" ] || continue

        rel_path="${file#$PACK_ROOT/}"
        
        size_bytes=$(wc -c < "$file" 2>/dev/null || true)
        size_bytes="${size_bytes//[!0-9]/}"
        size_bytes="${size_bytes:-0}"
        
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
            '{
                path: $path, 
                source_type: $type, 
                size_bytes: $size, 
                sha256: $sha, 
                record_count: $count, 
                first_event_time: (if $first == "null" then null else $first end), 
                last_event_time: (if $last == "null" then null else $last end)
            }' >> "$TEMP_MANIFEST"

    done < <(find "$target_dir" -type f -print0 | sort -z)
done

if [ ! -s "$TEMP_MANIFEST" ]; then
    echo "Error: Evidence pack is empty or missing required source paths." >&2
    exit 1
fi

jq -s '.' "$TEMP_MANIFEST" > "$MANIFEST_FILE"

if ! jq empty "$MANIFEST_FILE" 2>/dev/null; then
    echo "Error: Manifest contains invalid JSON syntax." >&2
    exit 1
fi

manifest_length=$(jq length "$MANIFEST_FILE")
if [ "$manifest_length" -eq 0 ]; then
    echo "Error: Manifest array is empty. Required inventory content missing." >&2
    exit 1
fi

invalid_count=$(jq '[.[] | select(.record_count <= 0 or .first_event_time == null or .last_event_time == null)] | length' "$MANIFEST_FILE")
if [ "$invalid_count" -gt 0 ]; then
    echo "Error: Integrity check failed. Found $invalid_count manifest entries with zero records or null timestamps." >&2
    exit 1
fi

total_files=$((win_count + linux_count + net_count))
total_bytes=$((win_bytes + linux_bytes + net_bytes))

win_mb=$(awk "BEGIN {print $win_bytes / 1024 / 1024}")
linux_mb=$(awk "BEGIN {print $linux_bytes / 1024 / 1024}")
net_mb=$(awk "BEGIN {print $net_bytes / 1024 / 1024}")
total_mb=$(awk "BEGIN {print $total_bytes / 1024 / 1024}")

printf "windows : %d files  | %5.1f MB\n" "$win_count" "$win_mb"
printf "linux   : %d files  | %5.1f MB\n" "$linux_count" "$linux_mb"
printf "network : %d files  | %5.1f MB\n" "$net_count" "$net_mb"
printf "total   : %d files  | %5.1f MB\n" "$total_files" "$total_mb"
echo "manifest written to $MANIFEST_FILE"
