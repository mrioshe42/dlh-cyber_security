#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
DATA_FILE="$HANDOFF_DIR/data/enriched_events.json"

[ -f "$DATA_FILE" ] || { echo "Error: Dataset not found at $DATA_FILE" >&2; exit 1; }

print_help() {
    cat << 'EOF'
query_toolkit.sh <verb> [options]
  filter   emit matching records as ndjson
  top      top N values of a field
  distinct distinct values of a field
  count    number of matching records
  window   bucketed counts by time window
  help     this message

Options for filters:
  --source <type>     Filter by log source / provider
  --host <h>          Filter by hostname or host identifier
  --from <iso>        Filter events >= ISO timestamp
  --to <iso>          Filter events <= ISO timestamp
  --category <c>      Filter by event category
  --field <name>      Target field for top, distinct, or window
  --limit <n>         Number of top results to return (default: 10)
  --bucket <hour|day> Time bucket granularity for window verb
EOF
}

[ $# -eq 0 ] || [ "$1" = "help" ] || [ "$1" = "--help" ] && { print_help; exit 0; }

VERB="$1" && shift

SOURCE="" HOST="" CATEGORY="" FROM="" TO="" FIELD="" LIMIT="10" BUCKET=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source)   SOURCE="$2"; shift 2 ;;
        --host)     HOST="$2"; shift 2 ;;
        --category) CATEGORY="$2"; shift 2 ;;
        --from)     FROM="$2"; shift 2 ;;
        --to)       TO="$2"; shift 2 ;;
        --field)    FIELD="$2"; shift 2 ;;
        --limit)    LIMIT="$2"; shift 2 ;;
        --bucket)   BUCKET="$2"; shift 2 ;;
        *)          echo "Error: Unknown option $1" >&2; exit 1 ;;
    esac
done

JQ_COND="true"
[ -n "$SOURCE" ]   && JQ_COND="$JQ_COND and ((.source // .source_type // .log_source // \"\") == \"$SOURCE\")"
[ -n "$HOST" ]     && JQ_COND="$JQ_COND and ((.host // .hostname // .source_host // \"\") == \"$HOST\")"
[ -n "$CATEGORY" ] && JQ_COND="$JQ_COND and ((.category // .event_category // \"\") == \"$CATEGORY\")"
[ -n "$FROM" ]     && JQ_COND="$JQ_COND and ((.timestamp // .time // .@timestamp // \"\") >= \"$FROM\")"
[ -n "$TO" ]       && JQ_COND="$JQ_COND and ((.timestamp // .time // .@timestamp // \"\") <= \"$TO\")"

case "$VERB" in
    filter)
        jq -c ".[] | select($JQ_COND)" "$DATA_FILE"
        ;;
    count)
        jq -r "[.[] | select($JQ_COND)] | length" "$DATA_FILE"
        ;;
    distinct)
        [ -n "$FIELD" ] || { echo "Error: --field is required for 'distinct'" >&2; exit 1; }
        jq -r --arg f "$FIELD" "[.[] | select($JQ_COND) | .[$f] // empty] | unique[]" "$DATA_FILE"
        ;;
    top)
        [ -n "$FIELD" ] || { echo "Error: --field is required for 'top'" >&2; exit 1; }
        jq -r --arg f "$FIELD" --argjson lim "$LIMIT" '
            [.[] | select('"$JQ_COND"') | .[$f] // "N/A"]
            | group_by(.) | map({value: .[0], count: length})
            | sort_by(.count) | reverse | .[0:$lim] | .[]
            | "\(.count)\t\(.value)"
        ' "$DATA_FILE"
        ;;
    window)
        [[ -n "$FIELD" && -n "$BUCKET" ]] || { echo "Error: Both --field and --bucket (<hour|day>) are required for 'window'" >&2; exit 1; }
        [[ "$BUCKET" =~ ^(hour|day)$ ]] || { echo "Error: Invalid bucket type. Use 'hour' or 'day'." >&2; exit 1; }
        SUB_LEN=$([[ "$BUCKET" == "hour" ]] && echo 13 || echo 10)
        jq -r --arg f "$FIELD" --argjson sl "$SUB_LEN" '
            [.[] | select('"$JQ_COND"') | .[$f] // .timestamp // .time // ""]
            | map(select(length >= $sl) | .[0:$sl])
            | group_by(.) | map({bucket: .[0], count: length})
            | sort_by(.bucket) | .[]
            | "\(.bucket)\t\(.count)"
        ' "$DATA_FILE"
        ;;
    *)
        echo "Error: Unknown verb '$VERB'" >&2
        print_help
        exit 1
        ;;
esac
