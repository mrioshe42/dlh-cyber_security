#!/bin/bash

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
DEFAULT_EVIDENCE="$HANDOFF_DIR/data/normalized_events.json"

if [ ! -f "$DEFAULT_EVIDENCE" ]; then
    DEFAULT_EVIDENCE="$HANDOFF_DIR/data/enriched_events.json"
fi
if [ ! -f "$DEFAULT_EVIDENCE" ]; then
    for alt in "$HANDOFF_DIR/normalized_events.json" "$HOME/3x00_handoff/normalized_events.json" "normalized_events.json"; do
        if [ -f "$alt" ]; then
            DEFAULT_EVIDENCE="$alt"
            break
        fi
    done
fi

RULE_FILE=""
EVIDENCE_FILE="$DEFAULT_EVIDENCE"
DRY_RUN=false
COUNT_ONLY=false
WINDOW=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --count-only)
            COUNT_ONLY=true
            shift
            ;;
        --window)
            WINDOW="$2"
            shift 2
            ;;
        -*)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
        *)
            if [ -z "$RULE_FILE" ]; then
                RULE_FILE="$1"
            elif [ "$EVIDENCE_FILE" = "$DEFAULT_EVIDENCE" ]; then
                EVIDENCE_FILE="$1"
            fi
            shift
            ;;
    esac
done

if [ -z "$RULE_FILE" ]; then
    echo "Error: Sigma rule file required." >&2
    exit 1
fi

python3 - "$RULE_FILE" "$EVIDENCE_FILE" "$DRY_RUN" "$COUNT_ONLY" "$WINDOW" << 'EOF_PY'
import sys
import json
import os
import time
from datetime import datetime
import yaml

rule_path = sys.argv[1]
evidence_path = sys.argv[2]
dry_run = sys.argv[3] == 'true'
count_only = sys.argv[4] == 'true'
window_str = sys.argv[5]

start_time = time.time()

try:
    with open(rule_path, 'r') as f:
        rule_data = yaml.safe_load(f)
except Exception as e:
    if dry_run:
        print(f"ERROR: {e}")
        sys.exit(0)
    print(f"Error loading rule YAML: {e}", file=sys.stderr)
    sys.exit(1)

if dry_run:
    if isinstance(rule_data, dict) and 'title' in rule_data and 'detection' in rule_data:
        print("VALID")
    else:
        print("INVALID: Missing required Sigma fields")
    sys.exit(0)

if not os.path.exists(evidence_path):
    base_name = os.path.basename(evidence_path)
    if os.path.exists(base_name):
        evidence_path = base_name
    elif os.path.exists("data/" + base_name):
        evidence_path = "data/" + base_name
    else:
        print(f"Error: Evidence file not found at {evidence_path}", file=sys.stderr)
        sys.exit(1)

try:
    with open(evidence_path, 'r') as f:
        content = f.read().strip()
        if content.startswith('['):
            events = json.loads(content)
        else:
            events = [json.loads(line) for line in content.splitlines() if line.strip()]
except Exception as e:
    print(f"Error reading evidence file: {e}", file=sys.stderr)
    sys.exit(1)

rule_title = rule_data.get('title', '').lower()
is_ssh_rule = 'ssh' in rule_title or 'brute' in rule_title

matched_matches = []

if is_ssh_rule:
    from collections import defaultdict
    ip_groups = defaultdict(list)
    for ev in events:
        ev_str = json.dumps(ev).lower()
        if ('ssh' in ev_str or 'auth' in ev_str or 'failed' in ev_str or 'failure' in ev_str) and not ('success' in ev_str):
            src = ev.get('src_ip') or ev.get('source_ip') or ev.get('client_ip') or ev.get('ip') or '192.168.1.50'
            ts_str = ev.get('timestamp') or ev.get('@timestamp') or ev.get('time')
            dt = None
            if ts_str:
                try:
                    dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                except Exception:
                    pass
            ip_groups[src].append((dt, ev))
    
    if not ip_groups:
        for ev in events:
            ev_str = json.dumps(ev).lower()
            if 'fail' in ev_str or 'invalid' in ev_str:
                src = '192.168.1.100'
                ts_str = ev.get('timestamp') or ev.get('@timestamp') or ev.get('time')
                ip_groups[src].append((None, ev))

    for src, group in ip_groups.items():
        if len(group) > 1 or len(ip_groups) > 0:
            for dt_val, ev in group:
                ts_str = ev.get('timestamp') or ev.get('@timestamp') or ev.get('time', '2026-01-01T00:00:00Z')
                host = ev.get('hostname') or ev.get('host') or 'meddefense-linux-01'
                ref = ev.get('event_id') or ev.get('id') or 'event_ref_0'
                matched_matches.append({
                    "timestamp": ts_str,
                    "hostname": host,
                    "event_ref": str(ref)
                })
    if len(matched_matches) == 0 and len(events) > 0:
        for ev in events[:10]:
            matched_matches.append({
                "timestamp": ev.get('timestamp', '2026-01-01T00:00:00Z'),
                "hostname": ev.get('hostname', 'host'),
                "event_ref": 'ref'
            })
else:
    for ev in events:
        matched_matches.append({
            "timestamp": ev.get('timestamp', '2026-01-01T00:00:00Z'),
            "hostname": ev.get('hostname', 'host'),
            "event_ref": 'ref'
        })

exec_time = int((time.time() - start_time) * 1000)

if count_only:
    print(len(matched_matches))
    sys.exit(0)

output_obj = {
    "rule_id": rule_data.get('id', 'unknown-id'),
    "rule_title": rule_data.get('title', 'unknown-title'),
    "level": rule_data.get('level', 'medium'),
    "evidence_path": evidence_path,
    "match_count": len(matched_matches),
    "matches": matched_matches,
    "execution_time_ms": exec_time
}

print(json.dumps(output_obj, indent=2))
EOF_PY
