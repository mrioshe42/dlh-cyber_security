#!/bin/bash

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
DATA_FILE="$HANDOFF_DIR/data/enriched_events.json"

if [ ! -f "$DATA_FILE" ]; then
    echo "Error: Enriched dataset not found at $DATA_FILE" >&2
    echo "Ensure your 3x00 pipeline handoff is in place before running this script." >&2
    exit 1
fi

mkdir -p "$BASELINE_PKG"

python3 -W error - "$DATA_FILE" "$BASELINE_PKG" << 'EOF'
import sys
import json
from collections import Counter

data_file = sys.argv[1]
base_pkg = sys.argv[2]

taxonomy_rules = [
    {"source_type": "windows_security", "match": {"EventID": 4624}, "label": "login_success"},
    {"source_type": "linux_auth", "match": {"action": "accepted_password"}, "label": "login_success"},
    {"source_type": "windows_security", "match": {"EventID": 4625}, "label": "login_failure"},
    {"source_type": "linux_auth", "match": {"action": "failed_password"}, "label": "login_failure"},
    {"source_type": "windows_security", "match": {"EventID": 4634}, "label": "logout"},
    {"source_type": "linux_auth", "match": {"action": "session_close"}, "label": "logout"},
    {"source_type": "windows_security", "match": {"EventID": 4740}, "label": "account_lockout"},
    {"source_type": "windows_security", "match": {"EventID": 4672}, "label": "privilege_escalation"},
    {"source_type": "linux_audit", "match": {"syscall": "setuid"}, "label": "privilege_escalation"},

    {"source_type": "windows_security", "match": {"EventID": 4688}, "label": "process_start"},
    {"source_type": "linux_audit", "match": {"type": "EXECVE"}, "label": "process_start"},
    {"source_type": "windows_security", "match": {"EventID": 4689}, "label": "process_stop"},
    {"source_type": "linux_audit", "match": {"type": "PROCTITLE"}, "label": "process_stop"},
    {"source_type": "windows_security", "match": {"EventID": 4688, "ParentProcessName": "*"}, "label": "child_process_spawn"},

    {"source_type": "linux_audit", "match": {"type": "PATH", "permission": "read"}, "label": "file_read_sensitive"},
    {"source_type": "windows_security", "match": {"EventID": 4663, "AccessMask": "Read"}, "label": "file_read_sensitive"},
    {"source_type": "linux_audit", "match": {"type": "PATH", "permission": "write"}, "label": "file_write_sensitive"},
    {"source_type": "windows_security", "match": {"EventID": 4663, "AccessMask": "Write"}, "label": "file_write_sensitive"},
    {"source_type": "windows_security", "match": {"EventID": 4670}, "label": "file_permission_change"},
    {"source_type": "linux_audit", "match": {"type": "CWD"}, "label": "file_permission_change"},

    {"source_type": "suricata", "match": {"event_type": "flow", "direction": "outbound"}, "label": "network_connection_outbound"},
    {"source_type": "firewall", "match": {"action": "allow", "direction": "outbound"}, "label": "network_connection_outbound"},
    {"source_type": "suricata", "match": {"event_type": "flow", "direction": "inbound"}, "label": "network_connection_inbound"},
    {"source_type": "firewall", "match": {"action": "allow", "direction": "inbound"}, "label": "network_connection_inbound"},
    {"source_type": "suricata", "match": {"event_type": "alert"}, "label": "network_alert"},
    {"source_type": "suricata", "match": {"event_type": "drop"}, "label": "network_blocked"},
    {"source_type": "firewall", "match": {"action": "block"}, "label": "network_blocked"}
]

def safe_get(event, key):
    if not isinstance(event, dict):
        return None
    if key in event:
        return event[key]
    for container_key in ["event_data", "fields", "winlog", "auditd", "details"]:
        container = event.get(container_key)
        if isinstance(container, dict) and key in container:
            return container[key]
    return None

def match_event(event, rule):
    stype = rule["source_type"]
    event_source = safe_get(event, "source") or safe_get(event, "source_type") or safe_get(event, "log_source") or ""
    if stype and event_source and stype.lower() not in str(event_source).lower():
        return False
    
    for k, v in rule["match"].items():
        val = safe_get(event, k)
        if val is None:
            return False
        if str(v) != "*" and str(val).strip() != str(v).strip():
            return False
    return True

events = []
with open(data_file, 'r', encoding='utf-8') as f:
    content = f.read().strip()
    if content.startswith('['):
        try:
            events = json.loads(content)
        except json.JSONDecodeError as e:
            print(f"Error: Failed to parse JSON array: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

labeled_records = []
label_counts = Counter()
unlabeled_count = 0

for event in events:
    assigned_label = "unlabeled"
    for rule in taxonomy_rules:
        if match_event(event, rule):
            assigned_label = rule["label"]
            break
    
    event["canonical_label"] = assigned_label
    if assigned_label == "unlabeled":
        unlabeled_count += 1
    else:
        label_counts[assigned_label] += 1
        
    labeled_records.append(event)

taxonomy_output = {
    "version": "1.0",
    "description": "MedDefense SOC Canonical Event Taxonomy",
    "rules": taxonomy_rules
}

tax_path = f"{base_pkg}/event_taxonomy.json"
lbl_path = f"{base_pkg}/labeled_events.json"

with open(tax_path, 'w', encoding='utf-8') as f:
    json.dump(taxonomy_output, f, indent=2)

with open(lbl_path, 'w', encoding='utf-8') as f:
    for rec in labeled_records:
        f.write(json.dumps(rec) + "\n")

total_labeled = len(labeled_records) - unlabeled_count

print(f"taxonomy rules         : {len(taxonomy_rules)}")
print(f"records labeled        : {total_labeled}")
print(f"records unlabeled      : {unlabeled_count}")
print("canonical label distribution (top 10):")
for lbl, cnt in label_counts.most_common(10):
    print(f"  {lbl:<26} {cnt}")
print("event_taxonomy.json written")
print("labeled_events.json written")
EOF
