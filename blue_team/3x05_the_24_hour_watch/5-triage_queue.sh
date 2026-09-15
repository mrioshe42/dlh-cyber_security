#!/bin/bash

set -euo pipefail

export SHIFT_WORKSPACE="${SHIFT_WORKSPACE:-$HOME/bt/3x05/shift_pack}"
export TRIAGE_BIN="${TRIAGE_BIN:-$HOME/bt/3x03/triage/triage.sh}"
export ASSETS_DIR="${ASSETS_DIR:-$HOME/evidence_pack_secondary}"

alert_queue_path="$SHIFT_WORKSPACE/alerts/alert_queue.json"
shift_briefing_path="$SHIFT_WORKSPACE/alerts/shift_briefing.json"

if [[ ! -s "$alert_queue_path" ]] || [[ ! -s "$shift_briefing_path" ]]; then
    echo "[triage] ERROR: alert_queue.json or shift_briefing.json is missing or empty." >&2
    exit 1
fi

alert_count=$(python3 -c "import json; print(len(json.load(open('$alert_queue_path', encoding='utf-8'))))")
echo "[triage] alert_queue: $alert_count alerts"

python3 - <<EOF
import json
with open("$shift_briefing_path", "r", encoding="utf-8") as f:
    b = json.load(f)
print(f"[triage] briefing loaded ({b.get('ioc_count', 0)} IOCs, {len(b.get('active_change_tickets', []))} change tickets)")
EOF

echo "[triage] invoking $TRIAGE_BIN"
if [[ -x "$TRIAGE_BIN" ]]; then
    "$TRIAGE_BIN" "$alert_queue_path" "$shift_briefing_path" "$SHIFT_WORKSPACE/enriched/baseline.json" "$ASSETS_DIR" || true
else
    echo "[triage] Note: $TRIAGE_BIN wrapper not executable or missing, proceeding with classification logic."
fi

echo "[triage] classifying $alert_count alerts"

python3 - <<EOF
import json
import os
import sys
from datetime import datetime, timezone

workspace = os.environ.get("SHIFT_WORKSPACE", "$HOME/bt/3x05/shift_pack")
queue_path = os.path.join(workspace, "alerts", "alert_queue.json")
briefing_path = os.path.join(workspace, "alerts", "shift_briefing.json")
log_path = os.path.join(workspace, "alerts", "triage_log.jsonl")

with open(queue_path, "r", encoding="utf-8") as f:
    alerts = json.load(f)

with open(briefing_path, "r", encoding="utf-8") as f:
    briefing = json.load(f)

ioc_values = set(briefing.get("ioc_values", []))
hot_hosts = set(briefing.get("baseline_hot_hosts", []))
tickets = briefing.get("active_change_tickets", [])

tp_count = 0
fp_count = 0
noise_count = 0
unclassified = 0

triage_records = []

for alert in alerts:
    alert_id = alert.get("alert_id", "ALT-UNKNOWN")
    rule_id = alert.get("rule_id", alert.get("rule", "unknown_rule"))
    host = str(alert.get("host", "unknown-host")).lower()
    user = alert.get("user") or alert.get("username") or None
    severity = alert.get("severity", "medium").lower()
    
    matched_ioc = []
    alert_str = json.dumps(alert)
    for ioc in ioc_values:
        if ioc in alert_str:
            matched_ioc.append(ioc)
            
    baseline_dev = (host in hot_hosts) or (len(matched_ioc) > 0)
    
    change_match = None
    for t in tickets:
        t_hosts = [h.lower() for h in t.get("hosts", [])]
        if host in t_hosts or not t_hosts:
            change_match = t.get("ticket_id")
            break
            
    if matched_ioc or severity == "critical" or not change_match:
        if severity == "low" and not matched_ioc:
            classification = "NOISE"
            noise_count += 1
            note = "Low severity alert with no IOC matches or critical deviations."
        elif change_match and not matched_ioc:
            classification = "FP"
            fp_count += 1
            note = f"Covered by active change ticket {change_match}."
        else:
            classification = "TP"
            tp_count += 1
            note = "Confirmed deviation or IOC match aligning with campaign indicator."
    else:
        classification = "FP"
        fp_count += 1
        note = "Covered by approved maintenance window."

    record = {
        "alert_id": alert_id,
        "rule_id": rule_id,
        "host": host,
        "user": user,
        "classification": classification,
        "severity": severity,
        "matches_ioc": matched_ioc,
        "baseline_deviation": baseline_dev,
        "change_ticket_match": change_match,
        "analyst_note": note[:200],
        "classified_at": datetime.now(timezone.utc).isoformat()
    }
    triage_records.append(record)

for rec in triage_records:
    if rec["classification"] not in ["TP", "FP", "NOISE"]:
        unclassified += 1

if unclassified > 0 or len(triage_records) != len(alerts):
    print(f"[triage] ERROR: Validation failed. Unclassified count: {unclassified}", file=sys.stderr)
    sys.exit(1)

with open(log_path, "w", encoding="utf-8") as out:
    for rec in triage_records:
        out.write(json.dumps(rec) + "\n")

print(f"[triage] TP={tp_count} FP={fp_count} NOISE={noise_count} unclassified={unclassified}")
EOF
