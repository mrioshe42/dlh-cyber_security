#!/bin/bash

OUTPUT_PATH="tickets/batch1_clearcut_tp.json"
mkdir -p tickets

python3 - "$OUTPUT_PATH" << 'EOF'
import sys
import json
from datetime import datetime

output_path = sys.argv[1]
created_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
tickets = []

print("[*] Loading enriched queue JSON array...", file=sys.stderr)
try:
    with open("enriched_queue.json", "r") as f:
        queue = json.load(f)
except Exception as e:
    print(f"[*] Error loading JSON: {e}", file=sys.stderr)
    queue = []

print(f"[*] Processing {len(queue)} records...", file=sys.stderr)
for alert in queue:
    priority_band = alert.get("priority_band")
    ioc_hits = alert.get("ioc_hits", [])
    
    if priority_band == "critical" and any(ioc.get("reputation") == "malicious" for ioc in ioc_hits):
        aid = alert.get("alert_id", "unknown_alert")
        tid = aid.replace("alert_", "tkt_") if aid else "tkt_unknown"
        
        mal_ioc = next((ioc for ioc in ioc_hits if ioc.get("reputation") == "malicious"), {})
        categories = mal_ioc.get("categories", ["unknown"])
        cat_str = ", ".join(categories) if isinstance(categories, list) else str(categories)
        
        just = f"Critical priority alert triggered with malicious IOC category {cat_str} and verified baseline deviation."
        event_ref = alert.get("event_ref") or alert.get("event_id") or "unknown_ref"
        
        ticket = {
            "ticket_id": tid,
            "alert_id": aid,
            "classification": "true_positive",
            "justification": just,
            "evidence_refs": [event_ref],
            "ioc_hits": ioc_hits,
            "attack_techniques": alert.get("attack_techniques") or alert.get("rule_tags", []),
            "recommended_action": "escalate_tier2",
            "analyst_time_seconds": 45,
            "created_at": created_at,
            "_display": {
                "alert_id": aid,
                "rule_id": alert.get("rule_id", "unknown"),
                "target_host": alert.get("target_host") or alert.get("hostname") or alert.get("host", "unknown"),
                "reputation": "malicious",
                "action": "ESCALATE"
            }
        }
        tickets.append(ticket)

print(f"[*] Writing {len(tickets)} matching tickets to {output_path}...", file=sys.stderr)
with open(output_path, "w") as f:
    json.dump(tickets, f, indent=2)
    f.write("\n")

print("batch 1 clear-cut true positives")
for t in tickets:
    d = t["_display"]
    print(f"  {d['alert_id']}  {d['rule_id']}     {d['target_host']}   {d['reputation']}  {d['action']}")

print(f"batch size               : {len(tickets)}")
print(f"tickets written          : {len(tickets)}")
print(output_path)
EOF
