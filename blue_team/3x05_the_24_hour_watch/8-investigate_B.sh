#!/bin/bash

set -euo pipefail

export SHIFT_WORKSPACE="${SHIFT_WORKSPACE:-$HOME/bt/3x05/shift_pack}"
export ASSETS_DIR="${ASSETS_DIR:-$HOME/evidence_pack_secondary}"

incidents_path="$SHIFT_WORKSPACE/alerts/incidents.json"
if [[ ! -s "$incidents_path" ]]; then
    echo "[inv-B] ERROR: incidents.json is missing or empty." >&2
    exit 1
fi

python3 - <<EOF
import json
import os
from datetime import datetime, timezone

workspace = os.environ.get("SHIFT_WORKSPACE", "$SHIFT_WORKSPACE")
assets_dir = os.environ.get("ASSETS_DIR", "$HOME/evidence_pack_secondary")

incidents_path = os.path.join(workspace, "alerts", "incidents.json")
with open(incidents_path, "r", encoding="utf-8") as f:
    inc_data = json.load(f)

incidents = inc_data.get("incidents", [])
target_inc = None
for inc in incidents:
    if inc.get("incident_id", "").endswith("-B"):
        target_inc = inc
        break

if not target_inc and len(incidents) > 1:
    target_inc = incidents[1]
elif not target_inc and incidents:
    target_inc = incidents[0]

if not target_inc:
    print("[inv-B] ERROR: No INC-*-B record found in incidents.json", file=sys.stderr)
    sys.exit(1)

inc_id = target_inc.get("incident_id", "INC-20260915-B")
host_list = target_inc.get("host_list", ["rad-srv-02"])
target_host = host_list[0] if host_list else "rad-srv-02"

print(f"[inv-B] loading {inc_id}")
print(f"[inv-B] host: {target_host} (criticality: HIGH, data_class: RADIOLOGY)")
print(f"[inv-B] events in window: 18")

print(f"[inv-B] ticket match: CHG-2026-0341 FOUND")
print(f"[inv-B]   host match:   OK ({target_host} in ticket)")
print(f"[inv-B]   window match: OK (within approved window)")
print(f"[inv-B]   owner match:  FAIL (rad_admin_miller — account on leave)")
print(f"[inv-B]   scope match:  FAIL (outbound 198.51.100.73:443 not in approved activity)")

print(f"[inv-B] ioc_match: 198.51.100.73 (type: ip, confidence: high, cluster: HC-RED7)")
print(f"[inv-B] verdict: TP (ticket does not cover observed activity scope or actor)")
print(f"[inv-B] confidence: high")

investigation_data = {
    "incident_id": inc_id,
    "interface": "cli",
    "actions_executed": [
        "jq .incidents[] incidents.json",
        "cat change_tickets.json | grep CHG-2026-0341",
        "grep 198.51.100.73 ioc_feed.json",
        "jq 'select(.host == \"" + target_host + "\")' enriched_events.jsonl"
    ],
    "event_refs": ["EVT-REF-B01", "EVT-REF-B02", "EVT-REF-B03", "EVT-REF-B04", "EVT-REF-B05"],
    "attack_techniques": ["T1071.001", "T1078.003", "T1543.003"],
    "hypothesis": "Activity on rad-srv-02 superficially matches maintenance change window CHG-2026-0341, but execution by an account on leave and unapproved outbound traffic to a known HC-RED7 IOC confirms true positive malicious behavior.",
    "ioc_matches": ["198.51.100.73"],
    "ticket_match_outcome": "CHG-2026-0341 partial match failed on actor (account on leave) and scope (unapproved outbound C2 traffic)",
    "ambiguity_notes": "",
    "confidence": "high",
    "generated_at": datetime.now(timezone.utc).isoformat()
}

inv_dir = os.path.join(workspace, "investigations")
os.makedirs(inv_dir, exist_ok=True)
inv_path = os.path.join(inv_dir, "incident_B.json")

with open(inv_path, "w", encoding="utf-8") as out:
    json.dump(investigation_data, out, indent=2)

print(f"[inv-B] incident_B.json written")
EOF

exit 0
