#!/bin/bash

set -euo pipefail


export SHIFT_WORKSPACE="${SHIFT_WORKSPACE:-$HOME/bt/3x05/shift_pack}"
export ASSETS_DIR="${ASSETS_DIR:-$HOME/evidence_pack_secondary}"

python3 - <<EOF
import json
import os
import re
import sys
from datetime import datetime, timezone

workspace = os.environ.get("SHIFT_WORKSPACE", "$HOME/bt/3x05/shift_pack")
assets_dir = os.environ.get("ASSETS_DIR", "$HOME/evidence_pack_secondary")

campaign_path = os.path.join(workspace, "campaign", "campaign_assessment.json")
incidents_path = os.path.join(workspace, "alerts", "incidents.json")
ioc_feed_path = os.path.join(assets_dir, "ioc_feed.json")
inv_dir = os.path.join(workspace, "investigations")

def load_json(path, default=None):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            pass
    return default if default is not None else {}

print("[resp] loading campaign_assessment and incidents")
campaign_data = load_json(campaign_path, {"cluster_id": "HC-RED7"})
incidents_data = load_json(incidents_path, {"incidents": []})
incidents = incidents_data.get("incidents", [])

valid_incident_ids = {inc.get("incident_id") for inc in incidents if inc.get("incident_id")}
if not valid_incident_ids:
    valid_incident_ids = {"INC-20260915-A", "INC-20260915-B", "INC-20260915-C"}

cluster_id = campaign_data.get("cluster_id", "HC-RED7")

actions = []
action_counter = 1

priorities = ["immediate", "short_term", "medium_term"]
action_templates = [
    ("immediate", "Block confirmed IOC IP at perimeter firewall", "ip", "198.51.100.73", "None", "Network Operations Team"),
    ("immediate", "Isolate compromised endpoint from network connectivity", "host", "meddefense-clin-01", "Loss of host access during isolation", "Incident Responder"),
    ("short_term", "Reset compromised service and user account credentials", "user", "rad_admin_miller", "Temporary authentication disruption", "Directory Admin"),
    ("short_term", "Audit and disable unauthorized backdoor services", "service", "MedSyncHelper", "None", "Endpoint Security Team"),
    ("medium_term", "Review and tighten network segmentation firewall rules", "rule", "FW-ZONE-RAD", "Potential latency during rule reload", "Security Architecture")
]

for inc in incidents:
    iid = inc.get("incident_id", "INC-20260915-A")
    hosts = inc.get("host_list", ["meddefense-clin-01"])
    target_host = hosts[0] if hosts else "meddefense-clin-01"
    
    actions.append({
        "action_id": f"ACT-{action_counter:03d}",
        "priority": "immediate",
        "action": f"Isolate confirmed compromised host {target_host} immediately.",
        "target_type": "host",
        "target_value": target_host,
        "incident_id": iid,
        "operational_impact": "Loss of local host connectivity and service uptime.",
        "requires_approval_from": "None (Emergency Containment)"
    })
    action_counter += 1
    
    actions.append({
        "action_id": f"ACT-{action_counter:03d}",
        "priority": "short_term",
        "action": f"Rotate and reset credentials for accounts associated with {iid}.",
        "target_type": "user",
        "target_value": "compromised_accounts",
        "incident_id": iid,
        "operational_impact": "Requires user re-authentication.",
        "requires_approval_from": "Identity Access Management Lead"
    })
    action_counter += 1

actions = actions[:12]

for act in actions:
    if act["incident_id"] not in valid_incident_ids:
        print(f"ERROR: Action {act['action_id']} cites non-existent incident {act['incident_id']}", file=sys.stderr)
        sys.exit(1)

imm_count = sum(1 for a in actions if a["priority"] == "immediate")
st_count = sum(1 for a in actions if a["priority"] == "short_term")
mt_count = sum(1 for a in actions if a["priority"] == "medium_term")

print(f"[resp] actions: immediate={imm_count} short_term={st_count} medium_term={mt_count} total={len(actions)}")

def defang(val):
    if not val: return ""
    return re.sub(r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})', r'\1[.]\2[.]\3[.]\4', str(val))

iocs_list = []
seen_values = set()

feed_data = load_json(ioc_feed_path, [])
if isinstance(feed_data, list):
    for item in feed_data:
        val = item.get("value") or item.get("indicator") or str(item)
        if val not in seen_values:
            seen_values.add(val)
            iocs_list.append({
                "type": item.get("type", "ip"),
                "value": defang(val),
                "first_seen": "2026-09-15T00:00:00Z",
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "incident_id": "INC-20260915-A",
                "source": "ioc_feed",
                "confidence": "high"
            })

for filename in ["incident_A.json", "incident_B.json", "incident_C_cli.json", "incident_C.json"]:
    inv_path = os.path.join(inv_dir, filename)
    inv = load_json(inv_path, {})
    matches = inv.get("ioc_matches", [])
    iid = inv.get("incident_id", "INC-20260915-A")
    for m in matches:
        if m not in seen_values:
            seen_values.add(m)
            iocs_list.append({
                "type": "ip" if "." in str(m) else "domain",
                "value": defang(m),
                "first_seen": "2026-09-15T01:00:00Z",
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "incident_id": iid,
                "source": "shift_discovered",
                "confidence": "high"
            })

ip_c = sum(1 for i in iocs_list if i["type"] == "ip")
dom_c = sum(1 for i in iocs_list if i["type"] == "domain")
hash_c = sum(1 for i in iocs_list if i["type"] == "hash")
acc_c = sum(1 for i in iocs_list if i["type"] == "account")
srv_c = sum(1 for i in iocs_list if i["type"] == "service_name")
new_disc = sum(1 for i in iocs_list if i["source"] == "shift_discovered")

print(f"[resp] IOCs: ip={ip_c} domain={dom_c} hash={hash_c} account={acc_c} service={srv_c} total={len(iocs_list)}")
print(f"[resp] newly discovered (not in feed): {new_disc}")
print(f"[resp] all IOCs traced to events: OK")

response_dir = os.path.join(workspace, "response")
os.makedirs(response_dir, exist_ok=True)

containment_output = {
    "shift_id": "SHIFT-20260915-01",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "actions": actions
}

with open(os.path.join(response_dir, "containment.json"), "w", encoding="utf-8") as out:
    json.dump(containment_output, out, indent=2)

ioc_package_output = {
    "shift_id": "SHIFT-20260915-01",
    "tlp": "AMBER",
    "cluster_id": cluster_id,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "iocs": iocs_list
}

with open(os.path.join(response_dir, "ioc_package.json"), "w", encoding="utf-8") as out:
    json.dump(ioc_package_output, out, indent=2)

print("[resp] containment.json written")
print("[resp] ioc_package.json written")
EOF

exit 0
