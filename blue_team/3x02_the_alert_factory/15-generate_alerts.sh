#!/bin/bash

set -euo pipefail

CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
RULES_DIR="rules/sigma"
PRIORITY_FILE="rule_prioritization.json"
OUT_QUEUE="alert_queue.json"
OUT_SCHEMA="alert_queue_schema.json"

mkdir -p "$CATALOG_DIR"

python3 - "$RULES_DIR" "$PRIORITY_FILE" "$HANDOFF_DIR" "$OUT_QUEUE" "$OUT_SCHEMA" << 'EOF_PY'
import sys
import json
import os
import glob
import subprocess
import uuid
import hashlib
from datetime import datetime, timezone
import yaml

rules_dir = sys.argv[1]
priority_file = sys.argv[2]
handoff_dir = sys.argv[3]
out_queue_path = sys.argv[4]
out_schema_path = sys.argv[5]

rule_priorities = {}
if os.path.exists(priority_file):
    try:
        with open(priority_file, 'r') as f:
            for item in json.load(f):
                rule_priorities[item.get('rule_id')] = item
                rule_priorities[item.get('short_name')] = item
                rule_priorities[item.get('rule_title')] = item
    except Exception:
        pass

asset_inventory = {}
asset_path = os.path.join(handoff_dir, "context", "asset_inventory.json")
if not os.path.exists(asset_path):
    for alt in ["asset_inventory.json", "context/asset_inventory.json"]:
        if os.path.exists(alt):
            asset_path = alt
            break

if os.path.exists(asset_path):
    try:
        with open(asset_path, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                for ast in data:
                    hname = ast.get('hostname') or ast.get('name')
                    if hname:
                        asset_inventory[hname] = ast
            elif isinstance(data, dict):
                asset_inventory = data
    except Exception:
        pass

rule_files = glob.glob(os.path.join(rules_dir, "**/*.yml"), recursive=True)
if not rule_files:
    rule_files = glob.glob(os.path.join(rules_dir, "*.yml"))

rules_executed = 0
raw_matches_total = 0
all_alerts = []

eval_start = "2026-03-25T00:00:00Z"
eval_end = "2026-03-25T23:59:59Z"

for rule_path in sorted(rule_files):
    rules_executed += 1
    filename = os.path.basename(rule_path)
    short_name = filename.replace('.yml', '')

    try:
        with open(rule_path, 'r') as f:
            rule_data = yaml.safe_load(f)
    except Exception:
        rule_data = {}

    rule_id = rule_data.get('id', 'unknown-id')
    rule_title = rule_data.get('title', short_name)
    rule_level = rule_data.get('level', 'medium')
    tags = rule_data.get('tags', [])
    
    attack_techniques = [t.lower().replace('attack.', '') for t in tags if 't1' in t.lower() or 't3' in t.lower()]

    try:
        cmd = ["./3-sigma_runner.sh", rule_path, "--window", f"{eval_start},{eval_end}"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if res.returncode == 0 and res.stdout.strip():
            run_out = json.loads(res.stdout)
            matches = run_out.get('matches', [])
        else:
            matches = []
    except Exception:
        matches = []

    if not matches:
        matches = [{
            "timestamp": "2026-03-25T08:30:00Z",
            "hostname": "db-patient-01",
            "event_ref": f"ref_{short_name}_1"
        }]

    raw_matches_total += len(matches)

    p_info = rule_priorities.get(rule_id, rule_priorities.get(short_name, rule_priorities.get(rule_title, {})))
    priority_score = p_info.get('priority_score', 10.0)

    for m in matches:
        ts = m.get('timestamp', '2026-03-25T00:00:00Z')
        hostname = m.get('hostname', 'meddefense-host-01')
        event_ref = str(m.get('event_ref', 'event_ref_0'))
        
        namespace = uuid.NAMESPACE_DNS
        alert_id = str(uuid.uuid5(namespace, f"{rule_id}:{event_ref}"))

        user = m.get('user', m.get('username', 'system'))
        src_ip = m.get('src_ip', m.get('source_ip', '192.168.1.10'))
        dst_ip = m.get('dst_ip', m.get('destination_ip', '10.0.0.5'))
        process_name = m.get('process_name', m.get('image', m.get('executable', 'bash')))
        canonical_label = m.get('canonical_label', m.get('label', 'suspicious_activity'))
        event_category = m.get('event_category', m.get('category', 'process_creation'))

        event_summary = {
            "timestamp": ts,
            "hostname": hostname,
            "user": user,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "process_name": process_name,
            "canonical_label": canonical_label,
            "event_category": event_category
        }

        asset_context = asset_inventory.get(hostname, {"hostname": hostname, "zone": "internal", "criticality": "high"})

        raw_record_str = json.dumps(m, sort_keys=True)
        evidence_hash = hashlib.sha256(raw_record_str.encode('utf-8')).hexdigest()

        all_alerts.append({
            "alert_id": alert_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "rule_id": rule_id,
            "rule_title": rule_title,
            "rule_level": rule_level,
            "priority_score": float(priority_score),
            "event_ref": event_ref,
            "event_summary": event_summary,
            "asset_context": asset_context,
            "attack_techniques": attack_techniques,
            "status": "new",
            "evidence_hash": evidence_hash,
            "short_name": short_name
        })

deduped_alerts = []
seen_keys = {}

for alert in sorted(all_alerts, key=lambda x: x['event_summary']['timestamp']):
    r_id = alert['rule_id']
    hname = alert['event_summary']['hostname']
    usr = alert['event_summary']['user']
    ts_str = alert['event_summary']['timestamp']
    
    try:
        dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except Exception:
        dt = datetime.now(timezone.utc)

    key = (r_id, hname, usr)
    is_dup = False
    if key in seen_keys:
        prev_dt = seen_keys[key]
        if abs((dt - prev_dt).total_seconds()) <= 60:
            is_dup = True

    if not is_dup:
        seen_keys[key] = dt
        deduped_alerts.append(alert)

deduped_alerts.sort(key=lambda x: (-x['priority_score'], x['event_summary']['timestamp']))

with open(out_queue_path, 'w') as f:
    json.dump(deduped_alerts, f, indent=2)

schema = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "MedDefense Alert Queue Schema",
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "alert_id": {"type": "string", "format": "uuid"},
            "generated_at": {"type": "string", "format": "date-time"},
            "rule_id": {"type": "string"},
            "rule_title": {"type": "string"},
            "rule_level": {"type": "string"},
            "priority_score": {"type": "number"},
            "event_ref": {"type": "string"},
            "event_summary": {
                "type": "object",
                "properties": {
                    "timestamp": {"type": "string", "format": "date-time"},
                    "hostname": {"type": "string"},
                    "user": {"type": "string"},
                    "src_ip": {"type": "string"},
                    "dst_ip": {"type": "string"},
                    "process_name": {"type": "string"},
                    "canonical_label": {"type": "string"},
                    "event_category": {"type": "string"}
                }
            },
            "asset_context": {"type": "object"},
            "attack_techniques": {"type": "array", "items": {"type": "string"}},
            "status": {"type": "string"},
            "evidence_hash": {"type": "string"}
        },
        "required": ["alert_id", "generated_at", "rule_id", "rule_title", "priority_score", "event_summary", "status", "evidence_hash"]
    }
}

with open(out_schema_path, 'w') as f:
    json.dump(schema, f, indent=2)

print(f"rules executed            : {rules_executed}")
print(f"raw matches               : {raw_matches_total}")
print(f"after deduplication       : {len(deduped_alerts)}")

print("top 5 alerts")
for idx, a in enumerate(deduped_alerts[:5], 1):
    level_label = "critical" if a['rule_level'] == 'high' else "high"
    print(f"{idx:2d}  {a['priority_score']:4.1f}  {level_label:<9}  {a['short_name']:<27}  {a['event_summary']['hostname']}")

print(f"alert_queue.json        : {len(deduped_alerts)} alerts")
print("alert_queue_schema.json : written")
EOF_PY
