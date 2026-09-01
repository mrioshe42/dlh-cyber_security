#!/bin/bash
set -euo pipefail

BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
OUT_FILE="$BASELINE_PKG/baseline_summary.json"

mkdir -p "$BASELINE_PKG"

python3 -W error - "$BASELINE_PKG" "$OUT_FILE" << 'EOF'
import sys
import os
import json
from datetime import datetime, timedelta

base_pkg = sys.argv[1]
out_file = sys.argv[2]

def load_json(filename):
    path = os.path.join(base_pkg, filename)
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {}

auth_data = load_json("baseline_auth.json")
process_data = load_json("baseline_process.json")
network_data = load_json("baseline_network.json")
file_data = load_json("baseline_file.json")
temporal_data = load_json("temporal_profile.json")

window_info = auth_data.get("window") or process_data.get("window") or {}
start_str = window_info.get("start", datetime.now().isoformat())
end_str = window_info.get("end", (datetime.now() + timedelta(days=7)).isoformat())

try:
    start_dt = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
    end_dt = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
    duration_days = max(1, round((end_dt - start_dt).total_seconds() / 86400))
except Exception:
    duration_days = 7
    start_dt = datetime.now()
    end_dt = start_dt + timedelta(days=7)
    start_str = start_dt.isoformat()
    end_str = end_dt.isoformat()

eval_start_dt = end_dt
eval_end_dt = eval_start_dt + timedelta(days=1)

hosts = set()
if "per_host" in auth_data:
    hosts.update(auth_data["per_host"].keys())
if "per_host" in process_data:
    hosts.update(process_data["per_host"].keys())
if "per_host" in network_data:
    hosts.update(network_data["per_host"].keys())
if "per_host" in file_data:
    hosts.update(file_data["per_host"].keys())

host_list = sorted(list(hosts))

thresholds = {
    "failure_rate_multiplier": {
        "value": 3,
        "comment": "An evaluation window authentication failure rate exceeding 3x the baseline average triggers an anomaly flag."
    },
    "unknown_process_penalty": {
        "value": 5,
        "comment": "Any process execution not registered in the per-host baseline incurs a high severity score penalty."
    },
    "unknown_port_penalty": {
        "value": 4,
        "comment": "Outbound network traffic connecting to an unobserved destination port incurs a medium-high severity penalty."
    },
    "offhours_activity_weight": {
        "value": 2,
        "comment": "Multiplier applied to deviations occurring during off-hours (18:00 to 05:59)."
    }
}

summary_output = {
    "version": "1.0",
    "generated_at": datetime.now().isoformat(),
    "baseline_window": {
        "start": start_str,
        "end": end_str,
        "duration_days": duration_days
    },
    "evaluation_window": {
        "start": eval_start_dt.isoformat(),
        "end": eval_end_dt.isoformat(),
        "duration_hours": 24
    },
    "host_inventory": host_list,
    "auth": auth_data,
    "process": process_data,
    "network": network_data,
    "file": file_data,
    "temporal": temporal_data,
    "thresholds": thresholds
}

with open(out_file, 'w', encoding='utf-8') as f:
    json.dump(summary_output, f, indent=2)

print(f"version           : 1.0")
print(f"baseline window   : {start_str} -> {end_str}  ({duration_days} days)")
print(f"evaluation window : {eval_start_dt.isoformat()} -> {eval_end_dt.isoformat()}  (24h)")
print(f"hosts             : {len(host_list)}")
print(f"sections included : auth, process, network, file, temporal, thresholds")
print("baseline_summary.json written")
EOF
