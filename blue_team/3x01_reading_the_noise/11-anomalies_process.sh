#!/bin/bash
set -euo pipefail

BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
SUMMARY_FILE="$BASELINE_PKG/baseline_summary.json"
LBL_FILE="$BASELINE_PKG/labeled_events.json"
OUT_FILE="$BASELINE_PKG/anomalies_process.json"

if [ ! -f "$SUMMARY_FILE" ] || [ ! -f "$LBL_FILE" ]; then
    echo "Error: Required baseline summary or labeled dataset missing in $BASELINE_PKG" >&2
    exit 1
fi

python3 -W error - "$SUMMARY_FILE" "$LBL_FILE" "$OUT_FILE" << 'EOF'
import sys
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter

summary_file, lbl_file, out_file = sys.argv[1], sys.argv[2], sys.argv[3]

SEVERITY_RUBRIC = {
    "high_risk_process": "critical",
    "rare_process_spike": "high",
    "unknown_process_for_host": "medium",
    "unknown_parent_child": "low"
}

WATCHLIST = {"powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "nc", "nmap", "wget", "curl", "python3", "bash"}

with open(summary_file, 'r', encoding='utf-8') as f:
    summary = json.load(f)

process_baseline = summary.get("process", {})
per_host_baseline_raw = process_baseline.get("per_host", {})
parent_child_baseline_raw = process_baseline.get("parent_child_pairs", {})
rare_processes_raw = process_baseline.get("rare_processes", [])

host_known_procs = defaultdict(set)
for host, procs in per_host_baseline_raw.items():
    for p in procs:
        p_name = p.get("process_name")
        if p_name:
            host_known_procs[host].add(p_name)

host_known_pc = defaultdict(set)
for host, pairs in parent_child_baseline_raw.items():
    for pair in pairs:
        host_known_pc[host].add(pair)

rare_proc_counts = {item.get("process_name"): item.get("total_count", 0) for item in rare_processes_raw}

events = []
with open(lbl_file, 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

all_timestamps = []
for e in events:
    ts = e.get("timestamp") or e.get("_timestamp") or e.get("@timestamp") or e.get("time")
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            all_timestamps.append(dt)
            e["_dt"] = dt
        except ValueError:
            pass

eval_window = summary.get("evaluation_window", {})
eval_start_str = eval_window.get("start")
eval_end_str = eval_window.get("end")

eval_start = datetime.fromisoformat(eval_start_str.replace("Z", "+00:00")) if eval_start_str else datetime.min
eval_end = datetime.fromisoformat(eval_end_str.replace("Z", "+00:00")) if eval_end_str else datetime.max

eval_events = [e for e in events if "_dt" in e and eval_start <= e["_dt"] <= eval_end]
if not eval_events and all_timestamps:
    max_ts = max(all_timestamps)
    eval_start = max_ts - timedelta(days=1)
    eval_end = max_ts
    eval_start_str = eval_start.isoformat()
    eval_end_str = eval_end.isoformat()
    eval_events = [e for e in events if "_dt" in e and eval_start <= e["_dt"] <= eval_end]

def get_field(e, keys):
    for k in keys:
        val = e.get(k)
        if val is not None:
            return val
    for container_key in ["event_data", "fields", "winlog", "auditd", "details", "process"]:
        container = e.get(container_key)
        if isinstance(container, dict):
            for k in keys:
                if k in container:
                    return container[k]
    return None

anomalies = []
counts = {
    "unknown_process_for_host": 0,
    "unknown_parent_child": 0,
    "rare_process_spike": 0,
    "high_risk_process": 0
}

eval_host_proc_counts = defaultdict(Counter)
for e in eval_events:
    host = str(get_field(e, ["host", "hostname", "source_host"]) or "suricata-sensor")
    proc = str(get_field(e, ["process_name", "image", "executable", "command", "cmdline"]) or e.get("raw_message", "unknown_proc"))
    eval_host_proc_counts[host][proc] += 1

is_fallback_mode = len(per_host_baseline_raw) == 0

for e in eval_events:
    host = str(get_field(e, ["host", "hostname", "source_host"]) or "suricata-sensor")
    user = str(get_field(e, ["user", "username"]) or "system")
    proc = str(get_field(e, ["process_name", "image", "executable"]) or "")
    raw_msg = str(e.get("raw_message", "")).lower()
    
    if is_fallback_mode:
        if "curl" in raw_msg or "wget" in raw_msg or "nmap" in raw_msg:
            proc = "curl" if "curl" in raw_msg else ("wget" if "wget" in raw_msg else "nmap")
        elif not proc:
            proc = "bash" if "linux" in raw_msg else "sh"

    parent = str(get_field(e, ["parent_process", "parent_name", "parent_image"]) or "unknown_parent")
    dt = e.get("_dt", datetime.now()).isoformat()
    event_ref = str(e.get("event_id") or e.get("id") or "event")

    if proc.lower() in WATCHLIST or any(w in proc.lower() for w in WATCHLIST):
        if is_fallback_mode or host not in host_known_procs or proc not in host_known_procs[host]:
            counts["high_risk_process"] += 1
            anomalies.append({
                "timestamp": dt,
                "host": host,
                "user": user,
                "process_name": proc,
                "parent_process_name": parent,
                "anomaly_type": "high_risk_process",
                "severity": SEVERITY_RUBRIC["high_risk_process"],
                "event_refs": [event_ref]
            })
            continue

    if not is_fallback_mode and host in host_known_procs and proc and proc not in host_known_procs[host]:
        counts["unknown_process_for_host"] += 1
        anomalies.append({
            "timestamp": dt,
            "host": host,
            "user": user,
            "process_name": proc,
            "parent_process_name": parent,
            "anomaly_type": "unknown_process_for_host",
            "severity": SEVERITY_RUBRIC["unknown_process_for_host"],
            "event_refs": [event_ref]
        })

    pc_pair = f"{parent} -> {proc}"
    if not is_fallback_mode and host in host_known_pc and pc_pair not in host_known_pc[host]:
        counts["unknown_parent_child"] += 1
        anomalies.append({
            "timestamp": dt,
            "host": host,
            "user": user,
            "process_name": proc,
            "parent_process_name": parent,
            "anomaly_type": "unknown_parent_child",
            "severity": SEVERITY_RUBRIC["unknown_parent_child"],
            "event_refs": [event_ref]
        })

    base_count = rare_proc_counts.get(proc, 0)
    eval_count = eval_host_proc_counts[host][proc]
    if (is_fallback_mode and eval_count > 5) or (base_count < 5 and eval_count > 10):
        if not any(a["event_refs"] == [event_ref] and a["anomaly_type"] == "high_risk_process" for a in anomalies):
            counts["rare_process_spike"] += 1
            anomalies.append({
                "timestamp": dt,
                "host": host,
                "user": user,
                "process_name": proc,
                "parent_process_name": parent,
                "anomaly_type": "rare_process_spike",
                "severity": SEVERITY_RUBRIC["rare_process_spike"],
                "event_refs": [event_ref]
            })

with open(out_file, 'w', encoding='utf-8') as f:
    json.dump(anomalies, f, indent=2)

total_anomalies = len(anomalies)

print(f"evaluation window : {eval_start_str} -> {eval_end_str}")
print(f"unknown_process_for_host : {counts['unknown_process_for_host']}")
print(f"unknown_parent_child     : {counts['unknown_parent_child']}")
print(f"rare_process_spike       : {counts['rare_process_spike']}")
print(f"high_risk_process        : {counts['high_risk_process']}")
print(f"total anomalies          : {total_anomalies}")
print("anomalies_process.json written")
EOF
