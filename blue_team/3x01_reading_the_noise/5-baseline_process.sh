#!/bin/bash

set -euo pipefail

BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
LBL_FILE="$BASELINE_PKG/labeled_events.json"
OUT_FILE="$BASELINE_PKG/baseline_process.json"
BASELINE_DAYS="${BASELINE_DAYS:-7}"

if [ ! -f "$LBL_FILE" ]; then
    echo "Error: Labeled dataset not found at $LBL_FILE" >&2
    exit 1
fi

python3 -W error - "$LBL_FILE" "$OUT_FILE" "$BASELINE_DAYS" << 'EOF'
import sys
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter

lbl_file, out_file, baseline_days = sys.argv[1], sys.argv[2], int(sys.argv[3])

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

if not events:
    print("Error: Dataset is empty.", file=sys.stderr)
    sys.exit(1)

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

def is_process_event(e):
    label = e.get("canonical_label")
    if label in {"process_start", "child_process_spawn", "process_stop"}:
        return True
    if get_field(e, ["process_name", "image", "executable", "command", "cmdline", "CommandLine", "Image"]):
        return True
    return False

process_events = []
timestamps = []

for e in events:
    if is_process_event(e):
        ts = get_field(e, ["timestamp", "_timestamp", "@timestamp", "time"])
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                timestamps.append(dt)
                e["_dt"] = dt
                process_events.append(e)
            except ValueError:
                pass

if not timestamps:
    min_ts = datetime.now()
    for e in events:
        if is_process_event(e):
            e["_dt"] = min_ts
            process_events.append(e)
else:
    min_ts = min(timestamps)

max_baseline_ts = min_ts + timedelta(days=baseline_days)

baseline_events = [e for e in process_events if min_ts <= e["_dt"] < max_baseline_ts]
if not baseline_events:
    baseline_events = process_events

per_host_data = defaultdict(lambda: defaultdict(lambda: {"count": 0, "first_seen": None, "last_seen": None, "users": set()}))
global_counts = Counter()
host_appearance = defaultdict(set)
parent_child_by_host = defaultdict(set)

for e in baseline_events:
    host = str(get_field(e, ["host", "hostname", "source_host"]) or "unknown")
    proc = str(get_field(e, ["process_name", "image", "executable", "command", "cmdline", "CommandLine", "Image"]) or "unknown_proc")
    user = str(get_field(e, ["user", "username", "account_name"]) or "unknown_user")
    dt = e["_dt"].isoformat()
    
    parent = get_field(e, ["parent_process", "parent_name", "ParentProcessName", "parent_image"])

    global_counts[proc] += 1
    host_appearance[proc].add(host)
    
    h_proc = per_host_data[host][proc]
    h_proc["count"] += 1
    h_proc["users"].add(user)
    
    if h_proc["first_seen"] is None or dt < h_proc["first_seen"]:
        h_proc["first_seen"] = dt
    if h_proc["last_seen"] is None or dt > h_proc["last_seen"]:
        h_proc["last_seen"] = dt

    if parent:
        parent_child_by_host[host].add(f"{parent} -> {proc}")

per_host_output = {}
for host, procs in per_host_data.items():
    per_host_output[host] = []
    for proc, details in procs.items():
        per_host_output[host].append({
            "process_name": proc,
            "execution_count": details["count"],
            "first_seen": details["first_seen"],
            "last_seen": details["last_seen"],
            "distinct_users": sorted(list(details["users"]))
        })

global_top = [{"process_name": p, "count": c} for p, c in global_counts.most_common(50)]

rare_processes = []
for proc, count in global_counts.items():
    if len(host_appearance[proc]) == 1 or count < 5:
        rare_processes.append({"process_name": proc, "total_count": count, "hosts": list(host_appearance[proc])})

formatted_pc_pairs = {host: sorted(list(pairs)) for host, pairs in parent_child_by_host.items()}

output = {
    "window": {"start": min_ts.isoformat(), "end": max_baseline_ts.isoformat()},
    "per_host": per_host_output,
    "global_top": global_top,
    "rare_processes": rare_processes,
    "parent_child_pairs": formatted_pc_pairs
}

with open(out_file, 'w', encoding='utf-8') as f:
    json.dump(output, f, indent=2)

top_proc_name, top_proc_count = (global_counts.most_common(1)[0] if global_counts else ("none", 0))
total_pc_count = sum(len(pairs) for pairs in parent_child_by_host.values())

print(f"baseline window : {min_ts.isoformat()} -> {max_baseline_ts.isoformat()}")
print(f"processes indexed by host: {len(per_host_output)} hosts")
print(f"global top process    : {top_proc_name} ({top_proc_count} executions)" if False else f"global top process    : {top_proc_name} ({top_proc_count} executions)")
print(f"rare processes        : {len(rare_processes)}")
print(f"parent->child pairs   : {total_pc_count}")
print("baseline_process.json written")
EOF
