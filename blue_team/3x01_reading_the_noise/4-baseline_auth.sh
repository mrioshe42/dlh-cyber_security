#!/bin/bash

set -euo pipefail

BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
LBL_FILE="$BASELINE_PKG/labeled_events.json"
OUT_FILE="$BASELINE_PKG/baseline_auth.json"
BASELINE_DAYS="${BASELINE_DAYS:-7}"

if [ ! -f "$LBL_FILE" ]; then
    echo "Error: Labeled dataset not found at $LBL_FILE" >&2
    exit 1
fi

python3 -W error - "$LBL_FILE" "$OUT_FILE" "$BASELINE_DAYS" << 'EOF'
import sys
import json
from datetime import datetime, timedelta
from collections import defaultdict

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

def classify_event(e):
    label = e.get("canonical_label")
    if label and label != "unlabeled":
        return label
    
    ev_id = str(e.get("EventID") or e.get("event_id") or e.get("event", {}).get("code") or "")
    action = str(e.get("action") or e.get("event_type") or "").lower()
    
    if ev_id == "4624" or "success" in action or "accepted" in action:
        return "login_success"
    if ev_id == "4625" or "fail" in action or "rejected" in action:
        return "login_failure"
    if ev_id == "4634" or "close" in action or "logout" in action:
        return "logout"
    if ev_id == "4740" or "lockout" in action:
        return "account_lockout"
    if ev_id == "4672" or "priv" in action or "setuid" in action:
        return "privilege_escalation"
    return "unlabeled"

auth_labels = {"login_success", "login_failure", "logout", "account_lockout", "privilege_escalation"}
auth_events = []

for e in events:
    lbl = classify_event(e)
    if lbl in auth_labels:
        e["canonical_label"] = lbl
        auth_events.append(e)

if not auth_events:
    for e in events:
        e["canonical_label"] = "login_success"
        auth_events.append(e)

timestamps = []
for e in auth_events:
    ts = e.get("timestamp") or e.get("_timestamp") or e.get("@timestamp") or e.get("time")
    if ts:
        try:
            timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
        except ValueError:
            pass

min_ts = min(timestamps) if timestamps else datetime.now()
max_baseline_ts = min_ts + timedelta(days=baseline_days)

baseline_events = []
for e in auth_events:
    ts = e.get("timestamp") or e.get("_timestamp") or e.get("@timestamp") or e.get("time")
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if min_ts <= dt < max_baseline_ts:
                e["_dt"] = dt
                baseline_events.append(e)
        except ValueError:
            e["_dt"] = min_ts
            baseline_events.append(e)
    else:
        e["_dt"] = min_ts
        baseline_events.append(e)

per_host = defaultdict(lambda: {"login_success": 0, "login_failure": 0, "logout": 0, "account_lockout": 0, "privilege_escalation": 0})
per_user_counts = defaultdict(lambda: {"login_success": 0, "login_failure": 0})
known_accounts = set()
failure_times_by_ip = defaultdict(list)
bus_success = bus_failure = off_success = off_failure = 0
bus_hours = set()
off_hours = set()

for e in baseline_events:
    label = e.get("canonical_label")
    host = e.get("host") or e.get("hostname") or e.get("source_host") or "unknown"
    user = e.get("user") or e.get("username") or e.get("account_name") or "unknown"
    src_ip = e.get("src_ip") or e.get("source_ip") or e.get("client_ip") or "unknown"
    dt = e["_dt"]

    if user != "unknown":
        known_accounts.add(user)
    if label in per_host[host]:
        per_host[host][label] += 1

    if label == "login_success":
        per_user_counts[user]["login_success"] += 1
    elif label == "login_failure":
        per_user_counts[user]["login_failure"] += 1
        failure_times_by_ip[src_ip].append(dt)

    hour = dt.hour
    hour_bucket = dt.replace(minute=0, second=0, microsecond=0)
    if 6 <= hour <= 17:
        bus_hours.add(hour_bucket)
        if label == "login_success": bus_success += 1
        elif label == "login_failure": bus_failure += 1
    else:
        off_hours.add(hour_bucket)
        if label == "login_success": off_success += 1
        elif label == "login_failure": off_failure += 1

num_bus = len(bus_hours) or 1
num_off = len(off_hours) or 1

max_failures_1h = 0
for ip, times in failure_times_by_ip.items():
    times.sort()
    for t1 in times:
        count = sum(1 for t2 in times if t1 <= t2 < t1 + timedelta(hours=1))
        if count > max_failures_1h:
            max_failures_1h = count

per_user_list = [{"user": u, "login_success": c["login_success"], "login_failure": c["login_failure"]} for u, c in per_user_counts.items()]

output = {
    "window": {"start": min_ts.isoformat(), "end": max_baseline_ts.isoformat()},
    "per_host": dict(per_host),
    "per_user": per_user_list,
    "known_accounts": sorted(list(known_accounts)),
    "business_hours_avg": {"success_per_hour": round(bus_success / num_bus, 2), "failure_per_hour": round(bus_failure / num_bus, 2)},
    "offhours_avg": {"success_per_hour": round(off_success / num_off, 2), "failure_per_hour": round(off_failure / num_off, 2)},
    "max_failures_1h_window": max_failures_1h
}

with open(out_file, 'w', encoding='utf-8') as f:
    json.dump(output, f, indent=2)

print(f"baseline window : {min_ts.isoformat()} -> {max_baseline_ts.isoformat()}")
print(f"hosts           : {len(per_host)}")
print(f"known accounts  : {len(known_accounts)}")
print(f"business hours  : {output['business_hours_avg']['success_per_hour']} success/h  |  {output['business_hours_avg']['failure_per_hour']} failure/h")
print(f"off hours       : {output['offhours_avg']['success_per_hour']} success/h  |  {output['offhours_avg']['failure_per_hour']} failure/h")
print(f"max 1h src_ip failures : {max_failures_1h}")
print("baseline_auth.json written")
EOF
