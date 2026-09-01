#!/bin/bash
set -euo pipefail

BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
AUTH_ANOM_FILE="$BASELINE_PKG/anomalies_auth.json"
PROC_ANOM_FILE="$BASELINE_PKG/anomalies_process.json"
NET_ANOM_FILE="$BASELINE_PKG/anomalies_network.json"
OUT_FILE="$BASELINE_PKG/correlated_anomalies.json"
CORRELATION_WINDOW="${CORRELATION_WINDOW:-300}" # seconds

python3 -W error - "$BASELINE_PKG" "$OUT_FILE" "$CORRELATION_WINDOW" << 'EOF'
import sys
import os
import json
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict

base_pkg, out_file, window_sec = sys.argv[1], sys.argv[2], int(sys.argv[3])

def load_anomalies(filename, source_name):
    path = os.path.join(base_pkg, filename)
    items = []
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        item["_source"] = source_name
                        items.append(item)
        except Exception:
            pass
    return items

auth_anoms = load_anomalies("anomalies_auth.json", "auth")
proc_anoms = load_anomalies("anomalies_process.json", "process")
net_anoms = load_anomalies("anomalies_network.json", "network")

all_anomalies = auth_anoms + proc_anoms + net_anoms
single_source_count = len(all_anomalies)

parsed_anomalies = []
for a in all_anomalies:
    ts_str = a.get("timestamp")
    if ts_str:
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            a["_dt"] = dt
            parsed_anomalies.append(a)
        except ValueError:
            pass

by_host = defaultdict(list)
for a in parsed_anomalies:
    host = a.get("host", "unknown")
    by_host[host].append(a)

correlated_findings = []
multi_host_count = 0
max_score = 0

for host, anoms in by_host.items():
    anoms.sort(key=lambda x: x["_dt"])
    
    clusters = []
    current_cluster = []
    cluster_start_time = None
    
    for a in anoms:
        dt = a["_dt"]
        if not current_cluster:
            current_cluster = [a]
            cluster_start_time = dt
        else:
            if (dt - cluster_start_time).total_seconds() <= window_sec:
                current_cluster.append(a)
            else:
                if len(current_cluster) >= 1:
                    clusters.append(current_cluster)
                current_cluster = [a]
                cluster_start_time = dt
    if current_cluster:
        clusters.append(current_cluster)
        
    for cluster in clusters:
        if len(cluster) < 2:
            continue
            
        sources = set(item["_source"] for item in cluster)
        anomaly_types = sorted(list(set(item.get("anomaly_type", "unknown") for item in cluster)))
        
        w_start = min(item["_dt"] for item in cluster).isoformat()
        w_end = max(item["_dt"] for item in cluster).isoformat()
        
        member_refs = []
        for item in cluster:
            ref = item.get("event_refs") or item.get("timestamp")
            if isinstance(ref, list):
                member_refs.extend(ref)
            else:
                member_refs.append(str(ref))
        
        score = len(sources) + len(anomaly_types) + 1
        if len(sources) > 1:
            multi_host_count += 1
            
        if score > max_score:
            max_score = score
            
        raw_id_string = f"{host}-{w_start}-{len(cluster)}"
        corr_id = hashlib.md5(raw_id_string.encode('utf-8')).hexdigest()[:10]
        
        correlated_findings.append({
            "correlation_id": corr_id,
            "host": host,
            "window_start": w_start,
            "window_end": w_end,
            "sources_involved": sorted(list(sources)),
            "anomaly_types": anomaly_types,
            "member_refs": list(set(member_refs)),
            "score": score
        })

with open(out_file, 'w', encoding='utf-8') as f:
    json.dump(correlated_findings, f, indent=2)

print(f"single-source anomalies  : {single_source_count}")
print(f"correlated findings      : {len(correlated_findings)}")
print(f"multi-host findings      : {multi_host_count}")
print(f"max score                : {max_score}")
print("correlated_anomalies.json written")
EOF
