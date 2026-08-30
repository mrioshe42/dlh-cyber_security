#!/bin/bash
set -euo pipefail

PACK_ROOT="${1:-$HOME/evidence_pack_primary}"
OUT_FILE="windows_events.json"

python3 - "$PACK_ROOT" "$OUT_FILE" <<'PY'
import sys, json
from pathlib import Path

root = Path(sys.argv[1])
out = Path(sys.argv[2])
w_dir = root / "windows"
t_dir = root / "student_telemetry"

req_keys = ["timestamp_raw", "hostname", "event_id", "channel", "provider", "raw_message", "event_data", "source_origin"]
recs = []

def read_src(p, orig):
    if not p.is_file():
        raise FileNotFoundError(f"Required input file not found: {p}")
    
    cnt = 0
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                r = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in {p} at line {ln}: {e}") from e
            
            if not isinstance(r, dict):
                raise ValueError(f"Expected JSON object in {p} at line {ln}")
            
            for k in req_keys:
                if k not in r:
                    r[k] = None
            
            if orig == "evidence_pack":
                if r.get("source_origin") != "evidence_pack":
                    raise ValueError(f"Invalid source_origin in {p} at line {ln}: {r.get('source_origin')!r}")
            elif not r.get("source_origin"):
                r["source_origin"] = "student_telemetry"
            
            recs.append(r)
            cnt += 1
    
    return cnt

for fname in ["security.json", "sysmon.json", "powershell.json"]:
    cnt = read_src(w_dir / fname, "evidence_pack")
    print(f"reading {fname:20} ... {cnt} records")

cnt = read_src(t_dir / "windows_events.json", "student_telemetry")
print(f"appending student telemetry ... {cnt} records")

with out.open("w", encoding="utf-8") as f:
    for r in recs:
        f.write(json.dumps(r, separators=(",", ":")) + "\n")

print(f"windows_events.json: {len(recs)} records")
PY
