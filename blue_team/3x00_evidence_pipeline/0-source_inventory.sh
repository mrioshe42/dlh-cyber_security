#!/bin/bash
set -euo pipefail

PACK_ROOT="${1:-$HOME/evidence_pack_primary}"
OUT="source_inventory.json"

python3 - "$PACK_ROOT" "$OUT" <<'PY'
import csv, hashlib, json, re, sys
from datetime import datetime, timezone
from pathlib import Path

def sha256_file(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1<<20), b""): h.update(chunk)
    return h.hexdigest()

def norm_time(v):
    if not v: return None
    v = str(v).strip()
    if not v: return None
    
    try:
        if re.fullmatch(r"\d+(?:\.\d+)?", v):
            return datetime.fromtimestamp(float(v), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        iso = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", v.replace("Z", "+00:00"))
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except: pass
    
    try:
        return datetime.strptime(v, "%m/%d/%Y %I:%M:%S %p").replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except: return None

def read_json(p):
    if p.stat().st_size == 0: return [], "empty"
    recs, bad = [], 0
    with p.open("r", encoding="utf-8", errors="replace") as f:
        fc = next((c for c in f.read() if not c.isspace()), "")
        f.seek(0)
        if fc == "[":
            try:
                data = json.load(f)
                if not isinstance(data, list): return [], "parse_error"
                for item in data:
                    if isinstance(item, dict): recs.append(item)
                    else: bad += 1
                return recs, ("partial" if bad else "ok")
            except: return [], "parse_error"
        
        for line in f:
            line = line.strip()
            if line:
                try:
                    item = json.loads(line)
                    if isinstance(item, dict): recs.append(item)
                    else: bad += 1
                except: bad += 1
    
    return recs, ("partial" if bad else "ok")

def add_entry(m, p, root, src_type, cnt_key, cnt, t1, t2, status):
    m.append({
        "path": str(p.relative_to(root)),
        "source_type": src_type,
        "size_bytes": p.stat().st_size,
        "sha256": sha256_file(p),
        cnt_key: cnt,
        "first_event_time": t1,
        "last_event_time": t2,
        "parse_status": status
    })

def times_range(ts):
    return (min(ts), max(ts)) if ts else (None, None)

root = Path(sys.argv[1] if len(sys.argv) > 1 else Path.home() / "evidence_pack_primary")
out = sys.argv[2] if len(sys.argv) > 2 else "source_inventory.json"
m = []

year = None
ap = root / "linux" / "audit.log"
if ap.is_file():
    try:
        with ap.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if match := re.search(r"audit\((\d+)", line):
                    epoch = int(match.group(1))
                    year = datetime.fromtimestamp(epoch, timezone.utc).year
                    break
    except: pass

for p in sorted((root / "windows").glob("*.json") if (root / "windows").is_dir() else []):
    recs, status = read_json(p)
    ts = []
    for r in recs:
        t = norm_time(r.get("timestamp_raw")) or norm_time(r.get("timestamp"))
        if t: ts.append(t)
    t1, t2 = times_range(ts)
    add_entry(m, p, root, "windows_json", "record_count", len(recs), t1, t2, status)

if (root / "linux").is_dir():
    fallback_year = datetime.now(timezone.utc).year
    effective_year = year if year else fallback_year
    
    for p in sorted((root / "linux").iterdir()):
        if not p.is_file(): continue
        cnt, bad_ts, ts = 0, 0, []
        try:
            with p.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    cnt += 1
                    if p.name == "audit.log":
                        if match := re.search(r"audit\((\d+)(?:\.\d+)?:", line):
                            t = norm_time(match.group(1))
                            if t:
                                ts.append(t)
                            else:
                                bad_ts += 1
                    else:
                        if match := re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line):
                            try:
                                dt = datetime.strptime(f"{match.group(1)} {effective_year}", "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                                ts.append(dt.strftime("%Y-%m-%dT%H:%M:%SZ"))
                            except: bad_ts += 1
        except: cnt, bad_ts = 0, 0
        
        status = "empty" if cnt == 0 else ("partial" if bad_ts else "ok")
        t1, t2 = times_range(ts)
        add_entry(m, p, root, "linux_text", "line_count", cnt, t1, t2, status)

if (root / "network").is_dir():
    for p in sorted((root / "network").iterdir()):
        if not p.is_file(): continue
        
        if p.suffix.lower() == ".csv":
            cnt, bad, ts = 0, 0, []
            status = "ok"
            try:
                with p.open("r", encoding="utf-8", errors="replace", newline="") as f:
                    for row in csv.DictReader(f):
                        cnt += 1
                        t = norm_time(row.get("timestamp"))
                        if t:
                            ts.append(t)
                        else:
                            bad += 1
                status = "empty" if cnt == 0 else ("partial" if bad else "ok")
            except:
                cnt, ts, status = 0, [], "parse_error"
            t1, t2 = times_range(ts)
            add_entry(m, p, root, "network_csv", "record_count", cnt, t1, t2, status)
        
        elif p.suffix.lower() == ".json":
            recs, status = read_json(p)
            if p.name == "pcap_summary.json":
                starts = [norm_time(r.get("start_time")) for r in recs]
                ends = [norm_time(r.get("end_time")) for r in recs]
                ts = [t for t in starts + ends if t]
                t1, t2 = times_range(ts)
            else:
                ts = [norm_time(r.get("timestamp")) for r in recs]
                ts = [t for t in ts if t]
                t1, t2 = times_range(ts)
            add_entry(m, p, root, "network_json", "record_count", len(recs), t1, t2, status)

m.sort(key=lambda x: x["path"])
Path(out).write_text(json.dumps(m, indent=2) + "\n")
print(f"manifest written to {out}")
PY

python3 - "$OUT" <<'SUMMARY'
import json, sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text())
cats = {"windows": {"files": 0, "bytes": 0}, "linux": {"files": 0, "bytes": 0}, "network": {"files": 0, "bytes": 0}}

for entry in data:
    cat = entry["source_type"].split("_")[0]
    cats[cat]["files"] += 1
    cats[cat]["bytes"] += entry["size_bytes"]

def fmt_bytes(b):
    for unit, div in [("GB", 1<<30), ("MB", 1<<20), ("KB", 1<<10)]:
        if b >= div: return f"{b/div:.1f} {unit}"
    return f"{b} B"

total_files = total_bytes = 0
for cat in ["windows", "linux", "network"]:
    f, b = cats[cat]["files"], cats[cat]["bytes"]
    total_files += f; total_bytes += b
    print(f"{cat:8} : {f} files  |  {fmt_bytes(b)}")

print(f"{'total':8} : {total_files} files  |  {fmt_bytes(total_bytes)}")
SUMMARY
