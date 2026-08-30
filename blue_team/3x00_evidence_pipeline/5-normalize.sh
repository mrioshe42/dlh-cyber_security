#!/bin/bash
set -euo pipefail

python3 <<'PY'
import json, re
from pathlib import Path
from datetime import datetime, timezone

SCHEMA = json.load(open("event_schema.json"))
FIELDS = [x["name"] for x in SCHEMA["fields"]]
REQUIRED = {x["name"] for x in SCHEMA["fields"] if x["required"]}
NORMAL, QUAR = [], []

def ts(v):
    if not v:
        return None
    s = str(v).strip()
    try:
        if s.startswith("audit("):
            s = re.search(r"audit\((\d+(?:\.\d+)?)", s).group(1)
        d = (datetime.fromtimestamp(float(s), timezone.utc)
             if re.fullmatch(r"\d+(?:\.\d+)?", s)
             else datetime.fromisoformat(s.replace("Z", "+00:00")))
        return d.replace(tzinfo=d.tzinfo or timezone.utc).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, AttributeError, OverflowError):
        return None

def run(file, source):
    good = bad = 0

    if not Path(file).is_file():
        raise FileNotFoundError(file)

    with open(file, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            r = None
            try:
                r = json.loads(line)
                if not isinstance(r, dict):
                    raise ValueError("record is not an object")

                data = r.get("event_data" if source == "windows" else "parsed_fields") or {}
                t = ts(r.get("timestamp_raw") or r.get("timestamp"))

                if source == "windows":
                    category = r.get("channel") or "unknown"
                    user = r.get("user") or data.get("SubjectUserName") or data.get("TargetUserName")
                    proc = r.get("process_name") or data.get("Image") or data.get("ProcessName")
                    provider = r.get("provider")
                    eid = r.get("event_id")
                    cmd = data.get("CommandLine")
                    path = data.get("TargetFilename") or data.get("FileName")
                    channel = r.get("channel")
                else:
                    category = r.get("audit_type") or r.get("program") or "unknown"
                    user = r.get("user") or data.get("auid") or data.get("uid") or data.get("acct")
                    proc = r.get("program")
                    provider = r.get("program") or r.get("audit_type")
                    eid = r.get("audit_type")
                    cmd = data.get("cmd") or data.get("command")
                    path = data.get("name") or data.get("path")
                    channel = r.get("program") or r.get("audit_type")

                event = {
                    "timestamp": t,
                    "hostname": r.get("hostname"),
                    "source_type": source,
                    "event_category": category,
                    "severity": r.get("severity") or data.get("severity"),
                    "user": user,
                    "process_name": proc,
                    "process_id": r.get("process_id", r.get("pid")),
                    "src_ip": r.get("src_ip") or data.get("SourceIp") or data.get("SourceAddress"),
                    "src_port": r.get("src_port") or data.get("SourcePort"),
                    "dst_ip": r.get("dst_ip") or data.get("DestinationIp") or data.get("DestinationAddress"),
                    "dst_port": r.get("dst_port") or data.get("DestinationPort"),
                    "protocol": r.get("protocol") or data.get("Protocol"),
                    "event_id": str(eid) if eid is not None else None,
                    "channel": channel,
                    "provider": provider,
                    "command_line": cmd,
                    "file_path": path,
                    "message": r.get("message") or r.get("raw_message"),
                    "raw_message": r.get("raw_message"),
                    "source_origin": r.get("source_origin"),
                    "parsed_fields": data
                }

                missing = [x for x in REQUIRED if event.get(x) is None]
                if missing:
                    raise ValueError("missing required: " + ", ".join(missing))

                NORMAL.append({x: event.get(x) for x in FIELDS})
                good += 1

            except Exception as e:
                QUAR.append({
                    "quarantine_reason": str(e),
                    "source_file": file,
                    "source_line": n,
                    "original_record": r or line.strip()
                })
                bad += 1

    print(f"{source:<17}: normalized {good} quarantined {bad}")
    return good, bad

w = run("windows_events.json", "windows")
l = run("linux_events.json", "linux")

with open("normalized_events.json", "w") as f:
    f.writelines(json.dumps(x, separators=(",", ":")) + "\n" for x in NORMAL)

with open("quarantine.json", "w") as f:
    f.writelines(json.dumps(x, separators=(",", ":")) + "\n" for x in QUAR)

print(f"{'total':17}: normalized {w[0]+l[0]} quarantined {w[1]+l[1]}")
print("normalized_events.json written")
print("quarantine.json  written")
PY
