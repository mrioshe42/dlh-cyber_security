#!/bin/bash
set -euo pipefail

python3 <<'PY'
import json, re
from pathlib import Path
from datetime import datetime, timezone

schema = json.load(open("event_schema.json"))
fields = schema["fields"]
required = {f["name"] for f in fields if f["required"]}
types = {f["name"]: f["type"] for f in fields}

ok, bad = [], []

def timestamp(v):
    if not v:
        return None
    s = str(v).strip()
    try:
        if s.startswith("audit("):
            s = re.search(r"audit\(([\d.]+)", s).group(1)
        if re.fullmatch(r"[\d.]+", s):
            d = datetime.fromtimestamp(float(s), timezone.utc)
        else:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
            d = d.replace(tzinfo=d.tzinfo or timezone.utc)
        return d.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, AttributeError, OverflowError):
        return None

def valid(name, value):
    if value is None:
        return name not in required
    t = types[name]
    return {
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "float": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "timestamp": bool(timestamp(value)),
        "object": isinstance(value, dict),
        "array": isinstance(value, list)
    }[t]

def normalize(file, source):
    good = badc = 0

    if not Path(file).is_file():
        raise FileNotFoundError(file)

    with open(file, encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue

            r = None
            try:
                r = json.loads(line)
                if not isinstance(r, dict):
                    raise ValueError("record is not an object")

                data_key = "event_data" if source == "windows_json" else "parsed_fields"
                data = r.get(data_key)
                if data is None:
                    data = {}
                if not isinstance(data, dict):
                    raise ValueError(f"{data_key} is not an object")

                if source == "windows_json":
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
                    "timestamp": timestamp(r.get("timestamp_raw") or r.get("timestamp")),
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
                    "source_origin": r.get("source_origin") or "evidence_pack",
                    "parsed_fields": data
                }

                for f in fields:
                    name = f["name"]
                    event.setdefault(name, None)

                missing = [x for x in required if event[x] is None]
                invalid = [x for x, v in event.items() if x in types and not valid(x, v)]

                if missing:
                    raise ValueError("missing required: " + ", ".join(missing))
                if invalid:
                    raise ValueError("invalid field types: " + ", ".join(invalid))

                ok.append(event)
                good += 1

            except Exception as e:
                bad.append({
                    "quarantine_reason": str(e),
                    "source_file": file,
                    "source_line": line_no,
                    "original_record": r if r is not None else line.strip()
                })
                badc += 1

    print(f"{source:<17}: normalized {good} quarantined {badc}")
    return good, badc

wn, wq = normalize("windows_events.json", "windows_json")
ln, lq = normalize("linux_events.json", "linux_text")

with open("normalized_events.json", "w", encoding="utf-8") as f:
    for r in ok:
        f.write(json.dumps(r, separators=(",", ":")) + "\n")

with open("quarantine.json", "w", encoding="utf-8") as f:
    for r in bad:
        f.write(json.dumps(r, separators=(",", ":")) + "\n")

print(f"total            : normalized {wn+ln} quarantined {wq+lq}")
print("normalized_events.json written")
print("quarantine.json  written")
PY
