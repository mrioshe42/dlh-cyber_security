#!/bin/bash
set -euo pipefail

python3 <<'PY'
import json, re, hashlib, sys
from pathlib import Path
from datetime import datetime, timezone

src = Path("normalized_events.json")
dst = Path("cleaned_events.json")
log = Path("cleaning_log.json")

if not src.is_file():
    print("Error: normalized_events.json not found.", file=sys.stderr)
    sys.exit(1)

good, fixes = [], []
stats = {
    "malformed": [0, 0, 0],
    "duplicates": [0, 0],
    "hostname": 0,
    "encoding": [0, 0],
    "timezone": 0
}

def rid(r):
    return r.get("event_id") or hashlib.md5(
        json.dumps(r, sort_keys=True).encode()
    ).hexdigest()[:10]

def parse_time(v):
    if not v:
        return None
    v = str(v).strip()

    try:
        if re.fullmatch(r"\d+(?:\.\d+)?", v):
            return datetime.fromtimestamp(float(v), timezone.utc)

        v = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", v.replace("Z", "+00:00"))
        t = datetime.fromisoformat(v)
        return t.replace(
            tzinfo=t.tzinfo or timezone.utc
        ).astimezone(timezone.utc)

    except (ValueError, OverflowError):
        return None

def add(kind, old, new, ident, why):
    fixes.append({
        "defect_type": kind,
        "original_value": old,
        "corrected_value": new,
        "record_id": ident,
        "reason": why
    })

records = []

with src.open(encoding="utf-8", errors="replace") as f:
    for num, line in enumerate(f, 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError("record is not a JSON object")
            records.append(item)
        except Exception as e:
            stats["malformed"][0] += 1
            stats["malformed"][2] += 1
            add(
                "malformed_json_record", line.strip()[:100], None,
                f"line_{num}", f"Invalid JSON record: {e}"
            )

times = []
valid = []

for item in records:
    ident = rid(item)
    old = item.get("timestamp")
    dt = parse_time(old)

    if not dt:
        stats["malformed"][0] += 1
        stats["malformed"][2] += 1
        add(
            "malformed_timestamp", old, None, ident,
            "Timestamp could not be parsed; record dropped."
        )
        continue

    new = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    if old != new:
        stats["malformed"][0] += 1
        stats["malformed"][1] += 1
        add(
            "malformed_timestamp", old, new, ident,
            "Timestamp converted to ISO 8601 UTC."
        )
        item["timestamp"] = new

    times.append(dt)
    valid.append(item)

if times:
    low, high = min(times), max(times)
else:
    low = high = None

seen = set()

for item in valid:
    ident = rid(item)

    host = item.get("hostname")
    if host and host != host.lower():
        fixed = host.lower()
        item["hostname"] = fixed
        stats["hostname"] += 1
        add(
            "hostname_case_inconsistency", host, fixed, ident,
            "Hostname normalized to lowercase."
        )

    msg = item.get("raw_message")
    if isinstance(msg, str) and ("\ufffd" in msg or "Ã" in msg or "Â" in msg):
        stats["encoding"][0] += 1
        try:
            fixed = msg.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            fixed = msg.replace("\ufffd", "")

        if fixed != msg:
            item["raw_message"] = fixed
            stats["encoding"][1] += 1
            add(
                "encoding_error", msg, fixed, ident,
                "Detected replacement characters or mojibake and repaired text."
            )

    dt = parse_time(item["timestamp"])
    if low and high and (dt < low or dt > high):
        stats["timezone"] += 1
        add(
            "suspected_wrong_tz", item["timestamp"], item["timestamp"], ident,
            "Timestamp falls outside the expected evidence-pack date range."
        )

    key = (
        item.get("timestamp"),
        item.get("hostname"),
        item.get("source_type"),
        item.get("raw_message")
    )

    if key in seen:
        stats["duplicates"][0] += 1
        stats["duplicates"][1] += 1
        add(
            "duplicate_record", str(key), None, ident,
            "Exact duplicate removed; first occurrence retained."
        )
        continue

    seen.add(key)
    good.append(item)

with dst.open("w", encoding="utf-8") as f:
    for item in good:
        f.write(json.dumps(item, separators=(",", ":")) + "\n")

with log.open("w", encoding="utf-8") as f:
    for item in fixes:
        f.write(json.dumps(item, separators=(",", ":")) + "\n")

print(f"malformed timestamps   : detected {stats['malformed'][0]} repaired {stats['malformed'][1]} dropped {stats['malformed'][2]}")
print(f"duplicates             : detected {stats['duplicates'][0]} removed {stats['duplicates'][1]}")
print(f"hostname case          : normalized {stats['hostname']}")
print(f"encoding errors        : detected {stats['encoding'][0]} repaired {stats['encoding'][1]}")
print(f"suspected wrong tz     : flagged {stats['timezone']}")
print("cleaned_events.json    written")
print("cleaning_log.json      written")
PY
