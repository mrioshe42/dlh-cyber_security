#!/bin/bash
set -euo pipefail

PACK_ROOT="${1:-$HOME/evidence_pack_primary}"
OUT_FILE="linux_events.json"

python3 - "$PACK_ROOT" "$OUT_FILE" <<'PY'
import sys, json, re
from pathlib import Path

root = Path(sys.argv[1])
out = Path(sys.argv[2])
l_dir = root / "linux"
t_dir = root / "student_telemetry"

recs = []

def parse_kv(line):
    m = re.findall(r'([a-zA-Z0-9_\-\.]+)=(?:"([^"]*)"|([^\s]+))', line)
    return {k: (v1 if v1 else v2) for k, v1, v2 in m}

def add_rec(ts_raw, hostname, prog, pid, user, raw_msg, pf):
    r = {
        "timestamp_raw": ts_raw,
        "hostname": hostname,
        "program": prog,
        "pid": pid,
        "user": user,
        "raw_message": raw_msg,
        "parsed_fields": pf,
        "source_origin": "evidence_pack"
    }
    recs.append(r)

def parse_syslog_like(p):
    if not p.is_file():
        raise FileNotFoundError(f"Required input file not found: {p}")
    
    cnt = 0
    regex = re.compile(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[:]+)(?:\[(\d+)\])?:?\s+(.*)$')
    
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for ln, line in enumerate(f, 1):
            raw_msg = line.rstrip('\n')
            if not raw_msg.strip():
                continue
            
            m = regex.match(raw_msg)
            ts_raw = m.group(1) if m else None
            hostname = m.group(2) if m else None
            prog = m.group(3).strip() if m else None
            pid = m.group(4) if m and m.group(4) else None
            
            user = None
            if m:
                um = re.search(r'(?:user|for|by|from)\s+([a-zA-Z0-9_\-\.]+)', raw_msg)
                user = um.group(1) if um else None
            
            pf = parse_kv(raw_msg)
            add_rec(ts_raw, hostname, prog, pid, user, raw_msg, pf)
            cnt += 1
    
    return cnt

def parse_audit(p):
    if not p.is_file():
        raise FileNotFoundError(f"Required input file not found: {p}")
    
    ln_cnt = 0
    rec_cnt = 0
    audit_re = re.compile(r'type=([A-Z_]+).*?msg=audit\(([^)]+)\)')
    audit_ts_re = re.compile(r'msg=audit\([^)]+\)')
    
    c_gid = None
    c_lines = []
    c_atype = None
    c_audit_ts = None
    
    def flush_grp(gid, lines, atype, audit_ts):
        nonlocal rec_cnt
        if not lines:
            return
        
        raw_msg = "\n".join(lines)
        pf = {"audit_group_id": gid}
        for l in lines:
            pf.update(parse_kv(l))
        
        user = pf.get("auid") or pf.get("uid")
        hostname = pf.get("node") or pf.get("hostname")
        
        recs.append({
            "timestamp_raw": audit_ts,
            "hostname": hostname,
            "audit_type": atype or "UNKNOWN",
            "pid": pf.get("pid"),
            "user": user,
            "raw_message": raw_msg,
            "parsed_fields": pf,
            "source_origin": "evidence_pack"
        })
        rec_cnt += 1
    
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            raw_msg = line.rstrip('\n')
            if not raw_msg.strip():
                continue
            ln_cnt += 1
            
            m = audit_re.search(raw_msg)
            if m:
                atype = m.group(1)
                audit_id = m.group(2)
                gid = audit_id.split(":")[-1]
                ts_match = audit_ts_re.search(raw_msg)
                audit_ts = ts_match.group(0) if ts_match else f"audit({audit_id})"
                
                if c_gid != gid:
                    if c_lines:
                        flush_grp(c_gid, c_lines, c_atype, c_audit_ts)
                        c_lines = []
                    c_gid = gid
                    c_atype = atype
                    c_audit_ts = audit_ts
                c_lines.append(raw_msg)
            else:
                if c_lines:
                    c_lines.append(raw_msg)
    
    if c_lines:
        flush_grp(c_gid, c_lines, c_atype, c_audit_ts)
    
    return ln_cnt, rec_cnt

def parse_tel(p):
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
            
            if r.get("source_origin") and r.get("source_origin") != "student_telemetry":
                raise ValueError(f"Invalid source_origin in {p} at line {ln}: {r.get('source_origin')!r}")
            
            r["source_origin"] = "student_telemetry"
            recs.append(r)
            cnt += 1
    
    return cnt

auth_cnt = parse_syslog_like(l_dir / "auth.log")
print(f"parsing auth.log      ... {auth_cnt} lines  -> ~{auth_cnt} records")

audit_ln, audit_rec = parse_audit(l_dir / "audit.log")
print(f"parsing audit.log     ... {audit_ln} lines  -> ~{audit_rec} records (grouped)")

syslog_cnt = parse_syslog_like(l_dir / "syslog")
print(f"parsing syslog        ... {syslog_cnt} lines  -> ~{syslog_cnt} records")

tel_cnt = parse_tel(t_dir / "linux_events.json")
print(f"appending student telemetry ... {tel_cnt} records")

with out.open("w", encoding="utf-8") as f:
    for r in recs:
        f.write(json.dumps(r, separators=(",", ":")) + "\n")

print(f"linux_events.json: {len(recs)} records")
PY
