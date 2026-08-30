#!/bin/bash
set -euo pipefail

python3 <<'PY'
import json,re
from pathlib import Path
from datetime import datetime,timezone

cfg=json.load(open("event_schema.json"))
spec={x["name"]:x for x in cfg["fields"]}
must={x for x,v in spec.items() if v["required"]}
out=[]; bad=[]

def conv(v):
    if not v:return None
    s=str(v).strip()
    try:
        if s.startswith("audit("):
            s=re.search(r"audit\(([\d.]+)",s).group(1)
        if re.fullmatch(r"[\d.]+",s):
            d=datetime.fromtimestamp(float(s),timezone.utc)
        else:
            d=datetime.fromisoformat(s.replace("Z","+00:00"))
            d=d.replace(tzinfo=d.tzinfo or timezone.utc)
        return d.astimezone(timezone.utc).isoformat().replace("+00:00","Z")
    except (ValueError,AttributeError,OverflowError):
        m=re.match(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)$",s)
        if not m:return None
        try:
            d=datetime.strptime(
                f"{datetime.now().year} {m.group(1)} {m.group(2)} {m.group(3)}",
                "%Y %b %d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
            return d.isoformat().replace("+00:00","Z")
        except ValueError:return None

def check(k,v):
    if v is None:return k not in must
    t=spec[k]["type"]
    return {
        "string":isinstance(v,str),
        "integer":isinstance(v,int) and not isinstance(v,bool),
        "float":isinstance(v,(int,float)) and not isinstance(v,bool),
        "boolean":isinstance(v,bool),
        "timestamp":bool(conv(v)),
        "object":isinstance(v,dict),
        "array":isinstance(v,list)
    }[t]

def load(src,tag):
    good=badc=0
    if not Path(src).is_file():raise FileNotFoundError(src)

    with open(src,encoding="utf-8",errors="replace") as fh:
        for num,line in enumerate(fh,1):
            if not line.strip():continue
            rec=None
            try:
                rec=json.loads(line)
                if not isinstance(rec,dict):
                    raise ValueError("record is not an object")

                win=tag=="windows_json"
                dat=rec.get("event_data" if win else "parsed_fields") or {}
                if not isinstance(dat,dict):
                    raise ValueError("source fields are not an object")

                if win:
                    cat=rec.get("channel") or "unknown"
                    usr=rec.get("user") or dat.get("SubjectUserName") or dat.get("TargetUserName")
                    proc=rec.get("process_name") or dat.get("Image") or dat.get("ProcessName")
                    prov=rec.get("provider")
                    eid=rec.get("event_id")
                    cmd=dat.get("CommandLine")
                    path=dat.get("TargetFilename") or dat.get("FileName")
                    chan=rec.get("channel")
                else:
                    cat=rec.get("audit_type") or rec.get("program") or "unknown"
                    usr=rec.get("user") or dat.get("auid") or dat.get("uid") or dat.get("acct")
                    proc=rec.get("program")
                    prov=rec.get("program") or rec.get("audit_type")
                    eid=rec.get("audit_type")
                    cmd=dat.get("cmd") or dat.get("command")
                    path=dat.get("name") or dat.get("path")
                    chan=rec.get("program") or rec.get("audit_type")

                evt={
                    "timestamp":conv(rec.get("timestamp_raw") or rec.get("timestamp")),
                    "hostname":rec.get("hostname") or "unknown",
                    "source_type":tag,
                    "event_category":cat,
                    "severity":rec.get("severity") or dat.get("severity"),
                    "user":usr,
                    "process_name":proc,
                    "process_id":rec.get("process_id",rec.get("pid")),
                    "src_ip":rec.get("src_ip") or dat.get("SourceIp") or dat.get("SourceAddress"),
                    "src_port":rec.get("src_port") or dat.get("SourcePort"),
                    "dst_ip":rec.get("dst_ip") or dat.get("DestinationIp") or dat.get("DestinationAddress"),
                    "dst_port":rec.get("dst_port") or dat.get("DestinationPort"),
                    "protocol":rec.get("protocol") or dat.get("Protocol"),
                    "event_id":str(eid) if eid is not None else None,
                    "channel":chan,
                    "provider":prov,
                    "command_line":cmd,
                    "file_path":path,
                    "message":rec.get("message") or rec.get("raw_message"),
                    "raw_message":rec.get("raw_message"),
                    "source_origin":rec.get("source_origin") or "evidence_pack",
                    "parsed_fields":dat
                }

                evt={k:evt.get(k) for k in spec}
                miss=[k for k in must if evt[k] is None]
                wrong=[k for k,v in evt.items() if not check(k,v)]

                if miss:raise ValueError("missing required: "+", ".join(miss))
                if wrong:raise ValueError("invalid field type: "+", ".join(wrong))

                out.append(evt);good+=1

            except Exception as e:
                bad.append({
                    "quarantine_reason":str(e),
                    "source_file":src,
                    "source_line":num,
                    "original_record":rec if rec is not None else line.strip()
                })
                badc+=1

    print(f"{tag:<17}: normalized {good} quarantined {badc}")
    return good,badc

a,b=load("windows_events.json","windows_json")
c,d=load("linux_events.json","linux_text")

with open("normalized_events.json","w",encoding="utf-8") as fh:
    for x in out:fh.write(json.dumps(x,separators=(",",":"))+"\n")

with open("quarantine.json","w",encoding="utf-8") as fh:
    for x in bad:fh.write(json.dumps(x,separators=(",",":"))+"\n")

print(f"total            : normalized {a+c} quarantined {b+d}")
print("normalized_events.json written")
print("quarantine.json  written")
