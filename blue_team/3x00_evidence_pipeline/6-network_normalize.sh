#!/bin/bash
set -euo pipefail

BASE="${1:-$HOME/evidence_pack_primary}/network"

python3 - "$BASE" <<'PY'
import sys,json,csv,re
from pathlib import Path
from datetime import datetime,timezone

d=Path(sys.argv[1])
out=Path("normalized_events.json")
net=Path("network_events.json")
events=[]

def time(v):
    if not v:return None
    v=str(v).strip()
    try:
        if re.fullmatch(r"\d+(?:\.\d+)?",v):
            return datetime.fromtimestamp(float(v),timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        v=v.replace("Z","+00:00")
        v=re.sub(r"([+-]\d{2})(\d{2})$",r"\1:\2",v)
        t=datetime.fromisoformat(v)
        return t.replace(tzinfo=t.tzinfo or timezone.utc).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError,OverflowError):
        try:
            return datetime.strptime(v,"%m/%d/%Y %I:%M:%S %p").replace(
                tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            return None

def port(v):
    return int(v) if v and str(v).isdigit() else None

def add(src,cat,host,row,raw,data,sev="info"):
    events.append({
        "timestamp":time(row),
        "hostname":host,
        "source_type":src,
        "event_category":cat,
        "severity":sev,
        "user":None,
        "process_name":None,
        "process_id":None,
        "src_ip":data.get("src_ip"),
        "src_port":port(data.get("src_port")),
        "dst_ip":data.get("dst_ip"),
        "dst_port":port(data.get("dst_port")),
        "protocol":data.get("protocol"),
        "event_id":data.get("event_id"),
        "provider":src,
        "raw_message":raw,
        "event_data":data.get("event_data",{}),
        "source_origin":row
    })

def firewall():
    p=d/"firewall.csv"; n=0
    if not p.is_file(): return n
    with p.open(encoding="utf-8",errors="replace") as f:
        for r in csv.DictReader(f):
            a=r.get("action")
            add("firewall","network","firewall-gateway",r,
                f"action={a} src={r.get('src_ip')}:{r.get('src_port')} dst={r.get('dst_ip')}:{r.get('dst_port')} proto={r.get('protocol')}",
                {"src_ip":r.get("src_ip"),"src_port":r.get("src_port"),
                 "dst_ip":r.get("dst_ip"),"dst_port":r.get("dst_port"),
                 "protocol":r.get("protocol"),
                 "event_data":{"action":a,"interface":r.get("interface"),
                 "rule_id":r.get("rule_id"),"bytes_in":r.get("bytes_in"),
                 "bytes_out":r.get("bytes_out")}},
                "info" if a=="ALLOW" else "medium")
            n+=1
    return n

def suricata():
    p=d/"suricata_eve.json"; n=0
    if not p.is_file(): return n
    with p.open(encoding="utf-8",errors="replace") as f:
        for line in f:
            try:
                r=json.loads(line); a=r.get("alert",{})
                s=a.get("severity")
                sev={1:"critical",2:"medium",3:"low"}.get(s,"info")
                add("suricata","network_alert",r.get("host") or "suricata-sensor",r.get("timestamp"),
                    a.get("signature") or line,
                    {"src_ip":r.get("src_ip"),"src_port":r.get("src_port"),
                     "dst_ip":r.get("dest_ip"),"dst_port":r.get("dst_port"),
                     "protocol":r.get("proto"),"event_id":str(a["signature_id"]) if a.get("signature_id") else None,
                     "event_data":{"signature":a.get("signature"),"category":a.get("category"),
                     "action":a.get("action")}},sev)
                n+=1
            except (json.JSONDecodeError,TypeError): continue
    return n

def pcap():
    p=d/"pcap_summary.json"; n=0
    if not p.is_file(): return n
    with p.open(encoding="utf-8",errors="replace") as f:
        for line in f:
            try:
                r=json.loads(line)
                add("pcap","network_flow",r.get("sensor_host") or "pcap-analyzer",r.get("start_time"),
                    r.get("summary") or f"Flow {r.get('src_ip')} -> {r.get('dst_ip')}",
                    {"src_ip":r.get("src_ip"),"src_port":r.get("src_port"),
                     "dst_ip":r.get("dst_ip"),"dst_port":r.get("dst_port"),
                     "protocol":r.get("protocol"),
                     "event_data":{"end_time":r.get("end_time"),
                     "packet_count":r.get("packet_count"),"byte_count":r.get("byte_count")}})
                n+=1
            except (json.JSONDecodeError,TypeError): continue
    return n

counts=[
    ("firewall.csv",firewall()),
    ("suricata_eve.json",suricata()),
    ("pcap_summary.json",pcap())
]

with net.open("w",encoding="utf-8") as f:
    for e in events:f.write(json.dumps(e,separators=(",",":"))+"\n")

with out.open("a",encoding="utf-8") as f:
    for e in events:f.write(json.dumps(e,separators=(",",":"))+"\n")

for name,n in counts:
    print(f"{name:<20}: {n:7} records normalized")
print("appended to normalized_events.json")
print("network_events.json written")
PY
