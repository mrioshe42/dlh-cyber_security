#!/bin/bash
set -euo pipefail

python3 - "${1:-$HOME/evidence_pack_primary}/context" <<'PY'
import sys,json,ipaddress
from pathlib import Path

ctx=Path(sys.argv[1])
inp=Path("cleaned_events.json")
out=Path("enriched_events.json")
invf=ctx/"asset_inventory.json"
znf=ctx/"network_zones.json"

assets={}
if invf.is_file():
    with invf.open(encoding="utf-8") as f:
        data=json.load(f)
    items=data if isinstance(data,list) else data.items()
    for x in items:
        if isinstance(data,list):
            host=x.get("hostname") or x.get("host")
            if host: assets[str(host).lower()]=x
        else:
            host,x=x
            assets[str(host).lower()]=x

zones=[]
if znf.is_file():
    with znf.open(encoding="utf-8") as f:
        data=json.load(f)
    items=data if isinstance(data,list) else data.get("zones",[])
    for x in items:
        try:
            net=x.get("cidr") or x.get("network")
            name=x.get("zone") or x.get("name")
            if net and name:
                zones.append((ipaddress.ip_network(net,strict=False),name))
        except ValueError:
            pass

def zone(value):
    try:
        ip=ipaddress.ip_address(str(value).strip())
        return next((z for n,z in zones if ip in n),"unknown")
    except (ValueError,TypeError):
        return "unknown"

unknown=set()
events=[]
total=asset=src=dst=0

if inp.is_file():
    with inp.open(encoding="utf-8",errors="replace") as f:
        for line in f:
            if not line.strip(): continue
            try:
                e=json.loads(line)
                if not isinstance(e,dict): continue
            except json.JSONDecodeError:
                continue

            total+=1
            host=str(e.get("hostname","")).lower()
            a=assets.get(host)

            if a:
                e["asset"]={k:a.get(k) for k in
                            ("role","criticality","os","owner","zone")}
                asset+=1
            else:
                e["asset"]={k:"unknown" for k in
                            ("role","criticality","os","owner","zone")}
                if host: unknown.add(host)

            sz=zone(e.get("src_ip"))
            dz=zone(e.get("dst_ip"))
            e["src_zone"]=sz
            e["dst_zone"]=dz

            if e.get("src_ip") and sz!="unknown": src+=1
            if e.get("dst_ip") and dz!="unknown": dst+=1

            events.append(e)

with out.open("w",encoding="utf-8") as f:
    for e in events:
        f.write(json.dumps(e,separators=(",",":"))+"\n")

pct=lambda n:f"{n/total*100:.1f}" if total else "0.0"

print(f"events processed    : {total}")
print(f"asset context added : {asset} ({pct(asset)}%)")
print(f"src_zone resolved   : {src} ({pct(src)}%)")
print(f"dst_zone resolved   : {dst} ({pct(dst)}%)")
print(f"unknown hosts       : {len(unknown)}")
print("enriched_events.json written")
PY
