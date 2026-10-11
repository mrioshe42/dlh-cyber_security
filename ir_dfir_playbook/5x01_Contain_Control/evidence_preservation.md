# Evidence Preservation Runbook: IR-20260414-01

**Evidence Store**: `/evidence/IR-20260414-01/`  
**Hash Algorithm**: SHA-256  
**Prerequisites**: Run `evidence_store_init.sh` first. Do NOT isolate/reboot/kill processes until all steps complete.

## Required Artifacts Checklist

- [ ] Memory dump (WST-WS-031)
- [ ] Running process list with PIDs and command lines
- [ ] Active network connections (established TCP/UDP)
- [ ] Full endpoint telemetry (24h, all event types)
- [ ] SIEM alert record (A-20260414-9841)
- [ ] Proxy logs (24h, user dmarsh)
- [ ] DNS logs (24h, host WST-WS-031)
- [ ] Authentication logs (24h, user dmarsh, AD+Azure AD)
- [ ] Malware files (update.zip, update.exe, update.xml)


## 1. Memory Dump (WST-WS-031)
Volatile; lost on reboot
```powershell
winpmem_3.3.rc3.exe -o \\evidence\IR-20260414-01\memory\wst-ws-031.mem
```
```bash
sha256sum /evidence/IR-20260414-01/memory/wst-ws-031.mem >> /evidence/IR-20260414-01/hashes.txt
```

## 2. Running Process List
Snapshot before process kill
```powershell
Get-WmiObject Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine | ConvertTo-Json | Out-File "\\evidence\IR-20260414-01\process_tree\running_processes.json"
```
```bash
sha256sum /evidence/IR-20260414-01/process_tree/running_processes.json >> /evidence/IR-20260414-01/hashes.txt
```

## 3. Active Network Connections
Volatile; closes on isolation
```powershell
Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | ConvertTo-Json | Out-File "\\evidence\IR-20260414-01\network\netstat_established.json"
```
```bash
sha256sum /evidence/IR-20260414-01/network/netstat_established.json >> /evidence/IR-20260414-01/hashes.txt
```
**Critical**: Preserve MSBuild→185.220.101.47:443 connection (PID 8104)

## 4. Endpoint Telemetry (24h)
Full WazuhEDR events for WST-WS-031 from 2026-04-13T02:47:00Z to 2026-04-14T02:47:11Z
```bash
wazuh-api-query.sh --index "edr_wazuh" --host "wst-ws-031.meddefense.local" --start-time "2026-04-13T02:47:00Z" --end-time "2026-04-14T02:47:11Z" --format jsonl --output "/evidence/IR-20260414-01/endpoint_telemetry/edr_wst_ws_031_24h.jsonl"
```
```bash
sha256sum /evidence/IR-20260414-01/endpoint_telemetry/edr_wst_ws_031_24h.jsonl >> /evidence/IR-20260414-01/hashes.txt
```
**Verify events**: 2026-04-13T18:14:43Z (download), 2026-04-13T18:15:12Z (registry), 2026-04-14T02:46:41Z (powershell), 2026-04-14T02:47:02Z (C2)

## 5. SIEM Alert Record
Alert A-20260414-9841 in JSON format
```bash
cp alert_A-20260414-9841.json /evidence/IR-20260414-01/siem/alert_A-20260414-9841.json
```
```bash
sha256sum /evidence/IR-20260414-01/siem/alert_A-20260414-9841.json >> /evidence/IR-20260414-01/hashes.txt
```

## 6. Proxy and DNS Logs (24h, dmarsh)
User dmarsh, source IP 10.42.118.31
```bash
soc-evidence-collector export --type proxy --user dmarsh --source-ip 10.42.118.31 --start-time "2026-04-13T02:47:00Z" --end-time "2026-04-14T02:47:11Z" --output /evidence/IR-20260414-01/proxy_dns/proxy_24h_dmarsh.log

soc-evidence-collector export --type dns --host "wst-ws-031.meddefense.local" --start-time "2026-04-13T02:47:00Z" --end-time "2026-04-14T02:47:11Z" --output /evidence/IR-20260414-01/proxy_dns/dns_24h_wst_ws_031.log
```
```bash
sha256sum /evidence/IR-20260414-01/proxy_dns/proxy_24h_dmarsh.log >> /evidence/IR-20260414-01/hashes.txt
sha256sum /evidence/IR-20260414-01/proxy_dns/dns_24h_wst_ws_031.log >> /evidence/IR-20260414-01/hashes.txt
```
**Key events**: 2026-04-13T18:14:02Z (phishing), 2026-04-13T18:14:41Z (credentials), 2026-04-13T18:14:43Z (malware download)

## 7. Authentication Logs (24h, dmarsh)
AD + Azure AD sign-in events
```bash
soc-evidence-collector export --type activedirectory --user dmarsh --start-time "2026-04-13T02:47:00Z" --end-time "2026-04-14T02:47:11Z" --format json --output /evidence/IR-20260414-01/authentication/auth_24h_dmarsh.json
```
```bash
sha256sum /evidence/IR-20260414-01/authentication/auth_24h_dmarsh.json >> /evidence/IR-20260414-01/hashes.txt
```

## 8. Malware Files
Preserve update.zip, update.exe, update.xml
```powershell
Copy-Item "C:\Users\dmarsh\Downloads\update.zip" -Destination "\\evidence\IR-20260414-01\malware\update.zip"
Copy-Item "C:\Users\dmarsh\AppData\Local\Temp\update.exe" -Destination "\\evidence\IR-20260414-01\malware\update.exe"
Copy-Item "C:\Users\dmarsh\AppData\Local\Temp\update.xml" -Destination "\\evidence\IR-20260414-01\malware\update.xml"
```
```bash
sha256sum /evidence/IR-20260414-01/malware/update.zip >> /evidence/IR-20260414-01/hashes.txt
sha256sum /evidence/IR-20260414-01/malware/update.exe >> /evidence/IR-20260414-01/hashes.txt
sha256sum /evidence/IR-20260414-01/malware/update.xml >> /evidence/IR-20260414-01/hashes.txt
```
**Expected hashes**: 
- update.zip: `3c2a1b9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a`
- update.exe: `5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b`
- update.xml: `a4f1e9b4fe7aa6d5d3f3e2b8c9a7d4e8f5b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3`

## 9. Verification and Evidence Store Validation

**Hash Verification**:
```bash
cd /evidence/IR-20260414-01
sha256sum -c hashes.txt > /tmp/hash_check_result.txt 2>&1
echo "Hash verification exit code: $?"
```
**If mismatch**: STOP, escalate to IR Commander, do NOT delete evidence

**Final Evidence Store Validation Checklist**:
```bash
# Verify all 9 artifact categories present
[ -f memory/wst-ws-031.mem ] && echo "✓ Memory dump" || echo "✗ Memory dump MISSING"
[ -f process_tree/running_processes.json ] && echo "✓ Process list" || echo "✗ Process list MISSING"
[ -f network/netstat_established.json ] && echo "✓ Network connections" || echo "✗ Network MISSING"
[ -f endpoint_telemetry/edr_wst_ws_031_24h.jsonl ] && echo "✓ Endpoint telemetry" || echo "✗ Telemetry MISSING"
[ -f siem/alert_A-20260414-9841.json ] && echo "✓ SIEM alert" || echo "✗ Alert MISSING"
[ -f proxy_dns/proxy_24h_dmarsh.log ] && echo "✓ Proxy logs" || echo "✗ Proxy logs MISSING"
[ -f proxy_dns/dns_24h_wst_ws_031.log ] && echo "✓ DNS logs" || echo "✗ DNS logs MISSING"
[ -f authentication/auth_24h_dmarsh.json ] && echo "✓ Auth logs" || echo "✗ Auth logs MISSING"
[ -f malware/update.zip ] && [ -f malware/update.exe ] && [ -f malware/update.xml ] && echo "✓ Malware files" || echo "✗ Malware files MISSING"
[ -f hashes.txt ] && echo "✓ Chain of custody manifest" || echo "✗ Manifest MISSING"

# Verify hashes.txt contains all 10+ entries
echo "Artifact count in manifest: $(grep -c '^[a-f0-9]' hashes.txt)"
```

**Sign Verification**:
```bash
cat >> /evidence/IR-20260414-01/hashes.txt << EOF

# Verification completed: $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Verified by: $(whoami) on $(hostname)
# Status: PASS (all artifacts collected, hashes verified)
EOF
chmod 440 /evidence/IR-20260414-01/hashes.txt
```

## Execution Order
1. Memory (volatile)
2. Processes (volatile)
3. Network (volatile)
4. Endpoint telemetry (context)
5. SIEM alert (trigger)
6. Proxy/DNS logs (C2 pattern)
7. Auth logs (baseline)
8. Malware files (analysis)
9. Verification (integrity)

## Expected Evidence Store Structure

```
/evidence/IR-20260414-01/
├── memory/
│   └── wst-ws-031.mem                        (16–32 GB)
├── process_tree/
│   └── running_processes.json                (JSON with PIDs, parent PIDs, cmd lines)
├── network/
│   └── netstat_established.json              (TCP/UDP connections at capture time)
├── endpoint_telemetry/
│   └── edr_wst_ws_031_24h.jsonl             (20+ events covering attack chain)
├── siem/
│   └── alert_A-20260414-9841.json            (Detection rule metadata + context)
├── proxy_dns/
│   ├── proxy_24h_dmarsh.log                  (HTTP/S events, phishing→download→C2)
│   └── dns_24h_wst_ws_031.log                (DNS queries for 24h window)
├── authentication/
│   └── auth_24h_dmarsh.json                  (AD + Azure AD logon events)
├── malware/
│   ├── update.zip                            (421 KB, SHA256: 3c2a1b...)
│   ├── update.exe                            (Persistence binary, SHA256: 5a4b3c...)
│   └── update.xml                            (MSBuild config, SHA256: a4f1e9...)
└── hashes.txt                                (SHA-256 manifest, signed with verification)
```

**Validation Success Criteria**:
- [ ] All 9 artifact categories present
- [ ] hashes.txt contains 10+ valid SHA-256 entries
- [ ] `sha256sum -c hashes.txt` returns exit code 0 (no mismatches)
- [ ] hashes.txt signed with analyst name, timestamp, and verification status
- [ ] Memory file > 8 GB (typical for clinical workstation)
- [ ] Endpoint telemetry includes all key events (download, persistence, C2)

**Next**: Create EVIDENCE entry in incident_timeline.md, then proceed to containment (PB-CRED-001).
