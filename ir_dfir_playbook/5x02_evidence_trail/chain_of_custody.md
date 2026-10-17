# Chain of Custody: LH-2026-0414-01

## Case Header

- **Case number:** LH-2026-0414-01
- **Incident ID:** IR-2026-0414-01 (5x01 files also call it IR-20260414-01)
- **Lead investigator:** Massimo
- **Date opened:** 2026-04-14
- **Litigation hold reference:** Memo from Helena Reyes, 2026-04-14T07:30Z

## Artifact Registry

Custody began at acquisition, not at first analysis. Mike Torres took no hashes at acquisition (`5x02/acquisition_notes.md`), so there is no trusted starting hash. The first hash we compute is the **baseline**. It proves nothing about the time before it.

| Artifact ID | Name | Format | Acquired By | Acquired At (UTC) | Tool | SHA-256 at Acquisition | Storage Path | Access Controls |
|---|---|---|---|---|---|---|---|---|
| ART-001 | wst-ws-031.dd | RAW | Mike Torres | 2026-04-14 04:51 – 06:14 | FTK Imager (raw/dd) | NOT RECORDED | `\\evidence\share\IR-2026-0414-01\wst-ws-031.dd` | read-only, IR team only (intended, not verified) |
| ART-002 | wst-ws-031.mem | RAW | Mike Torres | 2026-04-14 03:02 | WinPmem v3.3-rc3 | NOT RECORDED | `\\evidence\share\IR-2026-0414-01\wst-ws-031.mem` | read-only, IR team only (intended, not verified) |
| ART-003 | wst-ws-017.mem | RAW | Mike Torres | 2026-04-14 03:38 | WinPmem v3.3-rc3 | NOT RECORDED | `\\evidence\share\IR-2026-0414-01\wst-ws-017.mem` | read-only, IR team only (intended, not verified) |
| ART-004 | siem_alert_export.json | JSON | soc-evidence-collector | 2026-04-14 02:58:04 | SIEM export (MedDefense-SIEM-Alert-v1.2) | NOT RECORDED | `5x02/siem_alert_export.json` | working copy, rw (not read-only) |
| ART-005 | ad_auth_log.jsonl | JSONL | NOT RECORDED | NOT RECORDED (after 03:43:30, last event) | NOT RECORDED | NOT RECORDED | `5x02/ad_auth_log.jsonl` | working copy, rw (not read-only) |
| ART-006 | proxy_log.jsonl | JSONL | NOT RECORDED | NOT RECORDED (after 03:27:45, last event) | NOT RECORDED | NOT RECORDED | `5x02/proxy_log.jsonl` | working copy, rw (not read-only) |

## Baseline Hashes

| Artifact ID | SHA-256 (baseline) | Computed (UTC) |
|---|---|---|
| ART-001 | PENDING (file not available to the analyst yet) | |
| ART-002 | PENDING (file not available to the analyst yet) | |
| ART-003 | PENDING (file not available to the analyst yet) | |
| ART-004 | `d270a87e00d33f6f9f7261fd18b40db76a64bb4be53b08bf9c29f4f1b420f63d` | 2026-10-17 07:32 |
| ART-005 | `0596d6b2de97fe3bd6ccd7a65cb4e3eb3b2a5094c8d96787eaf38c30de25fbed` | 2026-10-17 07:32 |
| ART-006 | `340c4a575bf6dc0104e4a21c7c8219a1406615d8e3ffd08b66c2d9dcb73a68e9` | 2026-10-17 07:32 |

## Known Gaps and Deviations

- **No hashes** at acquisition for any artifact. No custody form was written. Nobody recorded who had access between acquisition and the evidence share.
- **DEVIATION, ART-001:** the live disk was mounted read-write before imaging and Explorer was opened on it. Access times on the source may have changed. The image was taken without remounting read-only.
- **DEVIATION, ART-001:** Massimo opened an SSH/PowerShell session to the live host at 03:21:30Z (`5x01/containment_execution.md`), before the disk image was taken. Logged below.
- **Copy path:** ART-002 went through Mike's workstation and a USB3 NVMe enclosure to the share. ART-003 used the "same workflow". Integrity of that hop cannot be proven.
- **Conflicting record:** `5x01/incident_timeline.md` (03:14:18Z) says the memory dump was collected by the SOC Evidence Collector with hashes verified in `/evidence/IR-20260414-01/hashes.txt`. Mike says his capture was at 03:02Z with no hash, and used a different path. Either there are two memory dumps with the same name, or one record is wrong. Find `hashes.txt` and confirm which file ART-002 is. Until then, treat it as no trusted hash.
- **Sources are gone:** WST-WS-031 and WST-WS-017 were rebuilt at 10:12Z and 11:04Z on 2026-04-14 (`5x01/incident_timeline.md`). These copies cannot be re-acquired.
- **Custody holes:** no record between the handoff (2026-04-14 07:42Z) and the first logged analyst access below. ART-004 to ART-006 are writable working copies.

## Access Log

| Timestamp (UTC) | Actor | Artifact ID | Action | Tool | Hash Verified | Notes |
|---|---|---|---|---|---|---|
| 2026-04-14 02:58:04 | soc-evidence-collector | ART-004 | export | SIEM export | no | From the file's own metadata. No hash taken. |
| 2026-04-14 03:02 | Mike Torres | ART-002 | acquire_memory | WinPmem v3.3-rc3 | no | From acquisition notes. Host still live. No hash taken. |
| 2026-04-14 03:21:30 | Massimo | ART-001 (source host) | remote_session | SSH + PowerShell | no | DEVIATION: live-host access before imaging. From `5x01/containment_execution.md`. |
| 2026-04-14 03:38 | Mike Torres | ART-003 | acquire_memory | WinPmem v3.3-rc3 | no | From acquisition notes. No hash taken. |
| 2026-04-14 before 04:51 (exact time not recorded) | Mike Torres | ART-001 (source disk) | read_write_mount | Windows / Explorer | no | DEVIATION: see Known Gaps. From acquisition notes. |
| 2026-04-14 04:51 – 06:14 | Mike Torres | ART-001 | acquire_disk | FTK Imager | no | Host already on VLAN 999. No hash taken. |
| 2026-04-14 07:42 | Mike Torres | ART-001, ART-002, ART-003 | handoff | n/a | no | Acquisition notes handed to the forensic analyst. |
| 2026-10-17 07:32 | Massimo | ART-004 | hash_verify | sha256sum | no | No earlier hash to compare. Baseline established; hash stored in Baseline Hashes. |
| 2026-10-17 07:32 | Massimo | ART-005 | hash_verify | sha256sum | no | No earlier hash to compare. Baseline established; hash stored in Baseline Hashes. |
| 2026-10-17 07:32 | Massimo | ART-006 | hash_verify | sha256sum | no | No earlier hash to compare. Baseline established; hash stored in Baseline Hashes. |

**Next entries:** baseline `hash_verify` for ART-001, ART-002, ART-003 once the files are available. Do this before any analysis.

## Rules

1. Hash each artifact **before** the first analysis access.
2. Every later access gets a new row, even a quick one.
3. If a hash does not match the baseline, log it right away as a `DEVIATION` note.
