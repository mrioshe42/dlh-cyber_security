# Chain of Custody: LH-2026-0414-01

## Case Header

- **Case number:** LH-2026-0414-01
- **Incident ID:** IR-2026-0414-01
- **Lead investigator:** Massimo
- **Date opened:** 2026-04-14
- **Litigation hold reference:** Memo from Helena Reyes, 2026-04-14T07:30Z

## Artifact Registry

Custody began at acquisition, not at first analysis. Mike Torres took no hashes at acquisition (see `5x02/acquisition_notes.md`), so there is no trusted starting hash. The first hash we compute becomes the **baseline**, not proof the files are unchanged.

| Artifact ID | Name | Format | Acquired By | Acquired At (UTC) | Tool | SHA-256 at Acquisition | Storage Path | Access Controls |
|---|---|---|---|---|---|---|---|---|
| ART-001 | wst-ws-031.dd | RAW | Mike Torres | 2026-04-14 04:51 – 06:14 | FTK Imager (raw/dd) | NOT RECORDED | `\\evidence\share\IR-2026-0414-01\wst-ws-031.dd` | read-only, IR team only |
| ART-002 | wst-ws-031.mem | RAW | Mike Torres | 2026-04-14 03:02 | WinPmem v3.3-rc3 | NOT RECORDED | `\\evidence\share\IR-2026-0414-01\wst-ws-031.mem` | read-only, IR team only |
| ART-003 | wst-ws-017.mem | RAW | Mike Torres | 2026-04-14 03:38 | WinPmem v3.3-rc3 | NOT RECORDED | `\\evidence\share\IR-2026-0414-01\wst-ws-017.mem` | read-only, IR team only |

## Known Gaps

- No hashes at acquisition for any artifact.
- No chain of custody form was written at acquisition.
- Nobody recorded who had access to the files between acquisition and the SOC evidence share.
- **ART-001:** the live filesystem was mounted read-write before imaging, and Explorer was opened on it. Access times on the source may have changed. The image was taken afterward without remounting read-only.
- ART-002 and ART-003 were copied to the share through a personal workstation and an external NVMe enclosure over USB3 (documented for ART-002, same workflow for ART-003). Integrity of that hop cannot be proven.

## Access Log

| Timestamp (UTC) | Actor | Artifact ID | Action | Tool | Hash Verified | Notes |
|---|---|---|---|---|---|---|
| 2026-04-14 03:02 | Mike Torres | ART-002 | acquire_memory | WinPmem v3.3-rc3 | no | From acquisition notes. No hash taken. |
| 2026-04-14 03:38 | Mike Torres | ART-003 | acquire_memory | WinPmem v3.3-rc3 | no | From acquisition notes. No hash taken. |
| 2026-04-14 04:51 | Mike Torres | ART-001 | read_write_mount (live source) | Windows / Explorer | no | DEVIATION: source filesystem mounted read-write before imaging. No writes claimed, but access times may have changed. From acquisition notes. |
| 2026-04-14 06:14 | Mike Torres | ART-001 | acquire_disk | FTK Imager | no | Imaging finished. No hash taken. |
| 2026-04-14 07:42 | Mike Torres | ART-001, ART-002, ART-003 | handoff | n/a | no | Acquisition notes handed to forensic analyst. |
| `<timestamp>` | Massimo | ART-001 | hash_verify | `sha256sum` | `<yes/no>` | Baseline established; hash stored in `<file>` |
| `<timestamp>` | Massimo | ART-002 | hash_verify | `sha256sum` | `<yes/no>` | Baseline established; hash stored in `<file>` |
| `<timestamp>` | Massimo | ART-003 | hash_verify | `sha256sum` | `<yes/no>` | Baseline established; hash stored in `<file>` |

## Rules

1. Hash each artifact **before** the first analysis access.
2. Every later access gets a new row, even a quick one.
3. If a hash does not match the baseline, log it right away as a `DEVIATION` note.
