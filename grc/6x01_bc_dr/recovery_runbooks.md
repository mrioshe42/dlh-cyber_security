# MedDefense Recovery Runbooks

**Version:** 1.0 | **Prepared by:** Massimo | **Date:** November 3, 2026

## Runbook 1: Laboratory Information System (LIS) Recovery

**RTO:** 2h | **RPO:** 30m | **Backup:** `/tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz`

| Step | Command | Expected Output | Verify | Deviation |
|------|---------|---|---|---|
| 1 | `ls -lah /tmp/meddefense-dr-test/backup/lis/*/` | `lis_backup.sql.gz (145M), backup_manifest.sha256` | Latest date dir exists; files present | If >4h old, escalate RPO breach |
| 2 | `cd /tmp/meddefense-dr-test/backup/lis/2026-04-21/ && sha256sum -c backup_manifest.sha256` | `lis_backup.sql.gz: OK` | Checksum passes | If fails, use previous day backup |
| 3 | `mkdir -p /tmp/meddefense-dr-test/recovery && cd /tmp/meddefense-dr-test/recovery` | `directory created` | Dir is empty | Archive old files if present |
| 4 | `gunzip -c /tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz > /tmp/meddefense-dr-test/recovery/lis_backup_staging.sql` | `No error; file written` | File size ~850M | If fails: disk space issue; check `df -h` |
| 5 | `sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db < /tmp/meddefense-dr-test/recovery/lis_backup_staging.sql && echo "Done"` | `Done` | File exists; >800M | If table exists error: `rm lis_recovered.db && retry` |
| 6 | `sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT COUNT(*) FROM patient_orders;"` | `42857` | Count within 100 of expected | If 0: table empty; verify SQL contains INSERTs |
| 7 | `sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT mrn, test_name, result_value FROM test_results WHERE mrn IN ('MRN-10043','MRN-10045') LIMIT 5;"` | `MRN-10043\|Hemoglobin\|14.2 g/dL` (and MRN-10045) | Both MRNs present; results valid | If missing: check backup window date |
| 8 | `cat /tmp/meddefense-dr-test/config/app_config.env \| grep DB_HOST` | `DB_HOST=lis-db-prod.meddefense.internal` | Production artifact identified | **Expected.** Override in Step 9. |
| 9 | `sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT COUNT(*) as orders, COUNT(DISTINCT mrn) as patients FROM patient_orders;" && echo "SUCCESS"` | `42857\|3142` then `SUCCESS` | Query succeeds; counts match Step 6 | If fails: DB corrupted; retry Step 5 |
| 10 | Notify Lab Director | Recovery complete; path: `/tmp/meddefense-dr-test/recovery/lis_recovered.db`; data as of 2026-04-21 03:00 UTC; data gap from 03:00 UTC to recovery completion. | Lab Director acknowledges | Do NOT cutover until acknowledged |

## Runbook 2: Active Directory Recovery

**RTO:** 45m | **RPO:** 15m | **Scenario:** DC01 unrecoverable; DC02 healthy  
**Status:** Documentation-only (Linux lab; typical Windows Server output examples below)

| Step | Command | Expected Output | Verify | Deviation |
|------|---------|---|---|---|
| 1 | `netdom query fsmo` | `Schema Master = DC02.meddefense.internal` (all 5 roles on DC02) | All FSMO on DC02 | If DC01 holds any: seize to DC02 first |
| 2 | **Decision:** DC02 healthy & replicating? | Yes → Non-authoritative restore | DC02 is authoritative source | If DC02 down: use authoritative restore (risky) |
| 3 | `dcdiag /s:DC02.meddefense.internal /e /v` | `Test passed on DC02` (all tests) | All tests PASS on DC02 | If fails: do NOT restore DC01; escalate |
| 4 | `wbadmin start systemstaterecovery -backupTarget:\\backup-vault\meddefense-ad\2026-04-21-02-00 -version:11042026-020000 -autoReboot:No` | `Recovered Files: 45012` then `Recovery completed successfully` | No errors; 45k+ files recovered | If hangs >20m: force reboot; retry |
| 5 | `repadmin /showrepl DC01.meddefense.internal` | `Last success @ 2026/11/03 14:45:30` and `Consecutive failure count: 0` | Sync recent (<5m); no failures | If >30m old: force `repadmin /syncall DC01` |
| 6 | `repadmin /replsummary DC01.meddefense.internal` | `DC01 -> DC02: SUCCEEDED` and `DC02 -> DC01: SUCCEEDED` Delay: 2 sec | Both directions SUCCEEDED; <5s delay | If failed: isolate DCs; escalate |
| 7 | `dcdiag /s:DC01.meddefense.internal /e /v` | `Test passed on DC01` (all tests); replication path successful | All Enterprise Tests PASS | If fails: escalate; do NOT declare complete |
| 8 | **Checklist:** DC02 dcdiag / DC01 restore / DC01 replication / DC01 dcdiag / No event log errors (IDs 2104, 2108) | All checks pass | Recovery declared complete | If any check fails: do NOT declare |
| 9 | Notify Directory Services Team | Recovery complete: DC01 restored non-auth from 2026-04-21 02:00 backup; DC02 is authoritative; plan DC01 rebuild within 5 days | DS Team acknowledges | Data gap: any AD changes after 02:00 UTC require manual re-entry if not replicated to DC02 |

## Testing

- **LIS:** Test quarterly from archived backup. Verify row counts (42857) and critical MRNs.
- **AD:** Annual non-auth restore test to spare DC. Verify replication <5 min convergence.
- **Both:** Update runbooks based on actual recovery experience.

## Approval

**Infrastructure Manager:** _________________________ | **DBA (LIS):** _______________ | **DS Manager (AD):** _______________ | **CISO:** _______________
