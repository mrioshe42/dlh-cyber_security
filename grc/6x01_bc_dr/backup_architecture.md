# MedDefense Backup Architecture

**Version:** 1.0 | **Prepared by:** Massimo | **Date:** November 3, 2026

## Strategy Overview

All Tier 1 systems use continuous replication or snapshots to meet RPO targets. Tier 2 systems use daily full + incremental. All ePHI: AES-256 at rest, TLS 1.2+ in transit. Tier 1 systems geographically replicated (100+ miles). Weekly restore tests on Tier 1; monthly on Tier 2.

## RPO Compliance Verification

| System | RPO | Backup Type | Frequency | Status |
|--------|-----|---|---|---|
| Active Directory | 15m | Real-time replication | Continuous | PASS |
| Epic EHR | 5m | Redo-log replication + incremental | Real-time + hourly | PASS |
| PACS/RIS | 15m | Snapshots + differential | Every 15m + hourly | PASS |
| Pharmacy | 10m | Redo-log replication + incremental | Real-time + hourly | PASS |
| Device Gateway | 5m | Real-time replication | Continuous | PASS |
| Network Core | Real-time | Config snapshots | Every 5m or on-change | PASS |
| Backup Infrastructure | 1h | Hourly incremental | Every 60m | PASS |
| LIS | 30m | Daily full + incremental | Nightly + every 30m | PASS |
| Email | 1h | Daily full + incremental | Nightly + hourly | PASS |
| Security Ops | 30m | Daily full + incremental | Nightly + every 30m | PASS |

## Per-System Backup Specifications

| System | Type | Primary | Secondary | Encryption | Restore Test |
|--------|------|---------|-----------|------------|---|
| **Active Directory** | Real-time replication + nightly full | On-site NAS RAID-6 | AWS S3 cross-region | AES-256 (Thales HSM) | Weekly; isolated DC |
| **Epic EHR** | Redo-log (hot standby) + hourly incremental | On-site SAN (Tier 1) | DR site + cloud vault | AES-256 (Thales HSM) | Bi-weekly; DR environment |
| **PACS/RIS** | 15-min snapshots + hourly differential | On-site SAN (RAID-6) + NAS | DR site SAN + S3 Glacier | AES-256 (Thales HSM) | Monthly; image verification |
| **Pharmacy** | Redo-log + hourly incremental | On-site DB server SSD | DR site + cloud S3 | AES-256 (Thales HSM) | Bi-weekly; drug engine test |
| **Device Gateway** | Real-time queue replication + 5-min snapshots | On-site SSD queue | DR site queue + S3 | AES-256 (Thales HSM) | Weekly; device heartbeat |
| **Network Core** | Config snapshots (5m/on-change) + nightly full | On-site air-gapped vault | DR site + cloud SFTP | AES-256 (Thales HSM) | Monthly; routing verification |
| **Backup Infrastructure** | Hourly incremental + nightly full | On-site RAID-6 vault | Off-site + encrypted tape | AES-256 (Thales HSM) | Weekly; job definitions |
| **LIS** | Daily full + 30-min incremental | On-site NAS RAID-6 | AWS S3 cross-region | AES-256 (Thales HSM) | Monthly; DB consistency |
| **Email** | Daily full + hourly incremental | On-site Exchange vault RAID-6 | Azure + tape archive | AES-256 (Azure KV) | Quarterly; mailbox recovery |
| **Security Ops** | Daily full + 30-min incremental | On-site SIEM vault RAID-6 | AWS S3 versioning + tape | AES-256 (Thales HSM) | Monthly; alert rule test |

**All systems:** TLS 1.2+ in transit. Retention: Recent (7–30 days), Monthly (full copies), Archive (quarterly/annual tape).


## Full Data Center Loss Recovery Sequence

**Phase 1 (Min 0–15, Parallel):** Network Core + Backup Infrastructure
- Activate DR site. Restore network configs from 5-min snapshot.
- Restore backup infrastructure metadata. Verify offsite vault connectivity.

**Phase 2 (Min 15–45, Sequential):** Active Directory
- Restore AD from offsite vault to isolated DC.
- Verify schema consistency. Promote DC. Test user login.

**Phase 3 (Min 45–75, Sequential):** Epic EHR
- Activate Epic DR hot standby (already replicated).
- Verify database consistency. Bring application online.

**Phase 4 (Min 75–105, Parallel):** PACS + Pharmacy + Device Gateway
- PACS: Restore metadata from 15-min snapshot + imaging from incremental.
- Pharmacy: Restore DB from transaction logs. Verify drug interactions.
- Device Gateway: Activate hot standby. Re-register bedside devices.

**Phase 5 (Min 105–125, Sequential):** Tier 2 Systems (LIS → Email → Security Ops)
- Restore each from nightly full backup + most recent incremental.

**Total Recovery Time: ~125 minutes (2 hours) to full operational status.**

## Dependency Restore Order

```
Network Core (15m) → AD (30m) → Epic (30m) → PACS/Pharmacy/Devices (30m) → LIS/Email/Security (20m)
                  ↑
           Backup Infrastructure (parallel)
```

**Critical Path:** Network Core → AD → Epic = 75 minutes before clinical workflows resume.

**Failure Cascade:** Network Core failure = all systems fail simultaneously. AD failure = all authentication blocked. Epic failure = all clinical workflows halted.

## Verification & Testing

- **Weekly:** Restore tests on Tier 1 systems (isolated equipment).
- **Monthly:** Full restore tests on all systems. Verify RTO achievement.
- **Quarterly:** DR site activation test (full data center loss simulation).

## Approval

**Backup Administrator:** _________________________ Date: _________  
**Infrastructure Manager:** _________________________ Date: _________  
**CISO:** _________________________ Date: _________

