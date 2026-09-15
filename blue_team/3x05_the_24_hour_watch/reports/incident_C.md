# Incident Report: INC-20260915-C

## Executive Summary
During the shift monitoring window, security telemetry flagged malicious behavior associated with the HC-RED7 threat gr
oup targeting meddefense-rad-01. Suspicious activity detected across critical endpoints requiring containment. Comprehe
nsive analysis confirmed unauthorized access patterns, validating the incident as a true positive.

## Timeline
2026-09-15T01:00:12Z | meddefense-rad-01 | Multiple failed authentication attempts recorded for privileged account.
2026-09-15T01:01:30Z | meddefense-rad-01 | Successful logon from unverified source IP.
2026-09-15T01:03:15Z | meddefense-rad-01 | Unauthorized service installation executed from temporary directory.
2026-09-15T01:05:00Z | meddefense-rad-01 | Outbound C2 beacon pattern observed connecting to 198[.]51[.]100[.]73.

## Affected Assets
| HOST | CRITICALITY | DATA_CLASS | ZONE |
| --- | --- | --- | --- |
| meddefense-rad-01 | HIGH | CLINICAL | INTERNAL |

## Indicators of Compromise
| TYPE | VALUE | CONFIDENCE | SOURCE |
| --- | --- | --- | --- |
| ip | 198[.]51[.]100[.]73 | high | feed_correlation |
| domain | MedSyncHelper | high | feed_correlation |

## ATT&CK Mapping
| TECHNIQUE | NAME | EVIDENCE |
| --- | --- | --- |
| T1110.003 | Brute Force: Password Spraying | Multiple authentication failures across accounts |
| T1543.003 | Create or Modify System Process: Windows Service | Unauthorized service installation |
| T1071.001 | Application Layer Protocol: Web Protocols | Outbound HTTPS beaconing to C2 infrastructure |

## Detection Performance
001_ssh_brute_force : fired successfully
002_offhours_priv : fired successfully

## Recommended Actions
1. Isolate affected host meddefense-rad-01 from network connectivity immediately.
2. Revoke and rotate credentials for all compromised service accounts.
3. Block malicious IP 198[.]51[.]100[.]73 at the perimeter firewall.
4. Review host audit logs for secondary persistence mechanisms.
5. Escalate incident package to Tier 3 Threat Hunting.

## Evidence References
EVT-REF-001
EVT-REF-002
EVT-REF-003
EVT-REF-004
