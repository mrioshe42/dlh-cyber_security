# Incident Report: INC-20260915-B

## Executive Summary
During the shift monitoring window, security telemetry flagged malicious behavior associated with the HC-RED7 threat gr
oup targeting meddefense-srv-01. Activity on rad-srv-02 superficially matches maintenance change window CHG-2026-0341, 
but execution by an account on leave and unapproved outbound traffic to a known HC-RED7 IOC confirms true positive mali
cious behavior. Comprehensive analysis confirmed unauthorized access patterns, validating the incident as a true positi
ve.

## Timeline
2026-09-15T01:00:12Z | meddefense-srv-01 | Multiple failed authentication attempts recorded for privileged account.
2026-09-15T01:01:30Z | meddefense-srv-01 | Successful logon from unverified source IP.
2026-09-15T01:03:15Z | meddefense-srv-01 | Unauthorized service installation executed from temporary directory.
2026-09-15T01:05:00Z | meddefense-srv-01 | Outbound C2 beacon pattern observed connecting to 198[.]51[.]100[.]73.

## Affected Assets
| HOST | CRITICALITY | DATA_CLASS | ZONE |
| --- | --- | --- | --- |
| meddefense-srv-01 | HIGH | CLINICAL | INTERNAL |

## Indicators of Compromise
| TYPE | VALUE | CONFIDENCE | SOURCE |
| --- | --- | --- | --- |
| ip | 198[.]51[.]100[.]73 | high | feed_correlation |

## ATT&CK Mapping
| TECHNIQUE | NAME | EVIDENCE |
| --- | --- | --- |
| T1071.001 | Application Layer Protocol: Web Protocols | Outbound HTTPS beaconing to C2 infrastructure |
| T1078.003 | Valid Accounts: Local Accounts | Abuse of dormant or compromised credentials |
| T1543.003 | Create or Modify System Process: Windows Service | Unauthorized service installation |

## Detection Performance
001_ssh_brute_force : fired successfully
002_offhours_priv : fired successfully

## Recommended Actions
1. Isolate affected host meddefense-srv-01 from network connectivity immediately.
2. Revoke and rotate credentials for all compromised service accounts.
3. Block malicious IP 198[.]51[.]100[.]73 at the perimeter firewall.
4. Review host audit logs for secondary persistence mechanisms.
5. Escalate incident package to Tier 3 Threat Hunting.

## Evidence References
EVT-REF-B01
EVT-REF-B02
EVT-REF-B03
EVT-REF-B04
EVT-REF-B05
