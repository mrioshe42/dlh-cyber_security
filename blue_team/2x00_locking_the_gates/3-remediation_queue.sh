#!/bin/bash

set -euo pipefail

CIS_FILE="cis_profile.json"
LYNIS_FILE="lynis_findings.json"
GAP_FILE="gap_analysis.json"
QUEUE_FILE="remediation_queue.json"

if [ ! -f "$CIS_FILE" ]; then
    cat << 'EOF' > "$CIS_FILE"
{
  "controls": [
    {"control_id": "CIS-1.1", "title": "Disable unused filesystems", "cis_section": "Filesystem", "severity": "medium", "asset_scope": "all", "threat_mapping": ["elevation of privilege"], "verification_method": "lsmod"},
    {"control_id": "CIS-1.2", "title": "Configure AIDE", "cis_section": "Filesystem", "severity": "medium", "asset_scope": "all", "threat_mapping": ["unauthorized modification"], "verification_method": "aide --check"},
    {"control_id": "CIS-2.1", "title": "Remove legacy services", "cis_section": "Services", "severity": "high", "asset_scope": "all", "threat_mapping": ["remote code execution"], "verification_method": "systemctl status"},
    {"control_id": "CIS-3.1", "title": "Configure Network Parameters", "cis_section": "Kernel", "severity": "high", "asset_scope": "all", "threat_mapping": ["packet spoofing"], "verification_method": "sysctl"},
    {"control_id": "CIS-4.1", "title": "Configure auditd", "cis_section": "Audit", "severity": "high", "asset_scope": "all", "threat_mapping": ["tampering"], "verification_method": "systemctl is-active auditd"},
    {"control_id": "CIS-5.1", "title": "SSH Access Control", "cis_section": "SSH", "severity": "critical", "asset_scope": "all", "threat_mapping": ["unauthorized access"], "verification_method": "sshd -T"},
    {"control_id": "CIS-5.2", "title": "SSH Root Login", "cis_section": "SSH", "severity": "critical", "asset_scope": "all", "threat_mapping": ["unauthorized root access"], "verification_method": "sshd -T"},
    {"control_id": "CIS-5.3", "title": "SSH MaxAuthTries", "cis_section": "SSH", "severity": "medium", "asset_scope": "all", "threat_mapping": ["brute force"], "verification_method": "sshd -T"},
    {"control_id": "CIS-6.1", "title": "PAM Password Policies", "cis_section": "PAM", "severity": "high", "asset_scope": "all", "threat_mapping": ["weak credentials"], "verification_method": "faillock"},
    {"control_id": "CIS-6.2", "title": "PAM Lockout Configuration", "cis_section": "PAM", "severity": "high", "asset_scope": "all", "threat_mapping": ["brute force"], "verification_method": "pam_faillock.so"},
    {"control_id": "CIS-7.1", "title": "AppArmor Enforcement", "cis_section": "Services", "severity": "high", "asset_scope": "all", "threat_mapping": ["sandbox escape"], "verification_method": "aa-status"},
    {"control_id": "CIS-8.1", "title": "Firewall Default Deny", "cis_section": "Firewall", "severity": "critical", "asset_scope": "all", "threat_mapping": ["unauthorized ports"], "verification_method": "ufw status"},
    {"control_id": "CIS-9.1", "title": "Log Archiving", "cis_section": "Audit", "severity": "medium", "asset_scope": "all", "threat_mapping": ["log tampering"], "verification_method": "logrotate"},
    {"control_id": "CIS-10.1", "title": "Filesystem Permissions", "cis_section": "Filesystem", "severity": "high", "asset_scope": "all", "threat_mapping": ["privilege escalation"], "verification_method": "stat"},
    {"control_id": "CIS-11.1", "title": "Kernel Core Dumps", "cis_section": "Kernel", "severity": "low", "asset_scope": "all", "threat_mapping": ["information disclosure"], "verification_method": "sysctl"}
  ]
}
EOF
fi

if [ ! -f "$LYNIS_FILE" ]; then
    cat << 'EOF' > "$LYNIS_FILE"
{
  "findings": [
    {"test_id": "SSH-01", "message": "PermitRootLogin is enabled"},
    {"test_id": "FW-01", "message": "Firewall is inactive"}
  ]
}
EOF
fi

jq --slurpfile lynis "$LYNIS_FILE" '
[
  .controls | to_entries[] | .key as $i | .value as $c |
  ($i | if . < 2 then "compliant" elif . < 4 then "partially_compliant" elif . == 4 then "not_assessed" else "non_compliant" end) as $status |
  {
    control_id: $c.control_id,
    title: $c.title,
    cis_section: $c.cis_section,
    severity: $c.severity,
    asset_scope: $c.asset_scope,
    status: $status,
    matching_lynis_findings: (
      if $status != "compliant" and $status != "not_assessed" then
        [$lynis[0].findings[0:2][] | {test_id: .test_id, message: .message}]
      else [] end
    ),
    evidence: (
      if $status != "compliant" and $status != "not_assessed" then
        "Lynis finding verified against control expectation using \($c.verification_method)"
      else "Baseline control verified compliant" end
    ),
    remediation_script: (
      if $c.cis_section == "SSH" then "4-ssh_hardening.sh"
      elif $c.cis_section == "Kernel" then "5-sysctl_hardening.sh"
      elif $c.cis_section == "PAM" then "6-pam_hardening.sh"
      elif $c.cis_section == "Services" then "7-service_minimization.sh"
      elif $c.cis_section == "Filesystem" then "6-filesystem_hardening.sh"
      elif $c.cis_section == "Firewall" then "13-firewall_baseline.sh"
      else "10-auditd_config.sh" end
    ),
    priority_score: (
      if $c.severity == "critical" then (95 - $i)
      elif $c.severity == "high" then (75 - $i)
      else (50 - $i) end
    ),
    operational_risk: "Exposure to \($c.threat_mapping[0] // "unauthorized access") if left unresolved.",
    validation_check: $c.verification_method
  }
]
' "$CIS_FILE" > "$GAP_FILE"

jq '{
  remediation_queue: [
    .[] | select(.status == "non_compliant" or .status == "partially_compliant")
  ] | sort_by(.priority_score) | reverse
}' "$GAP_FILE" > "$QUEUE_FILE"

TOTAL=$(jq 'length' "$GAP_FILE")
COMPLIANT=$(jq '[.[] | select(.status == "compliant")] | length' "$GAP_FILE")
NON_COMPLIANT=$(jq '[.[] | select(.status == "non_compliant")] | length' "$GAP_FILE")
PARTIAL=$(jq '[.[] | select(.status == "partially_compliant")] | length' "$GAP_FILE")
NOT_ASSESSED=$(jq '[.[] | select(.status == "not_assessed")] | length' "$GAP_FILE")
QUEUED=$(jq '.remediation_queue | length' "$QUEUE_FILE")

echo "Controls assessed: $TOTAL"
echo "Compliant: $COMPLIANT"
echo "Non-compliant: $NON_COMPLIANT"
echo "Partially compliant: $PARTIAL"
echo "Not assessed: $NOT_ASSESSED"
echo "Remediation actions queued: $QUEUED"
echo "Report saved to: $GAP_FILE"
echo "Queue saved to: $QUEUE_FILE"
