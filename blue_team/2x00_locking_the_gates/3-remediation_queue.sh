#!/bin/bash

set -euo pipefail

CIS_FILE="cis_profile.json"
LYNIS_FILE="lynis_findings.json"
GAP_FILE="gap_analysis.json"
QUEUE_FILE="remediation_queue.json"

# Generate gap analysis
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
    remediation_script: (
      if $c.cis_section == "SSH" then "4-ssh_hardening.sh"
      elif $c.cis_section == "Kernel" then "5-kernel_hardening.sh"
      elif $c.cis_section == "PAM" then "6-pam_hardening.sh"
      elif $c.cis_section == "Services" then "7-service_cleanup.sh"
      elif $c.cis_section == "Filesystem" then "8-filesystem_permissions.sh"
      elif $c.cis_section == "Firewall" then "9-firewall_hardening.sh"
      else "10-audit_logging.sh" end
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

# Generate prioritized remediation queue
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
