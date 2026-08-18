#!/bin/bash
# Script Name: 2-segmentation_rules.sh
# Description: Generates the structured segmentation rule set and zone definitions
#              for firewall consumption jq tcp/53 udp/53
# Author: Massimo

set -euo pipefail

OUTPUT_FILE="segmentation_rules.json"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[+] Generating MedDefense network segmentation rules..."

cat << 'EOF' > "${OUTPUT_FILE}"
{
  "generated_at": "2026-08-18T10:02:01Z",
  "topology": "MedDefense 4-Zone Security Model",
  "zones": [
    {
      "name": "DMZ",
      "cidr": "10.100.10.0/24",
      "purpose": "Public-facing services and web proxies",
      "default_inbound": "drop",
      "default_outbound": "accept_restricted"
    },
    {
      "name": "INTERNAL",
      "cidr": "10.100.20.0/24",
      "purpose": "Clinical applications, internal services, and databases",
      "default_inbound": "drop",
      "default_outbound": "accept_restricted"
    },
    {
      "name": "MGMT",
      "cidr": "10.100.30.0/24",
      "purpose": "Administration, management, and jump hosts",
      "default_inbound": "drop",
      "default_outbound": "accept_restricted"
    },
    {
      "name": "MEDDEV",
      "cidr": "10.100.40.0/24",
      "purpose": "Medical device VLAN and isolated clinical endpoints",
      "default_inbound": "drop",
      "default_outbound": "deny_internet_and_dmz"
    }
  ],
  "flows": [
    {
      "src_zone": "MGMT",
      "dst_zone": "INTERNAL",
      "proto": "tcp",
      "dport": 22,
      "justification": "Administration and management access",
      "exception_for": null
    },
    {
      "src_zone": "MGMT",
      "dst_zone": "DMZ",
      "proto": "tcp",
      "dport": 22,
      "justification": "Administration and management access",
      "exception_for": null
    },
    {
      "src_zone": "INTERNAL",
      "dst_zone": "INTERNAL",
      "proto": "tcp",
      "dport": 443,
      "justification": "Clinical workstations to internal server hosts (HTTPS)",
      "exception_for": null
    },
    {
      "src_zone": "INTERNAL",
      "dst_zone": "INTERNAL",
      "proto": "tcp",
      "dport": 3306,
      "justification": "Clinical workstations to internal databases",
      "exception_for": null
    },
    {
      "src_zone": "DMZ",
      "dst_zone": "INTERNAL",
      "proto": "tcp",
      "dport": 3306,
      "justification": "Named DMZ application hosts to internal databases only",
      "exception_for": null
    },
    {
      "src_zone": "MEDDEV",
      "dst_zone": "INTERNAL",
      "proto": "tcp",
      "dport": 4242,
      "justification": "DICOM imaging to PACS",
      "exception_for": null
    },
    {
      "src_zone": "MEDDEV",
      "dst_zone": "INTERNAL",
      "proto": "tcp",
      "dport": 443,
      "justification": "EHR web integration for device display",
      "exception_for": null
    },
    {
      "src_zone": "ANY",
      "dst_zone": "MGMT",
      "proto": "udp",
      "dport": 53,
      "justification": "DNS resolver lookup",
      "exception_for": null
    },
    {
      "src_zone": "ANY",
      "dst_zone": "MGMT",
      "proto": "tcp",
      "dport": 53,
      "justification": "DNS resolver lookup (TCP fallback)",
      "exception_for": null
    },
    {
      "src_zone": "MGMT",
      "dst_zone": "MEDDEV",
      "proto": "tcp",
      "dport": 22,
      "justification": "Administrative access to medical devices",
      "exception_for": null
    },
    {
      "src_zone": "MGMT",
      "dst_zone": "MEDDEV",
      "proto": "tcp",
      "dport": 4242,
      "justification": "Management telemetry / DICOM interface validation",
      "exception_for": null
    }
  ],
  "summary": {
    "total_flows": 11,
    "allow_count": 11,
    "deny_count": 0,
    "cross_zone_pairs": 6
  }
}
EOF

echo "[+] Segmentation rules successfully written to ${OUTPUT_FILE}."
