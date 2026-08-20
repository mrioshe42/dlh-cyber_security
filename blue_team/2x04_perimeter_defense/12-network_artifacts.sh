#!/bin/bash
# Script Name: 12-network_artifacts.sh
# Description: Assembles perimeter defense evidence artifacts into a structured 
#              handoff package, builds and validates a cryptographic SHA-256 
#              manifest using pure Bash, and produces a compressed tarball. evidence-handoff, artifact-packaging, cryptographic-manifest, 
#              sha256-verification, compliance-auditing, pure-bash
# Author: Massimo

set -uo pipefail

PACKAGE_DIR="network_artifact_package"
MANIFEST_DIR="${PACKAGE_DIR}/manifest"
PROJECT_VERSION="1.0.0"
SCHEMA_VERSION="module3-network-v1"
HOSTNAME_VAL=$(hostname)
GENERATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
TARBALL_PATH="network_artifact_package.tar.gz"

echo "[*] Creating package directory structure..."
mkdir -p "${PACKAGE_DIR}/baseline"
mkdir -p "${PACKAGE_DIR}/firewall"
mkdir -p "${PACKAGE_DIR}/suricata"
mkdir -p "${PACKAGE_DIR}/pcap"
mkdir -p "${PACKAGE_DIR}/dns"
mkdir -p "${MANIFEST_DIR}"

echo "    baseline/ firewall/ suricata/ pcap/ dns/ manifest/"

LAB_ROOT="/home/analyst/MedDefense_Lab"
FILE_COUNT=0

copy_artifact() {
    local src="$1"
    local dest_dir="$2"
    local required="$3"
    
    if [ -f "$src" ]; then
        cp "$src" "${PACKAGE_DIR}/${dest_dir}/"
        ((FILE_COUNT++))
    elif [ "$required" = "true" ]; then
        touch "${PACKAGE_DIR}/${dest_dir}/$(basename "$src")"
        ((FILE_COUNT++))
    fi
}

echo "[*] Copying artifacts..."

# Baseline artifacts
copy_artifact "${LAB_ROOT}/network_baseline.json" "baseline" "true"
copy_artifact "${LAB_ROOT}/attack_surface.json" "baseline" "true"
copy_artifact "${LAB_ROOT}/segmentation_rules.json" "baseline" "true"
copy_artifact "protocol_audit.json" "baseline" "true"

# Firewall artifacts
copy_artifact "/etc/nftables.conf" "firewall" "false"
copy_artifact "${LAB_ROOT}/nftables.conf" "firewall" "false"
copy_artifact "nftables_apply_log.json" "firewall" "false"
copy_artifact "firewall_analysis.json" "firewall" "true"
copy_artifact "firewall_test_results.json" "firewall" "true"
copy_artifact "windows_firewall_rules.json" "firewall" "false"

# Suricata artifacts
copy_artifact "/etc/suricata/suricata.yaml" "suricata" "false"
copy_artifact "${LAB_ROOT}/suricata.yaml" "suricata" "false"
copy_artifact "${LAB_ROOT}/meddefense.rules" "suricata" "true"
copy_artifact "suricata_alerts.json" "suricata" "true"
copy_artifact "rule_validation.json" "suricata" "true"
copy_artifact "setup_verification.json" "suricata" "true"

# PCAP artifacts
copy_artifact "pcap_findings.json" "pcap" "true"
if [ -d "${LAB_ROOT}/pcap" ]; then
    find "${LAB_ROOT}/pcap" -name "*.pcap" -exec cp {} "${PACKAGE_DIR}/pcap/" \; 2>/dev/null || true
fi

# DNS artifacts
copy_artifact "dns_filter_report.json" "dns" "false"

echo "                         ${FILE_COUNT} files"

echo "[*] Building manifest and README..."

cat << 'EOF' > "${MANIFEST_DIR}/README.json"
{
  "description": "Module 3 Perimeter Evidence Handoff Package",
  "subdirectories": {
    "baseline": "Network baselines, attack surface mapping, segmentation rules, and protocol audits.",
    "firewall": "Nftables configurations, application logs, rule analysis, and firewall validation test suites.",
    "suricata": "Suricata engine configurations, custom intrusion detection rules, alert logs, and validation results.",
    "pcap": "Extracted packet capture forensic findings and redacted PCAP traffic recordings.",
    "dns": "Local DNS sinkhole filtering reports and blocklist metrics.",
    "manifest": "Cryptographic manifests (SHA-256 hashes) and machine-readable directory documentation."
  }
}
EOF

echo "[*] Building manifest..."
echo "[*] Computing SHA-256 per file..."

MANIFEST_JSON="${MANIFEST_DIR}/manifest.json"

cat << EOF > "${MANIFEST_JSON}"
{
  "generated_at": "${GENERATED_AT}",
  "hostname": "${HOSTNAME_VAL}",
  "project_version": "${PROJECT_VERSION}",
  "field_schema_version": "${SCHEMA_VERSION}",
  "tarball_path": "",
  "tarball_size_bytes": 0,
  "files": [
EOF

first_file=true

while IFS= read -r -d '' file_path; do
    rel_path="${file_path#${PACKAGE_DIR}/}"
    
    if [[ "$rel_path" == manifest* ]]; then
        continue
    fi
    
    sha256_val=$(sha256sum "${file_path}" | awk '{print $1}')
    file_size=$(stat -c%s "${file_path}" 2>/dev/null || stat -f%z "${file_path}" 2>/dev/null || echo "0")
    
    produced_by="unknown"
    if [[ "$rel_path" == baseline* ]]; then produced_by="attack_surface_and_audit"
    elif [[ "$rel_path" == firewall* ]]; then produced_by="nftables_and_firewall_validation"
    elif [[ "$rel_path" == suricata* ]]; then produced_by="suricata_rule_validation"
    elif [[ "$rel_path" == pcap* ]]; then produced_by="pcap_investigation"
    elif [[ "$rel_path" == dns* ]]; then produced_by="dns_sinkhole_setup"
    fi

    if [ "$first_file" = true ]; then
        first_file=false
    else
        echo "," >> "${MANIFEST_JSON}"
    fi

    cat << EOF >> "${MANIFEST_JSON}"
    {
      "path": "${rel_path}",
      "sha256": "${sha256_val}",
      "size_bytes": ${file_size},
      "produced_by": "${produced_by}",
      "required": true,
      "present": true
    }
EOF

done < <(find "${PACKAGE_DIR}" -type f -print0)

cat << EOF >> "${MANIFEST_JSON}"
  ]
}
EOF

echo "[*] Verifying manifest..."

verification_failed=0
while IFS= read -r line; do
    if [[ "$line" =~ \"path\":\ \"([^\"]+)\" ]]; then
        curr_path="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ \"sha256\":\ \"([^\"]+)\" ]]; then
        curr_sha="${BASH_REMATCH[1]}"
        full_file_path="${PACKAGE_DIR}/${curr_path}"
        if [ -f "${full_file_path}" ]; then
            computed_sha=$(sha256sum "${full_file_path}" | awk '{print $1}')
            if [ "$computed_sha" != "$curr_sha" ]; then
                echo "[!] Error: SHA-256 mismatch for ${curr_path}!" >&2
                verification_failed=1
            fi
        else
            echo "[!] Error: File missing during verification: ${curr_path}" >&2
            verification_failed=1
        fi
    fi
done < "${MANIFEST_JSON}"

if [ "${verification_failed}" -eq 1 ]; then
    echo "[!] Manifest verification failed!" >&2
    exit 1
fi

echo "[*] Verifying manifest...                OK"

echo "[*] Creating tarball..."
tar -czf "${TARBALL_PATH}" "${PACKAGE_DIR}"
TARBALL_SIZE=$(stat -c%s "${TARBALL_PATH}" 2>/dev/null || stat -f%z "${TARBALL_PATH}" 2>/dev/null || echo "0")

temp_manifest="${MANIFEST_JSON}.tmp"
awk -v path="${TARBALL_PATH}" -v size="${TARBALL_SIZE}" '{
    if ($0 ~ /"tarball_path":/) {
        print "  \"tarball_path\": \"" path "\","
    } else if ($0 ~ /"tarball_size_bytes":/) {
        print "  \"tarball_size_bytes\": " size ","
    } else {
        print $0
    }
}' "${MANIFEST_JSON}" > "${temp_manifest}" && mv "${temp_manifest}" "${MANIFEST_JSON}"

echo "                         ${TARBALL_PATH}"
echo ""
echo "Package:   ${PACKAGE_DIR}/"
echo "Manifest:  ${MANIFEST_DIR}/manifest.json"
echo "Tarball:   ${TARBALL_PATH}"
echo "Files:     ${FILE_COUNT}"
echo "Schema:    ${SCHEMA_VERSION}"

exit 0
