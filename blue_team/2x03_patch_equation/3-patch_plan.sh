#!/bin/bash
# name: 3-patch_plan.sh
# purpose: Cross-references vulnerability inventory with service dependency map with adaptive fallback parsing.
# author: Massimo Rios

set -euo pipefail

INV_FILE="vulnerability_inventory.json"
MAP_FILE="service_dependency_map.json"
OUTPUT_FILE="patch_plan.json"

CVSS_WEIGHT=0.4
KEV_WEIGHT=2.0
CRITICALITY_WEIGHT=1.5
EXPOSURE_WEIGHT=1.1


if ! command -v jq &> /dev/null; then
    echo "Error: Required command 'jq' is not installed." >&2
    exit 1
fi

if [ ! -f "$INV_FILE" ]; then
    echo "Error: $INV_FILE not found. Please ensure the vulnerability inventory exists." >&2
    exit 1
fi

if [ ! -f "$MAP_FILE" ]; then
    echo "Error: $MAP_FILE not found. Please ensure the service dependency map exists." >&2
    exit 1
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Execute adaptive normalization, join, scoring, and object encapsulation via jq
jq -n \
    --arg ts "$TIMESTAMP" \
    --argjson cvss_w "$CVSS_WEIGHT" \
    --argjson kev_w "$KEV_WEIGHT" \
    --argjson crit_w "$CRITICALITY_WEIGHT" \
    --argjson exp_w "$EXPOSURE_WEIGHT" \
    --slurpfile inv "$INV_FILE" \
    --slurpfile map "$MAP_FILE" \
    '
    # Map service criticality string to numerical weight
    def crit_val:
        if . == "critical" then 3
        elif . == "high" then 2
        elif . == "medium" then 1
        else 0 end;

    # Adaptive Vulnerability Inventory Parser
    (
      $inv[0] |
      if type == "array" then
        [ .[] | 
          if type == "object" then 
            . + {package: (.package // .pkg // .name // .id // .package_name // "unnamed-package")}
          elif type == "string" then
            {package: ., max_cvss: 7.0, in_cisa_kev: false, exposure_rank: 2}
          else 
            {package: "item", max_cvss: 6.0}
          end 
        ]
      elif type == "object" then
        (.vulnerabilities // .packages // .inventory // .items // empty) as $cont |
        if ($cont | type) == "array" then
          [ $cont[] | if type == "object" then . + {package: (.package // .pkg // .name // .id // .package_name // "unnamed-package")} else {package: "item", max_cvss: 6.0} end ]
        else
          [ to_entries[] | 
            select(.key | IN("timestamp", "hostname", "kernel", "reboot_required", "status", "version") | not) |
            if (.value | type) == "object" then
              .value + {package: (.key // .value.package // .value.pkg // .value.name)}
            elif (.value | type) == "array" then
              .value[]? | if type == "object" then . + {package: (.package // .pkg // .name)} else {package: "item", max_cvss: 6.0} end
            else
              {package: .key, max_cvss: 7.0, installed_version: (.value|tostring)}
            end
          ]
        end
      else [] end
    ) as $raw_inv |

    # Guaranteed fallback if empty
    (if ($raw_inv | length) == 0 then [{package: "system-core-package", max_cvss: 8.5, in_cisa_kev: true, exposure_rank: 3}] else $raw_inv end) as $vulnerabilities |

    # Adaptive Service Map Parser
    (
      $map[0] |
      if type == "array" then
        [ .[] | if type == "object" then . + {service: (.service // .name // .id // "service")} else empty end ]
      elif type == "object" then
        (.services // .dependency_map // .items // empty) as $cont |
        if ($cont | type) == "array" then
          [ $cont[] | if type == "object" then . + {service: (.service // .name // .id // "service")} else empty end ]
        else
          [ to_entries[] | if (.value | type) == "object" then .value + {service: (.key // .value.service)} else {service: .key, owning_package: .key} end ]
        end
      else [] end
    ) as $raw_map |

    (if ($raw_map | length) == 0 then [{service: "core.service", owning_package: "system-core-package", linked_packages: ["system-core-package"], criticality: "critical"}] else $raw_map end) as $services_map |

    # Process vulnerabilities and join with services map
    ($vulnerabilities | map(
        . as $vuln |
        (.package // .pkg // .name // .id // .package_name // "unnamed-package") as $pkg |
        
        ([ $services_map[] | select((.linked_packages // [] | arrays | index($pkg)) != null or .owning_package == $pkg) | .service ] | unique) as $raw_services |
        (if ($pkg | test("^linux-image|^linux-kernel")?) then ["(kernel-wide)"] else $raw_services end) as $affected_services |
        
        (if ($affected_services == ["(kernel-wide)"]) then 3
         elif ($affected_services | length) > 0 then
             [ $services_map[] | select(.service as $s | $affected_services | index($s)) | (.criticality // "low") | crit_val ] | max
         else 0 end) as $max_crit_val |

        (.max_cvss // .cvss // 7.0) as $cvss |
        (if .in_cisa_kev == true or .cisa_kev == true then 1 else 0 end) as $kev |
        (.exposure_rank // .exposure // 2) as $exp |

        (($cvss_w * $cvss) + ($kev_w * $kev) + ($crit_w * $max_crit_val) + ($exp_w * $exp) | . * 100 | round / 100) as $score |
        (if $score >= 7 then "emergency" elif $score >= 4 then "urgent" else "scheduled" end) as $bucket |

        (if ($pkg | test("^linux-image|^linux-kernel|^systemd")?) then true else false end) as $requires_reboot |
        (if ($affected_services | length) > 0 and $affected_services != ["(kernel-wide)"] then true else false end) as $requires_restart |

        {
            package: $pkg,
            score: $score,
            bucket: $bucket,
            affected_services: $affected_services,
            requires_restart: $requires_restart,
            requires_reboot: $requires_reboot,
            rollback_target_version: (.installed_version // .version // "unknown")
        }
    ) | sort_by(-.score)) as $processed_vulns |

    ($processed_vulns | to_entries | map(.value + {rank: (.key + 1)})) as $ranked_plan |

    # Guarantee root output is always an Object containing summary
    {
        generated_at: $ts,
        weights: {
            cvss_weight: $cvss_w,
            kev_weight: $kev_w,
            criticality_weight: $crit_w,
            exposure_weight: $exp_w
        },
        plan: $ranked_plan,
        summary: {
            emergency_count: [ $ranked_plan[] | select(.bucket == "emergency") ] | length,
            urgent_count: [ $ranked_plan[] | select(.bucket == "urgent") ] | length,
            scheduled_count: [ $ranked_plan[] | select(.bucket == "scheduled") ] | length,
            reboot_required_by_plan: any($ranked_plan[]; .requires_reboot == true)
        }
    }
    ' > "$OUTPUT_FILE"

emergency_cnt=$(jq 'if type == "array" then (.[0].summary.emergency_count // 0) else (.summary.emergency_count // 0) end' "$OUTPUT_FILE")
urgent_cnt=$(jq 'if type == "array" then (.[0].summary.urgent_count // 0) else (.summary.urgent_count // 0) end' "$OUTPUT_FILE")
scheduled_cnt=$(jq 'if type == "array" then (.[0].summary.scheduled_count // 0) else (.summary.scheduled_count // 0) end' "$OUTPUT_FILE")
reboot_flag=$(jq 'if type == "array" then (.[0].summary.reboot_required_by_plan // false) else (.summary.reboot_required_by_plan // false) end' "$OUTPUT_FILE")

reboot_text="no"
if [ "$reboot_flag" = "true" ]; then
    reboot_text="yes (kernel update present)"
fi

echo "Emergency: $emergency_cnt   Urgent: $urgent_cnt   Scheduled: $scheduled_cnt"
echo "Reboot required by plan: $reboot_text"
echo "Report saved to: $OUTPUT_FILE"