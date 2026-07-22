# 8. The Budget Game

Making binding resource allocation decisions under a strict **$120,000 budget constraint** requires MedDefense to prioritize controls that provide the highest risk reduction value. Since the organization cannot fund every security improvement, each investment decision must be based on measurable risk reduction, Net Value, and operational feasibility.

James Chen’s concern reflects the reality of security budgeting: every dollar allocated to one control reduces the funding available for another. Therefore, MedDefense must select the combination of controls that maximizes overall risk reduction while accepting that some risks will remain until future funding becomes available.


# Part 1 — The Selection

## Funded Controls (6 controls, ranked by Net Value)

The following controls are funded because they provide the strongest combination of risk reduction, business value, and cost efficiency within the available budget.

| Control                               |        Cost | Net Value |
| ------------------------------------- | ----------: | --------: |
| MFA deployment                        |      $4,000 |  $317,900 |
| Offsite backup replication            |     $14,400 |  $407,070 |
| Network segmentation                  |     $25,500 |  $234,060 |
| EDR upgrade                           |     $22,000 |   $49,640 |
| Medical device isolation + monitoring |     $20,000 |   $35,890 |
| Westside Clinic firewall              |      $1,600 |    $5,900 |
| **Total**                             | **$87,500** |           |

These controls were selected because they address the highest-value security gaps, including identity protection, ransomware resilience, network containment, endpoint protection, medical device security, and remote-site protection.


## Deferred Controls (Next Fiscal Year)

**Enterprise SIEM (Wazuh) — $30,000**

Enterprise SIEM is deferred to the next fiscal year because it provides a lower Net Value compared with the selected controls. Although SIEM improves centralized monitoring and detection capabilities, it requires significant deployment effort and analyst time for configuration, tuning, and maintenance.

The current Security Analyst resources are already required to support the six funded controls. Deferring SIEM allows MedDefense to first stabilize MFA, network segmentation, backup isolation, and endpoint protections before expanding security monitoring capabilities.


## Rejected Controls

**24/7 Outsourced SOC — $150,000**

The 24/7 Outsourced SOC is rejected rather than deferred because it is not financially justified under current MedDefense conditions. The cost exceeds the entire security budget and provides negative Net Value.

This control does not represent a temporary funding problem; it represents an unsuitable investment decision for the organization’s current scale. The available budget provides significantly greater risk reduction when invested in the selected technical controls.

## Total Spend vs. Budget Remaining

Budget Usage Summary:

- Total budget available: $120,000 (120000)
- Total spend: $87,500
- Budget remaining: $32,500

The budget usage demonstrates that MedDefense funded the highest-value controls while maintaining financial flexibility. The remaining budget is reserved for additional security improvements and unresolved critical gaps identified during previous assessments. Maintaining budget remaining allows MedDefense to address emerging risks without reducing the effectiveness of the funded security controls.

# Part 2 — The Opportunity Cost

Deferring controls means that some security risks remain partially unaddressed. The opportunity cost represents the annual risk exposure MedDefense accepts by delaying specific investments.

**By deferring Enterprise SIEM (Wazuh), MedDefense accepts an estimated $53,400 in annual risk exposure.**

This remaining exposure relates to reduced visibility into security events and delayed detection capabilities. The funded EDR solution reduces part of this risk by improving endpoint detection, but SIEM would provide additional centralized monitoring and correlation capabilities.

The 24/7 Outsourced SOC does not receive an opportunity cost calculation because it was rejected rather than deferred. Since the decision is based on negative Net Value and poor cost effectiveness, it is not considered a future investment opportunity under the current budget model.


# Part 3 — The Alternative

An alternative allocation could replace the **EDR upgrade** with **Enterprise SIEM (Wazuh)** while keeping the remaining funded controls unchanged.

## Alternative Allocation: SIEM instead of EDR

|                     | Primary Allocation                                                          | Alternative Allocation                                                       |
| ------------------- | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Controls funded     | MFA, Backup, Segmentation, EDR, Medical device isolation, Westside firewall | MFA, Backup, Segmentation, SIEM, Medical device isolation, Westside firewall |
| Total cost          | $87,500                                                                     | $95,500                                                                      |
| Total ALE reduction | $1,137,960                                                                  | $1,119,720                                                                   |

The alternative provides stronger centralized visibility and improves detection capabilities for malware activity and suspicious behavior. However, replacing EDR removes broader endpoint protection across MedDefense systems.

The primary recommendation remains the preferred allocation because it achieves higher total risk reduction at a lower cost. The SIEM alternative is still a reasonable option if leadership prioritizes improved monitoring visibility over endpoint protection coverage.

This comparison demonstrates the trade-off involved in security budgeting: different control combinations can address different risks, but MedDefense must select the portfolio that provides the strongest overall protection within the available budget.
