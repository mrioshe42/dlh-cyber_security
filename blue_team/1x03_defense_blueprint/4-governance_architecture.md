# 4. The Governance Architecture

## Goal

The purpose of MedDefense's governance architecture is to establish clear security responsibilities, decision-making authority, and accountability. Effective governance ensures that security is managed consistently, reduces conflicts between departments, and allows the security program to continue operating effectively beyond its initial implementation.


# Part 1 – RACI Matrix

The following RACI matrix defines who is **Responsible (R)** for performing an activity, **Accountable (A)** for its final outcome, **Consulted (C)** before decisions are made, and **Informed (I)** after decisions are taken.

| Activity                    |  CEO  | Deputy CISO (James) | IT Director (Sarah) | Dept Heads | Security Analyst (You) |
| --------------------------- | :---: | :-----------------: | :-----------------: | :--------: | :--------------------: |
| Security budget approval    | **A** |        **R**        |          C          |      I     |            I           |
| Vulnerability remediation   |   I   |          C          |        **A**        |      I     |          **R**         |
| Incident response execution |   I   |        **A**        |          C          |      I     |          **R**         |
| Security policy approval    | **A** |        **R**        |          C          |      C     |            I           |
| Risk acceptance decisions   |   I   |        **R**        |          C          |    **A**   |            I           |
| Security awareness training |   I   |        **A**        |          I          |      C     |          **R**         |
| Vendor risk assessment      |   I   |        **A**        |          C          |      C     |          **R**         |
| Audit coordination          |   I   |        **A**        |          C          |      C     |          **R**         |

### Governance Rationale

**Security Budget Approval**

The Deputy CISO prepares the annual security budget by identifying security priorities, compliance requirements, and risk reduction initiatives. The CEO is accountable because executive management has final authority over organizational spending. The IT Director provides technical cost estimates and implementation information.

**Vulnerability Remediation**

The Security Analyst identifies vulnerabilities, prioritizes them according to risk, verifies remediation, and reports progress. The IT Director is accountable because IT owns the infrastructure and is responsible for implementing patches and configuration changes without disrupting business operations. The Deputy CISO provides guidance on risk prioritization.

**Incident Response Execution**

The Security Analyst performs monitoring, investigation, forensic analysis, containment support, and documentation. The Deputy CISO is accountable for directing the technical response, coordinating resources, and making security decisions throughout the incident. The IT Director assists with infrastructure recovery and containment activities.

**Security Policy Approval**

The Deputy CISO develops and maintains security policies based on regulatory requirements and security best practices. The CEO approves the policies, making them official organizational requirements. IT and Dept Heads are consulted to ensure policies are practical and support business operations.

**Risk Acceptance Decisions**

The Deputy CISO performs the security risk assessment, documents the risks, and provides recommendations. Dept Heads are accountable because they own the business processes affected by the risk and therefore decide whether the remaining risk is acceptable for their department.

**Security Awareness Training**

The Security Analyst develops training materials, delivers awareness sessions, and tracks employee completion. The Deputy CISO owns the awareness program and is accountable for ensuring that it satisfies organizational and regulatory requirements. Dept Heads support participation within their teams.

**Vendor Risk Assessment**

The Security Analyst performs technical assessments of vendors by reviewing security questionnaires, compliance certifications, and security controls. The Deputy CISO is accountable for approving the overall vendor risk evaluation. IT and Dept Heads provide technical and business input when necessary.

**Audit Coordination**

The Security Analyst gathers evidence, prepares documentation, and coordinates audit activities. The Deputy CISO is accountable for ensuring compliance with regulatory requirements and serving as the primary security representative during audits. IT and Dept Heads provide supporting documentation for their respective areas.


# Part 2 – Role Definitions

## Data Owner

**Assigned Role:** Dept Heads (for example, Dr. Patel for Cardiology)

**Definition:** The Data Owner is responsible for determining how business data is used, classified, and who is authorized to access it.

**Why this role fits:** Department Heads understand the operational and clinical value of their information and determine which employees require access to support patient care. However, they must follow organizational security policies and cannot override technical security controls.


## Data Controller

**Assigned Role:** MedDefense Executive Management (CEO on behalf of the organization)

**Definition:** The Data Controller determines the purposes and legal basis for processing personal information and is ultimately responsible for compliance with privacy regulations.

**Why this role fits:** MedDefense, represented by executive management, decides why patient information is collected and processed and is legally accountable for protecting that information.


## Data Processor

**Assigned Role:** Third-party vendors and cloud service providers

**Definition:** A Data Processor processes personal data on behalf of the Data Controller according to contractual agreements.

**Why this role fits:** External providers such as cloud-hosted healthcare systems, backup providers, and managed service vendors process MedDefense data only under the organization's instructions and contractual obligations.


## Data Custodian / Steward

**Assigned Role:** IT Department (Sarah and the Systems Administration team)

**Definition:** The Data Custodian is responsible for the technical protection, storage, backup, maintenance, and availability of organizational data.

**Why this role fits:** The IT Department manages servers, databases, backups, encryption, access controls, and system availability. Although IT protects the data, it does not decide how the data is used or who owns it.


# Part 3 – The CISO Question

## Consequences of Having No CISO

Operating without a permanent CISO creates several governance challenges for MedDefense. First, security lacks executive-level representation, making it more difficult for James, as Deputy CISO, to enforce security priorities when they conflict with operational or clinical objectives. Second, decision-making becomes inconsistent because responsibilities between Security, IT, and business units are not always clearly defined. Third, the Deputy CISO must divide time between daily operational work and strategic planning, reducing the organization's ability to develop long-term security initiatives. Finally, the absence of a dedicated CISO may weaken governance during regulatory audits because executive oversight of information security is limited.

## Recommendation

MedDefense should outsource the CISO role by hiring a **Virtual Chief Information Security Officer (vCISO)** rather than employing a full-time CISO. With an annual security budget of approximately **$120,000**, hiring a full-time executive would consume a significant portion of the available funding, leaving fewer resources for security controls and operational improvements. A vCISO provides executive security leadership, governance, strategic planning, policy oversight, and board reporting at a much lower cost while allowing MedDefense to invest the remaining budget in essential security capabilities such as vulnerability management, endpoint protection, employee awareness training, and incident response. As the organization grows and its security program matures, MedDefense can later evaluate whether a full-time CISO becomes financially and operationally justified.
