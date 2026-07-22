# 4. The Governance Architecture

## Goal

The purpose of MedDefense's governance architecture is to establish clear security responsibilities, decision-making authority, and accountability. Governance ensures that security decisions are made consistently, responsibilities are clearly assigned, and the security program can be sustained beyond its initial implementation.

# Part 1 – RACI Matrix

The following RACI matrix identifies who is **Responsible (R)** for performing an activity, **Accountable (A)** for the final decision, **Consulted (C)** before decisions are made, and **Informed (I)** of the outcome.

| Activity                    |  CEO  | Deputy CISO (James) | IT Director (Sarah) | Dept Heads | Security Analyst (You) |
| --------------------------- | :---: | :-----------------: | :-----------------: | :--------: | :--------------------: |
| Security budget approval    | **A** |          C          |        **R**        |      I     |            I           |
| Vulnerability remediation   |   I   |        **R**        |        **A**        |      I     |          **R**         |
| Incident response execution |   I   |        **A**        |        **R**        |      I     |          **R**         |
| Security policy approval    | **A** |        **R**        |          C          |      C     |            C           |
| Risk acceptance decisions   | **A** |        **R**        |          C          |      C     |            C           |
| Security awareness training |   I   |        **A**        |        **R**        |    **R**   |          **R**         |
| Vendor risk assessment      |   I   |        **R**        |          C          |      I     |          **R**         |
| Audit coordination          |   I   |        **A**        |          C          |      C     |          **R**         |

**Key:** **R** = Responsible, **A** = Accountable, **C** = Consulted, **I** = Informed


# Part 2 – Role Definitions

## Data Owner

**Assigned Role:** Dept Heads (for example, Dr. Patel for Cardiology)

**Definition:** The Data Owner is the business owner of the data. This role determines how the data is classified, who may access it, and approves business access requirements.

**Why this role:** Department Heads understand the operational and clinical value of their department's information. They own the data from a business perspective but must still follow MedDefense security policies.


## Data Controller

**Assigned Role:** CEO / Executive Management

**Definition:** The Data Controller determines why and how patient information is processed and is ultimately responsible for regulatory compliance.

**Why this role:** MedDefense, through executive leadership, is legally responsible for protecting patient information and ensuring compliance with healthcare regulations.


## Data Processor

**Assigned Role:** Third-party vendors and service providers

**Definition:** A Data Processor stores or processes MedDefense data on behalf of the organization under contractual agreements.

**Why this role:** Cloud providers, managed service providers, and healthcare technology vendors process patient information only according to MedDefense's instructions and contractual obligations.


## Data Custodian / Steward

**Assigned Role:** IT Director (Sarah) and the Security Analyst

**Definition:** The Data Custodian is responsible for implementing and maintaining the technical safeguards that protect organizational data, including system administration, backups, access controls, monitoring, and security operations.

**Why this role:** Sarah manages the technical infrastructure that stores and processes data, while the Security Analyst monitors security controls, verifies compliance, and supports day-to-day data governance. Although they protect the systems containing the data, they do not determine how the data is used or who owns it.


# Part 3 – The CISO Question

## Consequences of the Vacant CISO Position

MedDefense currently has **no CISO because the position is vacant**, with James serving as Deputy CISO. The vacant CISO position creates a gap in executive security leadership and governance. Without a dedicated CISO, security strategy can become focused on day-to-day operational issues rather than long-term risk management. It also becomes more difficult to resolve disagreements between Security, IT, and Dept Heads, establish consistent security priorities, and provide executive oversight for regulatory compliance and organizational risk.

## Recommendation

MedDefense should outsource the CISO function by using a **Virtual Chief Information Security Officer (vCISO)** instead of hiring a full-time CISO. Given the organization's **$120,000 security budget**, employing a full-time executive CISO would consume a large portion of the available funding, leaving fewer resources for technical security improvements. A vCISO provides strategic leadership, governance, policy oversight, executive reporting, and security guidance at a significantly lower cost, allowing MedDefense to strengthen governance while preserving its budget for vulnerability remediation, endpoint protection, backup security, and other operational security initiatives.
