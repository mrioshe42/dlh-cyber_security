# 4. The Governance Architecture

## Part 1: RACI Matrix

A strong security governance model requires a clear separation between decision authority, operational execution, and business ownership. The RACI model below defines who performs security activities, who is accountable for outcomes, who provides expertise, and who must remain informed.

This structure ensures that security governance decisions remain aligned with organizational leadership while operational security activities are handled by the appropriate technical teams. The Deputy CISO (James) provides security leadership and governance coordination, the IT Director (Sarah) manages technical implementation, Department Heads provide business and clinical input, and the Security Analyst supports daily security operations.

| Activity                    | CEO | Deputy CISO (James) | IT Director (Sarah) | Dept Heads | Security Analyst |
| :-------------------------- | :-: | :-----------------: | :-----------------: | :--------: | :--------------: |
| Security budget approval    |  A  |          C          |          R          |      I     |         I        |
| Vulnerability remediation   |  I  |          R          |          A          |      I     |         R        |
| Incident response execution |  I  |          A          |          R          |      I     |         R        |
| Security policy approval    |  A  |          R          |          C          |      C     |         C        |
| Risk acceptance decisions   |  A  |          R          |          C          |      C     |         C        |
| Security awareness training |  I  |          A          |          R          |      R     |         R        |
| Vendor risk assessment      |  I  |          R          |          C          |      I     |         R        |
| Audit coordination          |  I  |          A          |          C          |      C     |         R        |

Key: R = Responsible, A = Accountable, C = Consulted, I = Informed


# Part 2: Role Definitions

Managing sensitive healthcare information requires clear separation between data ownership, business decision-making, and technical system management. Data governance ensures that individuals who understand the importance of information remain involved in decisions, while technical teams provide the controls needed to protect MedDefense data.

| Role                     | Position                       | Definition                                                                                                                                                           | Justification                                                                                                                                                                                                                                                                                                                                                                                                                 |
| :----------------------- | :----------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Data Owner               | Department Heads               | The business-side authority responsible for deciding data classification, controlling access requirements, and approving exceptions related to information handling. | Department Heads have the required clinical knowledge to understand the importance of the information they manage. For example, Dr. Patel in Cardiology understands the sensitivity and operational value of patient records within his department. Because Department Heads act as Data Owners, they provide business and clinical input during risk acceptance decisions and policy exceptions involving their departments. |
| Data Controller          | CEO / Board                    | The entity responsible for deciding why and how patient data is processed across the organization.                                                                   | The CEO / Board carries the highest level of legal and regulatory responsibility as the HIPAA Covered Entity and ensures overall organizational compliance.                                                                                                                                                                                                                                                                   |
| Data Processor           | Third-Party Vendors            | Organizations that process MedDefense data based on contractual agreements and instructions provided by MedDefense.                                                  | Third-Party Vendors support MedDefense operations by processing information under defined agreements but do not independently determine how MedDefense data should be used.                                                                                                                                                                                                                                                   |
| Data Custodian / Steward | IT Director & Security Analyst | The role responsible for maintaining technical safeguards, protecting information assets, and ensuring data handling follows Data Owner requirements.                | Sarah manages infrastructure and technical custody, while the Security Analyst supports daily security monitoring, operational protection, and governance activities.                                                                                                                                                                                                                                                         |


# Part 3: The CISO Question

## Consequences of a Vacant CISO Position

The vacant CISO position creates a governance gap because MedDefense currently lacks a dedicated security executive responsible for coordinating the overall security program. Without a dedicated CISO, security decisions may become fragmented between departments, IT operations, and leadership, making it more difficult to maintain a consistent security strategy.

This gap can lead to unclear accountability for security risks, inconsistent risk acceptance decisions, and challenges in aligning security priorities with business objectives. A dedicated security leader is also important for coordinating incident response, supporting compliance activities, and communicating security risks to executive leadership.

Without a CISO, MedDefense may rely too heavily on operational teams to manage strategic security decisions, reducing the ability to maintain long-term governance and proactive risk management.


## Recommendation: vCISO

MedDefense should adopt a vCISO model rather than immediately hiring a full-time CISO. Given the current budget constraint, hiring a permanent executive could consume resources needed for technical remediation activities. The organization needs to preserve funding from the $120,000 technical remediation budget for critical improvements such as network segmentation and backup isolation.

A vCISO would provide security leadership, governance support, policy oversight, and executive-level reporting while requiring a lower financial commitment than a full-time CISO. This approach allows MedDefense to strengthen its security program, maintain appropriate governance, and continue investing in the technical improvements required to reduce risk.
