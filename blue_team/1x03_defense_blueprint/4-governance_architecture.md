# 4. The Governance Architecture

## Part 1: RACI Matrix

A strong security governance model requires a clear separation between executive decision-making, business ownership, security governance, and technical execution. The RACI model below defines who performs security activities, who is accountable for decisions, who provides expertise, and who must remain informed.

This structure ensures that security governance decisions remain aligned with organizational leadership while operational security activities are handled by the appropriate teams. The Deputy CISO (James) provides security governance, oversight, and recommendations; the IT Director (Sarah) manages technical implementation and operational controls; Department Heads maintain business ownership of departmental risks and data decisions; and the Security Analyst supports the execution of security activities.

| Activity                    | CEO | Deputy CISO (James) | IT Director (Sarah) | Dept Heads | Security Analyst |
| :-------------------------- | :-: | :-----------------: | :-----------------: | :--------: | :--------------: |
| Security budget approval    |  A  |          C          |          C          |      C     |         I        |
| Vulnerability remediation   |  I  |          C          |          A          |      C     |         R        |
| Incident response execution |  I  |          A          |          R          |      C     |         R        |
| Security policy approval    |  A  |          C          |          C          |      R     |         C        |
| Risk acceptance decisions   |  A  |          C          |          C          |      R     |         I        |
| Security awareness training |  I  |          A          |          C          |      R     |         R        |
| Vendor risk assessment      |  I  |          A          |          C          |      C     |         R        |
| Audit coordination          |  I  |          A          |          C          |      C     |         R        |

Key: R = Responsible, A = Accountable, C = Consulted, I = Informed


# Part 2: Role Definitions

Managing sensitive healthcare information requires a clear separation between data ownership, business decision-making, and technical system management. Data governance ensures that individuals who understand the operational and clinical importance of information remain involved in decisions, while technical teams provide the safeguards required to protect MedDefense data.

| Role                     | Position                       | Definition                                                                                                                                                           | Justification                                                                                                                                                                                                                                                                                                                                                                                             |
| :----------------------- | :----------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Data Owner               | Department Heads               | The business-side authority responsible for deciding data classification, controlling access requirements, and approving exceptions related to information handling. | Department Heads have the required clinical knowledge to understand the importance of the information they manage. For example, Dr. Patel in Cardiology understands the sensitivity and operational value of patient records within his department. Because Department Heads act as Data Owners, they provide business and clinical input for risk decisions and policy exceptions affecting their areas. |
| Data Controller          | CEO / Board                    | The entity responsible for deciding why and how patient data is processed across the organization.                                                                   | The CEO / Board carries the highest level of legal and regulatory responsibility as the HIPAA Covered Entity and ensures overall organizational compliance.                                                                                                                                                                                                                                               |
| Data Processor           | Third-Party Vendors            | Organizations that process MedDefense data based on contractual agreements and instructions provided by MedDefense.                                                  | Third-Party Vendors support MedDefense operations by handling information according to agreements but do not independently decide how MedDefense data should be used.                                                                                                                                                                                                                                     |
| Data Custodian / Steward | IT Director & Security Analyst | The role responsible for maintaining technical safeguards, protecting information assets, and ensuring data handling follows Data Owner requirements.                | Sarah manages infrastructure and technical custody, while the Security Analyst supports daily security monitoring, operational protection, and governance activities.                                                                                                                                                                                                                                     |


# Part 3: The CISO Question

## Consequences of a Vacant CISO Position

The vacant CISO position creates a governance gap because MedDefense currently lacks a dedicated security executive responsible for coordinating the overall security program. Without a dedicated CISO, security activities may become fragmented between departments, IT operations, and leadership, making it more difficult to maintain a consistent security strategy.

This gap can create unclear ownership of security risks, inconsistent risk acceptance decisions, and difficulty aligning security priorities with business objectives. A dedicated security leader is also important for coordinating incident response, supporting compliance activities, and communicating security risks to executive leadership.

Without a CISO, MedDefense may rely too heavily on operational teams for strategic security decisions, reducing the organization’s ability to maintain proactive governance and long-term risk management.


## Recommendation: vCISO

MedDefense should adopt a vCISO model rather than immediately hiring a full-time CISO. Given the current budget constraint, hiring a permanent executive could consume resources required for technical remediation activities. The organization needs to preserve funding from the $120,000 technical remediation budget for critical improvements such as network segmentation and backup isolation.

A vCISO would provide security leadership, governance support, policy oversight, and executive-level reporting while requiring a lower financial commitment than a full-time CISO. This approach allows MedDefense to strengthen its security program while continuing to invest in the technical improvements required to reduce risk.
