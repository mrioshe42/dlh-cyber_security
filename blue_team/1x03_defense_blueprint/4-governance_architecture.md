# 4. The Governance Architecture

## Part 1: RACI Matrix

Effective security governance depends on having clearly assigned responsibilities and decision authority. The RACI model defines ownership for security activities by identifying who executes tasks, who is accountable for outcomes, who contributes expertise, and who must receive updates. This structure helps avoid confusion between security responsibilities, IT operations, and business departments.

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


## Part 2: Role Definitions

Managing sensitive healthcare information requires clear separation of duties. The following roles establish who owns business decisions, who determines data usage, who processes information, and who provides technical protection for MedDefense data.

| Role                     | Position                       | Definition                                                                                                                                                           | Justification                                                                                                                                                                                                                                       |
| :----------------------- | :----------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Data Owner               | Department Heads               | The business-side authority responsible for deciding data classification, controlling access requirements, and approving exceptions related to information handling. | Department Heads have the required clinical knowledge to understand the importance of the information they manage. For example, Dr. Patel in Cardiology understands the sensitivity and operational value of patient records within his department. |
| Data Controller          | CEO / Board                    | The entity responsible for deciding why and how patient data is processed across the organization.                                                                   | The CEO / Board carries the highest level of legal and regulatory responsibility as the HIPAA Covered Entity and ensures overall organizational compliance.                                                                                         |
| Data Processor           | Third-Party Vendors            | Organizations that process MedDefense data based on contractual agreements and instructions provided by MedDefense.                                                  | Vendors such as MedTech, Microsoft, and Siemens support data processing activities but do not have independent authority over how the data is used.                                                                                                 |
| Data Custodian / Steward | IT Director & Security Analyst | The role responsible for maintaining technical controls, protecting information assets, and ensuring data handling follows Data Owner requirements.                  | Sarah manages infrastructure operations, while the Security Analyst supports security monitoring and daily governance activities.                                                                                                                   |


## Part 3: The CISO Question

### Consequences of a Vacant CISO Position

The absence of a dedicated CISO leaves MedDefense with a leadership gap in its security governance structure. With the CISO position currently vacant, security decisions may become inconsistent because there is no single executive responsible for coordinating security strategy, managing risk ownership, and aligning technical activities with business objectives.

Without a CISO, MedDefense may struggle to enforce accountability across departments, maintain a consistent security direction, and provide effective communication between security teams and executive leadership. This situation can increase exposure during security incidents, regulatory assessments, and risk acceptance decisions because responsibilities are distributed across multiple roles.

### Recommendation: vCISO

MedDefense should outsource the CISO function through a virtual CISO (vCISO) rather than immediately hiring a full-time CISO. Due to the existing budget constraint, a full-time executive position could significantly reduce the available $120,000 technical remediation budget required for important improvements such as network segmentation and backup isolation.

A vCISO would provide the necessary governance leadership, security strategy, policy oversight, and Board-level reporting while requiring less financial investment than a permanent executive hire. This solution allows MedDefense to strengthen its security program while continuing to dedicate resources toward critical technical remediation activities.
