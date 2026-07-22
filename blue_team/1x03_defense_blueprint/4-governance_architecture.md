# 4. The Governance Architecture

## Part 1: RACI Matrix

A strong security program requires clearly defined ownership. The RACI model below establishes who is responsible for performing security tasks, who has final accountability for decisions, who provides expertise or guidance, and who needs visibility into security activities. This structure prevents conflicts such as unclear ownership between IT operations, security teams, and business departments.

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

Clear data ownership is essential in a healthcare environment because different teams have different responsibilities when handling sensitive information. The following roles define who controls business decisions, who manages processing activities, and who maintains the technical environment supporting data protection.

| Role                     | Position                       | Definition                                                                                                                                                        | Justification                                                                                                                                                                                                    |
| :----------------------- | :----------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Data Owner               | Department Heads               | The business representative responsible for determining data classification levels, defining appropriate access requirements, and approving access exceptions.    | Department Heads understand the operational importance of the information they manage. For example, Dr. Patel in Cardiology understands the importance and sensitivity of patient records within his department. |
| Data Controller          | CEO / Board                    | The organization that determines the purpose, legal basis, and overall approach for processing patient information.                                               | The CEO / Board maintains final legal and regulatory responsibility as the HIPAA Covered Entity and ensures organizational accountability.                                                                       |
| Data Processor           | Third-Party Vendors            | External organizations that process or store MedDefense data according to established agreements and instructions.                                                | Vendors such as MedTech, Microsoft, and Siemens support data processing activities but do not independently determine how the information should be used.                                                        |
| Data Custodian / Steward | IT Director & Security Analyst | The technical role responsible for applying security controls, maintaining systems, and ensuring data is properly protected according to Data Owner requirements. | Sarah provides infrastructure management and operational support, while the Security Analyst handles daily security monitoring and governance activities.                                                        |


# Part 3: The CISO Question

## Consequences of Not Having a Dedicated CISO

The absence of a permanent CISO creates a leadership and governance gap within MedDefense’s security program. Security decisions may become inconsistent because there is no single executive authority responsible for aligning business priorities, technical controls, and organizational risk decisions. Without a CISO, departments may continue making independent security choices without a unified strategy, creating conflicts over ownership and accountability.

This gap also limits MedDefense’s ability to establish strong security governance, enforce consistent risk management practices, and communicate security risks effectively to executive leadership. During major events such as ransomware incidents or regulatory reviews, the organization may face delays because security responsibilities are distributed rather than centrally managed.

## Recommendation: vCISO

MedDefense should consider hiring a virtual CISO (vCISO) instead of immediately creating a full-time CISO position. Because the organization is operating under significant budget constraints, a permanent executive hire would require a substantial investment and could reduce the available $120,000 technical remediation budget needed for critical improvements such as network segmentation and backup isolation.

A vCISO would provide the strategic direction that MedDefense currently lacks by supporting governance decisions, improving security policies, and delivering leadership-level reporting without the financial commitment of a full-time executive role. This approach allows MedDefense to strengthen its security program while preserving budget availability for priority technical remediation activities.
