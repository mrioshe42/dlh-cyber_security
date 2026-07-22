# 4. The Governance Architecture

# Part 1: RACI Matrix

A successful security program requires clearly assigned ownership, accountability, and communication paths. The RACI model below establishes the governance structure for MedDefense by defining who performs security activities, who is ultimately accountable for decisions, who provides expertise, and who must remain informed.

This structure ensures that security responsibilities are distributed across leadership, security governance, technical operations, and business departments. The CEO provides executive accountability for major organizational decisions, the Deputy CISO (James) coordinates security governance activities and ensures alignment with security objectives, the IT Director (Sarah) manages technical implementation and operational responsibilities, Department Heads contribute business and clinical knowledge, and the Security Analyst supports daily security operations.

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

Managing sensitive healthcare information requires a clear separation between business ownership, regulatory responsibility, third-party processing, and technical protection. These roles ensure that MedDefense maintains proper governance over patient data while allowing technical teams to implement the necessary security safeguards.

| Role                     | Position                       | Definition                                                                                                                                                            | Justification                                                                                                                                                                                                                                                  |
| :----------------------- | :----------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Data Owner               | Department Heads               | The business-side individual accountable for classifying data, determining appropriate access requirements, and approving exceptions related to information handling. | Department Heads have direct knowledge of the clinical importance and operational requirements of the information they manage. For example, Dr. Patel in Cardiology understands the criticality and sensitivity of patient records used within his department. |
| Data Controller          | CEO / Board                    | The legal entity responsible for determining why and how patient data is processed across the organization.                                                           | The CEO / Board maintains overall legal and regulatory responsibility as the HIPAA Covered Entity and ensures that MedDefense remains accountable for how patient information is managed.                                                                      |
| Data Processor           | Third-Party Vendors            | External organizations that process MedDefense data according to contractual agreements and instructions provided by MedDefense.                                      | Third-Party Vendors such as MedTech, Microsoft, and Siemens handle MedDefense data under defined agreements but do not independently decide how the information is used.                                                                                       |
| Data Custodian / Steward | IT Director & Security Analyst | The role responsible for implementing technical safeguards, maintaining systems, and supporting data protection activities according to Data Owner requirements.      | Sarah manages infrastructure custody and technical operations, while the Security Analyst supports daily security activities, monitoring, and governance processes.                                                                                            |


# Part 3: The CISO Question

## Consequences of a Vacant CISO Position

The absence of a full-time CISO creates a governance gap where security activities may become reactive instead of being guided by a structured security strategy. Without a dedicated CISO, MedDefense lacks a central security authority responsible for coordinating security initiatives, connecting technical operations with executive risk decisions, and maintaining consistent security governance across the organization.

This gap can make it more difficult to ensure that Department Heads are accountable for security responsibilities, that security risks are communicated effectively to leadership, and that risk acceptance decisions follow a consistent process. A vacant CISO role may also increase exposure during events such as a HIPAA audit or ransomware incident because security leadership and coordination responsibilities are distributed across multiple roles.


## Recommendation: vCISO

MedDefense should outsource the security leadership function through a virtual CISO (vCISO) rather than immediately hiring a full-time executive. Due to severe budget constraints, hiring a permanent CISO would require significant financial investment and could reduce the resources available for important technical remediation activities.

A full-time hire could consume a large portion of the $120,000 technical remediation budget, leaving fewer resources available for critical improvements such as network segmentation and backup isolation. A vCISO would provide strategic security oversight, policy guidance, governance support, and Board-level reporting while requiring a lower financial commitment. This approach allows MedDefense to strengthen its security program while preserving funding for technical execution and risk reduction activities.
