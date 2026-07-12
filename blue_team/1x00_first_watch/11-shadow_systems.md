## 11: The Shadow Systems

### Shadow System 1: Dr. Patel's Personal NAS (Cardiology)

**Risk Assessment:**
- **Data:** Research data (possibly including de-identified patient cohorts for clinical trials); unknown if HIPAA-restricted or just research documentation
- **Controls NOT covering this system:** All controls in Exercise 10 (firewall, endpoint protection, backup, authentication, encryption) — NAS is on network but not managed by IT, not in asset registry, no password protection documented
- **Worst-case scenario:** Attacker gains access to unencrypted NAS, exfiltrates research data (identity theft if de-identification is incomplete), or encrypts NAS with ransomware; research data lost; regulatory investigation (IRB notification if human research involved); Dr. Patel's clinical trial compromised; potential $100K+ in legal/regulatory costs

**Recommended Response: LEGITIMIZE AND SECURE**
- Justify: Data appears clinically relevant (research); destroying it creates operational loss; migration is feasible
- Action: (1) Move research data to hospital-managed NAS with encryption at rest, access control via AD, and backup; (2) Enroll Dr. Patel in IT governance; (3) Apply standard security controls (data classification, access auditing, retention policy); (4) Decommission personal NAS

**Asset Registry Update:**
- Asset ID: A-038
- Name: Dr. Patel's Personal NAS
- Status: Shadow IT → Planned Migration to Approved NAS
- Notes: Contains cardiology research data; moving to managed storage with encryption and access control

### Shadow System 2: Google Drive (Marketing Shared Account)

**Risk Assessment:**
- **Data:** Marketing media files, press communications, possibly org charts, speaker bios, event coordination; linked to personal Gmail account (data residency unknown, possibly subject to Google's ToS privacy terms, not MedDefense's DPA)
- **Controls NOT covering:** None — external service outside MedDefense network; not managed by Microsoft O365 (which has contractual HIPAA terms); no encryption beyond Google's infrastructure; personal Gmail account = weak authentication, password reuse risk
- **Worst-case scenario:** Attacker compromises personal Gmail account (phishing, password reuse); accesses MedDefense media library and communications; modifies press releases (reputation attack); plants malware in downloadable media; market intelligence disclosed (strategic plans); potential liability if media contains compliance-related documentation

**Recommended Response: MIGRATE**
- Justify: Function (file sharing) already exists in O365; no technical barrier to migration; reduces compliance risk
- Action: (1) Migrate all Google Drive content to Microsoft Teams + SharePoint (O365) with proper governance; (2) Decommission personal Gmail sharing; (3) Apply MedDefense data governance (classification, retention, access control); (4) Ensure O365 instance has HIPAA BAA if any health-related data is stored

**Asset Registry Update:**
- Asset ID: A-039
- Name: Google Drive (Marketing)
- Status: Shadow IT → Planned Migration to O365
- Notes: Shared account linked to personal Gmail; moving to O365 for governance and contractual compliance

### Shadow System 3: Raspberry Pi (Network Monitor)

**Risk Assessment:**
- **Data:** Network traffic capture (potentially including unencrypted patient data, credentials, medical records if monitoring medical network segment); monitoring configuration/scripts
- **Controls NOT covering:** No IT inventory, no patching, no monitoring of the Pi itself, no authentication on access
- **Worst-case scenario:** Attacker finds unattended Raspberry Pi on second floor; steals SD card; accesses pcap files containing months of captured network traffic (patient records, lab results, credentials); replays or exfiltrates data; establishes persistent backdoor on Pi (low-power device, overlooked in security scans); uses Pi as pivot point to access network closet or other infrastructure; Marcus and previous intern both left without documentation or handoff

**Recommended Response: DECOMMISSION**
- Justify: Purpose (ad hoc network monitoring) should be fulfilled by managed solutions (SIEM, NetFlow, IDS); Raspberry Pi is not auditable, not supported, not compliant with healthcare environment standards; Marcus did not complete or document the use case
- Action: (1) Power down Pi immediately; (2) Secure SD card/storage (forensics if needed); (3) Verify no network traffic capture is being relied upon for operations; (4) Document lessons learned (why it was deployed, why it was abandoned); (5) Recommend proper SIEM solution (g-011) as replacement

**Asset Registry Update:**
- Asset ID: A-040
- Name: Raspberry Pi (Intern Network Monitor, Abandoned)
- Status: Shadow IT → Decommissioned
- Notes: Ad hoc network monitoring device; abandoned by previous intern; no documentation; replaced by formal monitoring solution in roadmap

### Shadow IT Policy Recommendation

**Policy:** "All IT systems, applications, and data storage services used for organizational purposes must be approved by the IT Security Committee before deployment. Unapproved systems found during network scans or audits will be disabled within 48 hours unless an exception request (with business justification and risk assessment) is submitted to the CISO for review. Exceptions require sign-off from both IT Director and CISO. This policy applies to personal devices, cloud services, and hardware deployed on organizational networks."

**Rationale:** Shadow IT exists because approval processes are perceived as slow or restrictive. A fast-track exception process (48 hours for CISO review) allows legitimate needs to be met while preventing systems from operating indefinitely without oversight. Three identified shadow systems (NAS, Google Drive, Pi) represent governance failures; a clear policy with rapid exception handling reduces friction and compliance risk simultaneously.
