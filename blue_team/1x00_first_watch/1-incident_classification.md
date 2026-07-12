## 1: The First Incidents

### Incident Classification Analysis

| Incident | Primary CIA Pillar | Justification | Secondary Pillar | Secondary Connection |
|----------|-------------------|---------------|------------------|----------------------|
| **A: Ransomware (Jan 15)** | Availability | billing-srv-01 encrypted for 4 days; finance team unable to process claims. | Confidentiality | Patient billing data may have been exfiltrated before encryption. Backup (3 weeks old) also potentially compromised. |
| **B: Portal Access Control (Feb 2)** | Confidentiality | Unauthorized patients accessed lab results of other patients via URL manipulation. | Integrity | Potential modification risk if the vulnerability extended to write operations; attackers could alter results. |
| **C: Dosage Display Error (Mar 18)** | Integrity | Database bug overwrote medication dosages across all sites; pharmacist detected manual intervention required. | Availability | 6-hour outage of accurate dosing information; clinical workflows forced to rely on printed references; patient safety at risk. |
| **D: Website Defacement (Apr 5)** | Availability | Homepage replaced with political message; website unavailable to public for 2 hours (until backup restore). | Confidentiality | No patient data on public website (low impact); Integrity not compromised (message was only visual). |
| **E: EHR Outage (May 22)** | Availability | 9-hour planned migration outage; physicians resorted to paper records; no clinical data processing. | Integrity | Rollback procedure never tested; risk of data corruption/loss if rollback failed during migration. |
| **F: Intern Laptop Torrent (Jun 10)** | Confidentiality | Unmanaged personal laptop on internal network for 3 weeks; torrent client sharing files; same network segment as HR file share. | Availability | Bandwidth consumption from file sharing degraded network performance; Integrity risk from potential file corruption during transfer.
