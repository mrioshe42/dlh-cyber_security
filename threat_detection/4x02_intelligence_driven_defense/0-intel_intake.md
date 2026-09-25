# Intelligence Intake

## 1. Source-by-Source Breakdown

### Source 1: HHS HC3 Sector Advisory
1. **Source Name:** HHS HC3 Sector Advisory (HEALTHBANE)
2. **Source Type:** Government advisory
3. **Date Published:** 2026-04-25
4. **TLP Classification:** TLP:CLEAR
5. **Number of Indicators:** 23
6. **Types of Indicators:** Domains, IPs, hashes, URLs
7. **One-Line Summary:** Coordinated multi-stage campaign (`HEALTHBANE`) targeting US healthcare organizations since 2026-04-14 via phishing, macro documents, and DNS exfiltration.
8. **Key Limitations / Caveats:** Attribution to a specific named group is unconfirmed (moderate confidence in a financially motivated mid-tier cybercrime actor); commercial tracking names are noted but not endorsed.

### Source 2: Commercial CTI Feed Extract
1. **Source Name:** Acme CTI Commercial Feed (`ACME-HEALTH-2026-0426-117`)
2. **Source Type:** Commercial feed
3. **Date Published:** 2026-04-26
4. **TLP Classification:** TLP:AMBER (Authorized for internal defense at MedDefense only)
5. **Number of Indicators:** 41
6. **Types of Indicators:** Domains, IPs, hashes, URLs
7. **One-Line Summary:** Tracks related adversary infrastructure under the proprietary label `VITALSCORE` using automated clustering.
8. **Key Limitations / Caveats:** Auto-tagged by an automated engine with sampled human review; contains intentional noise, shared infrastructure/CDN IPs (e.g., Microsoft, Azure, Cloudflare), and weakly clustered indicators that must not be used for automated blocking.

### Source 3: Public Researcher Blog Analysis
1. **Source Name:** Pseudo-Infosec Research Blog ("The Phishing Kit Behind The HEALTHBANE Campaign")
2. **Source Type:** Open-source research
3. **Date Published:** 2026-04-24 (Marcus Weller, `@mwresearch`)
4. **TLP Classification:** Public (N/A)
5. **Number of Indicators:** 14
6. **Types of Indicators:** Domains, IPs, hashes, URLs
7. **One-Line Summary:** Technical walkthrough of the PHP credential harvester kit, tooling signatures (PHPMailer 6.6.0, wkhtmltopdf 0.12.6), and historical attribution links.
8. **Key Limitations / Caveats:** Attribution is stated with medium confidence only, based entirely on open-source infrastructure/tooling overlap without victim telemetry.

### Source 4: MedDefense Internal Investigation Report
1. **Source Name:** MedDefense Internal Investigation Report (`MD-2026-IR-0414-001`)
2. **Source Type:** Internal investigation
3. **Date Published:** 2026-04-16
4. **TLP Classification:** INTERNAL
5. **Number of Indicators:** 11
6. **Types of Indicators:** Domains, IPs, hashes, URLs, email addresses
7. **One-Line Summary:** Documents initial Stage 1 phishing vector, local exposures at MedDefense (nurse dmarsh clicking a link), and initial Wazuh detection rules.
8. **Key Limitations / Caveats:** Avoids threat actor attribution entirely; visibility restricted to local telemetry and internal incident records.

## 2. Consolidated View & Deduplication Analysis

### Indicator Metrics
* **Total Raw Indicators Across All Sources:** 89 (HC3: 23, Commercial Feed: 41, Researcher Blog: 14, MedDefense 4x00: 11)
* **Total Unique Indicators (Deduped):** 64
* **Indicators Appearing in Multiple Sources:** 25
* **Indicators Appearing in Only One Source:** 39

### Source Conflicts and Resolutions
1. **Attribution Labels:** 
   * HC3 reports attribution as *unconfirmed*.
   * The commercial feed applies the proprietary label `VITALSCORE`.
   * The independent researcher tracks it under `APT-MEDAGENT` with *medium confidence*.
   * MedDefense internal report omits attribution.
   * *Resolution:* Do not overclaim attribution; treat labels as contextual campaign tags and focus on behavioral indicators.
2. **Confidence Differences:** Varying confidence ratings between government validation (high confidence on core assets), commercial automated machine-learning tags (ranging from high down to speculative low confidence), and researcher hypotheses.
3. **Commercial-Feed Noise:** The commercial feed (`VITALSCORE`) includes broad shared infrastructure and CDN/Cloud provider IPs (Microsoft, Azure, Cloudflare) along with pre-campaign artifacts. These must be filtered or handled as non-actionable context to prevent widespread operational outages.
4. **Asymmetrical Discrepancies:** Single-source indicators (such as researcher-scoped or commercial-exclusive artifacts) require rigorous vetting and secondary source enrichment before integration into active perimeter blocklists.
