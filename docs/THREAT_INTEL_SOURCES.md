# Threat Intelligence Source Evaluation & Research Matrix

**Document Version**: 1.0.0  
**Phase**: Phase 2C  
**Author**: RaxoSentinel Security Architecture Team  
**Status**: APPROVED EVALUATION  

This document evaluates candidate threat intelligence feeds for incorporation into the RaxoSentinel Intelligence Database (RSIDB) release pipeline.

Our guiding principle is: **genuine detection coverage, reliable updates, and low resource consumption—never artificially inflating signature counts, never assuming free API access implies redistribution rights, and never downloading live malware.**

---

## 1. Candidate Source Evaluation Matrix

| Criterion | 1. Abuse.ch MalwareBazaar | 2. Abuse.ch URLhaus | 3. VirusTotal | 4. VX-Underground | 5. CISA AIS | 6. CIRCL MISP OSINT |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Origin & Operator** | abuse.ch / Bern Univ. of Applied Sciences (BFH), Switzerland | abuse.ch / BFH, Switzerland | Chronicle Security / Google LLC, USA | Independent cybersecurity research group | Cybersecurity & Infrastructure Security Agency (DHS), USA | CIRCL (Luxembourg National CERT) |
| **Available Data** | SHA256, SHA1, MD5, file size, MIME type, file type, malware family/tag, first/last seen | Malicious URLs, payload hashes (SHA256, MD5), threat status, reporter | Multi-engine AV detections, static/dynamic analysis, file hashes | Malware samples, source code, whitepapers | STIX/TAXII indicators: hashes, IPs, domains, threat actors | OSINT threat events: SHA256/MD5 hashes, email indicators, phishing URLs |
| **Update Frequency** | Real-time API, hourly exports, daily full CSV dumps | Real-time API, exports updated every 5 minutes | Continuous real-time | Ad-hoc / periodic sample uploads | Continuous automated TAXII feed | Daily / continuous event sync |
| **Accuracy & Limitations** | **High accuracy**; verified by community & sandboxes. Focused on malware executables and documents | **High accuracy** for active payload distribution URLs and hashes | **Very high breadth**, but engine detection names vary widely | Uncurated raw samples; contains unverified binaries | Highly variable; contains government telemetry and historical IOCs | **High accuracy** for European targeted threats and phishing campaigns |
| **API Restrictions** | Free public API (100 req/min); no-rate-limit bulk CSV/JSON export downloads | Free public API and bulk text/CSV feeds | Strict API rate limits; commercial subscription required for bulk queries | No public bulk API for metadata; manual torrent/file downloads | Requires signed DHS AIS agreement and TAXII 2.1 client authentication | Free public access to TLP:WHITE feeds; API key required for full MISP sync |
| **Commercial Usage Conditions** | **Permitted**. All metadata and indicators are released under CC0 | **Permitted**. Released under CC0 | **Prohibited without enterprise tier**. Output cannot be used to compete or build AV databases | **Unclear / Prohibited**. No explicit commercial grant | Permitted for defensive purposes within participating organizations | Permitted under CC-BY 4.0 or Open Database License (ODbL) |
| **Redistribution Rights** | **UNRESTRICTED (CC0 1.0 Universal)** | **UNRESTRICTED (CC0 1.0 Universal)** | **STRICTLY PROHIBITED** (ToS § 3 explicit restriction) | **STRICTLY PROHIBITED** (No distribution license provided) | Conditional (TLP:WHITE shareable; TLP:AMBER restricted) | Permitted with attribution (CC-BY 4.0) |
| **Required Attribution** | *"Data provided by abuse.ch MalwareBazaar (https://bazaar.abuse.ch/)"* | *"Data provided by abuse.ch URLhaus (https://urlhaus.abuse.ch/)"* | N/A (redistribution prohibited) | N/A (redistribution prohibited) | Cite CISA AIS | *"CIRCL Open Source Threat Intelligence"* |
| **Decision / Eligibility** | **SELECTED (PRIMARY OPERATIONAL SOURCE)** | **SELECTED (SECONDARY PAYLOAD SOURCE)** | **DISQUALIFIED (LEGAL BLOCKER)** | **DISQUALIFIED (NO LICENSE / LIVE MALWARE)** | **DEFERRED (OPERATIONAL OVERHEAD)** | **QUALIFIED (FUTURE EXPANSION)** |

---

## 2. In-Depth Analysis of Selected Candidate: Abuse.ch MalwareBazaar

### 2.1 Legal & Licensing Foundation
Abuse.ch explicitly dedicates its threat indicator datasets to the public domain using the **Creative Commons CC0 1.0 Universal (CC0) Public Domain Dedication**:
> *"All data published by abuse.ch is licensed under CC0 1.0 Universal (CC0). You can copy, modify, distribute and perform the work, even for commercial purposes, all without asking permission."*

This provides full legal authorization for RaxoSentinel to:
1. Ingest indicator hashes and metadata into the RSIDB compiler.
2. Compile indicators into binary `.rsidb` distribution packages.
3. Distribute compiled databases to public users and commercial email operators.
4. Distribute derivative databases under GPL-2.0-or-later.

### 2.2 Required Attribution
Even though CC0 waives all copyright restrictions, academic and community attribution is strongly requested by abuse.ch. RaxoSentinel enforces this requirement programmatically:
- `SourceManifest.redistribution` is set to `Redistribution::AllowedWithAttribution`.
- `SourceManifest.attribution` is set to `"Data provided by abuse.ch MalwareBazaar (https://bazaar.abuse.ch/)"`.
- The ingestion pipeline validates that attribution text is present and non-empty.
- The compiled `BuildManifest` carries forward this attribution notice for downstream display in `raxosentinel db info`.

### 2.3 Safeguards: Distinguishing Metadata from Malware Binaries
> [!CAUTION]
> **Zero Live Malware Policy**:
> RaxoSentinel only ingests cryptographic digests (SHA-256, MD5), exact file sizes, and normalized threat family classifications (e.g. `Win32.Trojan.AgentTesla`, `Win32.Trojan.Formbook`).
>
> The RaxoSentinel pipeline **never downloads, unpacks, executes, or distributes live malware sample binaries**.

---

## 3. Disqualified Sources & Licensing Blockers

### 3.1 VirusTotal (Disqualified)
- **Legal Barrier**: VirusTotal Terms of Service, Section 3 ("Use Restrictions"):
  > *"You will not, and will not permit anyone else to: ... (c) use the Services to build, improve, or train any competing product, service, or database, including any antivirus or malware detection engine; or (d) redistribute, sublicense, or publicly display raw scan results or bulk indicator feeds."*
- **Conclusion**: Relying on VirusTotal as an indicator source for RSIDB would constitute a direct breach of contract and intellectual property infringement.

### 3.2 Cisco Talos Production CVD (`daily.cvd` / `main.cvd`) (Disqualified)
- **Legal Barrier**: While ClamAV engine source code is licensed under GPL-2.0, the Cisco Talos CVD threat database is proprietary threat intelligence owned by Cisco Systems, Inc. Cisco's terms of service prohibit unauthorized mirroring, republication, or redistributing parsed CVD signatures in third-party products without a commercial OEM agreement.
- **Conclusion**: RaxoSentinel incorporates only harmless ClamAV unit test signatures for regression tests; it never redistributes Cisco Talos production intelligence.

---

## 4. Ingestion Format & Provenance Preservation

MalwareBazaar indicators are ingested through the hardened `IngestPipeline`:
1. **Identifier**: `abuse-ch-malwarebazaar-recent`
2. **Provenance**: Recorded with acquisition timestamp, version, upstream URL, and CC0-1.0 license.
3. **Classification**: Marked as `SourceKind::Genuine` (distinguished from `SourceKind::SyntheticTest`).
4. **Validation**: Lines missing valid 64-char SHA256, valid file size, or valid name are individually rejected with line-level diagnostics.
5. **Deduplication & Canonicalization**: Duplicate indicators across daily feeds are consolidated into canonical records while preserving all detection names.
6. **Revocation Support**: If an indicator is later identified as a false positive, it is added to the revocation list, causing the compiler to emit a `revoked` tombstone and omit it from the active index.
