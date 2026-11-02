# Threat Intelligence Source Evaluation & Research Matrix

**Document Version**: 1.1.0 (Phase 2C Emergency Integrity Correction)  
**Phase**: Phase 2C  
**Author**: RaxoSentinel Security Architecture Team  
**Status**: APPROVED EVALUATION & AUDIT RECORD  

This document evaluates candidate threat intelligence feeds for incorporation into the RaxoSentinel Intelligence Database (RSIDB) release pipeline.

Our guiding principle is: **genuine detection coverage, reliable updates, and low resource consumption—never artificially inflating signature counts, never assuming free API access implies redistribution rights, and never manufacturing replacement signatures.**

---

## 1. Candidate Source Evaluation Matrix

| Criterion | 1. Abuse.ch MalwareBazaar | 2. Abuse.ch URLhaus | 3. VirusTotal | 4. VX-Underground | 5. CISA AIS | 6. Cisco Talos CVD (`daily.cvd`) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Origin & Operator** | abuse.ch / BFH (Switzerland), partnered with Spamhaus | abuse.ch / BFH (Switzerland), partnered with Spamhaus | Chronicle Security / Google LLC, USA | Independent cybersecurity research group | Cybersecurity & Infrastructure Security Agency (DHS), USA | Cisco Systems, Inc. / Cisco Talos |
| **Available Data** | SHA256, SHA1, MD5, file size, MIME type, malware family tags | Malicious URLs, payload hashes, threat status | Multi-engine AV detections, static/dynamic analysis, file hashes | Malware samples, source code, whitepapers | STIX/TAXII indicators: hashes, IPs, domains | ClamAV hash signatures (.hdb, .hsb), byte patterns (.ndb) |
| **Update Frequency** | Real-time API, hourly exports | Real-time API, exports every 5 min | Continuous real-time | Ad-hoc / periodic uploads | Continuous TAXII feed | Daily updates |
| **Accuracy & Limitations** | High accuracy; requires exact file size to avoid false positives | High accuracy for active distribution URLs and payload hashes | Very high breadth; detection names vary across engines | Uncurated raw samples; contains unverified binaries | Variable; government telemetry & historical IOCs | Highly tuned for email & endpoint; covers extensive threat families |
| **API / Access Status** | **AUTHENTICATION REQUIRED**: Anonymous requests return `{"error": "Unauthorized"}`. Requires personal `Auth-Key` | **AUTHENTICATION REQUIRED**: Anonymous requests return `{"error": "Unauthorized"}`. Requires personal `Auth-Key` | Strict API rate limits; commercial subscription required for bulk queries | No public bulk metadata API | Requires signed DHS AIS agreement and TAXII 2.1 client auth | HTTP/DNS mirror restrictions; Cloudflare bot management |
| **Commercial Usage Conditions** | **RESTRICTED / UNVERIFIED**: Governed by fair-use policy; commercial automated use transitions to Spamhaus commercial feeds | **RESTRICTED / UNVERIFIED**: Governed by fair-use policy | **PROHIBITED** without enterprise tier; ToS forbids building competing AV databases | **UNVERIFIED / PROHIBITED**: No commercial grant | Permitted for internal defensive purposes of participants | **PROHIBITED** without written commercial OEM agreement from Cisco |
| **Redistribution Rights** | **UNVERIFIED**: Redistribution terms for third-party public scanners are unconfirmed | **UNVERIFIED**: Redistribution terms for third-party public scanners are unconfirmed | **STRICTLY PROHIBITED** (ToS § 3 explicit restriction) | **STRICTLY PROHIBITED** (No distribution license provided) | Conditional (TLP:WHITE shareable; TLP:AMBER restricted) | **UNVERIFIED / RESTRICTED**: Mirroring without authorization violates Cisco terms |
| **Required Attribution** | Citation requested by abuse.ch | Citation requested by abuse.ch | N/A (prohibited) | N/A (prohibited) | Cite CISA AIS | Copyright Cisco Systems, Inc. |
| **Decision / Eligibility** | **BLOCKED (AUTH-KEY REQUIRED & RIGHTS UNVERIFIED)** | **BLOCKED (AUTH-KEY REQUIRED & RIGHTS UNVERIFIED)** | **DISQUALIFIED (LEGAL BLOCKER)** | **DISQUALIFIED (NO LICENSE / LIVE MALWARE)** | **DEFERRED (OPERATIONAL OVERHEAD)** | **UNVERIFIED / RESTRICTED (NO OEM AGREEMENT)** |

---

## 2. Technical Investigation of Abuse.ch Metadata API

### 2.1 Access Status: Authentication Required
During Phase 2C investigation, automated keyless queries to the MalwareBazaar and URLhaus API endpoints (`https://mb-api.abuse.ch/api/v1/`) were tested:
```
$ curl -s https://mb-api.abuse.ch/api/v1/ -d 'query=get_recent&selector=time'
{"error": "Unauthorized"}
```

**Key Finding**:
Abuse.ch has deprecated anonymous, unauthenticated access. All API endpoints and export feeds require an individual account and personal `Auth-Key` passed via the `Auth-Key: <KEY>` HTTP header.

### 2.2 Operational Policy: Zero Manufacturing of Signatures
Because unauthenticated access is blocked and automated pipeline credentials are not currently configured:
- **No external threat records were retrieved.**
- **No replacement records were manufactured.**
- **The verified genuine operational record count is strictly ZERO (0).**

---

## 3. Legal & Intellectual Property Review

### 3.1 Unresolved Rights Documented as UNVERIFIED
1. **Abuse.ch Community Feeds**:
   While historical documentation referenced CC0 public domain dedications, modern abuse.ch infrastructure operates in partnership with Spamhaus under community fair-use terms. Commercial redistribution in public antivirus databases without explicit written confirmation cannot be assumed. Therefore, public redistribution rights are officially documented as **UNVERIFIED**.
2. **Cisco ClamAV CVD Intelligence**:
   ClamAV engine code is licensed under GPL-2.0. However, the production threat intelligence database (`daily.cvd`, `main.cvd`) is proprietary threat intelligence copyrighted by Cisco Talos. Cisco restrictions prohibit unauthorized republication or commercial mirroring without an OEM license. Redistribution rights for RSIDB remain **UNVERIFIED / RESTRICTED**.

---

## 4. Current Operational Status

Until an authorized threat intelligence provider with verified redistribution rights, authenticated API credentials, and cryptographic provenance is established:
- **Verified Genuine Operational Records**: **0**
- **Synthetic Test Indicators**: **3** (EICAR MD5, EICAR SHA-256, ClamAV test file)
- **Quarantined Synthetic Test Fixtures**: **8** (confirmed synthetic preimages quarantined in `test_fixtures/quarantined_synthetic_fixtures/`)
- **Quarantined Unit Test Fixtures**: **19** (GPL-2.0 ClamAV unit test vectors)
