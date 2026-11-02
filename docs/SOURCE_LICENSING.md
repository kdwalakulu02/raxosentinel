# RaxoSentinel Source Licensing & Intellectual Property Matrix

**Document Version**: 1.1.0 (Phase 2C Emergency Integrity Correction)  
**Status**: APPROVED POLICY & AUDIT RECORD  

This document establishes the official intellectual property policy and licensing matrix for the RaxoSentinel project. It defines the provenance, distribution rights, and attribution requirements across all components of the repository and database release artifacts.

---

## 1. Intellectual Property Matrix

| Component | Source / Origin | Copyright Owner | License | Permitted in Public Binaries / Git | Permitted in Public RSIDB Releases | Required Notice / Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Original RaxoSentinel Engine** | Internal Raxo engineering (`crates/*`) | RaxoSentinel Contributors | **GPL-2.0-or-later** | **Yes** | N/A (code artifact) | Include GPL-2.0 header and license notice |
| **ClamAV Unit Test Fixtures** | Upstream ClamAV (`unit_tests/input/*`) | Cisco Systems, Inc. / Tomasz Kojm & ClamAV Team | **GPL-2.0** | **Yes** (in test directories only) | **No** (never shipped in operational public intelligence feeds) | Retain upstream `COPYING` (GPL-2.0) and `README`. Strictly do **not** label as public domain |
| **EICAR Test String** | EICAR Standard File | European Institute for Computer Antivirus Research | Public Anti-Virus Standard | **Yes** (harmless test vectors) | **Yes** (classified as `synthetic_test` in test builds) | Standard EICAR naming preserved |
| **Original Raxo Detection Rules** | Raxo internal heuristics and signature engineering | RaxoSentinel Authors | **GPL-2.0-or-later** | **Yes** | **Yes** | Authored by RaxoSentinel; full redistribution permitted |
| **Third-Party Threat Intel: Abuse.ch (MalwareBazaar / URLhaus)** | Abuse.ch / BFH / Spamhaus | Abuse.ch Contributors | **UNVERIFIED** (Requires individual `Auth-Key`; commercial terms unconfirmed) | **No** (unverified indicators removed) | **No** (redistribution permission unverified; 0 records distributed) | Automated keyless access returns `Unauthorized`. Rights documented as UNVERIFIED |
| **Third-Party Threat Intel: Cisco Talos Production CVD** | Cisco Systems / Cisco Talos (`daily.cvd`, `main.cvd`) | Cisco Systems, Inc. | **UNVERIFIED / RESTRICTED** (Proprietary Cisco ToS) | **No** (never committed or mirrored) | **STRICTLY PROHIBITED** | Redistribution without commercial OEM license violates Cisco terms |
| **Third-Party Threat Intel: VirusTotal** | Chronicle Security / Google LLC | Google LLC | **Proprietary / Commercial ToS** | **No** | **STRICTLY PROHIBITED** | Section 3 of ToS prohibits using indicators to build or redistribute public scanner databases |

---

## 2. Audit Finding: ClamAV Test Fixtures Attribution

### Background
During Phase 2B development, working notes in `HANDOFF_GEMINI.md` incorrectly referenced ClamAV test signatures (`clamav.hdb`) as "Public domain / Cisco test set."

### Corrective Finding
1. **No Public Domain Dedication**: Upstream ClamAV unit tests are not in the public domain. They were authored by Tomasz Kojm and contributors, subsequently maintained by Sourcefire and Cisco Systems.
2. **True License: GPL-2.0**: The test suite directory contains [`COPYING`](file:///workspace/projects/011-raxosentinelcore/Phase01/crates/raxosentinel-signatures/test_fixtures/COPYING), which is the GNU General Public License Version 2.
3. **Correct Attribution**: All ClamAV test fixtures retained in `crates/raxosentinel-signatures/test_fixtures/` are licensed under GPL-2.0.
4. **Distribution Boundary**: GPL-2.0 permits distributing test fixtures alongside source code, provided the license text and copyright notices are preserved. However, they are strictly quarantined to test fixtures and must **never** be conflated with operational threat intelligence or public domain feeds.

---

## 3. Threat Intelligence Database (RSIDB) Distribution Policy

To maintain unquestionable legal and ethical standing, public RSIDB releases are governed by four mandatory rules:

1. **Explicit Rights & Provenance Verification**:
   - The ingestion pipeline (`rsidb::ingest::IngestPipeline`) strictly verifies that `manifest.redistribution` is either `Allowed` or `AllowedWithAttribution`.
   - Third-party sources with unconfirmed redistribution rights are documented as **UNVERIFIED** and excluded from public builds.
   - Operator authorization (`--allow-source`), `--verify-genuine-source`, and content pinning do not establish source authenticity. Local manifests are not promoted to genuine status; see `MALWAREBAZAAR.md` for the separate authenticated research acquisition path.

2. **Truthful Coverage Reporting**:
   - RSIDB manifests strictly separate `genuine_records` from `synthetic_records`.
   - Synthetic test vectors (EICAR, ClamAV test binaries, simple string preimages) can **never** be counted toward genuine threat protection.
   - The current verified genuine operational record count is **0**.

3. **No Replacement Signature Manufacturing**:
   - If an external feed or API is inaccessible or rights are unresolved, the pipeline reports 0 genuine records. Under no circumstances may artificial or synthetic records be manufactured as replacements.

4. **Zero Live Malware**:
   - The repository and database pipelines process **only cryptographic hashes, file sizes, and threat classification metadata**.
   - No live or weaponized malware samples are downloaded, stored, or distributed.
