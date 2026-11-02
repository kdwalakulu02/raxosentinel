# RaxoSentinel Source Licensing & Intellectual Property Matrix

This document establishes the official intellectual property policy and licensing matrix for the RaxoSentinel project. It defines the provenance, distribution rights, and attribution requirements across all components of the repository and database release artifacts.

---

## 1. Intellectual Property Matrix

| Component | Source / Origin | Copyright Owner | License | Permitted in Public Binaries / Git | Permitted in Public RSIDB Releases | Required Notice / Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Original RaxoSentinel Engine** | Internal Raxo engineering (`crates/*`) | RaxoSentinel Contributors | **GPL-2.0-or-later** | **Yes** | N/A (code artifact) | Include GPL-2.0 header and license notice |
| **ClamAV Unit Test Fixtures** | Upstream ClamAV (`unit_tests/input/*`) | Cisco Systems, Inc. / Tomasz Kojm & ClamAV Team | **GPL-2.0** | **Yes** (in test directories only) | **No** (never shipped in operational public intelligence feeds) | Retain upstream `COPYING` (GPL-2.0) and `README`. Strictly do **not** label as public domain |
| **EICAR Test String** | EICAR Standard File | European Institute for Computer Antivirus Research | Public Anti-Virus Standard | **Yes** (harmless test vectors) | **Yes** (classified as `synthetic_test` in test builds) | Standard EICAR naming preserved |
| **Original Raxo Detection Rules** | Raxo internal heuristics and signature engineering | RaxoSentinel Authors | **GPL-2.0-or-later** | **Yes** | **Yes** | Authored by RaxoSentinel; full redistribution permitted |
| **Third-Party Threat Intel: Abuse.ch (MalwareBazaar / URLhaus)** | Abuse.ch / Bern University of Applied Sciences (BFH) | Abuse.ch Contributors | **CC0 1.0 Universal** (Public Domain Dedication) | **Yes** (metadata and indicators only; no live malware samples) | **Yes** | Attribution required: *"Data provided by abuse.ch MalwareBazaar (https://bazaar.abuse.ch/)"* |
| **Third-Party Threat Intel: Cisco Talos Production CVD** | Cisco Systems / Cisco Talos (`daily.cvd`, `main.cvd`) | Cisco Systems, Inc. | **Proprietary / Cisco ToS** | **No** (never committed or mirrored) | **STRICTLY PROHIBITED** | Redistribution without commercial license triggers immediate IP violation |
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

To maintain unquestionable legal and ethical standing, public RSIDB releases are governed by three mandatory rules:

1. **Explicit Rights Verification**:
   - The ingestion pipeline (`rsidb::ingest::IngestPipeline`) strictly verifies that `manifest.redistribution` is either `Allowed` or `AllowedWithAttribution`.
   - Manifests marked `InternalOnly`, `Prohibited`, or `Unknown` are immediately rejected during public database builds.
   - Self-approval (`approved: true` in `source.json`) is untrusted unless the operator explicitly passes `--allow-source <ID>` on the CLI.

2. **Truthful Coverage Reporting**:
   - RSIDB manifests explicitly distinguish `genuine_records` from `synthetic_records`.
   - Synthetic test vectors (EICAR, ClamAV test binaries) cannot be counted toward genuine threat protection.
   - We report exactly what threat coverage we possess without artificial inflation.

3. **No Live Malware**:
   - The repository and database pipelines process **only cryptographic hashes, file sizes, and threat classification metadata**.
   - No live or weaponized malware samples are downloaded, stored, or distributed.
