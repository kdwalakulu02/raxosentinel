# RaxoSentinel Test Fixtures — Licensing and Attribution Audit

This document records the provenance, copyright ownership, and licensing terms for all test fixtures located in this directory (`crates/raxosentinel-signatures/test_fixtures/`).

## Crucial Licensing Clarification: ClamAV Test Fixtures Are GPL-2.0 (Not Public Domain)

> [!IMPORTANT]
> **Audit Finding (Phase 2C Correction)**:
> In earlier development notes, ClamAV test signatures (`clamav.hdb`, `clam.exe`, `xor_testfile.py`) were informally referred to as "public domain".
> **This was inaccurate and has been corrected.**
>
> Upstream ClamAV test fixtures are copyrighted by Cisco Systems, Inc. / Tomasz Kojm and the ClamAV development team, licensed under the **GNU General Public License Version 2 (GPL-2.0)**. The complete text of this license is preserved in [`COPYING`](file:///workspace/projects/011-raxosentinelcore/Phase01/crates/raxosentinel-signatures/test_fixtures/COPYING).
>
> Under no circumstances may GPL-licensed test fixtures be labeled as public domain or distributed in a public database without adhering to GPL-2.0 requirements.

---

## Intellectual Property Categories

| Category | Description | Copyright Owner | License | Permitted Distribution |
| :--- | :--- | :--- | :--- | :--- |
| **1. Original RaxoSentinel Code** | Engine, CLI, parsing logic, compilers, indices (`crates/*`) | RaxoSentinel Contributors | GPL-2.0-or-later | Permitted under GPL-2.0-or-later |
| **2. Third-Party Test Fixtures** | ClamAV test files (`clamav.hdb`, `clam.exe`, `other_sigs/*`, `xor_testfile.py`) | Cisco Systems, Inc. / Tomasz Kojm | GPL-2.0 | Retained under upstream GPL-2.0 for testing only. Not for standalone redistribution |
| **2b. EICAR Test String** | Standard anti-virus test file (68 bytes) | EICAR | Publicly permitted test standard | Universally permitted for AV test suites |
| **3. Original Raxo Rules** | Raxo-authored email attachment rules, heuristic signatures | RaxoSentinel Authors | GPL-2.0-or-later | Permitted in public RSIDB releases |
| **4. Third-Party Threat Intel** | Indicator metadata from Abuse.ch (MalwareBazaar, URLhaus) | abuse.ch / BFH | CC0 1.0 Universal | Permitted with attribution in public RSIDB |
| **4b. Third-Party Proprietary Intel** | Cisco Talos CVD (`daily.cvd`, `main.cvd`), VirusTotal | Cisco Talos / Chronicle | Proprietary ToS | **PROHIBITED** from public RSIDB |

---

## Inventory of Files in `test_fixtures/`

1. [`COPYING`](file:///workspace/projects/011-raxosentinelcore/Phase01/crates/raxosentinel-signatures/test_fixtures/COPYING)
   - **Origin**: ClamAV upstream repository (`unit_tests/input/COPYING`).
   - **License**: GNU General Public License Version 2.
   - **Purpose**: Preserves upstream licensing notice for all imported ClamAV test files.

2. [`README`](file:///workspace/projects/011-raxosentinelcore/Phase01/crates/raxosentinel-signatures/test_fixtures/README)
   - **Origin**: ClamAV upstream repository (`unit_tests/input/README`).
   - **Description**: Upstream explanation of `clam.exe` test binary.

3. [`clamav.hdb`](file:///workspace/projects/011-raxosentinelcore/Phase01/crates/raxosentinel-signatures/test_fixtures/clamav.hdb)
   - **Hash**: `71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495:544:ClamAV-Test-File`
   - **Origin**: ClamAV test suite signature for the harmless `clam.exe` test executable.
   - **License**: GPL-2.0.
   - **Use**: Regression test for `.hdb` hash ingestion and matching.

4. [`xor_testfile.py`](file:///workspace/projects/011-raxosentinelcore/Phase01/crates/raxosentinel-signatures/test_fixtures/xor_testfile.py)
   - **Origin**: ClamAV upstream build tool (`unit_tests/input/xor_testfile.py`).
   - **License**: GPL-2.0.
   - **Use**: Generates de-obfuscated test binaries at test time to avoid triggering external scanners.

5. [`other_sigs/`](file:///workspace/projects/011-raxosentinelcore/Phase01/crates/raxosentinel-signatures/test_fixtures/other_sigs)
   - `Clamav-Unit-Test-Signature.ndb`: ClamAV upstream test pattern string.
   - `alz.hdb`, `logo.hsb`, `zstd.hdb`: Archive and hash test vectors from ClamAV unit tests.
   - **License**: GPL-2.0.

6. [`demo_source/`](file:///workspace/projects/011-raxosentinelcore/Phase01/crates/raxosentinel-signatures/test_fixtures/demo_source)
   - **Kind**: `synthetic_test`
   - **Origin**: RaxoSentinel internal synthetic fixture containing EICAR and ClamAV test hashes.
   - **License**: GPL-2.0-or-later.
   - **Redistribution**: Allowed for integration testing. Marked `synthetic_test` so build manifests report 0 genuine records.
