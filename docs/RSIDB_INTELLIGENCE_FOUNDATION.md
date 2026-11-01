# RaxoSentinel Intelligence Database (RSIDB)
## Threat Intelligence Pipeline & Architectural Specification

**Document Version**: 1.0.0  
**Phase**: Phase 2A Architecture Foundation  
**Status**: APPROVED DESIGN  
**Date**: November 2026  
**License**: GPL-2.0-or-later  

---

## Executive Summary

RaxoSentinel Intelligence Database (**RSIDB**) establishes an independent, high-performance, compact threat intelligence format and distribution pipeline for RaxoSentinel Core. 

This document defines the complete architectural lifecycle for threat intelligence: separating offline signature ingestion, compilation, and validation from the runtime email security engine. It establishes explicit operational policies for upstream feeds, intellectual property compliance, cryptographic release signing, incremental delta updates, false-positive protection, and atomic rollbacks.

```
       +-------------------------------------------------------------+
       |             UPSTREAM THREAT INTELLIGENCE SOURCES            |
       |  (Abuse.ch MalwareBazaar, MISP, CIRCL, Custom Raxo Feeds)   |
       +------------------------------+------------------------------+
                                      |
                                      v
       +-------------------------------------------------------------+
       |              OFFLINE CURATION & BUILD PIPELINE              |
       |  1. Syntax & Schema Validation                              |
       |  2. Attribution & Rights Enforcement (Talos / GPL / CC0)    |
       |  3. Deduplication & Family Normalization                    |
       |  4. False-Positive Filtering (Clean Corpus + Allowlist)     |
       |  5. Deterministic Binary Compilation (RSIDB Header + Sigs)  |
       |  6. Ed25519 Cryptographic Manifest Signing                  |
       +------------------------------+------------------------------+
                                      |
                           HTTPS / Content Network
                                      |
                                      v
       +-------------------------------------------------------------+
       |             CLIENT UPDATE AGENT (RaxoSentinel)              |
       |  1. Manifest Signature & Timestamp Verification             |
       |  2. SHA-256 Checksum Integrity Check                        |
       |  3. Atomic Staging (rsidb.new -> rsidb.active)              |
       |  4. Automated In-Memory Health & Parity Verification        |
       |  5. Instantaneous Rollback on Invalidation                  |
       +------------------------------+------------------------------+
                                      |
                                      v
       +-------------------------------------------------------------+
       |             RUNTIME SCANNING ENGINE (Zero-Copy)             |
       |  MmapCompactDirIndex (16-bit prefix directory + mmap)       |
       |  Near-zero heap allocation, O(1) candidate lookup           |
       +-------------------------------------------------------------+
```

---

## 1. Architectural Separation: Ingestion vs Runtime Loading

A core architectural principle of RaxoSentinel is the strict boundary between **Signature Ingestion** and **Runtime Database Loading**:

| Dimension | Ingestion & Build Pipeline (`rsidb-compiler`) | Runtime Engine (`rsidb-reader` / Core) |
| :--- | :--- | :--- |
| **Execution Context** | Offline build servers, CI/CD, intelligence workers | Production MTA nodes, Raxo Email VPS |
| **I/O & Compute** | High memory allowed, heavy sorting, parsing, deduplication | Strictly bounded memory, zero-copy `mmap`, zero allocation |
| **Failure Mode** | Fail build, reject invalid records, alert security team | Never crash; reject corrupt DBs; fail-safe status precedence |
| **Dependencies** | Network clients, parsers, cryptographic signing tools | Minimal verified dependencies (`memmap2`, RustCrypto) |
| **Dependencies on Upstream** | Full raw feed ingestion, normalization | Fully insulated from upstream network or schema instability |

The runtime scanning engine never parses raw text signature files, never performs regex compilation of upstream databases, and never communicates directly with third-party feed providers. It loads only pre-validated, cryptographically signed, deterministic binary RSIDB artifacts.

---

## 2. Permitted Upstream Feeds & Rights Management

### 2.1 Permitted Sources
RaxoSentinel incorporates signatures exclusively from authorized, sustainably licensed sources:
1. **RaxoSentinel Proprietary & Customer Telemetry**: Internal threat hunting rules, zero-day email attachment signatures, honeypot captures. Licensed under GPL-2.0-or-later.
2. **Abuse.ch Feeds (MalwareBazaar, ThreatFox, URLhaus)**: High-confidence hashes of active malware samples and malicious attachments. CC0 / Public Domain terms.
3. **CIRCL / MISP Threat Sharing Communities**: Structured indicators of compromise (IoCs) under open sharing frameworks.
4. **Harmless Test Fixtures (EICAR, ClamAV Public Unit Test Signatures)**: Public test signatures retained under upstream license terms (`upstream/unit_tests/input/COPYING`) exclusively for regression testing.

### 2.2 ClamAV Production Database Rights Warning
> [!CAUTION]
> **Prohibition on Unauthorized CVD Mirroring**:
> The official ClamAV production database (`daily.cvd`, `main.cvd`) is proprietary threat intelligence copyrighted by Cisco Systems / Cisco Talos. Redistribution of Talos production databases without explicit authorization violates Cisco terms of service and can trigger immediate HTTP 403 blocks or legal liability.
>
> RaxoSentinel **must never** redistribute complete ClamAV CVD databases or market itself as a drop-in Talos mirror without commercial licensing. Any imported ClamAV test signatures are strictly confined to harmless public unit-test fixtures.

---

## 3. Deduplication and Aliasing Strategy

When ingesting millions of indicators across heterogeneous sources, collisions and duplicate hashes are inevitable.

### 3.1 Key Canonicalization
A signature key is strictly defined by the tuple:
$$\text{Key} = (\text{Algorithm}, \text{FileSize}, \text{Digest})$$

### 3.2 Label Preservation and Aliasing
Unlike naive databases that overwrite earlier labels with later ones, RSIDB preserves detection provenance:
1. **Deterministic Name Deduplication**: All detection labels are stored in a deduplicated string table.
2. **Multiple Label Support**: When Feed A identifies a digest as `Win.Trojan.Agent` and Feed B identifies it as `Trojan.Generic.KD`, RSIDB stores multiple contiguous record rows pointing to the respective string table entries.
3. **Canonical Normalization**: The build pipeline attaches a standardized Raxo threat classification (Category, Severity, Threat Family) mapped according to CARO conventions.

---

## 4. Source Attribution & Provenance Tracking

Every compiled RSIDB release embeds immutable provenance metadata directly within the database file:
- **Build Timestamp**: Unix epoch and RFC 3339 timestamp.
- **Compiler Version**: Exact Git commit SHA of the `rsidb-compiler`.
- **Feed Manifest**: List of upstream feeds included, with feed versions, commit hashes, and licensing summaries.
- **Ingestion Audit**:
  - `records_accepted`: Total active signatures.
  - `records_rejected`: Count of invalid, malformed, or wildcard-size records.
  - `records_ignored`: Count of comments, non-hash rules, or empty lines.

This provenance is verifiable at runtime via `RsidbIndex::provenance()` and displayed in the CLI via `raxosentinel db-info`.

---

## 5. Multi-Stage Validation & Quality Gates

Before an RSIDB binary is released, it must pass a 4-tier automated validation gate:

```
+------------------------------------------------------------------------+
| TIER 1: Syntax & Bound Checks                                          |
| - Verify complete hash length (16, 20, 32 bytes)                       |
| - Enforce exact file-size constraints (reject wildcard '*' sizes)     |
| - Enforce ASCII/UTF-8 detection name validity                          |
+-----------------------------------+------------------------------------+
                                    |
                                    v
+------------------------------------------------------------------------+
| TIER 2: Deterministic Ordering & Alignment                             |
| - Sort records deterministically: (size, digest, name_id)              |
| - Verify 16-bit prefix directory monotonicity                          |
| - Verify SHA-256 payload checksum against header value                 |
+-----------------------------------+------------------------------------+
                                    |
                                    v
+------------------------------------------------------------------------+
| TIER 3: Clean Corpus False-Positive Filtering                          |
| - Scan 500,000+ known benign files (Debian/Ubuntu packages, Windows    |
|   system binaries, Office documents, standard email attachments)       |
| - Zero matches allowed against clean corpus                            |
+-----------------------------------+------------------------------------+
                                    |
                                    v
+------------------------------------------------------------------------+
| TIER 4: Regression & Detection Parity                                  |
| - Verify detection of 100% of pinned test fixtures (EICAR, clam.exe)   |
| - Verify zero regressions across historical true-positive sample bank  |
+------------------------------------------------------------------------+
```

---

## 6. Cryptographic Release Signing

To prevent man-in-the-middle tampering, DNS hijacking, or rogue signature injection:

1. **Ed25519 Digital Signatures**:
   Each database release produces an accompanying `manifest.json.sig` signed using an offline Ed25519 private key stored in an air-gapped Hardware Security Module (HSM).
2. **Pinned Public Keys**:
   The RaxoSentinel Core binary contains compiled-in Ed25519 public keys.
3. **Signed Manifest Schema**:
   ```json
   {
     "database_version": 2026110201,
     "format_version": 1,
     "release_timestamp": "2026-11-02T12:00:00Z",
     "sha256": "3fa98e...",
     "size_bytes": 4405408,
     "total_signatures": 100017,
     "signature_ed25519": "8fbc71..."
   }
   ```
4. **Verification Step**:
   The client agent validates the Ed25519 signature of the manifest, then verifies the SHA-256 checksum of the downloaded `.rsidb` binary *before* placing it in the staging directory.

---

## 7. Incremental Updates & Differential Patches

To conserve network bandwidth across thousands of deployed mail relays:

1. **Base Snapshots**:
   A weekly full snapshot (`base-YYYYMMDD.rsidb`) containing all active intelligence.
2. **Daily Delta Patches**:
   Differential patch files (`patch-YYYYMMDD-HH.rsidb.delta`) encoding:
   - **Additions**: New records sorted by algorithm.
   - **Revocations (Tombstones)**: Hashes removed due to false-positive reports.
3. **Client-Side Synthesis**:
   The client applies the patch to its local base file, rebuilds the compact prefix directory, verifies the resulting SHA-256 against the manifest, and atomically activates the new database.

---

## 8. Atomic Staging & Rollback Strategy

Production mail scanners must never encounter database corruption or mid-write locks:

```
  /var/lib/raxosentinel/db/
  ├── rsidb.active  ---> [Symlink to rsidb-2026110201.rsidb]
  ├── rsidb-2026110201.rsidb  (Currently active, memory-mapped)
  ├── rsidb-2026110101.rsidb  (Previous version for rollback)
  └── staging/
      └── rsidb-2026110202.tmp  (In-flight download)
```

1. **Staged Download**: Downloads write to `staging/*.tmp`.
2. **Integrity Validation**: Once complete, the client opens the file via `MmapCompactDirIndex::from_file()`, verifies the header, checks the SHA-256 payload checksum, and runs a self-check against built-in canary signatures.
3. **Atomic Activation**:
   A POSIX atomic rename (`renameat2(..., RENAME_EXCHANGE)` or atomic symlink update) switches `rsidb.active` to point to the new database.
4. **Hot Reload**:
   The scanning worker reloads the `MmapCompactDirIndex` descriptor. Existing worker threads finish current messages against their existing map, while new scans attach to the updated database.
5. **Instant Rollback**:
   If health checks fail or an unexpected spike in quarantine verdicts occurs, the agent switches `rsidb.active` back to `rsidb-prev` in $< 10$ milliseconds.

---

## 9. Next Steps for Real Threat Intelligence Deployment

Before launching a production intelligence service:
1. Establish legal agreements and data-sharing agreements with threat intelligence feeds (Abuse.ch, MISP communities).
2. Deploy the automated daily ingestion pipeline in an isolated infrastructure environment.
3. Construct the clean reference corpus (10+ million verified clean files) for automated false-positive testing.
4. Implement the client update daemon (`raxosentinel-update`) with Ed25519 manifest verification and atomic staging.
