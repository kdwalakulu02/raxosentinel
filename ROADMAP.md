# RaxoSentinel Project Roadmap

## Phase 1: Foundation (Completed)

Phase 1 establishes the native Rust core scanning engine, memory-bounded streaming pipeline, and initial email-specialized detection capabilities.

- [x] **Modular Rust Workspace**:
  - `raxosentinel-core`: Scanning interfaces, resource budgeting (`ResourceTracker`), streaming SHA-256 hasher, report generation, process memory telemetry.
  - `raxosentinel-filetypes`: Magic byte detection for executables, archives, documents, scripts, images, and MIME messages; extension mismatch detector.
  - `raxosentinel-signatures`: Aho-Corasick streaming multi-pattern engine with chunk boundary preservation, exact SHA-256 database, external JSON rule loader.
  - `raxosentinel-email`: Zero-copy RFC 5322 MIME parsing, attachment extraction, recursive nested message scanning, privacy preservation.
  - `raxosentinel-cli`: Standalone `raxosentinel` CLI binary with human-readable and structured `--json` outputs.
- [x] **Detection Primitives**:
  - Exact SHA-256 hash lookup.
  - Multi-pattern byte sequences.
  - Full EICAR standard test string and CRLF detection.
  - Deceptive extension mismatch detection (disguised PE executables, double extensions).
  - Common script and macro procedural triggers.
- [x] **Robustness & Testing**:
  - 39 automated tests covering valid/invalid headers, empty/truncated files, malformed MIME, multipart attachments, limit enforcement.
  - Comprehensive Criterion benchmarks measuring scan duration, throughput (~231 MiB/s), and memory consumption (~3.5 MiB RSS).
  - Strict quality gates: `cargo fmt`, `cargo clippy -D warnings`, `cargo test`.
- [x] **Documentation & Licensing**:
  - GPL-2.0-or-later licensing compliance.
  - Complete architecture, threat model, contributing guidelines, and security policies.

---

## Phase 2: Deep Extraction & Rule Expansion (Planned — Pending Approval)

> **Notice**: As per Phase 1 governance requirements, Phase 2 implementation will not begin without explicit stakeholder authorization.

- [ ] **Archive Deep Unpacking**:
  - Streaming decompression engines for `ZIP`, `GZIP`, `BZIP2`, `TAR`, `7z`, and `RAR`.
  - Nested archive limit enforcement (max recursion depth, decompression ratio monitoring to mitigate zip bombs).
- [ ] **Office Document & VBA Macro Analysis**:
  - OLE / CFBF compound document stream reader.
  - Extraction and analysis of VBA macro code modules (`vbaProject.bin`).
  - Heuristic scoring for suspicious macro APIs (shell execution, registry tampering, network socket creation).
- [ ] **Script De-obfuscation**:
  - Multi-layer Base64 unpacking for PowerShell and batch scripts.
  - String concatenation resolving (e.g. `c` + `m` + `d`).
- [ ] **YARA Compatibility Layer**:
  - Ability to ingest and compile community YARA rules directly into the engine.
- [ ] **Binary Signature Database Serialization**:
  - Pre-compiled binary signature format (`.rsdb`) for instant engine cold-start times.

---

## Phase 3: Infrastructure Integration & Performance (Future)

- [ ] **Email MTA Milter Protocol**:
  - Native milter interface (`libmilter` protocol implementation in Rust) for seamless Postfix and Sendmail integration.
- [ ] **High-Performance Scanning Daemon (`raxosentineld`)**:
  - Async UNIX domain socket service for zero-process-spawn scanning pipelines.
- [ ] **Comparative Benchmarking**:
  - Rigorous, reproducible benchmark suite comparing scan duration, memory footprint, and detection rates directly against ClamAV on synthetic and benign datasets.
- [ ] **C / FFI C-ABI Bindings**:
  - C-compatible shared library (`libraxosentinel.so`) and header files for integration into Python, Go, and C++ mail servers.
