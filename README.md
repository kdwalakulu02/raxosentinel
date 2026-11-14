# RaxoSentinel Core — Malware Detection Engine

[![License: GPL-2.0-or-later](https://img.shields.io/badge/License-GPL--2.0--or--later-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.80+-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/Status-Phase%201%20Complete-green.svg)]()

**RaxoSentinel** is a native, independent Rust malware-detection engine specializing in email infrastructure security. Designed from first principles to be fast, memory-bounded, and embeddable, RaxoSentinel provides email systems and developers with robust content-based file identification, recursive MIME parsing, and streaming signature matching without relying on external daemon wrappers or uncontrolled runtime allocations.

> **Important Project Boundary**:  
> RaxoSentinel is **NOT** a ClamAV wrapper, desktop antivirus, dashboard, or cloud SaaS. It contains zero copied ClamAV engine code and uses an independent, modular Rust workspace architecture.

---

## Architecture

RaxoSentinel is organized as a modular Rust workspace consisting of 5 specialized crates:

| Crate | Path | Responsibility |
|---|---|---|
| [`raxosentinel-core`](crates/raxosentinel-core) | `crates/raxosentinel-core` | Core scanning interfaces, resource limits (`ResourceTracker`), bounded streaming SHA-256 hashing, threat structures, memory profiling, and structured reporting. |
| [`raxosentinel-filetypes`](crates/raxosentinel-filetypes) | `crates/raxosentinel-filetypes` | Content-based file identification using magic bytes (PE, ELF, Mach-O, PDF, OLE, OpenXML, ZIP, GZIP, 7z, RAR, MIME, etc.) and deceptive extension mismatch detection. |
| [`raxosentinel-signatures`](crates/raxosentinel-signatures) | `crates/raxosentinel-signatures` | Exact SHA-256 hash lookup and high-throughput multi-pattern byte matching using an Aho-Corasick automaton with sliding window boundary overlap. |
| [`raxosentinel-email`](crates/raxosentinel-email) | `crates/raxosentinel-email` | RFC 5322 / MIME parser, recursive message and attachment extractor, nested message inspector, and attachment threat analyzer. |
| [`raxosentinel-cli`](crates/raxosentinel-cli) | `crates/raxosentinel-cli` | The `raxosentinel` standalone command-line scanner binary supporting structured JSON and human-readable output formats. |

---

## Detection Capabilities

### What the Engine Currently Detects (Phase 1 & Phase 1.1)
1. **Content-Based File Identification**:
   - Identifies executables (`PE`, `MS-DOS`, `ELF`, `Mach-O`, `Java Class`, `WebAssembly`), documents (`PDF`, `RTF`, `OLE CFBF`, `Office Open XML`), archives (`ZIP`, `GZIP`, `BZIP2`, `7z`, `RAR`, `TAR`, `XZ`), email messages (`RFC 822 / MIME`), scripts (`Shell`, `Python`, `Batch`, `PowerShell`, `HTML/XML`), and images (`PNG`, `JPEG`, `GIF`, `BMP`, `WebP`).
2. **Deceptive Extension Mismatches & Advanced Evasion Analysis**:
   - Detects executables disguised under benign extensions (e.g., a Windows PE executable named `invoice.pdf` or `photo.jpg`).
   - Detects deceptive double extensions (e.g., `document.pdf.exe`).
   - Detects Right-to-Left Override (RTLO) Unicode directional spoofing (e.g., `invoice\u{202E}cod.exe` disguised as `invoiceexe.doc`).
   - Detects trailing space and dot evasion attempts (e.g., `payload.exe. ` or `script.vbs.`).
3. **Exact SHA-256 Hash Matching**:
   - Matches file or attachment digests against precompiled and user-supplied hash databases with zero memory overhead.
4. **Streaming Byte-Pattern Matching (Aho-Corasick)**:
   - Scans streams in bounded chunks (default 64 KiB) using an overlap carry window to guarantee detection of signatures that cross chunk boundaries.
   - Built-in detection for:
     - Standard EICAR Antivirus Test File string (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`) and CRLF variations.
     - Synthetic test patterns for validation.
     - Obfuscated PowerShell execution commands (`powershell -enc`, `powershell.exe -encodedcommand`).
     - Certutil URL download and cache evasion patterns (`certutil -urlcache -split -f`).
     - MSHTA script payload execution patterns (`mshta vbscript:CreateObject`).
     - Document automatic macro procedure markers (`Sub AutoOpen()`, `Sub Document_Open()`).
5. **Recursive MIME Email & Attachment Inspection**:
   - Extracts and scans attachments in `multipart/mixed`, `multipart/related`, and `multipart/alternative` messages.
   - Recursively inspects nested `message/rfc822` email attachments up to configurable depth limits.
   - Scans plain text and HTML email bodies for embedded threats and payload strings.
   - Prevents Base64 and Quoted-Printable decompression memory bombs via pre-check of estimated decoded lengths.
   - Distinguishes deterministic signature hits from heuristic suspicion.
   - Enforces verdict integrity: scanning errors or unsupported encrypted attachments never return false `CLEAN` verdicts.

### What the Engine CANNOT Detect Yet (Phase 1 / 1.1 Boundaries)
To maintain technical integrity and security transparency, the following limitations are explicitly noted:
- **Packed and Cryptor-Protected Binaries**: The engine does not yet include runtime PE unpackers (e.g., UPX decompressors) or generic emulation to unpack dynamically packed binaries (planned for Phase 2).
- **Archive Unpackers**: Zip, tar, and rar decompression within attachments is deferred to Phase 2.
- **Polymorphic / Metamorphic Malware**: Samples that mutate their code sequence on every compile or infection without recognizable byte markers require behavioral or heuristic engines planned for future phases.
- **Password-Protected / Encrypted Containers**: Encrypted ZIPs, password-protected PDFs, or encrypted RAR archives cannot be inspected without keys and are classified as `UNSUPPORTED`.
- **Active Memory or In-Process Scanning**: RaxoSentinel is a file and email stream scanner; it does not inspect running process memory or kernel hooks.
- **Universal Safety Guarantee**: An outcome of `CLEAN` signifies that **no known threats were detected by current rules**. It is fundamentally not an absolute guarantee that the file is benign.

---

## Installation & Building

Ensure you have Rust stable installed:

```bash
# Clone the repository
git clone https://github.com/raxosentinel/raxosentinel.git
cd raxosentinel

# Build release binaries
cargo build --release

# The compiled binary will be located at:
# ./target/release/raxosentinel
```

---

## CLI Usage

### 1. Standalone Scan with JSON Output
```bash
./target/release/raxosentinel scan sample.eml --json
```

Example JSON Output:
```json
{
  "engine_version": "0.1.0",
  "target": {
    "path": "tests/samples/phishing_eicar_attachment.eml",
    "file_name": "phishing_eicar_attachment.eml",
    "file_size_bytes": 626,
    "sha256": "47cba878586687d64fe6f3c48afe0a4913c5d94b36117dec507b424ee9f1a885",
    "detected_mime": "message/rfc822",
    "declared_mime": "message/rfc822"
  },
  "status": "INFECTED",
  "status_description": "Detected 2 threat(s).",
  "safety_disclaimer": "NOTICE: Automated threat detection report.",
  "threats": [
    {
      "name": "EICAR-Standard-Antivirus-Test-File",
      "category": "test_signature",
      "severity": "high",
      "description": "Standard EICAR antivirus test file (68 bytes)",
      "matched_by": "sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      "location": "attachment:expense_report.com"
    }
  ],
  "sub_targets": [
    {
      "engine_version": "0.1.0",
      "target": {
        "path": null,
        "file_name": "expense_report.com",
        "file_size_bytes": 68,
        "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "detected_mime": "text/plain",
        "declared_mime": "application/octet-stream"
      },
      "status": "INFECTED",
      "status_description": "Detected 2 threat(s).",
      "safety_disclaimer": "NOTICE: Automated threat detection report.",
      "threats": [ ... ],
      "sub_targets": [],
      "scan_duration_ms": 0,
      "error": null
    }
  ],
  "scan_duration_ms": 0,
  "error": null
}
```

### 2. Human-Readable Terminal Scan
```bash
./target/release/raxosentinel scan sample.eml --memory
```

Output:
```text
================================================================================
                       RAXOSENTINEL MALWARE SCAN REPORT                         
================================================================================
Engine Version   : 0.1.0
Target Path      : tests/samples/phishing_eicar_attachment.eml
File Size        : 626 bytes (0.61 KiB)
SHA-256          : 47cba878586687d64fe6f3c48afe0a4913c5d94b36117dec507b424ee9f1a885
Content Type     : message/rfc822
Scan Duration    : 0 ms
Memory Usage     : RSS: 3.47 MiB | Peak RSS: 3.47 MiB
--------------------------------------------------------------------------------
Overall Status   : [ INFECTED ]
Summary          : Detected 2 threat(s).

Detected Threats (2):
  [1] EICAR-Standard-Antivirus-Test-File | Category: Test Signature | Severity: HIGH
      Description : Standard EICAR antivirus test file (68 bytes)
      Triggered By: sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
      Location    : attachment:expense_report.com
  [2] EICAR-Standard-Antivirus-Test-File | Category: Test Signature | Severity: HIGH
      Description : Matches the standard EICAR test string across any file or attachment
      Triggered By: pattern_match at byte offset 0
      Location    : attachment:expense_report.com
--------------------------------------------------------------------------------
Extracted Email Attachments / Parts (1):
  [1] Attachment: expense_report.com (68 bytes, Type: text/plain) -> Status: INFECTED
      - Threat: EICAR-Standard-Antivirus-Test-File [HIGH] (Test Signature)
      - Threat: EICAR-Standard-Antivirus-Test-File [HIGH] (Test Signature)
================================================================================
```

### 3. Exit Code Conventions
- `0`: **Clean** — No threats detected by active rules.
- `1`: **Infected** — One or more threats identified.
- `2`: **Unsupported** — Format is unsupported, encrypted, or corrupted.
- `3`: **Failed** — Scan error, I/O failure, or resource limit exceeded.

---

## Security & Resource Limits

RaxoSentinel enforces strict bounded limits to prevent denial-of-service, decompression bombs, and memory exhaustion:

| Parameter | CLI Flag | Default | Description |
|---|---|---|---|
| `max_file_size` | `--max-size <BYTES>` | 50 MiB | Maximum file size scanned. Larger files abort with `FileSizeLimitExceeded`. |
| `max_scan_duration_ms` | `--timeout <SECS>` | 10 s | Maximum wall-clock scan duration before triggering `Timeout`. |
| `max_email_depth` | `--max-depth <NUM>` | 5 | Maximum container nesting depth (MIME, archives, PDF streams). |
| `max_email_attachments` | Configuration | 100 | Maximum MIME parts expanded per message. |
| `max_archive_entries` | Configuration | 2,000 | Maximum ZIP/TAR members expanded per scan. |
| `max_pdf_streams` | Configuration | 10,000 | Maximum PDF streams decoded per scan. |
| `max_gzip_members` | Configuration | 64 | Maximum GZIP members expanded per scan. |
| `max_email_attachment_size` | Configuration | 50 MiB | Maximum size of any single extracted object. |
| `max_total_extracted_bytes`| Configuration | 200 MiB | Cumulative extracted quota across the whole scan. |
| `buffer_size` | Configuration | 64 KiB | Streaming read buffer size. Memory allocation does not scale with file size. |

Each object kind has its own count budget, so a many-page PDF never consumes the MIME or archive budget. Reaching a count, size or depth budget, or 70% of the time budget, stops further expansion without failing the scan: the verdict covers everything inspected, and the report lists what was skipped in `incomplete` (for example `"Only the first 2000 archive members were inspected"`). Content that cannot be inspected for structural reasons (password-protected PDFs, encrypted ZIP members, RAR/7-Zip/XZ/CAB containers, malformed archives) is still `UNSCANNED`, never `CLEAN`.

PDF streams are decoded through full filter chains (Flate with PNG/TIFF predictors, LZW, ASCII85, ASCIIHex, RunLength, Brotli). Image codecs (DCT, JPX, JBIG2, CCITT) are scanned as encoded bytes. PDFs with an empty user password are decrypted and inspected. TAR (ustar/GNU/PAX), GZIP and ZIP members are extracted in memory.

---

## Performance & Benchmarks

Measured using Criterion on modern Linux x86_64:

- **Bounded Stream Scanning (SHA-256 + Multi-Pattern Matching)**:
  - 64 KiB throughput: **~231.8 MiB/s** (~269 µs per file)
  - 512 KiB throughput: **~231.2 MiB/s** (~2.16 ms per file)
  - 2048 KiB throughput: **~210.9 MiB/s** (~9.48 ms per file)
- **MIME Email Parsing & Attachment Inspection**:
  - Full multipart email parsing, attachment extraction, hashing, and signature matching: **~7.61 µs** per message (**~64.4 MiB/s**).
- **Process Memory Consumption**:
  - Resident Set Size (RSS): **~3.04 - 3.47 MiB** across files up to 100 MiB
  - See detailed stress and comparative ClamAV benchmarks in [`BENCHMARKS_PHASE1_1.md`](BENCHMARKS_PHASE1_1.md).

---

## Quality Gates & Verification

All quality gates pass cleanly with zero errors and zero warnings:

```bash
# 1. Format verification
cargo fmt --all -- --check

# 2. Strict linter verification (warnings treated as errors)
cargo clippy --workspace --all-targets -- -D warnings

# 3. Complete test suite (44 unit and integration tests)
cargo test --workspace

# 4. Release compilation
cargo build --release

# 5. Dependency vulnerability audit
cargo audit

# 6. Fuzz testing campaign (4 libFuzzer targets, >1.2M executions)
cargo +nightly fuzz build
```

---

## Licensing

RaxoSentinel Core original source code is licensed under the **GNU General Public License v2.0 or later** ([GPL-2.0-or-later](LICENSE)).
All third-party dependencies use permissive licenses (MIT, Apache-2.0, Unlicense) compatible with GPL-2.0-or-later.
