# RaxoSentinel Threat Model

## 1. Introduction

Security scanners operate under an inherently hostile operating environment: their entire purpose is to ingest, parse, and analyze untrusted, potentially adversarial inputs. A vulnerability in an email malware scanner can allow remote code execution, denial of service, or compromise of an entire email gateway.

This document outlines the threat model for RaxoSentinel Core (Phase 1), covering the threats faced by the scanner itself, the threats it is designed to detect, and current residual risks.

---

## 2. Assets & Trust Boundaries

### Assets
1. **Host Stability & Availability**: Preventing denial of service, CPU exhaustion, and out-of-memory (OOM) conditions.
2. **Scanner Memory Integrity**: Ensuring the scanner cannot be exploited via memory corruption (buffer overflows, use-after-free, integer wraps).
3. **Email Gateway Throughput**: Ensuring predictable scanning latency and SLA compliance under high traffic.
4. **User Privacy**: Guaranteeing that confidential email bodies, credentials, or personal messages are not leaked into system logs or error reports.

### Trust Boundaries
- **Untrusted Zone**: All input files, MIME messages, email headers, and attachments are assumed to be malicious.
- **Trusted Zone**: Host environment, local configuration parameters, compiled signature databases.

---

## 3. Threat Vectors Against the Scanner & Mitigations

| Threat Vector | Attack Description | Mitigation in RaxoSentinel |
|---|---|---|
| **Memory Exhaustion (OOM)** | Attacker sends massive files or nested files designed to force heap exhaustion. | **Bounded Chunked I/O**: Files are streamed in fixed 64 KiB buffers.<br>**Size Limits**: Enforces `max_file_size` (default 50 MiB) before scanning. |
| **Extraction / Decompression Bombs** | Attacker crafts a small email with deeply nested or heavily expanding content. | **Cumulative Quotas**: Enforces `max_total_extracted_bytes` (100 MiB limit) across all extracted parts.<br>**Individual Limits**: Enforces `max_email_attachment_size` (25 MiB limit). |
| **Infinite MIME Nesting (Recursion Bomb)** | Nested `message/rfc822` or multipart containers designed to overflow the call stack. | **Explicit Depth Tracking**: `ResourceTracker::check_depth` aborts with `DepthLimitExceeded` if depth exceeds `max_email_depth` (default 5). |
| **Scanner Hang / ReDoS / CPU Exhaustion** | Pathological inputs designed to trigger algorithmic complexity attacks. | **Linear Time Pattern Matching**: Uses Aho-Corasick automaton with $O(N)$ scanning time independent of pattern count.<br>**Hard Timeout**: `check_timeout` aborts scans exceeding `max_scan_duration_ms` (default 10 s). |
| **Parser Exploits (Buffer Overflow / UAF)** | Malformed MIME headers, illegal boundaries, or corrupted binary headers crafted to crash the parser. | **Pure Safe Rust**: Zero `unsafe` blocks in scanner code. Memory safety and bounds checks are enforced at compile time.<br>**Resilient Parser**: `mail-parser` safely handles corrupted, truncated, or null-byte-injected MIME structures without panicking. |
| **Information Disclosure / Privacy Leak** | Scanner logs raw email body text, credentials, or attachments into system journals. | **Strict Privacy Policy**: Raw email bodies and attachment byte contents are never written to logs or error reports. Only metadata (hashes, sizes, MIME types) is retained. |

---

## 4. Threats Detected by the Scanner

RaxoSentinel Core Phase 1 is specifically designed to detect:
1. **Deceptive File Extensions & Spoofed Executables**:
   - Disguised Windows PE binaries or MS-DOS executables with benign extensions (`.pdf`, `.jpg`, `.txt`).
   - Deceptive double extensions (`.pdf.exe`, `.docx.scr`).
2. **Standard Test Threats**:
   - Exact EICAR test string (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`) and CRLF variants across files, attachments, or embedded email text.
3. **Exact Hash Signatures**:
   - SHA-256 match against pre-compiled signature records.
4. **Suspicious Script & Macro Procedures**:
   - Obfuscated PowerShell execution flags (`powershell -enc`, `powershell.exe -encodedcommand`).
   - Certutil network download and cache evasion patterns (`certutil -urlcache -split -f`).
   - MSHTA VBScript payload execution patterns.
   - Office macro auto-execution entry points (`Sub AutoOpen()`, `Sub Document_Open()`).

---

## 5. Residual Risks & Out-of-Scope (Phase 1)

The following attack vectors are explicitly out of scope for Phase 1 and will be addressed in future phases:
- **Packed Executables**: Binaries obfuscated with UPX or custom packers require unpacker routines planned for Phase 2.
- **Encrypted Archives / Containers**: Password-protected ZIPs or encrypted PDFs cannot be inspected without keys and are reported as `UNSUPPORTED`.
- **Polymorphic Code**: Samples lacking static byte patterns require heuristic or emulation engines.
- **Active Memory Rootkits**: In-memory inspection of running kernel or user space processes is out of scope.
