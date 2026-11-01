# RaxoSentinel Core v0.1.0 — Phase 1.1 Stress & Comparative Benchmarks

## Environment & Hardware Configuration

- **CPU**: Intel Core i5-12450H (12 vCPUs @ 2.50 GHz - 4.40 GHz)
- **Host Memory**: 15.6 GiB RAM
- **Operating System**: Linux 6.17 (Debian GNU/Linux 12 'bookworm') x86_64
- **Rust Compiler**: rustc 1.99.1 (stable-x86_64-unknown-linux-gnu)
- **Release Build Profile**: `opt-level = 3`, `lto = false`, `panic = 'unwind'`
- **ClamAV Engine**: ClamAV 1.4.6 (Database build 28167, ~8.6M active signatures)
- **RaxoSentinel Coverage**: Phase 1 native rule database (~10 default rules; 5,000 synthetic rules tested in stress suite)

> [!IMPORTANT]
> **Detection Coverage Context & Equivalence Warning**:
> ClamAV is an established engine running a production database of over 8.6 million signatures with unpackers, heuristics, and bytecode interpreters. RaxoSentinel Phase 1 is a foundation engine with a native Aho-Corasick automaton and hash database. Memory consumption comparisons must NOT be interpreted as architectural superiority at equivalent coverage. Rather, they validate that RaxoSentinel achieves bounded memory execution and high streaming throughput for email pipelines.

## Comprehensive Workload Benchmark Table

| Workload | Size | Description | Raxo Verdict | Raxo Time | Raxo Peak RSS | Raxo Throughput | ClamAV Verdict | ClamAV Time | ClamAV Peak RSS | ClamAV Throughput |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Plain 1 MiB** | 1.0 MiB | Plain synthetic binary/stream data (1 MiB) | `CLEAN` | 14 ms | **3.16 MiB** | 71.43 MB/s | `OK (CLEAN)` | 13571 ms | **965.29 MiB** | 0.07 MB/s |
| **Plain 10 MiB** | 10.0 MiB | Plain synthetic binary/stream data (10 MiB) | `CLEAN` | 61 ms | **3.31 MiB** | 163.93 MB/s | `OK (CLEAN)` | 14941 ms | **978.79 MiB** | 0.67 MB/s |
| **Plain 50 MiB** | 50.0 MiB | Plain synthetic binary/stream data (50 MiB) | `CLEAN` | 247 ms | **3.29 MiB** | 202.43 MB/s | `OK (CLEAN)` | 14316 ms | **1012.78 MiB** | 3.49 MB/s |
| **Plain 100 MiB (Streaming)** | 100.0 MiB | 100 MiB plain data scanned with 64 KiB buffer (--max-size=150M) | `CLEAN` | 815 ms | **3.04 MiB** | 122.70 MB/s | `OK (CLEAN)` | 15984 ms | **1063.15 MiB** | 6.26 MB/s |
| **Plain 100 MiB (Default Limit Abort)** | 100.0 MiB | 100 MiB plain file exceeding default 50 MiB limit (must safely abort) | `LIMIT_ABORTED` | 4 ms | **2.95 MiB** | 25000.00 MB/s | `OK (CLEAN)` | 16412 ms | **1063.37 MiB** | 6.09 MB/s |
| **EICAR Test File** | 68 B | Standard EICAR antivirus test string (68 bytes) | `INFECTED` | 4 ms | **3.16 MiB** | 0.02 MB/s | `FOUND (INFECTED)` | 13361 ms | **962.73 MiB** | 0.00 MB/s |
| **Clean Plain Email** | 106 B | Single-part text/plain clean email | `CLEAN` | 4 ms | **3.44 MiB** | 0.03 MB/s | `OK (CLEAN)` | 13855 ms | **963.37 MiB** | 0.00 MB/s |
| **MIME Base64 1 MiB** | 1.4 MiB | MIME message with 1 MiB Base64-encoded attachment | `CLEAN` | 15 ms | **5.57 MiB** | 91.69 MB/s | `OK (CLEAN)` | 15896 ms | **966.65 MiB** | 0.09 MB/s |
| **MIME Base64 10 MiB** | 13.8 MiB | MIME message with 10 MiB Base64-encoded attachment | `CLEAN` | 102 ms | **26.87 MiB** | 134.81 MB/s | `OK (CLEAN)` | 14045 ms | **1001.76 MiB** | 0.98 MB/s |
| **MIME Base64 EICAR** | 436 B | MIME email with Base64-encoded EICAR COM executable | `INFECTED` | 4 ms | **3.24 MiB** | 0.10 MB/s | `FOUND (INFECTED)` | 13404 ms | **963.28 MiB** | 0.00 MB/s |
| **Nested Email (depth 3)** | 489 B | Nested message/rfc822 within configured depth limit (depth 3) | `CLEAN` | 7 ms | **3.16 MiB** | 0.07 MB/s | `OK (CLEAN)` | 13303 ms | **963.07 MiB** | 0.00 MB/s |
| **Nested Email (depth 8, limit)** | 1.1 KiB | Pathological nesting exceeding max_email_depth (depth 8 vs limit 5) | `LIMIT_ABORTED` | 4 ms | **3.45 MiB** | 0.28 MB/s | `OK (CLEAN)` | 13135 ms | **962.84 MiB** | 0.00 MB/s |
| **Malformed MIME** | 125 B | Truncated MIME boundary and malformed RFC822 framing | `CLEAN` | 3 ms | **3.24 MiB** | 0.04 MB/s | `OK (CLEAN)` | 13930 ms | **963.11 MiB** | 0.00 MB/s |
| **Attachment Flood (60 parts)** | 6.6 KiB | 60 attachments exceeding max_email_attachments limit of 50 | `LIMIT_ABORTED` | 5 ms | **3.51 MiB** | 1.30 MB/s | `OK (CLEAN)` | 13640 ms | **963.38 MiB** | 0.00 MB/s |
| **10 MiB with 5,000 Rules** | 10.0 MiB | 10 MiB stream scanned against 5,000 compiled Aho-Corasick pattern rules | `CLEAN` | 91 ms | **22.34 MiB** | 109.89 MB/s | `OK (CLEAN)` | 14032 ms | **979.09 MiB** | 0.71 MB/s |

## Resource Limit Enforcement & Safety Verification

1. **Oversized Input Termination**: Plain files up to 100 MiB scan in streaming mode using a constant 64 KiB buffer without unbounded RAM growth.
2. **Base64 Expansion Bomb Defense**: MIME attachment sizes are validated against `max_email_attachment_size` and quota *prior* to in-memory decoding.
3. **Pathological Nesting Defense**: Messages exceeding `max_email_depth` terminate safely with `ResourceLimitExceeded`.
4. **Attachment Flood Defense**: Messages with attachment counts exceeding `max_email_attachments` (50) terminate immediately before allocations.
5. **Malformed Framing Defense**: Corrupted boundaries, truncated headers, and binary null bytes are handled gracefully without panics.
