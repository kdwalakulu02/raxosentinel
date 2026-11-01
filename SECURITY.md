# Security Policy

## Reporting Security Vulnerabilities

The RaxoSentinel team takes the security of our malware detection engine seriously. Because malware scanners ingest untrusted and potentially malicious data, our code must maintain the highest standards of safety and resilience.

If you believe you have found a security vulnerability in RaxoSentinel, please report it privately:

- **Email**: `security@raxosentinel.org`
- **PGP Key**: Available upon request
- Please do **not** open a public issue or discussion topic regarding potential vulnerabilities.

We commit to acknowledging your report within 48 hours and providing a remediation timeline within 7 days.

---

## Security Architecture Principles

RaxoSentinel incorporates defense-in-depth across all scanning components:

1. **Memory Safety by Construction**:
   Written in 100% safe Rust. Eliminates memory corruption vulnerabilities such as buffer overflows, use-after-free, double-free, and out-of-bounds array reads.
2. **Denial-of-Service Defense**:
   All operations enforce bounded limits via `ResourceTracker`:
   - `max_file_size`: Aborts processing of files exceeding the configured limit before reading into memory.
   - `max_email_depth`: Prevents stack overflow attacks via deeply nested MIME containers.
   - `max_email_attachments` & `max_total_extracted_bytes`: Defends against archive and MIME expansion bombs.
   - `max_scan_duration_ms`: Guarantees hard timeouts to stop algorithmic complexity attacks.
3. **Data Privacy**:
   The engine does not log or persist raw email contents, message bodies, or attachment payloads. Only non-sensitive scan metadata (hashes, MIME categories, threat classifications) is recorded.
4. **No External Network Access**:
   Scanning occurs completely offline. No network requests or telemetry uploads take place during scan execution.
