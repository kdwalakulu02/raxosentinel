# Contributing to RaxoSentinel

Thank you for your interest in contributing to **RaxoSentinel Core**!

RaxoSentinel is built to provide an independent, high-performance, and memory-safe malware detection engine specialized in email infrastructure.

---

## 1. Critical Rules & Boundaries

Before contributing, please read and adhere to our strict project rules:

1. **NO REAL MALWARE SAMPLES**:
   - **Never** commit, upload, or submit pull requests containing live or real malware binaries, exploits, or malicious payloads.
   - For testing, use the **EICAR standard test file** or **synthetic test signatures** (e.g., `RAXOSENTINEL-SYNTHETIC-TEST-SIGNATURE`).
2. **NO THIRD-PARTY PROPRIETARY OR COPYLEFT-CONFLICTING CODE**:
   - Do not copy ClamAV engine code, unverified signatures, or code with incompatible licensing.
   - All contributions must be original or under permissive licenses compatible with **GPL-2.0-or-later**.
3. **NO UNSAFE RUST**:
   - Avoid `unsafe` Rust unless strictly necessary and accompanied by detailed safety comments and justification.
4. **BOUNDED ALLOCATIONS**:
   - All file and stream operations must be chunked (bounded buffers) and check against `ResourceTracker` limits. Never load arbitrarily sized input streams into unbounded memory buffers.

---

## 2. Development & Quality Checks

All contributions must pass our required quality checks before being merged:

```bash
# 1. Format code according to project style
cargo fmt --all -- --check

# 2. Run clippy with warnings denied
cargo clippy --workspace --all-targets -- -D warnings

# 3. Ensure all unit and integration tests pass
cargo test --workspace
```

---

## 3. Pull Request Guidelines

1. **Focused Changes**: Keep PRs focused on a single feature, bug fix, or performance improvement.
2. **Automated Tests**: Every new feature or file type detector must include unit tests covering both valid inputs and truncated/malformed inputs.
3. **Commit Messages**: Write clear, descriptive commit messages.
4. **Licensing**: By contributing, you agree that your contributions will be licensed under the **GNU General Public License v2.0 or later** ([GPL-2.0-or-later](LICENSE)).
