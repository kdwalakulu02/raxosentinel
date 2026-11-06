# Phase 3B limited-scope private beta

This is a development candidate, not a production release. Scan results are indicator matches and inspection outcomes. CLEAN means no configured indicator was found in the inspection performed; it does not guarantee safety or comprehensive decoding of every encoding or polyglot. Mail applications must decide delivery and quarantine policy.

## Scope and limitations

* Raw bytes: hash and byte-signature matching for files including text, PDF, images, and binaries. PDFs receive raw inspection; PDF streams and arbitrary embedded objects are not generally decoded.
* ZIP: stored and deflated entries, including nested ZIPs and recognizable PDF-prefixed ZIPs, are inspected within configured recursion, size, count, memory and time limits. Multiple end records and extra local headers are conservatively reported UNSCANNED when no detection takes priority. Not all multiple, malformed or embedded archive layouts are discovered; marker bytes can also cause false UNSCANNED results.
* RFC 822/MIME: supported decoded message parts are inspected under shared limits. Unsupported encodings and structures may be incomplete.
* TAR, RAR, 7-Zip, GZIP, BZIP2, XZ and CAB are not unpacked. Recognizable structures or markers return UNSCANNED, but marker discovery cannot identify all variants or encodings. Encrypted ZIP entries and unsupported compression methods are UNSCANNED. Limits, operational errors and timeouts are ERROR. Never interpret UNSCANNED or ERROR as CLEAN.

The scanner operates without ClamAV in the scan path. The verified private RSIDB must be supplied; do not redistribute its third-party evidence publicly. Intelligence updates are not enabled by these instructions.

## Socket response

The existing Unix socket protocol and verdicts are unchanged. Request `client --json-envelope` for the coordinator envelope, including `database_generation`. `status` is CLEAN, DETECTED, UNSCANNED, ERROR or BUSY. Recognized scan or worker deadline failures retain ERROR and add `error_code: "TIMEOUT"`; other errors omit `error_code`. Inspect `error`, `report.error`, the report target's SHA-256, threat names and scan duration where present. Errors before a file is read may not have a SHA-256. Use the full envelope, not `--json`, to receive the timeout code and generation. The timeout code applies to recognized scan and worker deadlines; client transport deadlines may produce other errors. A missing code must not be interpreted as CLEAN.

## Ubuntu 24.04 verification (isolated, no deployment)

Perform on an authorized Ubuntu 24.04 x86_64 machine. Use a separate checkout and build directory; do not replace the current service, socket, executable or database. Confirm `cat /etc/os-release`, `uname -m`, and `ldd --version`. Install the project Rust toolchain from `rust-toolchain.toml` and standard build prerequisites. With the reviewed phase-3b commit checked out:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
CARGO_TARGET_DIR=/tmp/raxosentinel-beta-build cargo build --release --locked
BIN=/tmp/raxosentinel-beta-build/release/raxosentinel
"$BIN" --version
sha256sum "$BIN"
```

Set `PRIVATE_ROOT` to the existing owner-controlled private database root, readable by the test process, without changing its contents. Check the explicit immutable generation and compare the total record count with 542057. The `db sources` command verifies the private generation and evidence; `db verify` reports RSIDB counts and provenance.

```sh
PRIVATE_ROOT=/path/to/existing/private-root
"$BIN" db sources --root "$PRIVATE_ROOT" --generation phase2d6-unified
"$BIN" db verify "$PRIVATE_ROOT/phase2d6-unified/database.rsidb"
```

Use a private temporary directory, a separate socket, and harmless EICAR test bytes. No production services are started or modified. `serve` listens only on the specified Unix socket; it does not open a public TCP scanner port. Confirm with `ss -ltnp` before and during the test where permissions permit.

```sh
umask 077
TEST_DIR=$(mktemp -d /tmp/raxosentinel-beta.XXXXXX)
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$TEST_DIR/eicar.txt"
printf '%s\n' 'ordinary clean text' > "$TEST_DIR/clean.txt"
"$BIN" serve --socket "$TEST_DIR/scan.sock" --private-db-root "$PRIVATE_ROOT" --private-generation phase2d6-unified --max-workers 1 --max-pending 1 > "$TEST_DIR/server.log" 2>&1 &
SERVER_PID=$!
# Wait for startup; inspect server.log if the socket does not appear.
for i in $(seq 1 60); do [ -S "$TEST_DIR/scan.sock" ] && break; sleep 1; done
[ -S "$TEST_DIR/scan.sock" ] || { cat "$TEST_DIR/server.log"; kill "$SERVER_PID" 2>/dev/null || true; exit 1; }
"$BIN" client --socket "$TEST_DIR/scan.sock" --json-envelope "$TEST_DIR/clean.txt"
"$BIN" client --socket "$TEST_DIR/scan.sock" --json-envelope "$TEST_DIR/eicar.txt"; EICAR_EXIT=$?
printf 'EICAR exit: %s (expected 1)\n' "$EICAR_EXIT"
kill "$SERVER_PID"
wait "$SERVER_PID" 2>/dev/null || true
```

Check clean status CLEAN, EICAR status DETECTED, name, file SHA-256, duration, and `database_generation` of `phase2d6-unified`. Record OS, commit SHA, commands, test counts, binary SHA-256 and output (excluding private intelligence). Inspect the socket, process and TCP listeners; remove only the temporary test directory when finished. Do not install a service or start unattended updates. A private prerelease may be prepared only after the checks pass and the limitations are accepted; keep the previous tested release for rollback.
