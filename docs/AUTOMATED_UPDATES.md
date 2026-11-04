# Automated Intelligence Updates (Phase 2D.7)

RaxoSentinel features an automated, unattended multi-source intelligence update pipeline designed to keep the threat intelligence database current without human intervention, while maintaining strict architectural, cryptographic, and operational invariants.

---

## 1. Architectural Foundation: ONE Unified RSIDB

RaxoSentinel maintains exactly **ONE canonical runtime intelligence database**: the native binary RSIDB (`database.rsidb`).

Third-party threat intelligence providers—including **ClamAV** and **MalwareBazaar**—are treated strictly as **intelligence sources**, never as disparate runtime database formats or secondary scanner backends. Every acquired indicator undergoes verification, normalization, deduplication, and reconciliation into our single native format.

```
+--------------------+        +-----------------------+
|  ClamAV CVD Feeds  |        | MalwareBazaar (abuse) |
| (main.cvd/daily)   |        | (API / Fixtures)      |
+---------+----------+        +-----------+-----------+
          |                               |
          \--------------+----------------/
                         |
                         v
           [ Update Pipeline Engine ]
    1. SOURCE CHECK  -> 2. ACQUIRE  -> 3. VERIFY
    4. NORMALIZE     -> 5. VALIDATE -> 6. RECONCILE
    7. BUILD         -> 8. VERIFY   -> 9. ATOMIC ACTIVATE
                         |
                         v
              +---------------------+
              | ONE Canonical RSIDB |
              |  (database.rsidb)   |
              +---------------------+
                         |
                         v
              [ RaxoSentinel Scanner ]
```

---

## 2. Shared Pipeline Architecture

The automated update engine (`UpdateEngine`) executes a 9-stage linear verification pipeline:

1. **Source Check**: Each provider queries upstream endpoints to check for fresh revisions (CVD header versions, MalwareBazaar recent record sets). If no source has changed and `--force` is not passed, the process exits cleanly with zero disk writes.
2. **Acquisition**: Fresh source payloads and signatures are acquired within provider rate limits.
3. **Verification**: Upstream integrity and authenticity are verified. Corrupted or partial archives are rejected immediately.
4. **Normalization**: Hashes are extracted into canonical format (`RecordKey` with MD5, SHA-1, or SHA-256). Exclusions (`.fp`, `.sfp`, `.ign`, `.ign2`) are parsed and applied to eliminate known false positives.
5. **Validation**: Record formats, file sizes, and metadata are strictly validated. Bytecode signatures are strictly ignored—zero ClamAV bytecode is executed.
6. **Reconciliation**:
   - **Multi-Source Claims**: If multiple sources claim the same hash, both attributions are recorded. If Source A drops a hash but Source B still reports it, the indicator is preserved in the active database.
   - **Mass Deletion Protection**: If an update would reduce total active indicators by more than the configured anomaly threshold (default: 20%), the engine aborts with `UpdateError::SuspiciousReduction` to prevent upstream ingestion failures from disarming protection.
7. **Build**: A new immutable RSIDB generation is compiled inside an isolated `.staging-*` directory.
8. **Verify**: The generated database is verified end-to-end: header magic, checksums, index ordering, provenance records, and spot-check lookups.
9. **Atomic Activation**:
   - The verified staging directory is published via `renameat2(RENAME_NOREPLACE)`.
   - The active pointer `current` is atomically updated to point to the new generation.
   - The previous active generation is recorded in `previous` to enable instant rollback.

---

## 3. Concurrency & Failure Safety

- **Advisory Locking**: The update engine acquires an exclusive, non-blocking lock on `updater.lock` (`libc::flock(LOCK_EX | LOCK_NB)`). Concurrent invocations exit immediately with code 75 (`EX_TEMPFAIL` / lock contention) rather than corrupting staging state.
- **Fail-Closed Operation**: Network timeouts, truncated downloads, or verification failures terminate the update process prior to activation. The running scanner and active database remain completely untouched.
- **Instant Rollback**: If a newly published generation exhibits unexpected runtime issues, running `raxosentinel db rollback` atomically swings the `current` pointer back to `previous`.

---

## 4. CLI Operations

### Check Upstream Status (`--check`)
Inspect upstream providers for available updates without downloading or modifying state:

```bash
raxosentinel db update --check --root /home/USER/raxosentinel-private
```

### View Status & Provenance (`--status`)
Display the active generation, previous rollback target, last update timestamp, and provider statuses:

```bash
raxosentinel db update --status --root /home/USER/raxosentinel-private
```

### Apply Update (`--apply`)
Execute the full automated update pipeline:

```bash
raxosentinel db update --apply --root /home/USER/raxosentinel-private
```

Force a rebuild even when sources report unchanged versions:

```bash
raxosentinel db update --apply --force --root /home/USER/raxosentinel-private
```

### Emergency Rollback (`rollback`)
Revert the active generation pointer to the previous generation:

```bash
raxosentinel db rollback --root /home/USER/raxosentinel-private
```

---

## 5. Unattended Scheduling (systemd)

For production Linux environments, systemd service and timer units are provided in `docs/systemd/`.

### Installation

1. Copy service and timer units to `/etc/systemd/system/`:
   ```bash
   sudo cp docs/systemd/raxosentinel-update.service /etc/systemd/system/
   sudo cp docs/systemd/raxosentinel-update.timer /etc/systemd/system/
   ```

2. Reload systemd and enable the timer:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now raxosentinel-update.timer
   ```

3. Verify timer schedule:
   ```bash
   systemctl list-timers raxosentinel-update.timer
   ```

### Security Hardening
The `raxosentinel-update.service` unit enforces strict Linux security boundaries:
- `NoNewPrivileges=true`
- `ProtectSystem=strict` (all OS directories mounted read-only)
- `ProtectHome=read-only` (with explicit `ReadWritePaths` for the private storage root)
- `PrivateTmp=true`
- `ProtectKernelTunables=true`, `ProtectControlGroups=true`, `RestrictRealtime=true`
- `RandomizedDelaySec=1800` (avoids upstream thundering herd effects)
