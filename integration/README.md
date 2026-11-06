# Shadow staging harness

This is a standalone staging harness, not a Raxo Email integration. It copies one input to a private temporary directory and invokes ClamAV and the RaxoSentinel socket client without a shell. It emits two JSON records and never emits attachment contents. The caller must store those records and retain its existing ClamAV policy. Do not use this harness to replace the existing scan path: integration must ensure both scanners receive the exact same immutable snapshot, including when a mail attachment is changing.

On a Linux host with Node.js and ClamAV installed, start the coordinator as the same user that runs the harness, then run:

```
RAXOSENTINEL=/opt/raxosentinel/bin/raxosentinel RAXOSENTINEL_SOCKET=/run/raxosentinel/scan.sock node integration/shadow-scan.js receipt-id attachment-id /path/to/attachment
```

`SCAN_TIMEOUT_MS` bounds each subprocess. The records contain scanner verdict, generation where reported, wall duration and error. A missing or failed scanner is ERROR. This harness does not send mail or write PostgreSQL.

The systemd files are templates for Ubuntu. Install the release binary at `/opt/raxosentinel/bin/raxosentinel`, provision a dedicated `raxosentinel` account, place the private database at `/var/lib/raxosentinel/private` with the ownership and permissions required by the private store, and install the service and environment files under `/etc/systemd/system/raxosentinel.service` and `/etc/raxosentinel/coordinator.env`. Run `systemctl daemon-reload` and `systemctl enable --now raxosentinel`. The socket directory is private to the service user; the caller must run as that user. Do not copy private intelligence into the repository. Preserve the separately configured database updater and its credentials. This template has not been deployed or validated on the VPS.

A functional health check can scan a known clean, service-owned file using `raxosentinel client --socket /run/raxosentinel/scan.sock --json-envelope /path/to/health.txt` as the service user. Verify the returned status is CLEAN and generation is present; a socket file alone does not establish readiness. Stop with `systemctl stop raxosentinel`.
