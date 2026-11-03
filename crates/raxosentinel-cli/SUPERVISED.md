# Linux supervised scan prototype

`raxosentinel scan FILE --supervised --json` starts a fresh worker for one scan.
`--worker-timeout-ms` sets the parent deadline (default 10000); `--worker-memory`
sets the worker RLIMIT_AS address-space limit in bytes (default 1 GiB). The
existing `--max-size`, `--timeout`, `--max-depth`, rules, private-generation,
and signed-public-release options are passed to the worker. A scan without a
selected external database uses built-in signatures only. Legacy `--db` and
`--db-store` are rejected in supervised mode. Authenticated database failures
are errors; no fallback is attempted.

The parent opens the final path component with O_NOFOLLOW and O_NONBLOCK,
checks the opened descriptor with fstat, and passes it as worker stdin. The
worker checks that descriptor again and performs bounded reads; it does not
open the target path. The path is only used as a name and format hint. The
request uses an exec argument vector limited to 65536 bytes and a file
descriptor; the JSON response is limited to 2 MiB and validated against the
worker exit status. A deadline applies to startup, verification, and scanning;
the parent kills and waits for a timed-out child after process creation. The
standard library spawn operation itself is synchronous and cannot be interrupted
by this deadline if the operating system stalls during process creation. Worker failure, invalid
response, and limits return ERROR. Detections retain precedence over partial
inspection where supported by the existing scanner; uninspectable data must not
be treated as CLEAN. CLEAN does not establish safety.

RLIMIT_AS limits virtual address space, not RSS; mappings and shared libraries
count against it, and it does not guarantee a particular RSS or system-wide
memory bound. The wall deadline is enforced by the supervising process, not a
kernel real-time guarantee. File contents can still be modified through other
file descriptors while scanning, and symlinks in ancestor directories are not
excluded. The worker runs with the caller's identity and filesystem access;
there is no privilege separation, seccomp, namespace, filesystem isolation, or
process-tree sandbox. A compromised worker may access unrelated files and
spawn descendants. These are deployment blockers, not a security boundary for
hostile code execution. The direct CLI remains path-based and does not gain
the descriptor guarantee. Other operating systems report an error for
supervised scans. Debug builds include environment-controlled worker fault
injection for integration tests; do not use them in production.
