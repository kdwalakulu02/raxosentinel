# Linux supervised scan prototype

`raxosentinel scan FILE --supervised --json` runs one worker. The parent opens
and fstats the target and copies at most the configured file-size limit into an
anonymous memfd. It applies F_SEAL_WRITE, F_SEAL_GROW, F_SEAL_SHRINK and
F_SEAL_SEAL before passing the descriptor to the worker. The worker parses
stable bytes; a concurrent writer may nevertheless change the source while the
copy is in progress, so the snapshot is not an atomic point-in-time copy.
Mail integration must deliver or otherwise act on exactly the accepted snapshot,
not reopen or merely compare the original. This prototype does not return the
snapshot to a caller and therefore does not yet provide that integration.

The target's final component is opened O_NOFOLLOW; ancestor symlinks are still
followed. If a future service confines paths to a trusted directory, use a
trusted directory fd and evaluate openat2 RESOLVE_BENEATH or RESOLVE_IN_ROOT
with RESOLVE_NO_SYMLINKS and RESOLVE_NO_MAGICLINKS; no confinement is claimed
here. Filesystems and kernel support need explicit testing.

The parent removes inherited environment variables and marks extra descriptors
close-on-exec. The worker loads the configured private generation or signed
public release using existing strict verification, then closes all descriptors
except standard streams, enables no_new_privs and applies a Landlock ABI 1
ruleset that denies new filesystem access during parsing. Failure is ERROR.
The verified database, public trust keys, rule file and, for signed releases,
rollback state must be accessible to the caller during loading; the signed
release state needs its existing write permissions. A worker without a selected
external database uses built-in rules. Legacy --db and --db-store are rejected.
Landlock does not isolate the loader, existing memory, network, process creation,
or all kernel interfaces; it does not change UID. The loader executes with the
caller's privileges before confinement, so unrelated private files and secrets
are accessible to compromised loader code. Do not put signing credentials or
authentication secrets in that identity's accessible filesystem. This is not a
complete security boundary or a replacement for a separate dedicated identity.

The worker gets RLIMIT_AS (virtual address space, not RSS), no_new_privs, and a
separate process group. The parent kills the group on timeout and error, then
reaps the direct child. A forked descendant that stays in the group is killed;
a hostile process can change groups or sessions, and parent cancellation or
crash is not reliably handled. Descendants are not necessarily reaped by the
parent. No process-tree memory or process-count limits are enforced. A delegated
cgroup v2 with memory.max, pids.max and cgroup.kill could provide stronger tree
containment if properly delegated and managed; the current environment has a
read-only cgroup root and no delegated subtree. It is not used. These gaps are
deployment blockers.

The deadline is enforced after process creation; snapshot copying and the
synchronous spawn operation are outside its enforceable interval. Responses are
bounded and malformed or incomplete results fail closed. CLEAN is not a safety
guarantee. Direct CLI scanning remains path-based. Debug builds have
fault-injection hooks for integration tests and must not be used in production.
Other platforms do not support this supervised path.
