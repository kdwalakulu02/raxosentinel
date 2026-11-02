#!/usr/bin/env python3
# Copyright (C) 2026 RaxoSentinel Contributors
# SPDX-License-Identifier: GPL-2.0-or-later
"""Local warm-cache process benchmarks. All inputs are harmless synthetic fixtures."""
import json
import os
import statistics
import sys
import tempfile
import time
import zipfile

scanner, helper = sys.argv[1:3]
scanner, helper = os.path.abspath(scanner), os.path.abspath(helper)

def run(args):
    read_fd, write_fd = os.pipe()
    started = time.perf_counter_ns()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        os.dup2(write_fd, 1)
        null = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null, 2)
        os.execv(args[0], args)
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as output:
        raw = output.read()
    _, status, usage = os.wait4(pid, 0)
    elapsed = (time.perf_counter_ns() - started) / 1e6
    code = os.waitstatus_to_exitcode(status)
    if code != 0:
        raise RuntimeError(f"{args[0]} returned {code}")
    return elapsed, usage.ru_maxrss, json.loads(raw) if raw else None

with tempfile.TemporaryDirectory(prefix="raxo-3a-synthetic-") as root:
    run([helper, "prepare", root])
    db = os.path.join(root, "fixture.rsidb")
    with zipfile.ZipFile(os.path.join(root, "archive.zip"), "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(os.path.join(root, "10000000.bin"), "payload.bin")
    database = [run([helper, "db-load", db])[2]["elapsed_ms"] for _ in range(5)]
    print(f"synthetic_db_bytes={os.path.getsize(db)} db_load_ms_median={statistics.median(database):.3f} min={min(database):.3f} max={max(database):.3f}")
    for name in ["1000000.bin", "10000000.bin", "50000000.bin", "archive.zip"]:
        path = os.path.join(root, name)
        if name != "archive.zip":
            hashes = [run([helper, "hash", path])[2] for _ in range(3)]
            median_hash = statistics.median(x["elapsed_ms"] for x in hashes)
            print(f"hash file={name} bytes={os.path.getsize(path)} median_ms={median_hash:.3f} mib_per_sec={(os.path.getsize(path)/(1024*1024))/(median_hash/1000):.2f}")
        scans = [run([scanner, "scan", path, "--json", "--db", db, "--max-size", "60000000", "--timeout", "60"]) for _ in range(3)]
        timings = [x[0] for x in scans]
        assert all(x[2]["status"] == "CLEAN" for x in scans)
        print(f"scan file={name} bytes={os.path.getsize(path)} first_ms={timings[0]:.3f} median_ms={statistics.median(timings):.3f} min_ms={min(timings):.3f} max_ms={max(timings):.3f} peak_process_rss_kib={max(x[1] for x in scans)}")
