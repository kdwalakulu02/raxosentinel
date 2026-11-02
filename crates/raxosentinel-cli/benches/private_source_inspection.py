#!/usr/bin/env python3
# Copyright (C) 2026 RaxoSentinel Contributors
# SPDX-License-Identifier: GPL-2.0-or-later
"""Warm-cache end-to-end source inspection timings; private output is discarded."""
import statistics
import subprocess
import sys
import time

if len(sys.argv) != 5:
    raise SystemExit("usage: private_source_inspection.py CLI ROOT GENERATION SAMPLES")
cli, root, generation, count = sys.argv[1:]
command = [cli, "db", "sources", "--root", root, "--generation", generation]
subprocess.run(command, stdout=subprocess.DEVNULL, check=True)
times = []
for _ in range(int(count)):
    start = time.perf_counter_ns()
    subprocess.run(command, stdout=subprocess.DEVNULL, check=True)
    times.append((time.perf_counter_ns() - start) / 1_000_000)
if not times:
    raise SystemExit("samples must be positive")
print(f"samples={len(times)} warm-cache milliseconds median={statistics.median(times):.3f} min={min(times):.3f} max={max(times):.3f}")
