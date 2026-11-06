#!/usr/bin/env bash
# Copyright (C) 2026 RaxoSentinel Contributors
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Run the PDF regression corpus against a raxosentinel binary.
#   tests/pdf-corpus/run-corpus.sh <raxosentinel-binary> [output.tsv] [extra scan args...]
# Columns: file, expected, supervised verdict, match, in-process verdict, wall seconds,
# peak RSS KiB (in-process scan, GNU time), first diagnostic/error line.
# Verdicts come from the supervised worker (the production path); timing and peak RSS
# come from a separate in-process run so that the worker process is what is measured.
set -euo pipefail
BIN=${1:?usage: run-corpus.sh <binary> [output.tsv] [scan args...]}
OUT=${2:-/dev/stdout}
shift $(( $# >= 2 ? 2 : 1 ))
HERE=$(cd "$(dirname "$0")" && pwd)
verdict() { case $1 in 0) echo CLEAN;; 1) echo DETECTED;; 2) echo UNSCANNED;; 3) echo ERROR;; *) echo "EXIT$1";; esac; }
{
  printf 'file\texpected\tsupervised\tmatch\tin_process\twall_s\tpeak_rss_kib\tdetail\n'
  grep -v '^#' "$HERE/MANIFEST.tsv" | while IFS=$'\t' read -r file expected _rest; do
    f="$HERE/fixtures/$file"
    set +e
    json=$("$BIN" scan "$f" --supervised --json "$@" 2>/dev/null); code=$?
    tfile=$(mktemp)
    /usr/bin/time -o "$tfile" -f '%e %M' "$BIN" scan "$f" --json "$@" >/dev/null 2>&1; rc=$?
    set -e
    read -r wall rss < <(tail -1 "$tfile"); rm -f "$tfile"
    got=$(verdict "$code")
    detail=$(python3 -c 'import json,sys
try:
    r=json.loads(sys.stdin.read())
    print((r.get("error") or "").replace("\t"," ").replace("\n"," ")[:160])
except Exception: print("")' <<<"$json")
    match=$([ "$got" = "$expected" ] && echo ok || echo MISMATCH)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$file" "$expected" "$got" "$match" "$(verdict "$rc")" "$wall" "$rss" "$detail"
  done
} > "$OUT"
