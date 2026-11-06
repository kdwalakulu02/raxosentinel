# PDF regression corpus

Redistribution-safe fixtures generated locally by `generate.py` (LibreOffice, Chromium,
cairo, ReportLab, Ghostscript, img2pdf, qpdf, MuPDF and hand-built PDF 32000-1
structures). No third-party documents are included; the only malicious content is the
EICAR test string.

* `MANIFEST.tsv` — file, expected verdict, category, generator/version, structure,
  SHA-256, size.
* `run-corpus.sh <binary> [out.tsv]` — supervised verdicts plus in-process wall time and
  peak RSS per fixture.
* `results-baseline-551fd35.tsv`, `results-phase3c3.tsv` — measured results.
* `crates/raxosentinel-cli/tests/pdf_corpus.rs` enforces the manifest in `cargo test`.

`generate.py` regenerates every fixture; tool versions change bytes, so commit the
updated manifest together with the fixtures.
