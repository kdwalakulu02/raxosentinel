#!/usr/bin/env python3
# Copyright (C) 2026 RaxoSentinel Contributors
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generates large synthetic "scanned" PDFs for Phase 3D streaming measurements.

Each page is an A4 colour scan at 300 dpi: a 2480 x 3508 DeviceRGB image XObject
(26,099,520 decoded bytes) with FlateDecode, like scanners and img2pdf emit for
lossless scans. Content is a paper-like gradient with deterministic noise bands and
"text" lines. `--noise F` sets the fraction of rows carrying sensor-like noise, which
controls the Flate ratio (0.15 gives ~12:1 so 20 pages fit the 50 MiB input cap; 0.45
gives ~4:1, closer to a hard lossless scan).

Usage: generate_large_scans.py OUTDIR [--noise F] [--eicar-last-page] [PAGES ...]
(default pages: 1 5 10 20)
Optionally append EICAR to the last page's decoded image (--eicar-last-page) to check
that detection still happens deep inside a streamed object.

Outputs are not committed; they are produced on demand for measurements.
"""
import random
import sys
import zlib
from pathlib import Path

W, H = 2480, 3508
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def page_image(seed, noise_fraction):
    rnd = random.Random(seed)
    noise = bytes(rnd.randrange(236, 256) for _ in range(W * 3))
    pool = rnd.randbytes(1 << 20)
    rows = []
    for y in range(H):
        if rnd.random() < noise_fraction:
            off = rnd.randrange(len(pool) - W * 3)
            rows.append(bytes(236 + (b % 20) for b in pool[off:off + W * 3]))
        elif 300 < y < H - 300 and (y // 40) % 2 == 0 and (y % 40) < 22:
            # "Printed text" band: dark strokes on paper, varying per line.
            off = (y * 131 + seed) % (W * 3 - 600)
            row = bytearray(noise)
            for x in range(240 * 3, (W - 240) * 3, 37):
                row[x:x + 9] = b"\x20\x20\x28" * 3
            row[off:off + 600] = noise[:600]
            rows.append(bytes(row))
        else:
            shade = 250 - (y * 6 // H)
            rows.append(bytes((shade, shade, shade - 2)) * W)
    return b"".join(rows)


def build(pages, eicar_last_page=False, noise_fraction=0.15):
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", None]
    kids = []
    for p in range(pages):
        img = page_image(p, noise_fraction)
        if eicar_last_page and p == pages - 1:
            img = img[: -len(EICAR) - 4096] + EICAR + img[-4096:]
        data = zlib.compress(img, 6)
        img_num = len(objects) + 1
        objects.append(b"<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceRGB "
                       b"/BitsPerComponent 8 /Filter /FlateDecode /Length %d >>\nstream\n" % (W, H, len(data))
                       + data + b"\nendstream")
        content = b"q 595 0 0 842 0 0 cm /Im0 Do Q"
        objects.append(b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")
        page_num = len(objects) + 1
        objects.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /XObject << "
                       b"/Im0 %d 0 R >> >> /Contents %d 0 R >>" % (img_num, img_num + 1))
        kids.append(page_num)
    objects[1] = (b"<< /Type /Pages /Count %d /Kids [" % pages
                  + b" ".join(b"%d 0 R" % k for k in kids) + b"] >>")
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return bytes(out)


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    eicar = "--eicar-last-page" in argv
    args = [a for a in argv[1:] if a != "--eicar-last-page"]
    noise = 0.15
    if "--noise" in args:
        i = args.index("--noise")
        noise = float(args[i + 1])
        del args[i:i + 2]
    outdir = Path(args[0])
    outdir.mkdir(parents=True, exist_ok=True)
    for pages in [int(p) for p in args[1:]] or [1, 5, 10, 20]:
        name = f"scan-a4-300dpi-{pages}p-noise{noise}{'-eicar' if eicar else ''}.pdf"
        data = build(pages, eicar, noise)
        (outdir / name).write_bytes(data)
        print(f"{name}\t{len(data)} bytes\t{pages * W * H * 3} decoded image bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
