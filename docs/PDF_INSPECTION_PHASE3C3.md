# PDF inspection — Phase 3C.3

Supersedes the scope described in `PDF_INSPECTION_PHASE3C2.md`. The JSON envelope,
exit codes, Unix-socket protocol and verdict names are unchanged; PDF diagnostics are
carried in the existing `error` field as `CODE: message`.

## Design

* lopdf 0.47.0 parses structure in **strict** mode only. Cross-reference
  reconstruction and offset correction are never enabled: a file that a strict reader
  cannot resolve is reported as `UNSCANNED`, not repaired.
* Every stream is decoded by our own bounded decoders (`scanner/pdf_decode.rs`), never
  by lopdf's fail-open helpers. Decoding is fail-closed: truncated or corrupt data is a
  diagnostic, and any partial output is still scanned.
* Object streams (`/Type /ObjStm`) are intercepted through lopdf's load filter and
  expanded by RaxoSentinel. Each member is parsed from its own slot in isolation, so
  overlapping members cannot amplify memory. Members join the document only where the
  cross-reference data assigns them to that container.
* Coverage is enforced: every `endstream` keyword in the file must belong to a stream
  that was inspected. Streams no longer referenced by the latest revision are found by
  loading earlier `%%EOF`-terminated revisions (max 32). Anything still unexplained is
  `PDF_UNREFERENCED_STREAM` (UNSCANNED).
* Every declared cross-reference entry must be loaded (`PDF_OBJECT_UNREADABLE`
  otherwise).
* String objects (literal and hex) are matched after unescaping, including strings in
  shadowed object-stream members.
* Nothing is rendered, executed, rewritten or sanitised. JavaScript, actions, external
  references and fonts are treated as data only.

## Supported

| Feature | Status |
|---|---|
| Classic xref tables, xref streams, hybrid files | supported |
| Compressed object streams | supported (own bounded expansion) |
| Incremental updates, linearized files | supported; earlier-revision streams inspected |
| Embedded files / attachments (`/EmbeddedFile`) | decoded and scanned recursively |
| FlateDecode (zlib or raw deflate; missing/wrong Adler-32 tolerated) | supported |
| LZWDecode (`EarlyChange` 0/1), ASCIIHexDecode, ASCII85Decode, RunLengthDecode | supported |
| PNG predictors 10–15, TIFF predictor 2 (8-bit components) | supported |
| Filter chains | up to 8 filters |
| Identity `/Crypt` filter | supported |
| Encryption with empty user password (owner-password only; corpus covers RC4 and AES-256) | decrypted and inspected |
| DCT/JPX/JBIG2/CCITT image streams | left in codec form; raw bytes are covered by the whole-file scan |

## Verdict mapping and diagnostic codes

| Code | Verdict | Meaning |
|---|---|---|
| `PDF_PARSE_FAILED` | UNSCANNED | strict structure parse failed (malformed/truncated) |
| `PDF_ENCRYPTED` | UNSCANNED | password required |
| `PDF_UNSUPPORTED_FILTER` | UNSCANNED | unknown filter, unsupported parameters, non-identity Crypt |
| `PDF_STREAM_DECODE_FAILED` | UNSCANNED | corrupt or truncated encoded data |
| `PDF_EXTERNAL_STREAM` | UNSCANNED | stream data in an external file (`/F`) |
| `PDF_OBJSTM_INVALID` | UNSCANNED | malformed object-stream header or members |
| `PDF_OBJECT_UNREADABLE` | UNSCANNED | declared object could not be loaded |
| `PDF_UNREFERENCED_STREAM` | UNSCANNED | stream not explained by any loadable revision |
| `PDF_RESOURCE_LIMIT` | ERROR | a size, ratio, count or object limit was exceeded |
| `PDF_NESTED` | inherited | a nested scan (e.g. inside an attachment) was incomplete |

A detection always takes precedence (`DETECTED`) over incomplete inspection.

## Limits

| Limit | Value |
|---|---|
| Decoded bytes per stream | `max_email_attachment_size` (25 MiB) |
| Aggregate decoded bytes | `max_total_extracted_bytes` (100 MiB) |
| Chain output/input ratio | 1100:1 above 1 MiB of output |
| Object-stream decoded total | 64 MiB |
| lopdf internal decode (xref streams; encrypted object streams) | 4 MiB each |
| Indirect objects | 500,000 |
| Revisions examined | 32 |
| Embedded files | share the attachment-count limit (30) |
| Deadline | checked inside decoders and the load filter |
| Worker | RLIMIT_AS 1 GiB, SIGKILL at deadline (unchanged) |

## Known limitations

* Image codecs (DCT, JPX, JBIG2, CCITT) are not decoded; inline-image data is scanned
  in encoded form.
* Large Flate-compressed images count fully against the 100 MiB aggregate budget. A
  full-colour A4 page at 300 dpi decodes to ~26 MB, so a five-page colour scan of this
  kind returns ERROR (measured). Bounded windowed scanning of image streams is the
  planned remedy.
* Strings in shadowed non-stream objects of earlier revisions are matched in raw form only.
* lopdf's encrypted-document path expands object streams itself (4 MiB per stream)
  and tolerates per-object decryption failures; parse time on adversarial xref
  aliasing is bounded only by the worker deadline and address-space limit.
* Malformed PDFs are never repaired, so damaged-but-viewable files remain UNSCANNED.
* A `%PDF-` header is recognised within the first 1024 bytes.
