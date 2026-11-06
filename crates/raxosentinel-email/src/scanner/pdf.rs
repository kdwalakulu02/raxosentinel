/*
 * RaxoSentinel Core — Malware Detection Engine
 * Copyright (C) 2026 RaxoSentinel Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

//! Bounded, non-executing PDF inspection.
//!
//! lopdf (strict mode) resolves the cross-reference chain, classic tables, xref streams,
//! hybrid files and standard-security decryption. Everything that expands data is done
//! here under explicit budgets instead:
//!
//! * object streams are decoded by a load-time filter with the strict decoders in
//!   [`super::pdf_decode`], and each member is parsed from its own isolated slot so
//!   overlapping offsets cannot cause quadratic work;
//! * every stream is decoded with complete-or-reported semantics and recursively
//!   scanned; partial output is still scanned so detections are never lost;
//! * string objects are scanned after PDF unescaping/hex decoding/decryption;
//! * every `endstream` keyword in the file must belong to an inspected stream.
//!   Unreferenced streams are looked up in earlier incremental revisions, and any
//!   that remain unexplained make the result UNSCANNED.
//!
//! Nothing is rendered, executed, repaired or written back.

use super::pdf_decode::{self, Budget, FailureKind, FilterSpec, Params};
use super::EmailScanner;
use lopdf::xref::XrefEntry;
use lopdf::{Dictionary, Document, Object, ObjectId, ObjectStream, Stream};
use memchr::memmem;
use raxosentinel_core::{ResourceTracker, ScanError, ScanReport, ScanStatus, Threat};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// Maximum indirect objects, including object-stream members, per load.
const MAX_OBJECTS: usize = 500_000;
/// lopdf's own decode limit. It applies only to cross-reference streams and to object
/// streams of encrypted documents (which lopdf expands itself) and bounds the xref
/// entry tables built from them.
const LOPDF_DECODE_LIMIT: usize = 4 << 20;
/// Aggregate decoded object-stream bytes held during one load.
const MAX_OBJSTM_TOTAL: u64 = 64 << 20;
/// Sub-reports retained per PDF (embedded files and non-clean results). Threats and
/// issues of further streams are still propagated, keeping worker responses bounded.
const MAX_KEPT_REPORTS: usize = 64;
/// Earlier revisions loaded to explain streams the latest revision does not reference.
const MAX_REVISIONS: usize = 32;
/// The header may follow arbitrary bytes, as conforming readers accept (ISO 32000-2 §7.5.2).
const HEADER_WINDOW: usize = 1024;
/// Allowance for the EOL and whitespace between stream data and `endstream`.
const SPAN_SLACK: usize = 64;
const MIN_STRING_LEN: usize = 8;
const STRING_FLUSH: usize = 4 << 20;

pub(super) const CODE_PARSE: &str = "PDF_PARSE_FAILED";
pub(super) const CODE_ENCRYPTED: &str = "PDF_ENCRYPTED";
pub(super) const CODE_FILTER: &str = "PDF_UNSUPPORTED_FILTER";
pub(super) const CODE_DECODE: &str = "PDF_STREAM_DECODE_FAILED";
pub(super) const CODE_EXTERNAL: &str = "PDF_EXTERNAL_STREAM";
pub(super) const CODE_OBJSTM: &str = "PDF_OBJSTM_INVALID";
pub(super) const CODE_UNREADABLE: &str = "PDF_OBJECT_UNREADABLE";
pub(super) const CODE_UNREFERENCED: &str = "PDF_UNREFERENCED_STREAM";
pub(super) const CODE_LIMIT: &str = "PDF_RESOURCE_LIMIT";

/// Returns the offset of a `%PDF-n` header within the first 1024 bytes.
pub(super) fn header_offset(data: &[u8]) -> Option<usize> {
    let window = &data[..data.len().min(HEADER_WINDOW)];
    // lopdf anchors at the first `%PDF-` in the buffer, so only the first counts.
    let pos = memmem::find(window, b"%PDF-")?;
    data.get(pos + 5)
        .is_some_and(u8::is_ascii_digit)
        .then_some(pos)
}

/// Result of inspecting one PDF.
pub(super) struct PdfInspection {
    pub reports: Vec<ScanReport>,
    /// Threats from inspected objects whose reports were not retained.
    pub threats: Vec<Threat>,
    pub issue: Option<(ScanStatus, String)>,
    /// Absolute byte ranges of streams whose decoded content was recursively scanned.
    pub scanned_spans: Vec<(usize, usize)>,
}

#[derive(Default)]
struct Issues {
    failed: Option<String>,
    unsupported: Option<String>,
}

impl Issues {
    fn raise(&mut self, status: ScanStatus, code: &str, message: impl std::fmt::Display) {
        let slot = match status {
            ScanStatus::Failed => &mut self.failed,
            _ => &mut self.unsupported,
        };
        if slot.is_none() {
            *slot = Some(format!("{code}: {message}"));
        }
    }

    fn unsupported(&mut self, code: &str, message: impl std::fmt::Display) {
        self.raise(ScanStatus::Unsupported, code, message);
    }

    fn failed(&mut self, message: impl std::fmt::Display) {
        self.raise(ScanStatus::Failed, CODE_LIMIT, message);
    }

    fn merge(&mut self, other: Issues) {
        if self.failed.is_none() {
            self.failed = other.failed;
        }
        if self.unsupported.is_none() {
            self.unsupported = other.unsupported;
        }
    }

    fn into_issue(self) -> Option<(ScanStatus, String)> {
        self.failed
            .map(|m| (ScanStatus::Failed, m))
            .or_else(|| self.unsupported.map(|m| (ScanStatus::Unsupported, m)))
    }
}

/// A decoded object stream captured by the load filter.
struct ObjStm {
    id: ObjectId,
    raw_len: usize,
    declared_len: Option<usize>,
    data: Vec<u8>,
    members: Vec<(u32, Object)>,
}

enum Abort {
    Timeout,
    Limit(String),
}

/// State shared with the load filter, which lopdf accepts only as a plain `fn`.
/// lopdf is built without `rayon`, so the filter runs on the loading thread. If it
/// ever ran elsewhere the filter would drop every object, which the post-load
/// integrity check reports as unreadable rather than clean.
struct LoadState {
    deadline: Instant,
    objstm_cap: usize,
    objstm_remaining: u64,
    objstm_bytes: u64,
    objects: usize,
    abort: Option<Abort>,
    issues: Issues,
    objstms: Vec<ObjStm>,
}

thread_local! {
    static LOAD_STATE: RefCell<Option<LoadState>> = const { RefCell::new(None) };
}

struct LoadGuard;

impl Drop for LoadGuard {
    fn drop(&mut self) {
        LOAD_STATE.with(|state| state.borrow_mut().take());
    }
}

fn load_filter(id: ObjectId, object: &mut Object) -> Option<(ObjectId, Object)> {
    LOAD_STATE.with(|cell| {
        let mut guard = cell.borrow_mut();
        let state = guard.as_mut()?;
        if state.abort.is_some() {
            return None;
        }
        state.objects += 1;
        if state.objects > MAX_OBJECTS {
            state.abort = Some(Abort::Limit(format!(
                "more than {MAX_OBJECTS} indirect objects"
            )));
            return None;
        }
        if state.objects.is_multiple_of(256) && Instant::now() >= state.deadline {
            state.abort = Some(Abort::Timeout);
            return None;
        }
        if let Object::Stream(stream) = object {
            if stream.dict.has_type(b"ObjStm") {
                state.expand_objstm(id, stream);
                return None;
            }
        }
        // lopdf only tests the result for `Some` and keeps `object` itself.
        Some((id, Object::Null))
    })
}

impl LoadState {
    fn expand_objstm(&mut self, id: ObjectId, stream: &Stream) {
        let declared_len = stream
            .dict
            .get(b"Length")
            .and_then(Object::as_i64)
            .ok()
            .and_then(|n| usize::try_from(n).ok());
        let mut entry = ObjStm {
            id,
            raw_len: stream.content.len(),
            declared_len,
            data: Vec::new(),
            members: Vec::new(),
        };
        let label = format!("object stream {} {}", id.0, id.1);
        let specs = match filter_specs(&stream.dict, None) {
            Ok(specs) => specs,
            Err(message) => {
                self.issues
                    .unsupported(CODE_OBJSTM, format!("{label}: {message}"));
                self.objstms.push(entry);
                return;
            }
        };
        let cap = (self.objstm_cap as u64).min(self.objstm_remaining) as usize;
        let budget = Budget {
            cap,
            deadline: self.deadline,
        };
        match pdf_decode::decode_chain(&stream.content, &specs, budget) {
            Ok(decoded) if decoded.image_codec.is_none() => entry.data = decoded.data,
            Ok(decoded) => {
                self.issues
                    .unsupported(CODE_OBJSTM, format!("{label}: image filter"));
                entry.data = decoded.data;
            }
            Err(failure) => {
                match failure.kind {
                    FailureKind::Timeout => self.abort = Some(Abort::Timeout),
                    FailureKind::Limit => {
                        self.abort = Some(Abort::Limit(format!("{label}: {}", failure.message)))
                    }
                    FailureKind::Unsupported => self
                        .issues
                        .unsupported(CODE_FILTER, format!("{label}: {}", failure.message)),
                    FailureKind::Malformed => self
                        .issues
                        .unsupported(CODE_DECODE, format!("{label}: {}", failure.message)),
                }
                entry.data = failure.partial;
            }
        }
        let len = entry.data.len() as u64;
        self.objstm_bytes += len;
        self.objstm_remaining = self.objstm_remaining.saturating_sub(len);
        if self.abort.is_none() && entry.data.len() == len as usize {
            match parse_members(&stream.dict, &entry.data, self.deadline) {
                Ok(members) => entry.members = members,
                Err(message) => self
                    .issues
                    .unsupported(CODE_OBJSTM, format!("{label}: {message}")),
            }
        }
        self.objects += entry.members.len();
        if self.objects > MAX_OBJECTS {
            self.abort = Some(Abort::Limit(format!(
                "more than {MAX_OBJECTS} indirect objects"
            )));
        }
        self.objstms.push(entry);
    }
}

/// Parses the object-stream index and each member from its own slot. Offsets must
/// be strictly increasing once sorted; overlapping members are rejected.
fn parse_members(
    dict: &Dictionary,
    data: &[u8],
    deadline: Instant,
) -> Result<Vec<(u32, Object)>, String> {
    let int = |key: &[u8]| {
        dict.get(key)
            .and_then(Object::as_i64)
            .ok()
            .and_then(|v| usize::try_from(v).ok())
            .ok_or_else(|| format!("missing or invalid /{}", String::from_utf8_lossy(key)))
    };
    let n = int(b"N")?;
    let first = int(b"First")?;
    if first > data.len() {
        return Err(format!(
            "/First {first} beyond decoded length {}",
            data.len()
        ));
    }
    // Every index pair needs at least four bytes ("1 0 ").
    if n > first / 4 + 1 || n > MAX_OBJECTS {
        return Err(format!("/N {n} inconsistent with /First {first}"));
    }
    let numbers = parse_index(&data[..first], 2 * n)?;
    let mut entries: Vec<(usize, u32)> = Vec::with_capacity(n);
    for pair in numbers.as_chunks::<2>().0 {
        let num = u32::try_from(pair[0]).map_err(|_| "object number out of range")?;
        let offset = usize::try_from(pair[1])
            .ok()
            .and_then(|o| o.checked_add(first))
            .filter(|&o| o < data.len())
            .ok_or_else(|| format!("member {num} offset out of range"))?;
        entries.push((offset, num));
    }
    entries.sort_unstable();
    if entries.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err("overlapping member offsets".into());
    }
    let mut members = Vec::with_capacity(entries.len());
    for (i, &(offset, num)) in entries.iter().enumerate() {
        if i.is_multiple_of(1024) && Instant::now() >= deadline {
            return Err("deadline reached while parsing members".into());
        }
        let end = entries.get(i + 1).map_or(data.len(), |next| next.0);
        // Members that fail to parse are reported by the post-load xref check when
        // the current revision references them.
        if let Some(object) = parse_slot(num, &data[offset..end]) {
            members.push((num, object));
        }
    }
    Ok(members)
}

/// Parses the `N` integer pairs of an object-stream index (comments allowed).
fn parse_index(index: &[u8], count: usize) -> Result<Vec<u64>, String> {
    let mut numbers = Vec::with_capacity(count);
    let mut i = 0;
    while numbers.len() < count {
        while i < index.len() && (is_whitespace(index[i]) || index[i] == b'%') {
            if index[i] == b'%' {
                while i < index.len() && !matches!(index[i], b'\r' | b'\n') {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
        let start = i;
        while i < index.len() && index[i].is_ascii_digit() {
            i += 1;
        }
        if start == i {
            return Err(format!("index has {} of {count} integers", numbers.len()));
        }
        let digits = std::str::from_utf8(&index[start..i]).unwrap_or_default();
        numbers.push(
            digits
                .parse::<u64>()
                .map_err(|_| "index integer too large")?,
        );
    }
    Ok(numbers)
}

/// Parses one object-stream member in isolation with lopdf's object parser.
fn parse_slot(num: u32, slot: &[u8]) -> Option<Object> {
    let header = format!("{num} 0 ");
    let mut content = Vec::new();
    content.try_reserve_exact(header.len() + slot.len()).ok()?;
    content.extend_from_slice(header.as_bytes());
    content.extend_from_slice(slot);
    let mut dict = Dictionary::new();
    dict.set("N", 1);
    dict.set("First", header.len() as i64);
    let stream = Stream::new(dict, content);
    ObjectStream::new_with_limit(&stream, None)
        .ok()?
        .objects
        .remove(&(num, 0))
}

fn is_whitespace(b: u8) -> bool {
    matches!(b, b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

/// Builds the filter chain of a stream dictionary. Without a document (object
/// streams during load), indirect filter values cannot be resolved and are refused.
fn filter_specs(dict: &Dictionary, doc: Option<&Document>) -> Result<Vec<FilterSpec>, String> {
    let resolve = |object: &'_ Object| -> Result<Object, String> {
        match (object, doc) {
            (Object::Reference(_), None) => Err("indirect filter or parameter value".into()),
            (Object::Reference(_), Some(doc)) => doc
                .dereference(object)
                .map(|(_, o)| o.clone())
                .map_err(|e| format!("unresolvable filter reference: {e}")),
            (o, _) => Ok(o.clone()),
        }
    };
    let names: Vec<Vec<u8>> = match dict.get(b"Filter") {
        Err(_) => Vec::new(),
        Ok(value) => match resolve(value)? {
            Object::Null => Vec::new(),
            Object::Name(name) => vec![name],
            Object::Array(items) => items
                .iter()
                .map(|item| match resolve(item)? {
                    Object::Name(name) => Ok(name),
                    _ => Err("non-name entry in /Filter".to_string()),
                })
                .collect::<Result<_, _>>()?,
            _ => return Err("invalid /Filter type".into()),
        },
    };
    let parms: Vec<Option<Dictionary>> = match dict.get(b"DecodeParms") {
        Err(_) => Vec::new(),
        Ok(value) => match resolve(value)? {
            Object::Null => Vec::new(),
            Object::Dictionary(d) => vec![Some(d)],
            Object::Array(items) => items
                .iter()
                .map(|item| match resolve(item)? {
                    Object::Null => Ok(None),
                    Object::Dictionary(d) => Ok(Some(d)),
                    _ => Err("invalid /DecodeParms entry".to_string()),
                })
                .collect::<Result<_, _>>()?,
            _ => return Err("invalid /DecodeParms type".into()),
        },
    };
    if parms.len() > names.len() || (parms.len() == 1 && names.len() > 1 && parms[0].is_some()) {
        return Err("/DecodeParms does not match /Filter".into());
    }
    names
        .into_iter()
        .enumerate()
        .map(|(i, name)| {
            let params = match parms.get(i) {
                Some(Some(d)) => params_from(d, &resolve)?,
                _ => Params::default(),
            };
            Ok(FilterSpec { name, params })
        })
        .collect()
}

fn params_from(
    dict: &Dictionary,
    resolve: &dyn Fn(&Object) -> Result<Object, String>,
) -> Result<Params, String> {
    let int = |key: &[u8]| -> Result<Option<i64>, String> {
        match dict.get(key) {
            Err(_) => Ok(None),
            Ok(value) => match resolve(value)? {
                Object::Integer(v) => Ok(Some(v)),
                Object::Real(v) if v.fract() == 0.0 && v.abs() < 1e9 => Ok(Some(v as i64)),
                Object::Null => Ok(None),
                _ => Err(format!(
                    "invalid /{} decode parameter",
                    String::from_utf8_lossy(key)
                )),
            },
        }
    };
    let name = match dict.get(b"Name") {
        Ok(value) => match resolve(value)? {
            Object::Name(n) => Some(n),
            _ => None,
        },
        Err(_) => None,
    };
    Ok(Params {
        predictor: int(b"Predictor")?,
        colors: int(b"Colors")?,
        bits_per_component: int(b"BitsPerComponent")?,
        columns: int(b"Columns")?,
        early_change: int(b"EarlyChange")?,
        name,
    })
}

/// Loads one revision (the whole file or an earlier `%%EOF` prefix).
fn load_document(bytes: &[u8], state: LoadState) -> (Result<Document, String>, LoadState) {
    LOAD_STATE.with(|cell| *cell.borrow_mut() = Some(state));
    let guard = LoadGuard;
    let options = lopdf::LoadOptions {
        strict: true,
        max_decompressed_size: Some(LOPDF_DECODE_LIMIT),
        filter: Some(load_filter),
        ..Default::default()
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Document::load_mem_with_options(bytes, options)
    }));
    let state = LOAD_STATE
        .with(|cell| cell.borrow_mut().take())
        .expect("PDF load state is installed for the duration of the load");
    drop(guard);
    let result = match result {
        Ok(Ok(doc)) => Ok(doc),
        Ok(Err(lopdf::Error::Decompress(lopdf::DecompressError::MemoryLimitExceeded {
            limit,
        }))) => Err(format!(
            "{CODE_LIMIT}\u{0}decoded structure exceeds {limit} bytes"
        )),
        Ok(Err(e)) => Err(format!("{CODE_PARSE}\u{0}{e}")),
        Err(_) => Err(format!(
            "{CODE_PARSE}\u{0}parser panicked on malformed input"
        )),
    };
    (result, state)
}

/// Byte range of a stream object in the file, conservatively including its data.
fn stream_span(
    data: &[u8],
    base: usize,
    offset: u64,
    content_len: usize,
    declared_len: Option<usize>,
) -> Option<(usize, usize)> {
    let start = base.checked_add(usize::try_from(offset).ok()?)?;
    let rest = data.get(start..)?;
    let keyword = memmem::find(rest, b"stream")?;
    let mut data_start = start + keyword + 6;
    if data.get(data_start) == Some(&b'\r') {
        data_start += 1;
    }
    if data.get(data_start) == Some(&b'\n') {
        data_start += 1;
    }
    let len = content_len.max(declared_len.unwrap_or(0));
    let end = data_start
        .saturating_add(len)
        .saturating_add(SPAN_SLACK)
        .min(data.len());
    Some((start, end))
}

fn declared_length(dict: &Dictionary, doc: &Document) -> Option<usize> {
    let value = dict.get(b"Length").ok()?;
    let (_, value) = doc.dereference(value).ok()?;
    usize::try_from(value.as_i64().ok()?).ok()
}

fn normal_offset(doc: &Document, num: u32) -> Option<u64> {
    match doc.reference_table.get(num)? {
        XrefEntry::Normal { offset, .. } => Some(u64::from(*offset)),
        _ => None,
    }
}

/// Per-inspection accumulator.
struct Inspection<'p> {
    parent: &'p str,
    depth: usize,
    data: &'p [u8],
    base: usize,
    deadline: Instant,
    issues: Issues,
    reports: Vec<ScanReport>,
    threats: Vec<Threat>,
    /// Spans of all inspected streams (coverage of `endstream` keywords).
    covered: Vec<(usize, usize)>,
    covered_starts: BTreeSet<usize>,
    /// Spans whose content was recursively scanned (container-magic masking).
    scanned: Vec<(usize, usize)>,
    streams: usize,
    raw_images: usize,
    embedded: usize,
    revisions: usize,
}

impl Inspection<'_> {
    fn cover(&mut self, span: (usize, usize), recursed: bool) {
        self.covered.push(span);
        self.covered_starts.insert(span.0);
        if recursed {
            self.scanned.push(span);
        }
    }
}

impl EmailScanner<'_> {
    /// Inspects a PDF whose header starts at `base`.
    pub(super) fn inspect_pdf(
        &self,
        data: &[u8],
        base: usize,
        parent: &str,
        tracker: &mut ResourceTracker,
        depth: usize,
    ) -> Result<PdfInspection, ScanError> {
        tracker.check_depth(depth)?;
        let limits = tracker.limits();
        let remaining_ms = limits
            .max_scan_duration_ms
            .saturating_sub(tracker.elapsed_millis());
        let mut ctx = Inspection {
            parent,
            depth,
            data,
            base,
            deadline: Instant::now() + Duration::from_millis(remaining_ms),
            issues: Issues::default(),
            reports: Vec::new(),
            threats: Vec::new(),
            covered: Vec::new(),
            covered_starts: BTreeSet::new(),
            scanned: Vec::new(),
            streams: 0,
            raw_images: 0,
            embedded: 0,
            revisions: 0,
        };

        if let Some(doc) = self.load_revision(&data[base..], tracker, &mut ctx, true)? {
            let encrypted = doc.encryption_state.is_some();
            self.inspect_streams(&doc, encrypted, None, tracker, &mut ctx)?;
            self.scan_strings(&doc, tracker, &mut ctx)?;
            self.cover_revisions(tracker, &mut ctx)?;
        }

        tracing::debug!(
            target: "raxosentinel::pdf",
            parent,
            streams = ctx.streams,
            raw_images = ctx.raw_images,
            embedded = ctx.embedded,
            revisions = ctx.revisions,
            "PDF inspection finished"
        );
        Ok(PdfInspection {
            reports: ctx.reports,
            threats: ctx.threats,
            issue: ctx.issues.into_issue(),
            scanned_spans: ctx.scanned,
        })
    }

    /// Loads and validates one revision. Returns `None` when nothing can be inspected.
    fn load_revision(
        &self,
        bytes: &[u8],
        tracker: &mut ResourceTracker,
        ctx: &mut Inspection<'_>,
        latest: bool,
    ) -> Result<Option<Document>, ScanError> {
        tracker.check_timeout()?;
        let limits = tracker.limits();
        let remaining = limits
            .max_total_extracted_bytes
            .saturating_sub(tracker.total_extracted_bytes());
        let state = LoadState {
            deadline: ctx.deadline,
            objstm_cap: limits.max_email_attachment_size.min(remaining) as usize,
            objstm_remaining: remaining.min(MAX_OBJSTM_TOTAL),
            objstm_bytes: 0,
            objects: 0,
            abort: None,
            issues: Issues::default(),
            objstms: Vec::new(),
        };
        let (result, state) = load_document(bytes, state);
        ctx.revisions += 1;
        let LoadState {
            abort,
            issues,
            objstms,
            objstm_bytes,
            ..
        } = state;
        match abort {
            Some(Abort::Timeout) => {
                tracker.check_timeout()?;
                return Err(ScanError::Timeout {
                    duration_ms: tracker.elapsed_millis(),
                });
            }
            Some(Abort::Limit(message)) => {
                if latest {
                    ctx.issues.failed(message);
                }
                return Ok(None);
            }
            None => {}
        }
        let mut doc = match result {
            Ok(doc) => doc,
            Err(message) => {
                if latest {
                    let (code, message) = message.split_once('\u{0}').unwrap_or((CODE_PARSE, ""));
                    if code == CODE_LIMIT {
                        ctx.issues.failed(message);
                    } else {
                        ctx.issues
                            .unsupported(code, format!("PDF structure not inspected: {message}"));
                    }
                }
                return Ok(None);
            }
        };
        tracker.check_timeout()?;
        if latest {
            ctx.issues.merge(issues);
            if doc.trailer.has(b"Encrypt") {
                ctx.issues.unsupported(
                    CODE_ENCRYPTED,
                    "encrypted PDF requires a password; content not inspected",
                );
                return Ok(None);
            }
        } else if doc.trailer.has(b"Encrypt") {
            return Ok(None);
        }
        if let Err(e) = tracker.record_extracted_bytes(objstm_bytes as usize) {
            match e {
                ScanError::Timeout { .. } => return Err(e),
                e => {
                    ctx.issues.failed(format!("object streams: {e}"));
                    return Ok(None);
                }
            }
        }

        // lopdf expands object streams of encrypted documents itself.
        if doc.objects.len() > MAX_OBJECTS {
            if latest {
                ctx.issues
                    .failed(format!("more than {MAX_OBJECTS} indirect objects"));
            }
            return Ok(None);
        }
        let consumed: BTreeSet<u32> = objstms.iter().map(|o| o.id.0).collect();
        // Object-stream contents are scanned as data, and their members joined to the
        // document only where the current cross-reference data assigns them.
        let mut stale: Vec<Object> = Vec::new();
        for objstm in objstms {
            let container = objstm.id.0;
            let span = normal_offset(&doc, container).and_then(|offset| {
                stream_span(
                    ctx.data,
                    ctx.base,
                    offset,
                    objstm.raw_len,
                    objstm.declared_len,
                )
            });
            // In earlier revisions, only object streams not inspected already.
            let fresh = latest || span.is_some_and(|(s, _)| !ctx.covered_starts.contains(&s));
            for (num, object) in objstm.members {
                let assigned = matches!(
                    doc.reference_table.get(num),
                    Some(XrefEntry::Compressed { container: c, .. }) if *c == container
                );
                if assigned && !doc.objects.contains_key(&(num, 0)) {
                    doc.objects.insert((num, 0), object);
                } else {
                    stale.push(object);
                }
            }
            if fresh {
                ctx.streams += 1;
                let mut recursed = true;
                if !objstm.data.is_empty() {
                    let label =
                        format!("{}/pdf-objstm-{}-{}", ctx.parent, objstm.id.0, objstm.id.1);
                    recursed = self.scan_extracted(&objstm.data, &label, false, tracker, ctx)?;
                }
                if let Some(span) = span {
                    ctx.cover(span, recursed);
                }
            }
        }
        if latest {
            self.scan_string_objects(stale.iter(), tracker, ctx)?;
            check_integrity(&doc, &consumed, &mut ctx.issues);
        }
        Ok(Some(doc))
    }

    /// Decodes and scans every stream of `doc`. With `only`, streams whose span does
    /// not contain one of those positions are skipped (earlier revisions).
    fn inspect_streams(
        &self,
        doc: &Document,
        encrypted: bool,
        only: Option<&[usize]>,
        tracker: &mut ResourceTracker,
        ctx: &mut Inspection<'_>,
    ) -> Result<(), ScanError> {
        for (&id, object) in &doc.objects {
            let Object::Stream(stream) = object else {
                continue;
            };
            let span = normal_offset(doc, id.0).and_then(|offset| {
                stream_span(
                    ctx.data,
                    ctx.base,
                    offset,
                    stream.content.len(),
                    declared_length(&stream.dict, doc),
                )
            });
            if let Some(positions) = only {
                // Earlier revisions: only streams that explain an uncovered `endstream`
                // and were not already inspected at the same offset.
                let relevant = span.is_some_and(|(s, e)| {
                    !ctx.covered_starts.contains(&s) && positions.iter().any(|&p| s <= p && p < e)
                });
                if !relevant {
                    continue;
                }
            }
            tracker.check_timeout()?;
            ctx.streams += 1;
            let recursed = self.inspect_stream(doc, id, stream, encrypted, tracker, ctx)?;
            if let Some(span) = span {
                ctx.cover(span, recursed);
            }
        }
        Ok(())
    }

    /// Returns whether the stream content was recursively scanned.
    fn inspect_stream(
        &self,
        doc: &Document,
        id: ObjectId,
        stream: &Stream,
        encrypted: bool,
        tracker: &mut ResourceTracker,
        ctx: &mut Inspection<'_>,
    ) -> Result<bool, ScanError> {
        let embedded = stream.dict.has_type(b"EmbeddedFile");
        let kind = if embedded { "embedded" } else { "object" };
        let label = format!("{}/pdf-{kind}-{}-{}", ctx.parent, id.0, id.1);
        if stream.dict.has(b"F") {
            ctx.issues.unsupported(
                CODE_EXTERNAL,
                format!("{label}: stream data is in an external file"),
            );
        }
        let specs = match filter_specs(&stream.dict, Some(doc)) {
            Ok(specs) => specs,
            Err(message) => {
                ctx.issues
                    .unsupported(CODE_FILTER, format!("{label}: {message}"));
                return Ok(false);
            }
        };
        let limits = tracker.limits();
        let cap = limits.max_email_attachment_size.min(
            limits
                .max_total_extracted_bytes
                .saturating_sub(tracker.total_extracted_bytes()),
        ) as usize;
        let budget = Budget {
            cap,
            deadline: ctx.deadline,
        };
        let content = match pdf_decode::decode_chain(&stream.content, &specs, budget) {
            Ok(decoded) => {
                // Image data left in its codec, unchanged from the file bytes that the
                // enclosing scan has already matched, is not scanned twice.
                if decoded.image_codec.is_some() && decoded.applied == 0 && !encrypted && !embedded
                {
                    ctx.raw_images += 1;
                    return Ok(false);
                }
                decoded.data
            }
            Err(failure) => {
                let message = format!("{label}: {}", failure.message);
                match failure.kind {
                    FailureKind::Timeout => {
                        tracker.check_timeout()?;
                        return Err(ScanError::Timeout {
                            duration_ms: tracker.elapsed_millis(),
                        });
                    }
                    FailureKind::Limit => ctx.issues.failed(message),
                    FailureKind::Unsupported => ctx.issues.unsupported(CODE_FILTER, message),
                    FailureKind::Malformed => ctx.issues.unsupported(CODE_DECODE, message),
                }
                failure.partial
            }
        };
        if embedded {
            ctx.embedded += 1;
            if let Err(e) = tracker.register_attachment(content.len() as u64) {
                return match e {
                    ScanError::Timeout { .. } => Err(e),
                    e => {
                        ctx.issues.failed(format!("{label}: {e}"));
                        Ok(false)
                    }
                };
            }
        }
        if content.is_empty() {
            return Ok(true);
        }
        self.scan_extracted(&content, &label, embedded, tracker, ctx)
    }

    /// Accounts for and recursively scans extracted bytes.
    fn scan_extracted(
        &self,
        content: &[u8],
        label: &str,
        keep: bool,
        tracker: &mut ResourceTracker,
        ctx: &mut Inspection<'_>,
    ) -> Result<bool, ScanError> {
        if let Err(e) = tracker.record_extracted_bytes(content.len()) {
            return match e {
                ScanError::Timeout { .. } => Err(e),
                e => {
                    ctx.issues.failed(format!("{label}: {e}"));
                    Ok(false)
                }
            };
        }
        match self.scan_object(content, label, None, tracker, ctx.depth) {
            Ok(report) => {
                match report.status {
                    ScanStatus::Failed | ScanStatus::Unsupported => {
                        let message = report
                            .error
                            .clone()
                            .unwrap_or_else(|| report.status_description.clone());
                        ctx.issues.raise(
                            report.status,
                            "PDF_NESTED",
                            format!("{label}: {message}"),
                        );
                    }
                    _ => {}
                }
                let interesting = keep || report.status != ScanStatus::Clean;
                if interesting && ctx.reports.len() < MAX_KEPT_REPORTS {
                    ctx.reports.push(report);
                } else {
                    ctx.threats.extend(report.threats);
                }
                Ok(true)
            }
            Err(e @ ScanError::Timeout { .. }) => Err(e),
            Err(e) => {
                ctx.issues.failed(format!("{label}: scan failed: {e}"));
                Ok(false)
            }
        }
    }

    /// Matches byte patterns against decoded string objects, which may be
    /// escaped, hex-encoded or encrypted in the file.
    fn scan_strings(
        &self,
        doc: &Document,
        tracker: &mut ResourceTracker,
        ctx: &mut Inspection<'_>,
    ) -> Result<(), ScanError> {
        self.scan_string_objects(doc.objects.values(), tracker, ctx)
    }

    fn scan_string_objects<'o>(
        &self,
        objects: impl Iterator<Item = &'o Object>,
        tracker: &mut ResourceTracker,
        ctx: &mut Inspection<'_>,
    ) -> Result<(), ScanError> {
        let location = format!("{}/pdf-strings", ctx.parent);
        let mut buffer: Vec<u8> = Vec::new();
        let mut stack: Vec<&Object> = Vec::new();
        let mut visited = 0usize;
        let flush = |buffer: &mut Vec<u8>, ctx: &mut Inspection<'_>| {
            if !buffer.is_empty() {
                for t in self.db.match_bytes(buffer) {
                    ctx.threats.push(t.with_location(location.clone()));
                }
                buffer.clear();
            }
        };
        for root in objects {
            stack.push(root);
            while let Some(object) = stack.pop() {
                visited += 1;
                if visited.is_multiple_of(4096) {
                    tracker.check_timeout()?;
                }
                let bytes = match object {
                    Object::String(bytes, _) => bytes,
                    Object::Array(items) => {
                        stack.extend(items.iter());
                        continue;
                    }
                    Object::Dictionary(dict) => {
                        stack.extend(dict.iter().map(|(_, v)| v));
                        continue;
                    }
                    Object::Stream(stream) => {
                        stack.extend(stream.dict.iter().map(|(_, v)| v));
                        continue;
                    }
                    _ => continue,
                };
                if bytes.len() >= MIN_STRING_LEN {
                    buffer.extend_from_slice(bytes);
                    buffer.push(b'\n');
                    if buffer.len() >= STRING_FLUSH {
                        flush(&mut buffer, ctx);
                    }
                }
            }
        }
        flush(&mut buffer, ctx);
        Ok(())
    }

    /// Requires every `endstream` keyword in the file to belong to an inspected
    /// stream, loading earlier incremental revisions for streams the latest
    /// revision no longer references.
    fn cover_revisions(
        &self,
        tracker: &mut ResourceTracker,
        ctx: &mut Inspection<'_>,
    ) -> Result<(), ScanError> {
        let data = ctx.data;
        let mut uncovered = uncovered_positions(data, &ctx.covered);
        if uncovered.is_empty() {
            return Ok(());
        }
        let eofs: Vec<usize> = memmem::find_iter(&data[ctx.base..], b"%%EOF")
            .map(|p| ctx.base + p + 5)
            .collect();
        let mut loads = 0usize;
        for &end in eofs.iter().rev() {
            if uncovered.is_empty() || loads >= MAX_REVISIONS {
                break;
            }
            // Only prefixes that end before the trailing data and contain an
            // unexplained stream can help.
            if end + 2 >= data.len() || !uncovered.iter().any(|&p| p < end) {
                continue;
            }
            loads += 1;
            let Some(doc) = self.load_revision(&data[ctx.base..end], tracker, ctx, false)? else {
                continue;
            };
            let encrypted = doc.encryption_state.is_some();
            let targets: Vec<usize> = uncovered.iter().copied().filter(|&p| p < end).collect();
            self.inspect_streams(&doc, encrypted, Some(&targets), tracker, ctx)?;
            uncovered = uncovered_positions(data, &ctx.covered);
        }
        if let Some(&first) = uncovered.first() {
            ctx.issues.unsupported(
                CODE_UNREFERENCED,
                format!(
                    "{} stream(s) not referenced by any loadable revision (first ends at byte {first})",
                    uncovered.len()
                ),
            );
        }
        Ok(())
    }
}

fn uncovered_positions(data: &[u8], covered: &[(usize, usize)]) -> Vec<usize> {
    let mut spans = covered.to_vec();
    spans.sort_unstable();
    // Merge into disjoint, sorted ranges and test with a single pass.
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (s, e) in spans {
        match merged.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => merged.push((s, e)),
        }
    }
    let mut out = Vec::new();
    let mut idx = 0usize;
    for pos in memmem::find_iter(data, b"endstream") {
        while idx < merged.len() && merged[idx].1 <= pos {
            idx += 1;
        }
        if !(idx < merged.len() && merged[idx].0 <= pos) {
            out.push(pos);
        }
    }
    out
}

/// Every object the cross-reference data declares must have been loaded.
fn check_integrity(doc: &Document, consumed: &BTreeSet<u32>, issues: &mut Issues) {
    let encrypt_id = doc
        .encryption_state
        .as_ref()
        .and_then(|state| state.encrypt_object_id());
    let mut missing = 0usize;
    let mut first: Option<u32> = None;
    for (&num, entry) in &doc.reference_table.entries {
        let present = match entry {
            XrefEntry::Normal { .. } => {
                consumed.contains(&num)
                    || encrypt_id.is_some_and(|id| id.0 == num)
                    || doc
                        .objects
                        .range((num, 0)..=(num, u16::MAX))
                        .next()
                        .is_some()
            }
            XrefEntry::Compressed { .. } => doc.objects.contains_key(&(num, 0)),
            _ => true,
        };
        if !present {
            missing += 1;
            first.get_or_insert(num);
        }
    }
    if let Some(first) = first {
        issues.unsupported(
            CODE_UNREADABLE,
            format!("{missing} declared object(s) could not be read (first: object {first})"),
        );
    }
}
