// RaxoSentinel - Email and file malware scanning engine
// Copyright (C) 2026 RaxoSentinel Contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! Bounded inspection of extracted objects (decoded PDF streams, archive members).
//!
//! An [`Extractor`] receives an object's bytes in chunks. While the object fits in
//! its buffer limit it is held in memory and later gets full recursive inspection
//! (`scan_object`), charged to `max_total_extracted_bytes`. When it outgrows the
//! limit it switches to *streaming mode*: the buffered prefix and every later chunk
//! go through a [`StreamMatcher`] (byte patterns across chunk boundaries,
//! incremental hashes, optional YARA-X block scan) and an embedded-container
//! scanner, and are then discarded. Streamed bytes are charged to
//! `max_streamed_object_bytes` (per object) and `max_total_streamed_bytes` (per
//! scan). A streamed object that is itself a container, or that contains a
//! recognisable container, cannot be inspected recursively and is never CLEAN.

use super::pdf_decode::{ChunkSink, DecodeFailure, FailureKind};
use raxosentinel_core::{ResourceTracker, ScanError, ScanReport, ScanStatus, TargetMetadata};
use raxosentinel_signatures::{SignatureDatabase, StreamMatcher};

/// Bytes after a candidate magic needed by the container validators.
const LOOKAHEAD: usize = 64;
/// Streamed-object prefix kept for format identification.
const HEAD_BYTES: usize = 4096;
/// Diagnostic code: a streamed object is a container too large to unpack.
pub(crate) const CODE_STREAM_CONTAINER: &str = "STREAM_CONTAINER_TOO_LARGE";
/// Diagnostic code: a streamed object contains an embedded container signature.
pub(crate) const CODE_STREAM_EMBEDDED: &str = "STREAM_EMBEDDED_CONTAINER";

/// Result of feeding an object through an [`Extractor`].
pub(crate) enum Extracted {
    /// Complete object held in memory, not yet charged or scanned.
    Buffered(Vec<u8>),
    /// Object inspected in streaming mode.
    Streamed(StreamedObject),
}

pub(crate) struct StreamedObject {
    pub threats: Vec<raxosentinel_core::Threat>,
    /// `None` when the object was incomplete (never hash-compared).
    pub sha256: Option<String>,
    pub bytes: u64,
    /// Why the object cannot be considered completely inspected, if so.
    pub issue: Option<(ScanStatus, String)>,
}

impl StreamedObject {
    /// Builds a sub-report for the streamed object.
    pub fn report(&self, label: &str, duration_ms: u64) -> ScanReport {
        let status = if !self.threats.is_empty() {
            ScanStatus::Infected
        } else {
            self.issue
                .as_ref()
                .map(|(s, _)| *s)
                .unwrap_or(ScanStatus::Clean)
        };
        ScanReport::new(
            TargetMetadata {
                path: None,
                file_name: Some(label.to_string()),
                file_size_bytes: self.bytes,
                sha256: self.sha256.clone().unwrap_or_default(),
                detected_mime: "application/octet-stream".to_string(),
                declared_mime: None,
            },
            status,
            self.threats.clone(),
            Vec::new(),
            duration_ms,
            self.issue.as_ref().map(|(_, m)| m.clone()),
        )
    }
}

/// Chunk sink implementing the buffer-then-stream policy.
pub(crate) struct Extractor<'a, 't> {
    db: &'a SignatureDatabase,
    tracker: &'t mut ResourceTracker,
    buffer_limit: usize,
    buf: Vec<u8>,
    stream: Option<Streaming<'a>>,
    /// Hard error (resource budget, timeout) that aborted streaming.
    error: Option<ScanError>,
}

struct Streaming<'a> {
    matcher: StreamMatcher<'a>,
    head: Vec<u8>,
    magic: MagicScanner,
}

impl<'a, 't> Extractor<'a, 't> {
    /// `buffer_limit` is the most this object may hold in memory; it is further
    /// bounded by the remaining extracted-bytes budget.
    pub fn new(
        db: &'a SignatureDatabase,
        tracker: &'t mut ResourceTracker,
        buffer_limit: u64,
    ) -> Self {
        let limits = tracker.limits();
        let remaining = limits
            .max_total_extracted_bytes
            .saturating_sub(tracker.total_extracted_bytes());
        let buffer_limit = buffer_limit
            .min(limits.max_buffered_object_bytes)
            .min(remaining) as usize;
        Self {
            db,
            tracker,
            buffer_limit,
            buf: Vec::new(),
            stream: None,
            error: None,
        }
    }

    fn fail(&mut self, e: ScanError) -> DecodeFailure {
        let e = match e {
            ScanError::Timeout { .. } => self.tracker.timeout_error(),
            other => other,
        };
        let kind = match e {
            ScanError::Timeout { .. } => FailureKind::Timeout,
            _ => FailureKind::Limit,
        };
        let failure = DecodeFailure::new(kind, e.to_string());
        self.error = Some(e);
        failure
    }

    fn begin_streaming(&mut self) {
        self.stream = Some(Streaming {
            matcher: self.db.stream_matcher(),
            head: Vec::with_capacity(HEAD_BYTES),
            magic: MagicScanner::default(),
        });
    }

    fn stream_bytes(&mut self, data: &[u8]) -> Result<(), DecodeFailure> {
        let max = self.tracker.limits().max_streamed_object_bytes;
        let stream = self.stream.as_mut().expect("streaming mode");
        if stream.matcher.bytes() + data.len() as u64 > max {
            let e = ScanError::ExtractedSizeLimitExceeded {
                limit: max,
                current: stream.matcher.bytes() + data.len() as u64,
            };
            return Err(self.fail(e));
        }
        if let Err(e) = self.tracker.record_streamed_bytes(data.len()) {
            return Err(self.fail(e));
        }
        let remaining = self.tracker.remaining();
        let stream = self.stream.as_mut().expect("streaming mode");
        if stream.head.len() < HEAD_BYTES {
            let take = (HEAD_BYTES - stream.head.len()).min(data.len());
            stream.head.extend_from_slice(&data[..take]);
        }
        stream.magic.update(data);
        if let Err(e) = stream.matcher.update(data, remaining) {
            return Err(self.fail(e));
        }
        Ok(())
    }

    /// Finishes the object. `complete` is false when decoding/extraction failed.
    pub fn finish(mut self, complete: bool) -> Result<Extracted, ScanError> {
        if let Some(e) = self.error.take() {
            return Err(e);
        }
        // Incomplete objects are never hash-compared or unpacked, even when small:
        // they get pattern/YARA matching only.
        if !complete && self.stream.is_none() {
            self.begin_streaming();
            let prefix = std::mem::take(&mut self.buf);
            if self.stream_bytes(&prefix).is_err() {
                return Err(self
                    .error
                    .take()
                    .unwrap_or_else(|| ScanError::Internal("streaming failed".into())));
            }
        }
        let Some(stream) = self.stream.take() else {
            return Ok(Extracted::Buffered(std::mem::take(&mut self.buf)));
        };
        let embedded = stream.magic.finish();
        let outcome = stream
            .matcher
            .finish(complete, self.tracker.remaining())
            .map_err(|e| match e {
                ScanError::Timeout { .. } => self.tracker.timeout_error(),
                other => other,
            })?;
        let head_kind = super::container_head(&stream.head);
        let issue = if let (Some(kind), false) = (head_kind, complete) {
            Some((
                ScanStatus::Unsupported,
                format!(
                    "{CODE_STREAM_CONTAINER}: incomplete {kind} object of {} bytes cannot be \
                     inspected recursively",
                    outcome.bytes
                ),
            ))
        } else if let Some(kind) = head_kind {
            Some((
                ScanStatus::Failed,
                format!(
                    "{CODE_STREAM_CONTAINER}: {kind} object of {} bytes exceeds the {}-byte \
                     in-memory limit for recursive inspection",
                    outcome.bytes, self.buffer_limit
                ),
            ))
        } else {
            embedded.map(|(kind, offset)| {
                (
                    ScanStatus::Unsupported,
                    format!(
                        "{CODE_STREAM_EMBEDDED}: possible embedded {kind} at offset {offset} \
                         of a streamed object; contents not inspected"
                    ),
                )
            })
        };
        Ok(Extracted::Streamed(StreamedObject {
            threats: outcome.threats,
            sha256: outcome.sha256,
            bytes: outcome.bytes,
            issue,
        }))
    }
}

impl ChunkSink for Extractor<'_, '_> {
    fn write(&mut self, data: &[u8]) -> Result<(), DecodeFailure> {
        if data.is_empty() {
            return Ok(());
        }
        if let Err(e) = self.tracker.check_timeout() {
            return Err(self.fail(e));
        }
        if self.stream.is_none() {
            if self.buf.len() + data.len() <= self.buffer_limit {
                if self.buf.try_reserve(data.len()).is_err() {
                    return Err(self.fail(ScanError::Internal(
                        "cannot allocate extraction buffer".into(),
                    )));
                }
                self.buf.extend_from_slice(data);
                return Ok(());
            }
            // Switch to streaming mode: the buffered prefix is inspected and freed.
            self.begin_streaming();
            let prefix = std::mem::take(&mut self.buf);
            self.stream_bytes(&prefix)?;
        }
        self.stream_bytes(data)
    }
}

/// Finds validated embedded-container signatures across chunk boundaries. Holds at
/// most one chunk plus a small lookahead.
#[derive(Default)]
struct MagicScanner {
    pending: Vec<u8>,
    /// Absolute offset of `pending[0]`.
    base: u64,
    found: Option<(&'static str, u64)>,
}

impl MagicScanner {
    fn update(&mut self, data: &[u8]) {
        if self.found.is_some() {
            return;
        }
        self.pending.extend_from_slice(data);
        if self.pending.len() > LOOKAHEAD {
            let limit = self.pending.len() - LOOKAHEAD;
            self.check(limit);
            self.pending.drain(..limit);
            self.base += limit as u64;
        }
    }

    /// Checks candidate positions below `limit` (each has full lookahead).
    fn check(&mut self, limit: usize) {
        if self.found.is_some() {
            return;
        }
        for (magic, kind, valid) in super::streamed_container_candidates() {
            let hit = memchr::memmem::find_iter(&self.pending, magic)
                .take_while(|&pos| pos < limit)
                .find(|&pos| valid(&self.pending[pos..]));
            if let Some(pos) = hit {
                let offset = self.base + pos as u64;
                if self.found.is_none_or(|(_, o)| offset < o) {
                    self.found = Some((kind, offset));
                }
            }
        }
    }

    fn finish(mut self) -> Option<(&'static str, u64)> {
        let len = self.pending.len();
        self.check(len);
        self.found
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxosentinel_core::ResourceLimits;

    fn feed(ex: &mut Extractor<'_, '_>, data: &[u8], chunk: usize) {
        for c in data.chunks(chunk) {
            ex.write(c).unwrap();
        }
    }

    #[test]
    fn small_objects_are_buffered_large_ones_streamed() {
        let db = SignatureDatabase::with_defaults();
        let mut tracker = ResourceTracker::new(ResourceLimits::default());
        let mut ex = Extractor::new(&db, &mut tracker, 1000);
        feed(&mut ex, &[7u8; 1000], 100);
        assert!(matches!(ex.finish(true).unwrap(), Extracted::Buffered(b) if b.len() == 1000));

        let mut ex = Extractor::new(&db, &mut tracker, 1000);
        let mut data = vec![b'.'; 5000];
        data[2990..3027].copy_from_slice(b"RAXOSENTINEL-SYNTHETIC-TEST-SIGNATURE");
        feed(&mut ex, &data, 333);
        let Extracted::Streamed(s) = ex.finish(true).unwrap() else {
            panic!("expected streaming");
        };
        assert_eq!(s.bytes, 5000);
        assert!(s.sha256.is_some());
        assert!(!s.threats.is_empty());
        assert!(s.issue.is_none());
        assert_eq!(tracker.total_streamed_bytes(), 5000);
        assert_eq!(tracker.total_extracted_bytes(), 0);
    }

    #[test]
    fn streamed_containers_are_never_clean() {
        let db = SignatureDatabase::with_defaults();
        let mut tracker = ResourceTracker::new(ResourceLimits::default());
        // A ZIP that is too large to buffer.
        let mut zip = b"PK\x03\x04\x14\x00\x00\x00\x08\x00".to_vec();
        zip.resize(5000, 0);
        let mut ex = Extractor::new(&db, &mut tracker, 100);
        feed(&mut ex, &zip, 64);
        let Extracted::Streamed(s) = ex.finish(true).unwrap() else {
            panic!()
        };
        assert_eq!(s.issue.as_ref().unwrap().0, ScanStatus::Failed);
        // An embedded 7-Zip signature split across chunks.
        let mut data = vec![0u8; 5000];
        data[3000..3007].copy_from_slice(b"7z\xbc\xaf\x27\x1c\x00");
        let mut ex = Extractor::new(&db, &mut tracker, 100);
        feed(&mut ex, &data, 3003);
        let Extracted::Streamed(s) = ex.finish(true).unwrap() else {
            panic!()
        };
        let (status, msg) = s.issue.unwrap();
        assert_eq!(status, ScanStatus::Unsupported);
        assert!(msg.contains("7-Zip") && msg.contains("3000"), "{msg}");
    }

    #[test]
    fn streaming_budgets_are_enforced() {
        let db = SignatureDatabase::with_defaults();
        let limits = ResourceLimits {
            max_streamed_object_bytes: 4000,
            max_total_streamed_bytes: 6000,
            ..Default::default()
        };
        let mut tracker = ResourceTracker::new(limits);
        let mut ex = Extractor::new(&db, &mut tracker, 10);
        let err = [0u8; 5000]
            .chunks(1000)
            .find_map(|c| ex.write(c).err())
            .unwrap();
        assert_eq!(err.kind, FailureKind::Limit);
        assert!(ex.finish(false).is_err());
        let mut ex = Extractor::new(&db, &mut tracker, 10);
        let err = [0u8; 4000]
            .chunks(1000)
            .find_map(|c| ex.write(c).err())
            .unwrap();
        assert_eq!(err.kind, FailureKind::Limit);
    }
}
