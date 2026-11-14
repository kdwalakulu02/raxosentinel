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

use mail_parser::{Message, MessageParser, MessagePart};
use raxosentinel_core::report::MAX_INCOMPLETE_REASONS;
use raxosentinel_core::{
    hash_bytes, ObjectKind, ResourceTracker, ScanError, ScanReport, ScanStatus, TargetMetadata,
    Threat,
};
use raxosentinel_filetypes::{check_extension_mismatch, detect_type, is_tar_header};
use raxosentinel_signatures::content::Target;
use raxosentinel_signatures::SignatureDatabase;
use std::path::Path;

/// Scanner dedicated to RFC 822 and MIME email messages, parts, and attachments.
pub struct EmailScanner<'a> {
    db: &'a SignatureDatabase,
}

impl<'a> EmailScanner<'a> {
    pub fn new(db: &'a SignatureDatabase) -> Self {
        Self { db }
    }

    /// Scans an email message from a byte slice.
    pub fn scan_bytes(
        &self,
        raw_bytes: &[u8],
        path_hint: Option<&str>,
        tracker: &mut ResourceTracker,
    ) -> Result<ScanReport, ScanError> {
        tracker.check_file_size(raw_bytes.len() as u64)?;
        tracker.record_bytes_read(raw_bytes.len())?;
        self.scan_internal(raw_bytes, path_hint, tracker, 0)
    }

    /// Scans an email message from a file on disk.
    pub fn scan_file(
        &self,
        path: &Path,
        tracker: &mut ResourceTracker,
    ) -> Result<ScanReport, ScanError> {
        let metadata = std::fs::metadata(path).map_err(|e| ScanError::IoWithPath {
            path: path.to_path_buf(),
            source: e,
        })?;

        if !metadata.is_file() {
            return Err(ScanError::UnsupportedFormat(format!(
                "Target '{}' is not a regular file",
                path.display()
            )));
        }

        tracker.check_file_size(metadata.len())?;
        use std::io::Read;
        let mut file = std::fs::File::open(path).map_err(|e| ScanError::IoWithPath {
            path: path.to_path_buf(),
            source: e,
        })?;
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 64 * 1024];
        loop {
            tracker.check_timeout()?;
            let n = file.read(&mut chunk).map_err(|e| ScanError::IoWithPath {
                path: path.to_path_buf(),
                source: e,
            })?;
            if n == 0 {
                break;
            }
            tracker.record_bytes_read(n)?;
            bytes
                .try_reserve(n)
                .map_err(|_| ScanError::Internal("Cannot allocate email buffer".into()))?;
            bytes.extend_from_slice(&chunk[..n]);
        }

        self.scan_internal(&bytes, path.to_str(), tracker, 0)
    }

    fn scan_internal(
        &self,
        raw_bytes: &[u8],
        path_hint: Option<&str>,
        tracker: &mut ResourceTracker,
        depth: usize,
    ) -> Result<ScanReport, ScanError> {
        let start_ms = tracker.elapsed_millis();
        tracker.check_depth(depth)?;
        tracker.check_timeout()?;

        let sha256 = hash_bytes(raw_bytes);
        let detected_type = detect_type(raw_bytes);

        // Parse MIME message structure with limits
        let parser = MessageParser::new()
            .max_depth(tracker.limits().max_email_depth)
            .max_parts(tracker.limits().max_email_attachments + 10);

        let parsed = match parser.parse(raw_bytes) {
            Some(msg) => msg,
            None => {
                // If it's unparseable as MIME, check raw threat signatures first (Infected > Unsupported)
                let mut unparsed_threats: Vec<Threat> = Vec::new();
                if let Some(hash_threat) = self.db.match_hash(&sha256) {
                    unparsed_threats.push(hash_threat.with_location("email_root"));
                }
                for t in self.db.match_rsidb(raw_bytes) {
                    unparsed_threats.push(t.with_location("email_root"));
                }
                for t in self.db.match_bytes(raw_bytes) {
                    unparsed_threats.push(t.with_location("email_root"));
                }
                for t in self.db.match_content(raw_bytes).0 {
                    unparsed_threats.push(t.with_location("email_root"));
                }

                let duration_ms = tracker.elapsed_millis().saturating_sub(start_ms);
                let (status, details) = if !unparsed_threats.is_empty() {
                    (ScanStatus::Infected, None)
                } else {
                    (
                        ScanStatus::Unsupported,
                        Some("Malformed or corrupted MIME message format".to_string()),
                    )
                };

                return Ok(ScanReport::new(
                    TargetMetadata {
                        path: path_hint.map(|s| s.to_string()),
                        file_name: path_hint
                            .and_then(|p| Path::new(p).file_name())
                            .map(|n| n.to_string_lossy().to_string()),
                        file_size_bytes: raw_bytes.len() as u64,
                        sha256,
                        detected_mime: detected_type.mime_type,
                        declared_mime: Some("message/rfc822".to_string()),
                    },
                    status,
                    unparsed_threats,
                    Vec::new(),
                    duration_ms,
                    details,
                ));
            }
        };

        // Validate MIME container boundary integrity
        let (container_status, container_details) =
            match validate_mime_boundaries(raw_bytes, &parsed) {
                Ok(()) => (ScanStatus::Clean, None),
                Err(err) => (ScanStatus::Unsupported, Some(err)),
            };

        let mut threats: Vec<Threat> = Vec::new();
        let mut ex = Extraction::default();

        // 1. Check raw email hash (builtin rules and RSIDB)
        if let Some(hash_threat) = self.db.match_hash(&sha256) {
            threats.push(hash_threat.with_location("email_root"));
        }
        for t in self.db.match_rsidb(raw_bytes) {
            threats.push(t.with_location("email_root"));
        }
        let (mail_threats, mail_partial) = self.db.match_content_as(raw_bytes, Target::Mail);
        for t in mail_threats {
            threats.push(t.with_location("email_root"));
        }
        if mail_partial {
            ex.partial(CONTENT_BUDGET_REASON);
        }

        // 2. Scan email bodies (text and html)
        self.scan_bodies(&parsed, &mut threats, &mut ex, tracker)?;

        // 3. Scan attachments and embedded parts (including inline payloads)
        self.scan_attachments(raw_bytes, &parsed, &mut threats, &mut ex, tracker, depth)?;
        let sub_reports = ex.reports;

        // Consolidate duplicate threats across bodies or attachments
        let threats = SignatureDatabase::deduplicate_threats(threats);

        let has_threats =
            !threats.is_empty() || sub_reports.iter().any(|r| r.status == ScanStatus::Infected);

        // Critical verdict semantics:
        // Status precedence: Infected > Failed > Unsupported > Clean
        let (overall_status, overall_details) = if has_threats {
            (ScanStatus::Infected, None)
        } else if container_status == ScanStatus::Failed
            || sub_reports.iter().any(|r| r.status == ScanStatus::Failed)
        {
            let details = if container_status == ScanStatus::Failed {
                container_details
            } else {
                sub_reports
                    .iter()
                    .find(|r| r.status == ScanStatus::Failed)
                    .and_then(|r| r.error.clone())
            };
            (ScanStatus::Failed, details)
        } else if container_status == ScanStatus::Unsupported
            || sub_reports
                .iter()
                .any(|r| r.status == ScanStatus::Unsupported)
        {
            let details = if container_status == ScanStatus::Unsupported {
                container_details
            } else {
                sub_reports
                    .iter()
                    .find(|r| r.status == ScanStatus::Unsupported)
                    .and_then(|r| r.error.clone())
            };
            (ScanStatus::Unsupported, details)
        } else {
            (ScanStatus::Clean, None)
        };

        let duration_ms = tracker.elapsed_millis().saturating_sub(start_ms);

        Ok(ScanReport::new(
            TargetMetadata {
                path: path_hint.map(|s| s.to_string()),
                file_name: path_hint
                    .and_then(|p| Path::new(p).file_name())
                    .map(|n| n.to_string_lossy().to_string()),
                file_size_bytes: raw_bytes.len() as u64,
                sha256,
                detected_mime: detected_type.mime_type,
                declared_mime: Some("message/rfc822".to_string()),
            },
            overall_status,
            threats,
            sub_reports,
            duration_ms,
            overall_details,
        )
        .with_incomplete(ex.partial))
    }

    fn scan_bodies(
        &self,
        msg: &Message,
        threats: &mut Vec<Threat>,
        ex: &mut Extraction,
        tracker: &ResourceTracker,
    ) -> Result<(), ScanError> {
        tracker.check_timeout()?;

        // Scan text bodies if message has plain text parts or default unlabelled body
        let has_plain_body = msg
            .text_body()
            .any(|p| p.is_content_type("text", "plain") || p.content_type().is_none());
        if has_plain_body {
            for (idx, text) in msg.text_bodies().enumerate() {
                tracker.check_timeout()?;
                let body_bytes = text.as_bytes();
                for t in self.db.match_rsidb(body_bytes) {
                    threats.push(t.with_location(format!("body:text/plain:part_{}", idx)));
                }
                let body_threats = self.db.match_bytes(body_bytes);
                for t in body_threats {
                    threats.push(t.with_location(format!("body:text/plain:part_{}", idx)));
                }
                let (content, partial) = self.db.match_content(body_bytes);
                for t in content {
                    threats.push(t.with_location(format!("body:text/plain:part_{}", idx)));
                }
                if partial {
                    ex.partial(CONTENT_BUDGET_REASON);
                }
            }
        }

        // Scan HTML bodies only if the email actually contained distinct HTML part(s),
        // preventing duplicate scans and duplicate threat reports from mail-parser's synthetic conversion.
        let has_explicit_html = msg.html_body().any(|p| p.is_content_type("text", "html"));
        if has_explicit_html {
            for (idx, html) in msg.html_bodies().enumerate() {
                tracker.check_timeout()?;
                let body_bytes = html.as_bytes();
                for t in self.db.match_rsidb(body_bytes) {
                    threats.push(t.with_location(format!("body:text/html:part_{}", idx)));
                }
                let body_threats = self.db.match_bytes(body_bytes);
                for t in body_threats {
                    threats.push(t.with_location(format!("body:text/html:part_{}", idx)));
                }
                let (content, partial) = self.db.match_content(body_bytes);
                for t in content {
                    threats.push(t.with_location(format!("body:text/html:part_{}", idx)));
                }
                if partial {
                    ex.partial(CONTENT_BUDGET_REASON);
                }
            }
        }

        Ok(())
    }

    fn scan_attachments(
        &self,
        raw_bytes: &[u8],
        msg: &Message,
        threats: &mut Vec<Threat>,
        ex: &mut Extraction,
        tracker: &mut ResourceTracker,
        depth: usize,
    ) -> Result<(), ScanError> {
        // Explicit attachments first, then inline/unclassified non-body parts.
        let parts: Vec<(MessagePart, String)> = msg
            .attachments()
            .enumerate()
            .map(|(i, p)| (p, format!("attachment_{i}")))
            .chain(
                msg.other_parts()
                    .enumerate()
                    .filter(|(_, p)| !p.in_text_body() && !p.in_html_body())
                    .map(|(i, p)| (p, format!("inline_part_{i}"))),
            )
            .collect();

        for (part, fallback_name) in parts {
            tracker.check_timeout()?;
            if tracker.soft_deadline_reached() {
                ex.partial(SOFT_DEADLINE_REASON);
                break;
            }

            let filename = part
                .attachment_name()
                .map(|s| s.to_string())
                .unwrap_or(fallback_name);
            let declared_mime = part
                .content_type()
                .map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("*")));

            // Pre-check estimated decoded length to prevent Base64 / QP memory expansion bomb!
            let estimated_size = part.decoded_len() as u64;
            if let Err(e) = tracker.register_attachment(estimated_size) {
                if !e.is_budget() {
                    return Err(e);
                }
                ex.partial(budget_reason(&e));
                if matches!(e, ScanError::FileSizeLimitExceeded { .. }) {
                    continue;
                }
                break;
            }

            let decoded_data = part.decoded();
            match self.scan_single_attachment(
                &filename,
                declared_mime.as_deref(),
                &part,
                raw_bytes,
                &decoded_data,
                tracker,
                depth,
            ) {
                Ok(sub_report) => {
                    threats.extend(sub_report.threats.iter().cloned());
                    ex.reports.push(sub_report);
                }
                Err(e @ ScanError::Timeout { .. }) => return Err(e),
                Err(e) if e.is_budget() => ex.partial(budget_reason(&e)),
                Err(e) => ex.reports.push(ScanReport::new(
                    TargetMetadata {
                        path: None,
                        file_name: Some(filename),
                        file_size_bytes: decoded_data.len() as u64,
                        sha256: hash_bytes(&decoded_data),
                        detected_mime: detect_type(&decoded_data).mime_type,
                        declared_mime,
                    },
                    ScanStatus::Failed,
                    Vec::new(),
                    Vec::new(),
                    0,
                    Some(format!("Attachment scan failed: {}", e)),
                )),
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_single_attachment(
        &self,
        filename: &str,
        declared_mime: Option<&str>,
        part: &MessagePart,
        raw_bytes: &[u8],
        data: &[u8],
        tracker: &mut ResourceTracker,
        depth: usize,
    ) -> Result<ScanReport, ScanError> {
        let start_ms = tracker.elapsed_millis();
        tracker.check_timeout()?;

        let detected_type = detect_type(data);

        // Check if this part is a nested email message
        if part.is_message() || detected_type.mime_type == "message/rfc822" {
            // Recursive scan with increased depth
            return self.scan_internal(data, Some(filename), tracker, depth + 1);
        }

        // Full object inspection (builtin hashes, RSIDB, patterns, containers).
        let report = self.scan_object(data, filename, declared_mime, tracker, depth)?;

        // Validate encoding integrity: an encoding issue prevents a Clean verdict.
        if report.status == ScanStatus::Clean {
            if let Some(issue) = validate_attachment_encoding(part, raw_bytes, data).err() {
                let duration_ms = tracker.elapsed_millis().saturating_sub(start_ms);
                let incomplete = report.incomplete.clone();
                return Ok(ScanReport::new(
                    report.target,
                    ScanStatus::Unsupported,
                    report.threats,
                    report.sub_targets,
                    duration_ms,
                    Some(issue),
                )
                .with_incomplete(incomplete));
            }
        }
        Ok(report)
    }

    /// Scans one complete, already-extracted object (raw file, decoded attachment or
    /// archive member): extension mismatch, builtin SHA-256 rules, RSIDB exact-hash
    /// lookups, byte patterns, and bounded recursion into supported containers.
    ///
    /// Verdict precedence: Infected > Failed > Unsupported > Clean. Content that cannot
    /// be inspected for structural reasons (encryption, unsupported formats) is never
    /// Clean. Content skipped only because a resource budget ran out keeps the verdict
    /// of what was inspected and is listed in `incomplete`.
    pub fn scan_object(
        &self,
        data: &[u8],
        filename: &str,
        declared_mime: Option<&str>,
        tracker: &mut ResourceTracker,
        depth: usize,
    ) -> Result<ScanReport, ScanError> {
        let start_ms = tracker.elapsed_millis();
        tracker.check_depth(depth)?;

        let sha256 = hash_bytes(data);
        let detected_type = detect_type(data);

        if depth > 0 && detected_type.mime_type == "message/rfc822" {
            return self.scan_internal(data, Some(filename), tracker, depth + 1);
        }

        let location = format!("attachment:{}", filename);
        let mut threats: Vec<Threat> = Vec::new();
        if let Some(mismatch) = check_extension_mismatch(filename, &detected_type) {
            threats.push(mismatch);
        }
        if let Some(t) = self.db.match_hash(&sha256) {
            threats.push(t.with_location(location.clone()));
        }
        for t in self.db.match_rsidb(data) {
            threats.push(t.with_location(location.clone()));
        }
        for t in self.db.match_bytes(data) {
            threats.push(t.with_location(location.clone()));
        }
        let (content, content_partial) = self.db.match_content(data);
        for t in content {
            threats.push(t.with_location(location.clone()));
        }
        tracker.check_timeout()?;

        let mut ex = match classify_container(data, filename, declared_mime) {
            ContainerKind::Zip => self.scan_zip(data, filename, tracker, depth + 1)?,
            ContainerKind::Gzip => self.scan_gzip(data, filename, tracker, depth + 1)?,
            ContainerKind::Tar => self.scan_tar(data, filename, tracker, depth + 1)?,
            ContainerKind::Unsupported(kind) => {
                let mut ex = Extraction::default();
                ex.raise(
                    ScanStatus::Unsupported,
                    format!("{kind} container cannot be extracted; contents not inspected"),
                );
                ex
            }
            ContainerKind::None => Extraction::default(),
        };

        if content_partial {
            ex.partial(CONTENT_BUDGET_REASON);
        }
        if data.starts_with(b"%PDF-") {
            ex.absorb(self.scan_pdf(data, filename, tracker, depth + 1)?);
        }

        // Recognizable unsupported embedded containers cannot be silently treated
        // as fully inspected, even when the outer object is another format.
        if ex.issue.is_none() {
            tracker.check_timeout()?;
            if let Some(kind) = find_embedded_container(data) {
                ex.raise(
                    ScanStatus::Unsupported,
                    format!(
                        "Embedded {kind} container cannot be extracted; contents not inspected"
                    ),
                );
            }
        }

        for sr in &ex.reports {
            threats.extend(sr.threats.iter().cloned());
        }
        let threats = SignatureDatabase::deduplicate_threats(threats);
        let (status, details) = combine_verdict(&threats, ex.issue, &ex.reports);
        let duration_ms = tracker.elapsed_millis().saturating_sub(start_ms);

        Ok(ScanReport::new(
            TargetMetadata {
                path: None,
                file_name: Some(filename.to_string()),
                file_size_bytes: data.len() as u64,
                sha256,
                detected_mime: detected_type.mime_type,
                declared_mime: declared_mime.map(|s| s.to_string()),
            },
            status,
            threats,
            ex.reports,
            duration_ms,
            details,
        )
        .with_incomplete(ex.partial))
    }

    /// Decodes and scans every PDF stream (full filter chains incl. predictors).
    /// Parsing is lenient so damaged-but-readable documents are still inspected;
    /// only password-protected documents are reported as not inspectable.
    fn scan_pdf(
        &self,
        data: &[u8],
        parent: &str,
        tracker: &mut ResourceTracker,
        depth: usize,
    ) -> Result<Extraction, ScanError> {
        let mut ex = Extraction::default();
        if let Err(e) = tracker.check_depth(depth) {
            ex.budget(e)?;
            return Ok(ex);
        }
        let load = |strict: bool| {
            lopdf::Document::load_mem_with_options(
                data,
                lopdf::LoadOptions {
                    strict,
                    max_decompressed_size: Some(PDF_LOAD_STREAM_LIMIT),
                    ..Default::default()
                },
            )
        };
        let doc = match load(true).or_else(|_| load(false)) {
            Ok(doc) => doc,
            Err(e) => {
                ex.partial(format!(
                    "PDF structure could not be parsed ({}); embedded streams not inspected",
                    short_error(&e.to_string())
                ));
                return Ok(ex);
            }
        };
        tracker.check_timeout()?;
        // An empty user password is tried during loading; only a real password remains.
        if doc.is_encrypted() {
            ex.raise(
                ScanStatus::Unsupported,
                "Password-protected PDF; content not inspected".into(),
            );
            return Ok(ex);
        }

        for (id, object) in &doc.objects {
            let lopdf::Object::Stream(stream) = object else {
                continue;
            };
            tracker.check_timeout()?;
            if tracker.soft_deadline_reached() {
                ex.partial(SOFT_DEADLINE_REASON);
                break;
            }
            if let Err(e) = tracker.register_object(ObjectKind::PdfStream) {
                ex.budget(e)?;
                break;
            }
            let cap = tracker.object_extraction_cap() as usize;
            let bytes = match decode_pdf_stream(stream, cap) {
                Ok(bytes) => bytes,
                Err(PdfDecodeError::Budget) => {
                    ex.partial(oversize_reason(tracker, "Decoded PDF stream"));
                    continue;
                }
                Err(PdfDecodeError::Undecodable(raw, why)) => {
                    ex.partial(format!("PDF stream {why}; raw stream bytes inspected"));
                    raw
                }
            };
            if let Err(e) = tracker.record_extracted_bytes(bytes.len()) {
                ex.budget(e)?;
                break;
            }
            match self.scan_object(
                &bytes,
                &format!("{parent}/pdf-object-{}-{}", id.0, id.1),
                None,
                tracker,
                depth,
            ) {
                // Clean leaf streams carry no information; keep reports bounded.
                Ok(r)
                    if r.status == ScanStatus::Clean
                        && r.threats.is_empty()
                        && r.sub_targets.is_empty()
                        && r.incomplete.is_empty() => {}
                Ok(r) => ex.reports.push(r),
                Err(e) if e.is_budget() => ex.partial(budget_reason(&e)),
                Err(e) => return Err(e),
            }
        }
        Ok(ex)
    }

    /// Inspect each GZIP member independently, preserving exact-hash matching.
    fn scan_gzip(
        &self,
        data: &[u8],
        parent: &str,
        tracker: &mut ResourceTracker,
        depth: usize,
    ) -> Result<Extraction, ScanError> {
        use std::io::Read;
        let mut ex = Extraction::default();
        if let Err(e) = tracker.check_depth(depth) {
            ex.budget(e)?;
            return Ok(ex);
        }
        let mut remaining = data;
        let mut member = 0usize;
        while !remaining.is_empty() {
            tracker.check_timeout()?;
            if !remaining.starts_with(b"\x1f\x8b\x08") {
                // Zero padding after the last member is common and harmless.
                if remaining.iter().any(|&b| b != 0) {
                    ex.raise(
                        ScanStatus::Unsupported,
                        "Uninspected trailing GZIP content".into(),
                    );
                }
                break;
            }
            if tracker.soft_deadline_reached() {
                ex.partial(SOFT_DEADLINE_REASON);
                break;
            }
            if let Err(e) = tracker.register_object(ObjectKind::GzipMember) {
                ex.budget(e)?;
                break;
            }
            let cap = tracker.object_extraction_cap();
            // bufread leaves the following member untouched; read::GzDecoder may over-read.
            let mut decoder = flate2::bufread::GzDecoder::new(remaining);
            let mut buf = Vec::new();
            let mut chunk = [0u8; 65536];
            loop {
                tracker.check_timeout()?;
                match decoder.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        let consumed = remaining.len().saturating_sub(decoder.get_ref().len());
                        let total = (buf.len() as u64).saturating_add(n as u64);
                        if total > cap || total > (consumed as u64).saturating_mul(1000) {
                            ex.partial(
                                "GZIP member exceeds the extraction budget (size or 1000:1 ratio); not inspected",
                            );
                            return Ok(ex);
                        }
                        buf.try_reserve(n).map_err(|_| {
                            ScanError::Internal("Cannot allocate gzip buffer".into())
                        })?;
                        if let Err(e) = tracker.record_extracted_bytes(n) {
                            ex.budget(e)?;
                            return Ok(ex);
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    Err(e) => {
                        ex.raise(
                            ScanStatus::Unsupported,
                            format!("GZIP member not inspected: {e}"),
                        );
                        return Ok(ex);
                    }
                }
            }
            let next = decoder.into_inner();
            if next.len() >= remaining.len() {
                ex.raise(ScanStatus::Failed, "GZIP decoder made no progress".into());
                return Ok(ex);
            }
            match self.scan_object(
                &buf,
                &format!("{parent}/gzip-member-{member}"),
                None,
                tracker,
                depth,
            ) {
                Ok(r) => ex.reports.push(r),
                Err(e) if e.is_budget() => ex.partial(budget_reason(&e)),
                Err(e) => return Err(e),
            }
            member += 1;
            remaining = next;
        }
        Ok(ex)
    }

    /// Extracts and scans regular-file TAR members (ustar, GNU, PAX) in memory.
    /// Links, devices and directories carry no content and are skipped.
    fn scan_tar(
        &self,
        data: &[u8],
        parent: &str,
        tracker: &mut ResourceTracker,
        depth: usize,
    ) -> Result<Extraction, ScanError> {
        use std::io::Read;
        let mut ex = Extraction::default();
        if let Err(e) = tracker.check_depth(depth) {
            ex.budget(e)?;
            return Ok(ex);
        }
        let mut archive = tar::Archive::new(std::io::Cursor::new(data));
        let entries = match archive.entries() {
            Ok(entries) => entries,
            Err(e) => {
                ex.raise(
                    ScanStatus::Unsupported,
                    format!("Malformed TAR container: {}", short_error(&e.to_string())),
                );
                return Ok(ex);
            }
        };
        let mut members = 0usize;
        for entry in entries {
            tracker.check_timeout()?;
            if tracker.soft_deadline_reached() {
                ex.partial(SOFT_DEADLINE_REASON);
                break;
            }
            let mut entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    ex.raise(
                        ScanStatus::Unsupported,
                        format!(
                            "TAR container unreadable after {members} members: {}",
                            short_error(&e.to_string())
                        ),
                    );
                    break;
                }
            };
            let kind = entry.header().entry_type();
            if !(kind.is_file() || kind.is_gnu_sparse()) {
                continue;
            }
            members += 1;
            let name: String = String::from_utf8_lossy(&entry.path_bytes())
                .chars()
                .take(256)
                .collect();
            let label = format!("{parent}/{name}");
            if let Err(e) = tracker.register_object(ObjectKind::ArchiveEntry) {
                ex.budget(e)?;
                break;
            }
            let output_limit = tracker.object_extraction_cap();
            if entry.size() > output_limit {
                ex.partial(oversize_reason(tracker, "Archive member"));
                continue;
            }
            let mut buf = Vec::new();
            if let Err(e) = (&mut entry)
                .take(output_limit.saturating_add(1))
                .read_to_end(&mut buf)
            {
                ex.raise(
                    ScanStatus::Unsupported,
                    format!(
                        "TAR member {label} unreadable: {}",
                        short_error(&e.to_string())
                    ),
                );
                break;
            }
            if buf.len() as u64 > output_limit {
                ex.partial(oversize_reason(tracker, "Archive member"));
                continue;
            }
            if let Err(e) = tracker.record_extracted_bytes(buf.len()) {
                ex.budget(e)?;
                break;
            }
            match self.scan_object(&buf, &label, None, tracker, depth) {
                Ok(r) => ex.reports.push(r),
                Err(e) if e.is_budget() => ex.partial(budget_reason(&e)),
                Err(e) => return Err(e),
            }
        }
        Ok(ex)
    }

    /// Extracts and scans ZIP members in memory under the shared resource budget.
    /// Never writes to disk; member names are used only as display labels.
    fn scan_zip(
        &self,
        data: &[u8],
        parent: &str,
        tracker: &mut ResourceTracker,
        depth: usize,
    ) -> Result<Extraction, ScanError> {
        use std::io::Read;
        let mut ex = Extraction::default();
        if let Err(e) = tracker.check_depth(depth) {
            ex.budget(e)?;
            return Ok(ex);
        }

        let mut archive = match zip::ZipArchive::new(std::io::Cursor::new(data)) {
            Ok(a) => a,
            Err(e) => {
                ex.raise(
                    ScanStatus::Unsupported,
                    format!("Malformed ZIP container: {}", e),
                );
                return Ok(ex);
            }
        };

        // ZipArchive exposes one central directory. Local headers or end records
        // outside every member's byte range may belong to another (or a truncated)
        // embedded archive, so the container cannot be reported as fully inspected.
        // Signatures inside member data (e.g. a stored nested ZIP) are inspected
        // when that member is extracted.
        let mut ranges: Vec<(u64, u64)> = Vec::with_capacity(archive.len());
        for i in 0..archive.len() {
            if let Ok(f) = archive.by_index_raw(i) {
                let end = f.data_start().saturating_add(f.compressed_size());
                ranges.push((f.header_start(), end));
            }
        }
        // The directory region runs from the central directory to the end of the
        // archive's end-of-central-directory record (including its comment); any
        // later bytes (appended archives) are outside it. Offsets are absolute.
        let central_start = archive.central_directory_start();
        let dir_end = memchr_all(data, b"PK\x05\x06")
            .find(|&p| p as u64 >= central_start)
            .map(|p| {
                let comment = data
                    .get(p + 20..p + 22)
                    .map_or(0, |c| u16::from_le_bytes([c[0], c[1]]) as usize);
                (p + 22 + comment) as u64
            })
            .unwrap_or(data.len() as u64);
        let outside = |pos: usize| {
            let pos = pos as u64;
            !(central_start..dir_end).contains(&pos)
                && !ranges.iter().any(|&(s, e)| pos > s && pos < e)
        };
        let stray_local = memchr_all(data, b"PK\x03\x04")
            .filter(|&p| outside(p))
            .any(|p| !ranges.iter().any(|&(s, _)| s == p as u64));
        let stray_eocd = memchr_all(data, b"PK\x05\x06").any(&outside);
        if stray_local || stray_eocd {
            ex.raise(
                ScanStatus::Unsupported,
                "Additional ZIP structures outside the central directory may contain uninspected content".into(),
            );
        }

        for i in 0..archive.len() {
            tracker.check_timeout()?;
            if tracker.soft_deadline_reached() {
                ex.partial(SOFT_DEADLINE_REASON);
                break;
            }
            let mut file = match archive.by_index(i) {
                Ok(f) => f,
                Err(zip::result::ZipError::UnsupportedArchive(m)) => {
                    ex.raise(
                        ScanStatus::Unsupported,
                        format!("ZIP member {} not inspectable: {}", i, m),
                    );
                    continue;
                }
                Err(e) => {
                    ex.raise(
                        ScanStatus::Failed,
                        format!("ZIP member {} unreadable: {}", i, e),
                    );
                    continue;
                }
            };
            if file.is_dir() {
                continue;
            }
            let name: String = file.name().chars().take(256).collect();
            let label = format!("{}/{}", parent, name);
            if file.encrypted() {
                ex.raise(
                    ScanStatus::Unsupported,
                    format!("Encrypted ZIP member: {}", label),
                );
                continue;
            }

            if let Err(e) = tracker.register_object(ObjectKind::ArchiveEntry) {
                ex.budget(e)?;
                break;
            }
            let output_limit = tracker.object_extraction_cap();
            let declared = file.size();
            if declared > output_limit {
                ex.partial(oversize_reason(tracker, "Archive member"));
                continue;
            }

            // Check the deadline between bounded decompression reads.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 64 * 1024];
            let mut extraction_error = None;
            loop {
                tracker.check_timeout()?;
                let remaining = output_limit
                    .saturating_add(1)
                    .saturating_sub(buf.len() as u64);
                if remaining == 0 {
                    break;
                }
                let limit = remaining.min(chunk.len() as u64) as usize;
                match file.read(&mut chunk[..limit]) {
                    Ok(0) => break,
                    Ok(n) => {
                        if buf.try_reserve(n).is_err() {
                            extraction_error = Some("allocation failed".to_string());
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    Err(e) => {
                        extraction_error = Some(e.to_string());
                        break;
                    }
                }
            }
            if let Some(e) = extraction_error {
                ex.raise(
                    ScanStatus::Failed,
                    format!("ZIP member {} extraction failed: {}", label, e),
                );
                continue;
            }
            if buf.len() as u64 > output_limit {
                ex.partial(oversize_reason(tracker, "Archive member"));
                continue;
            }
            if let Err(e) = tracker.record_extracted_bytes(buf.len()) {
                ex.budget(e)?;
                break;
            }
            drop(file);

            match self.scan_object(&buf, &label, None, tracker, depth) {
                Ok(r) => ex.reports.push(r),
                Err(e @ ScanError::Timeout { .. }) => return Err(e),
                Err(e) if e.is_budget() => ex.partial(budget_reason(&e)),
                Err(e) => ex.raise(
                    ScanStatus::Failed,
                    format!("ZIP member {} scan failed: {}", label, e),
                ),
            }
        }
        Ok(ex)
    }
}

const CONTENT_BUDGET_REASON: &str =
    "Content signature matching reached its work budget; object partially inspected";
const SOFT_DEADLINE_REASON: &str = "Scan time budget reached; remaining content not inspected";

/// Per-stream bound for object/xref streams decoded while a PDF is loaded.
const PDF_LOAD_STREAM_LIMIT: usize = 16 * 1024 * 1024;

/// Result of expanding one container: child reports, a structural issue that
/// prevents a Clean verdict, and reasons inspection was partial.
#[derive(Default)]
struct Extraction {
    reports: Vec<ScanReport>,
    issue: Option<(ScanStatus, String)>,
    partial: Vec<String>,
}

impl Extraction {
    /// Keeps the first issue, upgrading Unsupported to Failed.
    fn raise(&mut self, status: ScanStatus, msg: String) {
        let replace = match &self.issue {
            None => true,
            Some((cur, _)) => *cur == ScanStatus::Unsupported && status == ScanStatus::Failed,
        };
        if replace {
            self.issue = Some((status, msg));
        }
    }

    fn partial(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        if self.partial.len() < MAX_INCOMPLETE_REASONS && !self.partial.contains(&msg) {
            self.partial.push(msg);
        }
    }

    /// Records a budget error as partial inspection; propagates any other error.
    fn budget(&mut self, e: ScanError) -> Result<(), ScanError> {
        if e.is_budget() {
            self.partial(budget_reason(&e));
            Ok(())
        } else {
            Err(e)
        }
    }

    fn absorb(&mut self, other: Extraction) {
        self.reports.extend(other.reports);
        if let Some((status, msg)) = other.issue {
            self.raise(status, msg);
        }
        for p in other.partial {
            self.partial(p);
        }
    }
}

/// Stable, deduplicable description of an exhausted budget.
fn budget_reason(e: &ScanError) -> String {
    const MIB: u64 = 1024 * 1024;
    match e {
        ScanError::DepthLimitExceeded { limit, .. } => {
            format!("Content nested deeper than {limit} levels not inspected")
        }
        ScanError::AttachmentLimitExceeded { limit } => {
            format!("Only the first {limit} MIME parts were inspected")
        }
        ScanError::ObjectLimitExceeded { kind, limit } => {
            format!("Only the first {limit} {kind}s were inspected")
        }
        ScanError::ExtractedSizeLimitExceeded { limit, .. } => format!(
            "Extraction budget of {} MiB reached; remaining content not inspected",
            limit / MIB
        ),
        ScanError::FileSizeLimitExceeded { limit, .. } => {
            format!(
                "Embedded object larger than {} MiB not inspected",
                limit / MIB
            )
        }
        other => other.to_string(),
    }
}

/// Explains why an object exceeding `object_extraction_cap` was skipped.
fn oversize_reason(tracker: &ResourceTracker, what: &str) -> String {
    let limits = tracker.limits();
    let per_object = limits.max_email_attachment_size;
    if tracker.object_extraction_cap() < per_object {
        budget_reason(&ScanError::ExtractedSizeLimitExceeded {
            limit: limits.max_total_extracted_bytes,
            current: 0,
        })
    } else {
        format!(
            "{what} larger than {} MiB not inspected",
            per_object / (1024 * 1024)
        )
    }
}

fn short_error(msg: &str) -> String {
    msg.chars().take(120).collect()
}

enum PdfDecodeError {
    /// Decoded output would exceed the extraction budget.
    Budget,
    /// The stream cannot be fully decoded; carries the best bytes available.
    Undecodable(Vec<u8>, String),
}

/// Image codecs whose output is pixels, not embedded files or scripts. Their
/// encoded bytes are scanned as-is, which is what exact-hash and byte rules expect.
const PDF_IMAGE_FILTERS: &[&[u8]] = &[
    b"DCTDecode",
    b"JPXDecode",
    b"JBIG2Decode",
    b"CCITTFaxDecode",
];

fn decode_pdf_stream(stream: &lopdf::Stream, cap: usize) -> Result<Vec<u8>, PdfDecodeError> {
    let is_budget = |e: &lopdf::Error| {
        matches!(
            e,
            lopdf::Error::Decompress(lopdf::DecompressError::MemoryLimitExceeded { .. })
        )
    };
    let filters: Vec<Vec<u8>> = match stream.filters() {
        Ok(f) => f.into_iter().map(|f| f.to_vec()).collect(),
        Err(_) if !stream.dict.has(b"Filter") => Vec::new(),
        Err(_) => {
            return Err(PdfDecodeError::Undecodable(
                stream.content.clone(),
                "has a malformed /Filter entry".into(),
            ))
        }
    };
    if filters.is_empty() {
        if stream.content.len() > cap {
            return Err(PdfDecodeError::Budget);
        }
        return Ok(stream.content.clone());
    }

    // Decode the general-purpose prefix of the chain; stop at the first image codec.
    let prefix_len = filters
        .iter()
        .position(|f| PDF_IMAGE_FILTERS.contains(&f.as_slice()))
        .unwrap_or(filters.len());
    if prefix_len == 0 {
        if stream.content.len() > cap {
            return Err(PdfDecodeError::Budget);
        }
        return Ok(stream.content.clone());
    }
    let decoded = if prefix_len == filters.len() {
        stream.decompressed_content_with_limit(cap)
    } else {
        let mut dict = stream.dict.clone();
        let prefix: Vec<lopdf::Object> = filters[..prefix_len]
            .iter()
            .map(|f| lopdf::Object::Name(f.clone()))
            .collect();
        dict.set("Filter", lopdf::Object::Array(prefix));
        if let Ok(lopdf::Object::Array(params)) = stream.dict.get(b"DecodeParms") {
            let params: Vec<lopdf::Object> = params.iter().take(prefix_len).cloned().collect();
            dict.set("DecodeParms", lopdf::Object::Array(params));
        }
        lopdf::Stream::new(dict, stream.content.clone())
            .with_compression(false)
            .decompressed_content_with_limit(cap)
    };
    match decoded {
        Ok(bytes) => Ok(bytes),
        Err(e) if is_budget(&e) => Err(PdfDecodeError::Budget),
        Err(lopdf::Error::Unimplemented(_)) => {
            let names: Vec<String> = filters[..prefix_len]
                .iter()
                .map(|f| String::from_utf8_lossy(f).chars().take(32).collect())
                .collect();
            Err(PdfDecodeError::Undecodable(
                stream.content.clone(),
                format!("uses unsupported filter chain [{}]", names.join(", ")),
            ))
        }
        Err(_) => Err(PdfDecodeError::Undecodable(
            stream.content.clone(),
            "could not be decoded (corrupt data)".into(),
        )),
    }
}

/// Positions of every occurrence of `needle` in `hay`.
fn memchr_all<'h>(hay: &'h [u8], needle: &'static [u8]) -> impl Iterator<Item = usize> + 'h {
    hay.windows(needle.len())
        .enumerate()
        .filter(move |(_, w)| *w == needle)
        .map(|(i, _)| i)
}

/// Strong (6+ byte) signatures of container formats that cannot be extracted yet.
/// Short magics (e.g. 3-byte GZIP/BZIP2 prefixes) occur by chance in compressed
/// or image data and are deliberately not used.
fn find_embedded_container(data: &[u8]) -> Option<&'static str> {
    const MAGICS: &[(&[u8], &str)] = &[
        (b"Rar!\x1a\x07", "RAR"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
        (b"\xfd7zXZ\x00", "XZ"),
        (b"MSCF\x00\x00\x00\x00", "CAB"),
    ];
    for (magic, kind) in MAGICS {
        if memchr_all(data, magic).next().is_some() {
            return Some(kind);
        }
    }
    // BZIP2 stream header: "BZh" + block size 1-9 + block magic (pi digits).
    memchr_all(data, b"1AY&SY")
        .any(|p| p >= 4 && &data[p - 4..p - 1] == b"BZh" && (b'1'..=b'9').contains(&data[p - 1]))
        .then_some("BZIP2")
}

enum ContainerKind {
    None,
    Gzip,
    Tar,
    Zip,
    Unsupported(&'static str),
}

/// Content-based container classification, with fallback to declared metadata
/// for truncated or incomplete containers that cannot be safely inspected.
fn classify_container(data: &[u8], filename: &str, declared_mime: Option<&str>) -> ContainerKind {
    // An embedded ZIP (self-extractor, polyglot, prepended data) is recognized by a
    // structurally plausible local header, so the four bytes "PK\3\4" occurring by
    // chance in compressed or image data do not turn a PDF into a malformed ZIP.
    let claims_zip = data.starts_with(b"PK\x03\x04")
        || data.starts_with(b"PK\x05\x06")
        || filename.to_ascii_lowercase().ends_with(".zip")
        || declared_mime.is_some_and(|m| m.eq_ignore_ascii_case("application/zip"));
    let embedded_zip = || memchr_all(data, b"PK\x03\x04").any(|p| plausible_local_header(data, p));
    if claims_zip || embedded_zip() {
        ContainerKind::Zip
    } else if is_tar_header(data) || is_tar_claim(data, filename, declared_mime) {
        ContainerKind::Tar
    } else if data.starts_with(b"Rar!\x1a\x07") {
        ContainerKind::Unsupported("RAR")
    } else if data.starts_with(b"7z\xbc\xaf\x27\x1c") {
        ContainerKind::Unsupported("7-Zip")
    } else if data.starts_with(&[0x1f, 0x8b]) {
        ContainerKind::Gzip
    } else if data.starts_with(b"BZh") && data.len() > 3 && data[3].is_ascii_digit() {
        ContainerKind::Unsupported("BZIP2")
    } else if data.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        ContainerKind::Unsupported("XZ")
    } else if data.starts_with(b"MSCF") {
        ContainerKind::Unsupported("CAB")
    } else {
        ContainerKind::None
    }
}

/// Whether a ZIP local file header at `pos` has sane fields (version, method,
/// name length, printable name). Truncated archives still qualify.
fn plausible_local_header(data: &[u8], pos: usize) -> bool {
    let Some(h) = data.get(pos..pos + 30) else {
        return false;
    };
    let u16le = |o: usize| u16::from_le_bytes([h[o], h[o + 1]]);
    let version = u16le(4);
    let method = u16le(8);
    let name_len = u16le(26) as usize;
    let extra_len = u16le(28) as usize;
    const METHODS: &[u16] = &[0, 1, 6, 8, 9, 12, 14, 19, 93, 95, 96, 97, 98, 99];
    if (version & 0xff) > 63 || !METHODS.contains(&method) || name_len == 0 || name_len > 1024 {
        return false;
    }
    if extra_len > 8192 {
        return false;
    }
    match data.get(pos + 30..pos + 30 + name_len) {
        Some(name) => name.iter().all(|&b| b >= 0x20 && b != 0x7f),
        None => false,
    }
}

fn is_tar_claim(data: &[u8], filename: &str, declared_mime: Option<&str>) -> bool {
    let lower_name = filename.to_ascii_lowercase();
    let is_tar_named = lower_name.ends_with(".tar");
    let is_tar_mime = declared_mime.is_some_and(|m| {
        m.eq_ignore_ascii_case("application/x-tar")
            || m.eq_ignore_ascii_case("application/tar")
            || m.eq_ignore_ascii_case("application/x-gtar")
    });
    (is_tar_named || is_tar_mime) && !data.is_empty()
}

/// Applies verdict precedence Infected > Failed > Unsupported > Clean.
fn combine_verdict(
    threats: &[Threat],
    container_issue: Option<(ScanStatus, String)>,
    subs: &[ScanReport],
) -> (ScanStatus, Option<String>) {
    if !threats.is_empty() || subs.iter().any(|r| r.status == ScanStatus::Infected) {
        return (ScanStatus::Infected, None);
    }
    for st in [ScanStatus::Failed, ScanStatus::Unsupported] {
        if let Some((s, m)) = &container_issue {
            if *s == st {
                return (st, Some(m.clone()));
            }
        }
        if let Some(r) = subs.iter().find(|r| r.status == st) {
            return (
                st,
                r.error
                    .clone()
                    .or_else(|| Some(r.status_description.clone())),
            );
        }
    }
    (ScanStatus::Clean, None)
}

/// Helper to identify RFC 2046 boundary delimiter lines.
/// Returns byte offsets in `raw_bytes` where opening delimiter lines (`--<boundary>`)
/// and closing delimiter lines (`--<boundary>--`) start.
fn find_boundary_lines(raw_bytes: &[u8], boundary: &str) -> (Vec<usize>, Vec<usize>) {
    let mut open_lines = Vec::new();
    let mut close_lines = Vec::new();

    let open_delim = format!("--{}", boundary);
    let close_delim = format!("--{}--", boundary);
    let open_bytes = open_delim.as_bytes();
    let close_bytes = close_delim.as_bytes();

    let mut i = 0;
    while i < raw_bytes.len() {
        // RFC 2046 Section 5.1.1: delimiter MUST occur at the beginning of a line
        let is_line_start = i == 0 || raw_bytes[i - 1] == b'\n' || raw_bytes[i - 1] == b'\r';
        if is_line_start {
            // Check closing boundary delimiter first (longer match: "--boundary--")
            if raw_bytes[i..].starts_with(close_bytes) {
                let mut after = i + close_bytes.len();
                // RFC 2046: optional linear whitespace ([ \t]*)
                while after < raw_bytes.len()
                    && (raw_bytes[after] == b' ' || raw_bytes[after] == b'\t')
                {
                    after += 1;
                }
                // Must be followed by CRLF, LF, CR, or EOF
                if after == raw_bytes.len()
                    || raw_bytes[after] == b'\n'
                    || raw_bytes[after] == b'\r'
                {
                    close_lines.push(i);
                    i = after;
                    continue;
                }
            } else if raw_bytes[i..].starts_with(open_bytes) {
                let mut after = i + open_bytes.len();
                while after < raw_bytes.len()
                    && (raw_bytes[after] == b' ' || raw_bytes[after] == b'\t')
                {
                    after += 1;
                }
                if after == raw_bytes.len()
                    || raw_bytes[after] == b'\n'
                    || raw_bytes[after] == b'\r'
                {
                    open_lines.push(i);
                    i = after;
                    continue;
                }
            }
        }
        i += 1;
    }

    (open_lines, close_lines)
}

fn is_multipart_part(part: &MessagePart) -> bool {
    part.content_type()
        .map(|ct| ct.ctype().eq_ignore_ascii_case("multipart"))
        .unwrap_or(false)
}

/// Validates RFC 2046 MIME boundary integrity.
fn validate_mime_boundaries(raw_bytes: &[u8], msg: &Message) -> Result<(), String> {
    // Collect leaf (non-multipart) part body spans to ensure closing boundaries do not appear inside part contents
    let leaf_spans: Vec<(usize, usize)> = msg
        .parts()
        .filter(|p| !is_multipart_part(p))
        .map(|p| (p.offset_body() as usize, p.offset_end() as usize))
        .filter(|(start, end)| start < end)
        .collect();

    let is_inside_leaf = |pos: usize| -> bool {
        leaf_spans
            .iter()
            .any(|&(start, end)| start <= pos && pos < end)
    };

    // 1. Check root message Content-Type
    if let Some(ct) = msg.content_type() {
        if ct.ctype().eq_ignore_ascii_case("multipart") {
            let boundary = match ct.attribute("boundary") {
                Some(b) if !b.is_empty() => b,
                _ => {
                    return Err(
                        "Malformed multipart MIME: missing required 'boundary' parameter in Content-Type header"
                            .to_string(),
                    );
                }
            };

            let (open_lines, close_lines) = find_boundary_lines(raw_bytes, boundary);
            if open_lines.is_empty() {
                return Err(format!(
                    "Malformed multipart MIME: boundary delimiter '--{}' not found in message",
                    boundary
                ));
            }
            if close_lines.is_empty() {
                return Err(format!(
                    "Incomplete multipart MIME: missing closing boundary delimiter '--{}--'",
                    boundary
                ));
            }

            // Exclude closing delimiter candidates that fall inside ordinary part content
            let non_leaf_close: Vec<usize> = close_lines
                .into_iter()
                .filter(|&pos| !is_inside_leaf(pos))
                .collect();

            if non_leaf_close.is_empty() {
                return Err(format!(
                    "Incomplete multipart MIME: missing closing boundary delimiter '--{}--'",
                    boundary
                ));
            }

            // The closing boundary must occur at or after all child parts belonging to root
            let max_child_end = msg
                .parts()
                .filter(|p| p.offset_header() > 0)
                .map(|p| p.offset_end() as usize)
                .max()
                .unwrap_or(0);

            let valid_close = non_leaf_close.into_iter().find(|&pos| pos >= max_child_end);
            let valid_close_pos = match valid_close {
                Some(p) => p,
                None => {
                    return Err(format!(
                        "Incomplete multipart MIME: missing closing boundary delimiter '--{}--'",
                        boundary
                    ));
                }
            };

            // Opening boundary lines must not appear after the closing delimiter
            if open_lines
                .iter()
                .any(|&open_pos| open_pos > valid_close_pos)
            {
                return Err(format!(
                    "Malformed multipart MIME: opening delimiter '--{}' appears after closing delimiter",
                    boundary
                ));
            }

            // No body part may start after the closing boundary
            if msg
                .parts()
                .any(|p| !is_multipart_part(&p) && (p.offset_header() as usize) > valid_close_pos)
            {
                return Err(format!(
                    "Malformed multipart MIME: part appears after closing delimiter '--{}--'",
                    boundary
                ));
            }
        }
    }

    // 2. Check any parts that declare multipart sub-structures
    for part in msg.parts() {
        if part.offset_header() > 0 && is_multipart_part(&part) {
            let ct = part.content_type().unwrap();
            let b = match ct.attribute("boundary") {
                Some(b) if !b.is_empty() => b,
                _ => {
                    return Err(
                        "Malformed multipart MIME: missing required 'boundary' parameter in part Content-Type header"
                            .to_string(),
                    );
                }
            };

            let (open_lines, close_lines) = find_boundary_lines(raw_bytes, b);
            if open_lines.is_empty() {
                return Err(format!(
                    "Malformed multipart MIME: sub-part boundary delimiter '--{}' not found in message",
                    b
                ));
            }
            if close_lines.is_empty() {
                return Err(format!(
                    "Incomplete multipart MIME: missing sub-part boundary delimiter '--{}--'",
                    b
                ));
            }

            let non_leaf_close: Vec<usize> = close_lines
                .into_iter()
                .filter(|&pos| !is_inside_leaf(pos))
                .collect();

            if non_leaf_close.is_empty() {
                return Err(format!(
                    "Incomplete multipart MIME: missing sub-part boundary delimiter '--{}--'",
                    b
                ));
            }

            // For sub-parts, the closing boundary must occur within this container's span and after all its child parts
            let sub_start = part.offset_body() as usize;
            let sub_end = part.offset_end() as usize;

            let max_sub_child_end = msg
                .parts()
                .filter(|c| {
                    (c.offset_header() as usize) >= sub_start
                        && (c.offset_end() as usize) <= sub_end
                        && (c.offset_header() as usize) != (part.offset_header() as usize)
                })
                .map(|c| c.offset_end() as usize)
                .max()
                .unwrap_or(sub_start);

            let valid_sub_close = non_leaf_close
                .into_iter()
                .find(|&pos| pos >= max_sub_child_end && pos <= sub_end);

            let valid_close_pos = match valid_sub_close {
                Some(p) => p,
                None => {
                    return Err(format!(
                        "Incomplete multipart MIME: missing sub-part boundary delimiter '--{}--'",
                        b
                    ));
                }
            };

            if open_lines
                .iter()
                .any(|&open_pos| open_pos > valid_close_pos)
            {
                return Err(format!(
                    "Malformed multipart MIME: sub-part opening delimiter '--{}' appears after closing delimiter",
                    b
                ));
            }
        }
    }

    Ok(())
}

/// Validates transfer encoding (Base64 / Quoted-Printable) against raw payload bytes.
fn validate_attachment_encoding(
    part: &MessagePart,
    raw_bytes: &[u8],
    decoded_data: &[u8],
) -> Result<(), String> {
    if let Some(enc) = part.content_transfer_encoding() {
        let enc_clean = enc.trim().to_ascii_lowercase();
        if enc_clean == "base64" {
            let start = part.offset_body() as usize;
            let end = part.offset_end() as usize;
            if start <= end && end <= raw_bytes.len() {
                let raw_payload = &raw_bytes[start..end];
                let non_ws: Vec<u8> = raw_payload
                    .iter()
                    .copied()
                    .filter(|b| !b.is_ascii_whitespace())
                    .collect();

                if !non_ws.is_empty() {
                    if decoded_data.is_empty() {
                        return Err(
                            "Malformed attachment: invalid base64 encoding; decoded payload is empty"
                                .to_string(),
                        );
                    }

                    let has_invalid_chars = non_ws.iter().any(|&b| {
                        !(b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
                    });
                    if has_invalid_chars {
                        return Err(
                            "Malformed attachment: invalid characters in base64 encoding stream"
                                .to_string(),
                        );
                    }

                    if !non_ws.len().is_multiple_of(4) {
                        return Err(
                            "Malformed attachment: truncated base64 stream (length is not a multiple of 4)"
                                .to_string(),
                        );
                    }

                    let pad_count = non_ws.iter().rev().take_while(|&&b| b == b'=').count();
                    if pad_count > 2 {
                        return Err(
                            "Malformed attachment: excessive base64 padding characters".to_string()
                        );
                    }
                    if non_ws[..non_ws.len() - pad_count].contains(&b'=') {
                        return Err(
                            "Malformed attachment: misplaced base64 padding character".to_string()
                        );
                    }
                }
            }
        } else if enc_clean == "quoted-printable" {
            let start = part.offset_body() as usize;
            let end = part.offset_end() as usize;
            if start <= end && end <= raw_bytes.len() {
                let raw_payload = &raw_bytes[start..end];
                let mut i = 0;
                while i < raw_payload.len() {
                    if raw_payload[i] == b'=' {
                        if i + 1 >= raw_payload.len() {
                            return Err(
                                "Truncated Quoted-Printable attachment: trailing '=' at end of stream"
                                    .to_string(),
                            );
                        }
                        if raw_payload[i + 1] == b'\n'
                            || (raw_payload[i + 1] == b'\r'
                                && i + 2 < raw_payload.len()
                                && raw_payload[i + 2] == b'\n')
                        {
                            i += if raw_payload[i + 1] == b'\r' { 3 } else { 2 };
                            continue;
                        }
                        if i + 2 >= raw_payload.len() {
                            return Err(
                                "Truncated Quoted-Printable attachment: incomplete hex escape"
                                    .to_string(),
                            );
                        }
                        let h1 = raw_payload[i + 1];
                        let h2 = raw_payload[i + 2];
                        if !h1.is_ascii_hexdigit() || !h2.is_ascii_hexdigit() {
                            return Err(
                                "Malformed Quoted-Printable attachment: invalid hex sequence following '='"
                                    .to_string(),
                            );
                        }
                        i += 3;
                    } else {
                        i += 1;
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxosentinel_core::{ResourceLimits, ThreatCategory};
    use std::io::Write;

    #[test]
    fn pdf_streams_detection_and_limits() {
        use lopdf::{dictionary, Document, Stream};
        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        for compressed in [false, true] {
            for payload in [
                b"ordinary clean text".as_slice(),
                b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".as_slice(),
            ] {
                let mut doc = Document::with_version("1.4");
                let pages = doc.add_object(dictionary! { "Type" => "Pages", "Kids" => Vec::<lopdf::Object>::new(), "Count" => 0 });
                let root = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages });
                doc.trailer.set("Root", root);
                let mut stream =
                    Stream::new(dictionary! { "Type" => "EmbeddedFile" }, payload.to_vec());
                if compressed {
                    let mut encoder =
                        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                    encoder.write_all(payload).unwrap();
                    stream.set_content(encoder.finish().unwrap());
                    stream.dict.set("Filter", "FlateDecode");
                }
                doc.add_object(stream);
                let mut data = Vec::new();
                doc.save_to(&mut data).unwrap();
                let mut tracker = ResourceTracker::new(ResourceLimits::default());
                let report = scanner
                    .scan_object(&data, "fixture.pdf", None, &mut tracker, 0)
                    .unwrap();
                assert_eq!(
                    report.status,
                    if payload.starts_with(b"ordinary") {
                        ScanStatus::Clean
                    } else {
                        ScanStatus::Infected
                    }
                );
                // Clean leaf streams are omitted from the report; detections are kept.
                assert_eq!(
                    report.sub_targets.is_empty(),
                    report.status == ScanStatus::Clean
                );
                assert!(report.incomplete.is_empty());
                // An exhausted budget is reported as partial inspection, not a failure.
                let mut tracker = ResourceTracker::new(ResourceLimits {
                    max_total_extracted_bytes: 1,
                    ..Default::default()
                });
                let limited = scanner
                    .scan_object(&data, "limited.pdf", None, &mut tracker, 0)
                    .unwrap();
                assert!(!limited.incomplete.is_empty());
                if compressed && report.status == ScanStatus::Clean {
                    assert_eq!(limited.status, ScanStatus::Clean);
                }
            }
        }
        let mut tracker = ResourceTracker::new(ResourceLimits::default());
        let broken = scanner
            .scan_object(b"%PDF-1.4\ntruncated", "broken.pdf", None, &mut tracker, 0)
            .unwrap();
        assert_eq!(broken.status, ScanStatus::Clean);
        assert!(broken.incomplete[0].contains("could not be parsed"));
    }

    fn pdf_with_stream(dict: lopdf::Dictionary, content: Vec<u8>) -> Vec<u8> {
        use lopdf::{dictionary, Document, Stream};
        let mut doc = Document::with_version("1.4");
        let pages = doc.add_object(
            dictionary! { "Type" => "Pages", "Kids" => Vec::<lopdf::Object>::new(), "Count" => 0 },
        );
        let root = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages });
        doc.trailer.set("Root", root);
        doc.add_object(Stream::new(dict, content).with_compression(false));
        let mut data = Vec::new();
        doc.save_to(&mut data).unwrap();
        data
    }

    #[test]
    fn pdf_many_streams_predictors_and_filter_chains() {
        use lopdf::dictionary;
        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        // More streams than the old shared 30-object limit: fully inspected and clean.
        let mut doc = lopdf::Document::with_version("1.4");
        let pages = doc.add_object(
            dictionary! { "Type" => "Pages", "Kids" => Vec::<lopdf::Object>::new(), "Count" => 0 },
        );
        let root = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages });
        doc.trailer.set("Root", root);
        for i in 0..120 {
            let mut enc =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(format!("BT /F1 12 Tf ({i}) Tj ET").as_bytes())
                .unwrap();
            doc.add_object(
                lopdf::Stream::new(
                    dictionary! { "Filter" => "FlateDecode" },
                    enc.finish().unwrap(),
                )
                .with_compression(false),
            );
        }
        let mut data = Vec::new();
        doc.save_to(&mut data).unwrap();
        let mut tracker = ResourceTracker::new(ResourceLimits::default());
        let report = scanner
            .scan_object(&data, "pages.pdf", None, &mut tracker, 0)
            .unwrap();
        assert_eq!(report.status, ScanStatus::Clean, "{:?}", report.error);
        assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);

        // Flate with a PNG predictor (DecodeParms) is decoded and inspected.
        let mut rows = Vec::new();
        for chunk in eicar.chunks(17) {
            rows.push(0u8); // PNG "None" predictor per row
            rows.extend_from_slice(chunk);
            rows.extend(std::iter::repeat_n(b' ', 17 - chunk.len()));
        }
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&rows).unwrap();
        let data = pdf_with_stream(
            dictionary! {
                "Filter" => "FlateDecode",
                "DecodeParms" => dictionary! { "Predictor" => 12, "Columns" => 17 },
            },
            enc.finish().unwrap(),
        );
        let mut tracker = ResourceTracker::new(ResourceLimits::default());
        let report = scanner
            .scan_object(&data, "predictor.pdf", None, &mut tracker, 0)
            .unwrap();
        assert_eq!(report.status, ScanStatus::Infected);

        // ASCIIHex + Flate chain is decoded.
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(eicar).unwrap();
        let hex: String = enc
            .finish()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let data = pdf_with_stream(
            dictionary! { "Filter" => vec![lopdf::Object::Name(b"ASCIIHexDecode".to_vec()), lopdf::Object::Name(b"FlateDecode".to_vec())] },
            format!("{hex}>").into_bytes(),
        );
        let mut tracker = ResourceTracker::new(ResourceLimits::default());
        let report = scanner
            .scan_object(&data, "chain.pdf", None, &mut tracker, 0)
            .unwrap();
        assert_eq!(report.status, ScanStatus::Infected);

        // Image codecs are not decoded; their bytes are scanned as-is without a partial note.
        let data = pdf_with_stream(
            dictionary! { "Filter" => "DCTDecode" },
            b"\xff\xd8\xff\xe0 not really a jpeg".to_vec(),
        );
        let mut tracker = ResourceTracker::new(ResourceLimits::default());
        let report = scanner
            .scan_object(&data, "image.pdf", None, &mut tracker, 0)
            .unwrap();
        assert_eq!(report.status, ScanStatus::Clean);
        assert!(report.incomplete.is_empty(), "{:?}", report.incomplete);

        // An unknown filter is a partial inspection of the raw bytes, not a withhold.
        let data = pdf_with_stream(
            dictionary! { "Filter" => "MadeUpDecode" },
            b"opaque".to_vec(),
        );
        let mut tracker = ResourceTracker::new(ResourceLimits::default());
        let report = scanner
            .scan_object(&data, "unknown.pdf", None, &mut tracker, 0)
            .unwrap();
        assert_eq!(report.status, ScanStatus::Clean);
        assert!(report.incomplete[0].contains("unsupported filter"));
    }

    #[test]
    fn weak_embedded_magic_is_not_a_container() {
        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        // Short magics that appear by chance in ordinary binary data.
        let data = b"\x89PNG....BZh9....\x1f\x8b\x08....MSCF....PK\x03\x04....".to_vec();
        let mut tracker = ResourceTracker::new(ResourceLimits::default());
        let report = scanner
            .scan_object(&data, "image.png", None, &mut tracker, 0)
            .unwrap();
        assert_eq!(report.status, ScanStatus::Clean, "{:?}", report.error);
        // Strong magics are still treated as uninspectable embedded containers.
        let mut data = data;
        data.extend_from_slice(b"Rar!\x1a\x07\x01\x00");
        let mut tracker = ResourceTracker::new(ResourceLimits::default());
        let report = scanner
            .scan_object(&data, "image.png", None, &mut tracker, 0)
            .unwrap();
        assert_eq!(report.status, ScanStatus::Unsupported);
    }

    #[test]
    fn gzip_members_clean_trailing_and_count_limit() {
        use flate2::{write::GzEncoder, Compression};
        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"ordinary clean text").unwrap();
        let member = enc.finish().unwrap();
        let mut data = member.clone();
        data.extend_from_slice(&member);
        let mut tracker = ResourceTracker::new(ResourceLimits::default());
        let report = scanner
            .scan_object(&data, "members.gz", None, &mut tracker, 0)
            .unwrap();
        assert_eq!(report.status, ScanStatus::Clean);
        assert_eq!(report.sub_targets.len(), 2);
        let mut tracker = ResourceTracker::new(ResourceLimits {
            max_gzip_members: 1,
            ..Default::default()
        });
        let limited = scanner
            .scan_object(&data, "limited.gz", None, &mut tracker, 0)
            .unwrap();
        assert_eq!(limited.status, ScanStatus::Clean);
        assert_eq!(limited.sub_targets.len(), 1);
        assert!(limited.incomplete[0].contains("GZIP member"));
        data.extend_from_slice(b"uninspected suffix");
        let mut tracker = ResourceTracker::new(ResourceLimits::default());
        assert_eq!(
            scanner
                .scan_object(&data, "trailing.gz", None, &mut tracker, 0)
                .unwrap()
                .status,
            ScanStatus::Unsupported
        );
    }

    #[test]
    fn gzip_detection_truncation_and_limits() {
        use flate2::{write::GzEncoder, Compression};
        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(eicar).unwrap();
        let data = enc.finish().unwrap();
        let mut tracker = ResourceTracker::new(ResourceLimits::default());
        assert_eq!(
            scanner
                .scan_object(&data, "fixture.gz", None, &mut tracker, 0)
                .unwrap()
                .status,
            ScanStatus::Infected
        );
        let mut tracker = ResourceTracker::new(ResourceLimits::default());
        assert_ne!(
            scanner
                .scan_object(
                    &data[..data.len() - 4],
                    "truncated.gz",
                    None,
                    &mut tracker,
                    0
                )
                .unwrap()
                .status,
            ScanStatus::Clean
        );
        let mut tracker = ResourceTracker::new(ResourceLimits {
            max_total_extracted_bytes: 4,
            ..Default::default()
        });
        assert_ne!(
            scanner
                .scan_object(&data, "limited.gz", None, &mut tracker, 0)
                .unwrap()
                .status,
            ScanStatus::Clean
        );
    }

    #[test]
    fn content_signatures_detect_and_budget_only_marks_partial() {
        use raxosentinel_signatures::content::ContentEngine;
        let sigs = "ndb\tTest.Body-1:0:*:6576696c*7061796c6f6164\n\
                    ldb\tTest.Mail-1;Target:4;0;582d4576696c2d4d61696c65723a\n";
        let mime = |attachment: &str| {
            format!(
                "From: a@example.com\r\nX-Evil-Mailer: 1\r\nTo: b@example.com\r\nSubject: t\r\n\
                 MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n\
                 --B\r\nContent-Type: text/plain\r\n\r\nhello\r\n\
                 --B\r\nContent-Type: application/octet-stream\r\n\
                 Content-Disposition: attachment; filename=\"cv.bin\"\r\n\r\n{attachment}\r\n--B--\r\n"
            )
        };
        let mut db = SignatureDatabase::with_defaults();
        db.attach_content(std::sync::Arc::new(ContentEngine::from_text(sigs).unwrap()));
        let scanner = EmailScanner::new(&db);
        let scan = |db_scanner: &EmailScanner, raw: &str| {
            let mut tracker = ResourceTracker::new(ResourceLimits::default());
            db_scanner
                .scan_bytes(raw.as_bytes(), Some("m.eml"), &mut tracker)
                .unwrap()
        };

        let report = scan(&scanner, &mime("evil ... payload"));
        assert_eq!(report.status, ScanStatus::Infected);
        let names: Vec<_> = report.threats.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"Test.Body-1"), "{names:?}");
        // The raw message carries `X-Evil-Mailer:` and is matched as a Mail target.
        assert!(names.contains(&"Test.Mail-1"), "{names:?}");

        // Running out of matching budget is a partial-inspection note, never a withhold.
        let mut slow = SignatureDatabase::with_defaults();
        slow.attach_content(std::sync::Arc::new(
            ContentEngine::from_text("ndb\tTest.Slow-1:0:*:616263*78797a\n")
                .unwrap()
                .with_step_budget(100),
        ));
        let report = scan(&EmailScanner::new(&slow), &mime(&"abc".repeat(2000)));
        assert_eq!(report.status, ScanStatus::Clean);
        assert!(
            report
                .incomplete
                .iter()
                .any(|r| r.contains("Content signature")),
            "{:?}",
            report.incomplete
        );
    }

    #[test]
    fn test_scan_plain_clean_email() {
        let email = b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hello\r\n\r\nThis is a friendly clean email.";
        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(email, Some("clean.eml"), &mut tracker)
            .unwrap();
        assert_eq!(report.status, ScanStatus::Clean);
        assert!(report.threats.is_empty());
        assert!(report.sub_targets.is_empty());
    }

    #[test]
    fn test_scan_email_with_eicar_in_body() {
        let email = b"From: test@example.com\r\nTo: user@example.com\r\nSubject: Test Virus\r\n\r\nX5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(email, Some("eicar_body.eml"), &mut tracker)
            .unwrap();
        assert_eq!(report.status, ScanStatus::Infected);
        assert_eq!(report.threats.len(), 1);
        assert_eq!(report.threats[0].name, "EICAR-Standard-Antivirus-Test-File");
    }

    #[test]
    fn test_scan_multipart_attachment_with_eicar() {
        let raw_mime = b"MIME-Version: 1.0\r\n\
From: sender@example.com\r\n\
To: recipient@example.com\r\n\
Subject: Attachment Test\r\n\
Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\
\r\n\
--BOUNDARY\r\n\
Content-Type: text/plain\r\n\
\r\n\
Please see attached document.\r\n\
--BOUNDARY\r\n\
Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=\"eicar.com\"\r\n\
\r\n\
X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\r\n\
--BOUNDARY--\r\n";

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(raw_mime, Some("multipart.eml"), &mut tracker)
            .unwrap();
        assert_eq!(report.status, ScanStatus::Infected);
        assert_eq!(report.sub_targets.len(), 1);
        assert_eq!(report.sub_targets[0].status, ScanStatus::Infected);
        assert_eq!(
            report.sub_targets[0].target.file_name.as_deref(),
            Some("eicar.com")
        );
        // Deduplicated threat consolidated
        assert_eq!(report.threats.len(), 1);
        assert_eq!(report.threats[0].name, "EICAR-Standard-Antivirus-Test-File");
    }

    #[test]
    fn test_scan_multipart_disguised_executable_mismatch() {
        let mut pe_bytes = vec![0u8; 128];
        pe_bytes[0] = b'M';
        pe_bytes[1] = b'Z';
        pe_bytes[0x3C] = 0x40;
        pe_bytes[0x40..0x44].copy_from_slice(b"PE\0\0");

        let mut raw_mime = Vec::new();
        raw_mime.extend_from_slice(
            b"MIME-Version: 1.0\r\n\
From: scam@malicious.com\r\n\
To: target@victim.com\r\n\
Subject: Overdue Invoice\r\n\
Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
\r\n\
--BOUND\r\n\
Content-Type: text/plain\r\n\
\r\n\
Here is the invoice.\r\n\
--BOUND\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
\r\n",
        );
        raw_mime.extend_from_slice(&pe_bytes);
        raw_mime.extend_from_slice(b"\r\n--BOUND--\r\n");

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(&raw_mime, Some("spoofed.eml"), &mut tracker)
            .unwrap();
        assert_eq!(report.status, ScanStatus::Infected);
        assert_eq!(report.sub_targets.len(), 1);
        let att = &report.sub_targets[0];
        assert_eq!(att.status, ScanStatus::Infected);
        assert!(att
            .threats
            .iter()
            .any(|t| t.category == ThreatCategory::ExtensionMismatch));
    }

    #[test]
    fn test_email_attachment_limit_is_partial() {
        let raw_mime = b"MIME-Version: 1.0\r\n\
From: sender@example.com\r\n\
To: recipient@example.com\r\n\
Subject: Many attachments\r\n\
Content-Type: multipart/mixed; boundary=\"B\"\r\n\
\r\n\
--B\r\n\
Content-Type: text/plain\r\n\
Content-Disposition: attachment; filename=\"1.txt\"\r\n\
\r\n\
A\r\n\
--B\r\n\
Content-Type: text/plain\r\n\
Content-Disposition: attachment; filename=\"2.txt\"\r\n\
\r\n\
B\r\n\
--B--\r\n";

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits {
            max_email_attachments: 1,
            ..Default::default()
        };
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner.scan_bytes(raw_mime, None, &mut tracker).unwrap();
        assert_eq!(report.status, ScanStatus::Clean);
        assert_eq!(report.sub_targets.len(), 1);
        assert_eq!(
            report.incomplete,
            vec!["Only the first 1 MIME parts were inspected".to_string()]
        );
    }

    #[test]
    fn test_scan_bytes_enforces_file_size_limit() {
        let large_email = vec![b'A'; 2000];
        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits {
            max_file_size: 1000,
            ..Default::default()
        };
        let mut tracker = ResourceTracker::new(limits);

        let res = scanner.scan_bytes(&large_email, None, &mut tracker);
        assert!(res.is_err());
        match res.unwrap_err() {
            ScanError::FileSizeLimitExceeded { limit, actual } => {
                assert_eq!(limit, 1000);
                assert_eq!(actual, 2000);
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_scan_inline_attachment_covered() {
        let raw_mime = b"MIME-Version: 1.0\r\n\
From: sender@example.com\r\n\
To: recipient@example.com\r\n\
Subject: Inline Test\r\n\
Content-Type: multipart/related; boundary=\"REL_BOUND\"\r\n\
\r\n\
--REL_BOUND\r\n\
Content-Type: text/html\r\n\
\r\n\
<p>Look at inline payload</p>\r\n\
--REL_BOUND\r\n\
Content-Type: application/octet-stream\r\n\
Content-Disposition: inline; filename=\"inline_eicar.com\"\r\n\
\r\n\
X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\r\n\
--REL_BOUND--\r\n";

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(raw_mime, Some("inline.eml"), &mut tracker)
            .unwrap();
        assert_eq!(report.status, ScanStatus::Infected);
        assert!(!report.sub_targets.is_empty());
        assert_eq!(report.threats.len(), 1);
        assert_eq!(report.threats[0].name, "EICAR-Standard-Antivirus-Test-File");
    }

    #[test]
    fn test_truncated_mime_missing_boundary_terminator() {
        let malformed_data = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n\
--BOUND\r\n\
Content-Type: text/plain\r\n\r\n\
Partial data\r\n\
--BO";

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(malformed_data, Some("truncated.eml"), &mut tracker)
            .unwrap();

        assert_eq!(report.status, ScanStatus::Unsupported);
        assert!(report
            .error
            .as_ref()
            .unwrap()
            .contains("missing closing boundary delimiter '--BOUND--'"));
    }

    #[test]
    fn test_malformed_mime_missing_boundary_param() {
        let malformed_data = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed\r\n\r\n\
This multipart is missing the required boundary parameter.";

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(malformed_data, Some("no_boundary_param.eml"), &mut tracker)
            .unwrap();

        assert_eq!(report.status, ScanStatus::Unsupported);
        assert!(report
            .error
            .as_ref()
            .unwrap()
            .contains("missing required 'boundary' parameter"));
    }

    #[test]
    fn test_malformed_mime_boundary_not_found_in_body() {
        let malformed_data = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"MY_MISSING_BOUND\"\r\n\r\n\
The declared boundary was never placed in the email body.";

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(malformed_data, Some("missing_bound.eml"), &mut tracker)
            .unwrap();

        assert_eq!(report.status, ScanStatus::Unsupported);
        assert!(report
            .error
            .as_ref()
            .unwrap()
            .contains("boundary delimiter '--MY_MISSING_BOUND' not found"));
    }

    #[test]
    fn test_benign_email_with_unsupported_attachment() {
        let raw_mime = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n\
--BOUND\r\n\
Content-Type: text/plain\r\n\r\n\
Benign email message text.\r\n\
--BOUND\r\n\
Content-Type: application/octet-stream; name=\"corrupt.bin\"\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Disposition: attachment; filename=\"corrupt.bin\"\r\n\r\n\
!@#$%^&*()\r\n\
--BOUND--\r\n";

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(raw_mime, Some("unsupported_att.eml"), &mut tracker)
            .unwrap();

        assert_eq!(report.status, ScanStatus::Unsupported);
        assert_eq!(report.sub_targets.len(), 1);
        assert_eq!(report.sub_targets[0].status, ScanStatus::Unsupported);
        assert!(report.threats.is_empty());
    }

    #[test]
    fn test_oversized_attachment_is_partial_not_failed() {
        // Attachment exceeds max_email_attachment_size
        let raw_mime = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n\
--BOUND\r\n\
Content-Type: text/plain\r\n\r\n\
Benign message.\r\n\
--BOUND\r\n\
Content-Type: application/octet-stream; name=\"large.bin\"\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Disposition: attachment; filename=\"large.bin\"\r\n\r\n\
QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk=\r\n\
--BOUND--\r\n";

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits {
            max_email_attachment_size: 10, // Quota smaller than attachment length
            ..Default::default()
        };
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(raw_mime, Some("failed_att.eml"), &mut tracker)
            .unwrap();

        assert_eq!(report.status, ScanStatus::Clean);
        assert!(report.sub_targets.is_empty());
        assert!(report.incomplete[0].contains("larger than"));
    }

    #[test]
    fn test_infected_attachment_with_unsupported_attachment() {
        let eicar_b64 = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=";
        let raw_mime = format!(
            "MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n\
--BOUND\r\n\
Content-Type: text/plain\r\n\r\n\
Please inspect these two files.\r\n\
--BOUND\r\n\
Content-Type: application/x-dosexec\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Disposition: attachment; filename=\"eicar.com\"\r\n\r\n\
{}\r\n\
--BOUND\r\n\
Content-Type: application/octet-stream\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Disposition: attachment; filename=\"corrupt.bin\"\r\n\r\n\
!@#$%^&*()\r\n\
--BOUND--\r\n",
            eicar_b64
        );

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(raw_mime.as_bytes(), Some("mixed_threat.eml"), &mut tracker)
            .unwrap();

        // Document status precedence: Infected > Unsupported
        assert_eq!(report.status, ScanStatus::Infected);
        assert_eq!(report.threats.len(), 1);
        assert_eq!(report.threats[0].name, "EICAR-Standard-Antivirus-Test-File");
        assert_eq!(report.sub_targets.len(), 2);
        assert_eq!(report.sub_targets[0].status, ScanStatus::Infected);
        assert_eq!(report.sub_targets[1].status, ScanStatus::Unsupported);
    }

    #[test]
    fn test_malformed_attachment_with_otherwise_benign_content() {
        let raw_mime = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n\
--BOUND\r\n\
Content-Type: text/plain\r\n\r\n\
Benign email message text.\r\n\
--BOUND\r\n\
Content-Type: application/octet-stream; name=\"bad_pad.bin\"\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Disposition: attachment; filename=\"bad_pad.bin\"\r\n\r\n\
AAAA====\r\n\
--BOUND--\r\n";

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(raw_mime, Some("bad_pad.eml"), &mut tracker)
            .unwrap();

        // Malformed attachment must not yield Clean!
        assert_eq!(report.status, ScanStatus::Unsupported);
        assert_eq!(report.sub_targets.len(), 1);
        assert_eq!(report.sub_targets[0].status, ScanStatus::Unsupported);
        assert!(report.sub_targets[0]
            .error
            .as_ref()
            .unwrap()
            .contains("excessive base64 padding"));
    }

    #[test]
    fn test_mixed_valid_and_invalid_parts() {
        let raw_mime = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n\
--BOUND\r\n\
Content-Type: text/plain\r\n\r\n\
Part 1 is valid clean text.\r\n\
--BOUND\r\n\
Content-Type: application/octet-stream; name=\"clean.bin\"\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Disposition: attachment; filename=\"clean.bin\"\r\n\r\n\
dGVzdA==\r\n\
--BOUND\r\n\
Content-Type: application/octet-stream; name=\"trunc.bin\"\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Disposition: attachment; filename=\"trunc.bin\"\r\n\r\n\
QUJ\r\n\
--BOUND--\r\n";

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(raw_mime, Some("mixed_parts.eml"), &mut tracker)
            .unwrap();

        // One invalid attachment makes the uninfected container Unsupported
        assert_eq!(report.status, ScanStatus::Unsupported);
        assert_eq!(report.sub_targets.len(), 2);
        assert_eq!(report.sub_targets[0].status, ScanStatus::Clean);
        assert_eq!(report.sub_targets[1].status, ScanStatus::Unsupported);
        assert!(report.sub_targets[1]
            .error
            .as_ref()
            .unwrap()
            .contains("truncated base64 stream"));
    }

    #[test]
    fn test_malformed_quoted_printable_attachment() {
        let raw_mime = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n\
--BOUND\r\n\
Content-Type: text/plain\r\n\r\n\
Benign text body.\r\n\
--BOUND\r\n\
Content-Type: text/plain; name=\"corrupt_qp.txt\"\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
Content-Disposition: attachment; filename=\"corrupt_qp.txt\"\r\n\r\n\
Hello world=ZZ invalid escape\r\n\
--BOUND--\r\n";

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(raw_mime, Some("corrupt_qp.eml"), &mut tracker)
            .unwrap();

        assert_eq!(report.status, ScanStatus::Unsupported);
        assert_eq!(report.sub_targets.len(), 1);
        assert_eq!(report.sub_targets[0].status, ScanStatus::Unsupported);
        assert!(report.sub_targets[0]
            .error
            .as_ref()
            .unwrap()
            .contains("invalid hex sequence following '='"));
    }

    fn make_test_tar(name: &str, content: &[u8]) -> Vec<u8> {
        let mut tar = vec![0u8; 512];
        let name_bytes = name.as_bytes();
        tar[..name_bytes.len()].copy_from_slice(name_bytes);
        tar[100..108].copy_from_slice(b"0000644\0");
        tar[108..116].copy_from_slice(b"0000000\0");
        tar[116..124].copy_from_slice(b"0000000\0");
        let size_str = format!("{:011o}\0", content.len());
        tar[124..136].copy_from_slice(size_str.as_bytes());
        tar[136..148].copy_from_slice(b"00000000000\0");
        tar[156] = b'0';
        tar[257..263].copy_from_slice(b"ustar\0");
        tar[263..265].copy_from_slice(b"00");
        tar[148..156].copy_from_slice(b"        ");
        let chksum: u32 = tar.iter().map(|&b| b as u32).sum();
        let chksum_str = format!("{:06o}\0 ", chksum);
        tar[148..156].copy_from_slice(chksum_str.as_bytes());

        tar.extend_from_slice(content);
        let pad = (512 - (content.len() % 512)) % 512;
        tar.extend(vec![0u8; pad]);
        tar.extend(vec![0u8; 1024]);
        tar
    }

    #[test]
    fn test_tar_archive_members_are_extracted_and_scanned() {
        let tar_data = make_test_tar("clean_document.txt", b"Benign text content inside TAR.");
        let db = SignatureDatabase::new();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_object(
                &tar_data,
                "archive.tar",
                Some("application/x-tar"),
                &mut tracker,
                0,
            )
            .unwrap();

        assert_eq!(report.status, ScanStatus::Clean, "{:?}", report.error);
        assert_eq!(report.sub_targets.len(), 1);
        assert!(report.incomplete.is_empty());
    }

    #[test]
    fn test_tar_archive_with_malware_member_is_detected() {
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let tar_data = make_test_tar("eicar.txt", eicar);

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_object(
                &tar_data,
                "eicar_payload.tar",
                Some("application/x-tar"),
                &mut tracker,
                0,
            )
            .unwrap();

        assert_eq!(report.status, ScanStatus::Infected);
        assert_eq!(report.sub_targets[0].status, ScanStatus::Infected);
    }

    #[test]
    fn test_truncated_tar_produces_unsupported() {
        let truncated_tar = b"ustar archive truncated before header complete";
        let db = SignatureDatabase::new();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_object(
                truncated_tar,
                "damaged.tar",
                Some("application/x-tar"),
                &mut tracker,
                0,
            )
            .unwrap();

        assert_eq!(report.status, ScanStatus::Unsupported);
        assert!(report.error.as_ref().unwrap().contains("TAR"));
    }

    #[test]
    fn test_nested_tar_inside_zip_is_scanned() {
        use std::io::Write;
        let tar_data = make_test_tar("inner.txt", b"Safe inner text");

        let mut zip_buf = std::io::Cursor::new(Vec::new());
        {
            let mut zip_writer = zip::ZipWriter::new(&mut zip_buf);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            zip_writer
                .start_file("nested_archive.tar", options)
                .unwrap();
            zip_writer.write_all(&tar_data).unwrap();
            zip_writer.finish().unwrap();
        }
        let zip_bytes = zip_buf.into_inner();

        let db = SignatureDatabase::new();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_object(
                &zip_bytes,
                "outer.zip",
                Some("application/zip"),
                &mut tracker,
                0,
            )
            .unwrap();

        assert_eq!(report.status, ScanStatus::Clean, "{:?}", report.error);
        assert_eq!(report.sub_targets.len(), 1);
        assert_eq!(report.sub_targets[0].sub_targets.len(), 1);
    }

    fn base64_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0];
            let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
            out.push(ALPHABET[(b0 >> 2) as usize] as char);
            out.push(ALPHABET[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[(((b1 & 0xf) << 2) | (b2 >> 6)) as usize] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[(b2 & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    // ---------------------------------------------------------------------------
    // Fix 3 Validation Tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_valid_multipart_message() {
        let raw_mime = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"VALID_BOUND\"\r\n\r\n\
--VALID_BOUND\r\n\
Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n\
Clean body content.\r\n\
--VALID_BOUND--\r\n";

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(raw_mime, Some("valid.eml"), &mut tracker)
            .unwrap();

        assert_eq!(report.status, ScanStatus::Clean);
        assert!(report.threats.is_empty());
    }

    #[test]
    fn test_missing_closing_boundary() {
        let raw_mime = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n\
--BOUND\r\n\
Content-Type: text/plain\r\n\r\n\
Some body text without closing boundary delimiter.";

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(raw_mime, Some("missing_close.eml"), &mut tracker)
            .unwrap();

        assert_eq!(report.status, ScanStatus::Unsupported);
        assert!(report
            .error
            .as_ref()
            .unwrap()
            .contains("missing closing boundary delimiter '--BOUND--'"));
    }

    #[test]
    fn test_closing_delimiter_embedded_inside_body() {
        // Substring inside ordinary body line must not satisfy closing boundary check
        let raw_mime1 = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n\
--BOUND\r\n\
Content-Type: text/plain\r\n\r\n\
Here is some text with --BOUND-- embedded in the middle of a line.\r\n";

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let mut tracker1 = ResourceTracker::new(ResourceLimits::default());

        let report1 = scanner
            .scan_bytes(raw_mime1, Some("embedded_in_line.eml"), &mut tracker1)
            .unwrap();

        assert_eq!(report1.status, ScanStatus::Unsupported);
        assert!(report1
            .error
            .as_ref()
            .unwrap()
            .contains("missing closing boundary delimiter '--BOUND--'"));

        // Boundary delimiter text followed by additional parts without final closing delimiter
        let raw_mime2 = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n\
--BOUND\r\n\
Content-Type: text/plain\r\n\r\n\
First part.\r\n\
--BOUND--\r\n\
--BOUND\r\n\
Content-Type: text/plain\r\n\r\n\
Second part after closing delimiter line.\r\n";

        let mut tracker2 = ResourceTracker::new(ResourceLimits::default());
        let report2 = scanner
            .scan_bytes(raw_mime2, Some("embedded_middle.eml"), &mut tracker2)
            .unwrap();

        assert_eq!(report2.status, ScanStatus::Unsupported);
    }

    #[test]
    fn test_nested_multipart_message() {
        let valid_nested = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"OUTER\"\r\n\r\n\
--OUTER\r\n\
Content-Type: multipart/alternative; boundary=\"INNER\"\r\n\r\n\
--INNER\r\n\
Content-Type: text/plain\r\n\r\n\
Plain text version.\r\n\
--INNER\r\n\
Content-Type: text/html\r\n\r\n\
<b>HTML version</b>\r\n\
--INNER--\r\n\
--OUTER\r\n\
Content-Type: text/plain; name=\"note.txt\"\r\n\
Content-Disposition: attachment; filename=\"note.txt\"\r\n\r\n\
Attachment content.\r\n\
--OUTER--\r\n";

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let mut tracker = ResourceTracker::new(ResourceLimits::default());

        let report = scanner
            .scan_bytes(valid_nested, Some("nested.eml"), &mut tracker)
            .unwrap();
        assert_eq!(report.status, ScanStatus::Clean);

        // Nested message where inner closing boundary delimiter is missing
        let missing_inner = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"OUTER\"\r\n\r\n\
--OUTER\r\n\
Content-Type: multipart/alternative; boundary=\"INNER\"\r\n\r\n\
--INNER\r\n\
Content-Type: text/plain\r\n\r\n\
Plain text version.\r\n\
--OUTER\r\n\
Content-Type: text/plain; name=\"note.txt\"\r\n\
Content-Disposition: attachment; filename=\"note.txt\"\r\n\r\n\
Attachment content.\r\n\
--OUTER--\r\n";

        let mut tracker2 = ResourceTracker::new(ResourceLimits::default());
        let report2 = scanner
            .scan_bytes(missing_inner, Some("missing_inner.eml"), &mut tracker2)
            .unwrap();
        assert_eq!(report2.status, ScanStatus::Unsupported);
        assert!(report2
            .error
            .as_ref()
            .unwrap()
            .contains("missing sub-part boundary delimiter '--INNER--'"));
    }

    #[test]
    fn test_truncated_final_attachment() {
        let truncated = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\r\n\
--BOUND\r\n\
Content-Type: text/plain\r\n\r\n\
Initial body.\r\n\
--BOUND\r\n\
Content-Type: application/octet-stream; name=\"data.bin\"\r\n\
Content-Disposition: attachment; filename=\"data.bin\"\r\n\r\n\
Binary data truncated right here";

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(truncated, Some("truncated_att.eml"), &mut tracker)
            .unwrap();
        assert_eq!(report.status, ScanStatus::Unsupported);
        assert!(report
            .error
            .as_ref()
            .unwrap()
            .contains("missing closing boundary delimiter '--BOUND--'"));
    }

    #[test]
    fn test_valid_crlf_formatting() {
        // Test RFC 2046 compliant CRLF formatting with optional linear whitespace before line ends
        let crlf_mime = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"CRLF_BOUND\"\r\n\r\n\
--CRLF_BOUND \r\n\
Content-Type: text/plain\r\n\r\n\
Clean line 1\r\n\
Clean line 2\r\n\
--CRLF_BOUND--  \t  \r\n";

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(crlf_mime, Some("crlf.eml"), &mut tracker)
            .unwrap();
        assert_eq!(report.status, ScanStatus::Clean);
    }

    #[test]
    fn test_zip_attachment_detection_preserved() {
        let eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let mut zip_buf = std::io::Cursor::new(Vec::new());
        {
            let mut zip_writer = zip::ZipWriter::new(&mut zip_buf);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip_writer.start_file("eicar.com", options).unwrap();
            zip_writer.write_all(eicar_bytes).unwrap();
            zip_writer.finish().unwrap();
        }
        let zip_bytes = zip_buf.into_inner();
        let encoded_zip = base64_encode(&zip_bytes);

        let mime = format!(
            "MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"ZIP_BOUND\"\r\n\r\n\
--ZIP_BOUND\r\n\
Content-Type: text/plain\r\n\r\n\
Please review the attached archive.\r\n\
--ZIP_BOUND\r\n\
Content-Type: application/zip; name=\"test.zip\"\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Disposition: attachment; filename=\"test.zip\"\r\n\r\n\
{}\r\n\
--ZIP_BOUND--\r\n",
            encoded_zip
        );

        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        let report = scanner
            .scan_bytes(mime.as_bytes(), Some("zip_threat.eml"), &mut tracker)
            .unwrap();

        assert_eq!(report.status, ScanStatus::Infected);
        assert!(report.threats.iter().any(|t| t.name.contains("EICAR")));
        assert_eq!(report.sub_targets.len(), 1);
        assert_eq!(report.sub_targets[0].status, ScanStatus::Infected);
    }
}
