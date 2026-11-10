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
use raxosentinel_core::{
    hash_bytes, ResourceTracker, ScanError, ScanReport, ScanStatus, TargetMetadata, Threat,
};
use raxosentinel_filetypes::{check_extension_mismatch, detect_type, is_tar_header};
use raxosentinel_signatures::SignatureDatabase;
use std::path::Path;

mod archive;
use archive::StreamFormat;
mod extract;
mod pdf;
mod pdf_decode;

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
                for t in self.match_yara(raw_bytes, tracker)? {
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
        let mut sub_reports: Vec<ScanReport> = Vec::new();

        // 1. Check raw email hash (builtin rules and RSIDB)
        if let Some(hash_threat) = self.db.match_hash(&sha256) {
            threats.push(hash_threat.with_location("email_root"));
        }
        for t in self.db.match_rsidb(raw_bytes) {
            threats.push(t.with_location("email_root"));
        }
        // Optional YARA-X rules over the raw message.
        for t in self.match_yara(raw_bytes, tracker)? {
            threats.push(t.with_location("email_root"));
        }

        // 2. Scan email bodies (text and html)
        self.scan_bodies(&parsed, &mut threats, tracker)?;

        // 3. Scan attachments and embedded parts (including inline payloads)
        self.scan_attachments(
            raw_bytes,
            &parsed,
            &mut threats,
            &mut sub_reports,
            tracker,
            depth,
        )?;

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
        ))
    }

    fn scan_bodies(
        &self,
        msg: &Message,
        threats: &mut Vec<Threat>,
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
            }
        }

        Ok(())
    }

    fn scan_attachments(
        &self,
        raw_bytes: &[u8],
        msg: &Message,
        threats: &mut Vec<Threat>,
        sub_reports: &mut Vec<ScanReport>,
        tracker: &mut ResourceTracker,
        depth: usize,
    ) -> Result<(), ScanError> {
        // 1. Scan explicit attachments
        for (idx, attachment) in msg.attachments().enumerate() {
            tracker.check_timeout()?;

            let filename = attachment
                .attachment_name()
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("attachment_{}", idx));

            let declared_mime = attachment
                .content_type()
                .map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("*")));

            // Pre-check estimated decoded length to prevent Base64 / QP memory expansion bomb!
            let estimated_size = attachment.decoded_len() as u64;
            if let Err(e) = tracker.register_attachment(estimated_size) {
                match e {
                    ScanError::AttachmentLimitExceeded { .. }
                    | ScanError::ExtractedSizeLimitExceeded { .. }
                    | ScanError::Timeout { .. } => return Err(e),
                    _ => {
                        let sub_report = ScanReport::new(
                            TargetMetadata {
                                path: None,
                                file_name: Some(filename),
                                file_size_bytes: estimated_size,
                                sha256: String::new(),
                                detected_mime: "application/octet-stream".to_string(),
                                declared_mime,
                            },
                            ScanStatus::Failed,
                            Vec::new(),
                            Vec::new(),
                            0,
                            Some(format!("Attachment quota error: {}", e)),
                        );
                        sub_reports.push(sub_report);
                        continue;
                    }
                }
            }

            let decoded_data = attachment.decoded();

            let sub_report_res = self.scan_single_attachment(
                &filename,
                declared_mime.as_deref(),
                &attachment,
                raw_bytes,
                &decoded_data,
                tracker,
                depth,
            );

            match sub_report_res {
                Ok(sub_report) => {
                    for t in &sub_report.threats {
                        threats.push(t.clone());
                    }
                    sub_reports.push(sub_report);
                }
                Err(e) => match e {
                    ScanError::Timeout { .. } => return Err(e),
                    _ => {
                        let sub_report = ScanReport::new(
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
                        );
                        sub_reports.push(sub_report);
                    }
                },
            }
        }

        // 2. Scan other parts (e.g. inline attachments, unclassified non-body parts)
        for (idx, part) in msg.other_parts().enumerate() {
            tracker.check_timeout()?;
            if part.in_text_body() || part.in_html_body() {
                continue;
            }

            let filename = part
                .attachment_name()
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("inline_part_{}", idx));

            let declared_mime = part
                .content_type()
                .map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("*")));

            let estimated_size = part.decoded_len() as u64;
            if let Err(e) = tracker.register_attachment(estimated_size) {
                match e {
                    ScanError::AttachmentLimitExceeded { .. }
                    | ScanError::ExtractedSizeLimitExceeded { .. }
                    | ScanError::Timeout { .. } => return Err(e),
                    _ => {
                        let sub_report = ScanReport::new(
                            TargetMetadata {
                                path: None,
                                file_name: Some(filename),
                                file_size_bytes: estimated_size,
                                sha256: String::new(),
                                detected_mime: "application/octet-stream".to_string(),
                                declared_mime,
                            },
                            ScanStatus::Failed,
                            Vec::new(),
                            Vec::new(),
                            0,
                            Some(format!("Attachment quota error: {}", e)),
                        );
                        sub_reports.push(sub_report);
                        continue;
                    }
                }
            }

            let decoded_data = part.decoded();

            let sub_report_res = self.scan_single_attachment(
                &filename,
                declared_mime.as_deref(),
                &part,
                raw_bytes,
                &decoded_data,
                tracker,
                depth,
            );

            match sub_report_res {
                Ok(sub_report) => {
                    for t in &sub_report.threats {
                        threats.push(t.clone());
                    }
                    sub_reports.push(sub_report);
                }
                Err(e) => match e {
                    ScanError::Timeout { .. } => return Err(e),
                    _ => {
                        let sub_report = ScanReport::new(
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
                        );
                        sub_reports.push(sub_report);
                    }
                },
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

        let sha256 = hash_bytes(data);
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
                return Ok(ScanReport::new(
                    report.target,
                    ScanStatus::Unsupported,
                    report.threats,
                    report.sub_targets,
                    duration_ms,
                    Some(issue),
                ));
            }
        }
        let _ = sha256;
        Ok(report)
    }

    /// Optional YARA-X rules over a complete object; a rule-evaluation timeout is a
    /// scan timeout reported with the elapsed scan time.
    fn match_yara(
        &self,
        data: &[u8],
        tracker: &ResourceTracker,
    ) -> Result<Vec<Threat>, ScanError> {
        self.db
            .match_yara(data, tracker.remaining())
            .map_err(|e| match e {
                ScanError::Timeout { .. } => tracker.timeout_error(),
                other => other,
            })
    }

    /// Scans one complete, already-extracted object (raw file, decoded attachment or
    /// archive member): extension mismatch, builtin SHA-256 rules, RSIDB exact-hash
    /// lookups, byte patterns, and bounded recursion into supported containers.
    ///
    /// Verdict precedence: Infected > Failed > Unsupported > Clean. Archives that cannot
    /// be fully inspected (encrypted, unsupported format/method, limits) are never Clean.
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
        // Optional YARA-X rules; a rule-evaluation timeout is a scan timeout.
        for t in self.match_yara(data, tracker)? {
            threats.push(t.with_location(location.clone()));
        }
        tracker.check_timeout()?;

        // PDF structure is inspected first so container signatures inside its
        // already-inspected streams are not mistaken for embedded archives.
        let mut pdf = match pdf::header_offset(data) {
            Some(base) => Some(self.inspect_pdf(data, base, filename, tracker, depth + 1)?),
            None => None,
        };
        let spans = pdf
            .as_mut()
            .map(|p| std::mem::take(&mut p.scanned_spans))
            .unwrap_or_default();
        let inspected_spans = spans.as_slice();

        let mut sub_reports = Vec::new();
        let mut container_issue: Option<(ScanStatus, String)> = None;
        let inspected = match classify_container(data, filename, declared_mime, inspected_spans) {
            ContainerKind::Zip => {
                Some(self.scan_zip(data, filename, inspected_spans, tracker, depth + 1)?)
            }
            ContainerKind::Tar => Some(self.scan_tar(data, filename, tracker, depth + 1)?),
            ContainerKind::Compressed(format) => {
                Some(self.scan_compressed(format, data, filename, tracker, depth + 1)?)
            }
            ContainerKind::Cfb => Some(self.scan_cfb(data, filename, tracker, depth + 1)?),
            ContainerKind::Unsupported(kind) => {
                container_issue = Some((
                    ScanStatus::Unsupported,
                    format!(
                        "ARCHIVE_UNSUPPORTED_FORMAT: {} container cannot be extracted; \
                         contents not inspected",
                        kind
                    ),
                ));
                None
            }
            ContainerKind::None => None,
        };
        let mut swept_spans = spans.clone();
        if let Some(inspected) = inspected {
            sub_reports = inspected.subs;
            container_issue = inspected.issue;
            swept_spans.extend(inspected.covered);
        }

        if let Some(pdf) = pdf {
            sub_reports.extend(pdf.reports);
            threats.extend(pdf.threats);
            container_issue = more_severe(container_issue, pdf.issue);
        }

        // Recognizable unsupported embedded containers cannot be silently treated
        // as fully inspected, even when the outer object is another format.
        if container_issue.is_none() {
            tracker.check_timeout()?;
            if let Some(kind) = embedded_container_magic(data, &swept_spans) {
                container_issue = Some((
                    ScanStatus::Unsupported,
                    format!(
                        "Possible embedded {} container; contents not inspected",
                        kind
                    ),
                ));
            }
        }

        for sr in &sub_reports {
            threats.extend(sr.threats.iter().cloned());
        }
        let threats = SignatureDatabase::deduplicate_threats(threats);
        let (status, details) = combine_verdict(&threats, container_issue, &sub_reports);
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
            sub_reports,
            duration_ms,
            details,
        ))
    }
}

enum ContainerKind {
    None,
    Zip,
    Tar,
    Compressed(StreamFormat),
    Cfb,
    Unsupported(&'static str),
}

/// Content-based container classification, with fallback to declared metadata
/// for truncated or incomplete containers that cannot be safely inspected.
fn classify_container(
    data: &[u8],
    filename: &str,
    declared_mime: Option<&str>,
    inspected_spans: &[(usize, usize)],
) -> ContainerKind {
    if find_outside(data, b"PK\x03\x04", inspected_spans).is_some()
        || data.starts_with(b"PK\x05\x06")
        || (!inspected_spans.is_empty()
            && find_outside(data, b"PK\x05\x06", inspected_spans).is_some())
        || filename.to_ascii_lowercase().ends_with(".zip")
        || declared_mime.is_some_and(|m| m.eq_ignore_ascii_case("application/zip"))
    {
        ContainerKind::Zip
    } else if is_tar_header(data) || is_tar_claim(data, filename, declared_mime) {
        ContainerKind::Tar
    } else if data.starts_with(b"Rar!\x1a\x07") {
        ContainerKind::Unsupported("RAR")
    } else if data.starts_with(b"7z\xbc\xaf\x27\x1c") {
        ContainerKind::Unsupported("7-Zip")
    } else if data.starts_with(&[0x1f, 0x8b]) {
        ContainerKind::Compressed(StreamFormat::Gzip)
    } else if data.starts_with(b"BZh") && data.len() > 3 && data[3].is_ascii_digit() {
        ContainerKind::Compressed(StreamFormat::Bzip2)
    } else if data.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        ContainerKind::Compressed(StreamFormat::Xz)
    } else if data.starts_with(b"MSCF") {
        ContainerKind::Unsupported("CAB")
    } else if data.starts_with(OLE2_MAGIC) {
        ContainerKind::Cfb
    } else {
        ContainerKind::None
    }
}

const OLE2_MAGIC: &[u8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";

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

/// First occurrence of `needle` not inside an already-inspected span.
fn find_outside(data: &[u8], needle: &[u8], skip: &[(usize, usize)]) -> Option<usize> {
    memchr::memmem::find_iter(data, needle)
        .find(|&pos| !skip.iter().any(|&(start, end)| start <= pos && pos < end))
}

/// Finds a signature of an unsupported (or not separately extracted) container
/// format outside inspected spans. Candidates are validated beyond the magic bytes
/// so random binary data does not trigger false UNSCANNED results; a candidate cut
/// off by the end of the data cannot be ruled out and still counts.
fn embedded_container_magic(data: &[u8], skip: &[(usize, usize)]) -> Option<&'static str> {
    let candidates = unsupported_container_candidates();
    for (magic, kind, valid) in candidates {
        // A leading GZIP stream is the object itself and is decoded separately.
        if kind == "GZIP" && data.starts_with(magic) {
            continue;
        }
        let found = memchr::memmem::find_iter(data, magic).any(|pos| {
            !skip.iter().any(|&(start, end)| start <= pos && pos < end) && valid(&data[pos..])
        });
        if found {
            return Some(kind);
        }
    }
    None
}

type Validator = fn(&[u8]) -> bool;
type Candidate = (&'static [u8], &'static str, Validator);

/// Signatures of containers not separately extracted when embedded in another
/// object. `rest` starts at the candidate; each validator returns false only when
/// the bytes present contradict the format.
fn unsupported_container_candidates() -> [Candidate; 6] {
    [
        (b"Rar!\x1a\x07", "RAR", |r| match r.get(6) {
            None => true,
            Some(0) => true,
            Some(1) => r.get(7).is_none_or(|&b| b == 0),
            _ => false,
        }),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip", |r| {
            r.get(6).is_none_or(|&b| b == 0)
        }),
        (b"\x1f\x8b\x08", "GZIP", |r| {
            r.get(3).is_none_or(|&flags| flags & 0xe0 == 0)
                && r.get(8).is_none_or(|&xfl| matches!(xfl, 0 | 2 | 4))
                && r.get(9).is_none_or(|&os| os <= 13 || os == 255)
        }),
        (b"BZh", "BZIP2", |r| {
            const BLOCK: &[u8] = b"\x31\x41\x59\x26\x53\x59";
            const END: &[u8] = b"\x17\x72\x45\x38\x50\x90";
            let tail = r.get(4..).unwrap_or_default();
            let n = tail.len().min(6);
            r.get(3).is_none_or(|&level| (b'1'..=b'9').contains(&level))
                && (tail[..n] == BLOCK[..n] || tail[..n] == END[..n])
        }),
        (b"\xfd7zXZ\x00", "XZ", |r| {
            r.get(6).is_none_or(|&b| b == 0)
                && r.get(7)
                    .is_none_or(|&check| matches!(check, 0x00 | 0x01 | 0x04 | 0x0a))
        }),
        (b"MSCF", "CAB", |r| {
            let reserved = r.get(4..8).unwrap_or(r.get(4..).unwrap_or_default());
            reserved.iter().all(|&b| b == 0)
        }),
    ]
}

/// Plausible ZIP local file header: version, flags, method and name length.
fn plausible_zip_local_header(r: &[u8]) -> bool {
    let u16_at = |i: usize| r.get(i..i + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    u16_at(4).is_none_or(|v| v <= 100)
        && u16_at(6).is_none_or(|flags| flags & 0xc780 == 0 || flags & 0x0001 != 0)
        && u16_at(8).is_none_or(|m| matches!(m, 0..=20 | 93 | 95 | 96 | 97 | 98 | 99))
        && u16_at(26).is_none_or(|n| (1..=4096).contains(&n))
}

/// Container signatures searched for in objects inspected in streaming mode, which
/// cannot be unpacked recursively. Stronger validation than the buffered path keeps
/// random image data from producing false UNSCANNED results.
fn streamed_container_candidates() -> Vec<Candidate> {
    let mut list: Vec<Candidate> = vec![
        (b"PK\x03\x04", "ZIP", plausible_zip_local_header),
        (b"%PDF-", "PDF", |r| {
            r.get(5).is_none_or(|b| b.is_ascii_digit()) && r.get(6).is_none_or(|&b| b == b'.')
        }),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2/CFB", |_| true),
    ];
    list.extend(unsupported_container_candidates());
    list
}

/// Identifies a container format from the start of an object.
fn container_head(head: &[u8]) -> Option<&'static str> {
    if head.starts_with(b"PK\x03\x04") || head.starts_with(b"PK\x05\x06") {
        return Some("ZIP");
    }
    if pdf::header_offset(head).is_some() {
        return Some("PDF");
    }
    if head.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        return Some("OLE2/CFB");
    }
    if is_tar_header(head) {
        return Some("TAR");
    }
    unsupported_container_candidates()
        .into_iter()
        .find(|(magic, _, valid)| head.starts_with(magic) && valid(head))
        .map(|(_, kind, _)| kind)
}

/// Keeps the more severe of two inspection issues (Failed > Unsupported).
fn more_severe(
    a: Option<(ScanStatus, String)>,
    b: Option<(ScanStatus, String)>,
) -> Option<(ScanStatus, String)> {
    match (&a, &b) {
        (None, _) => b,
        (Some((ScanStatus::Unsupported, _)), Some((ScanStatus::Failed, _))) => b,
        _ => a,
    }
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
                    },
                    "{:?}",
                    report.error
                );
                assert!(!report.sub_targets.is_empty());
                // An exhausted buffered budget switches to streaming, which still
                // inspects every byte; only exhausting the streamed budget as well
                // leaves content uninspected, and that must never be CLEAN.
                let mut tracker = ResourceTracker::new(ResourceLimits {
                    max_total_extracted_bytes: 1,
                    ..Default::default()
                });
                assert_eq!(
                    scanner
                        .scan_object(&data, "buffer-exhausted.pdf", None, &mut tracker, 0)
                        .unwrap()
                        .status,
                    report.status
                );
                let mut tracker = ResourceTracker::new(ResourceLimits {
                    max_total_extracted_bytes: 1,
                    max_total_streamed_bytes: 1,
                    ..Default::default()
                });
                assert_ne!(
                    scanner
                        .scan_object(&data, "limited.pdf", None, &mut tracker, 0)
                        .unwrap()
                        .status,
                    ScanStatus::Clean
                );
            }
        }
        let mut tracker = ResourceTracker::new(ResourceLimits::default());
        assert_eq!(
            scanner
                .scan_object(b"%PDF-1.4\ntruncated", "broken.pdf", None, &mut tracker, 0)
                .unwrap()
                .status,
            ScanStatus::Unsupported
        );
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
            max_archive_members: 1,
            ..Default::default()
        });
        let limited = scanner
            .scan_object(&data, "limited.gz", None, &mut tracker, 0)
            .unwrap();
        assert_eq!(limited.status, ScanStatus::Failed);
        assert!(limited.error.unwrap().contains("ARCHIVE_LIMIT"));
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
    fn test_email_attachment_limit_exceeded() {
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

        let res = scanner.scan_bytes(raw_mime, None, &mut tracker);
        assert!(res.is_err());
        match res.unwrap_err() {
            ScanError::AttachmentLimitExceeded { limit } => assert_eq!(limit, 1),
            other => panic!("Unexpected error: {:?}", other),
        }
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
    fn test_benign_email_with_failed_attachment_scan() {
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

        assert_eq!(report.status, ScanStatus::Failed);
        assert_eq!(report.sub_targets.len(), 1);
        assert_eq!(report.sub_targets[0].status, ScanStatus::Failed);
        assert!(report.sub_targets[0]
            .error
            .as_ref()
            .unwrap()
            .contains("Attachment quota error"));
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
    fn test_tar_archive_members_are_inspected() {
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
        assert_eq!(
            report.sub_targets[0].target.file_name.as_deref(),
            Some("archive.tar/clean_document.txt")
        );
    }

    #[test]
    fn test_tar_member_malware_is_detected() {
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
        assert!(report.threats.iter().any(|t| t.name.contains("EICAR")));

        // A truncated copy of the same archive is never CLEAN.
        let mut tracker = ResourceTracker::new(ResourceLimits::default());
        let truncated = scanner
            .scan_object(&tar_data[..600], "cut.tar", None, &mut tracker, 0)
            .unwrap();
        assert_ne!(truncated.status, ScanStatus::Clean);
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
    fn test_nested_tar_inside_zip_is_inspected() {
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
        assert_eq!(report.sub_targets[0].status, ScanStatus::Clean);
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
