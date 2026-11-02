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
use raxosentinel_filetypes::{check_extension_mismatch, detect_type};
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
        let max_sz = tracker.limits().max_file_size;
        let mut file = std::fs::File::open(path).map_err(|e| ScanError::IoWithPath {
            path: path.to_path_buf(),
            source: e,
        })?;
        let mut bytes = Vec::with_capacity(metadata.len().min(max_sz) as usize);
        file.by_ref()
            .take(max_sz.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|e| ScanError::IoWithPath {
                path: path.to_path_buf(),
                source: e,
            })?;
        if bytes.len() as u64 > max_sz {
            return Err(ScanError::FileSizeLimitExceeded {
                limit: max_sz,
                actual: bytes.len() as u64,
            });
        }

        tracker.record_bytes_read(bytes.len())?;
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
        tracker.check_timeout()?;

        let mut sub_reports = Vec::new();
        let mut container_issue: Option<(ScanStatus, String)> = None;
        match classify_container(data) {
            ContainerKind::Zip => {
                let (subs, issue) = self.scan_zip(data, filename, tracker, depth + 1)?;
                sub_reports = subs;
                container_issue = issue;
            }
            ContainerKind::Unsupported(kind) => {
                container_issue = Some((
                    ScanStatus::Unsupported,
                    format!(
                        "{} container cannot be extracted; contents not inspected",
                        kind
                    ),
                ));
            }
            ContainerKind::None => {}
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

    /// Extracts and scans ZIP members in memory under the shared resource budget.
    /// Never writes to disk; member names are used only as display labels.
    #[allow(clippy::type_complexity)]
    fn scan_zip(
        &self,
        data: &[u8],
        parent: &str,
        tracker: &mut ResourceTracker,
        depth: usize,
    ) -> Result<(Vec<ScanReport>, Option<(ScanStatus, String)>), ScanError> {
        use std::io::Read;
        let mut subs = Vec::new();

        if let Err(e) = tracker.check_depth(depth) {
            if matches!(e, ScanError::Timeout { .. }) {
                return Err(e);
            }
            return Ok((
                subs,
                Some((ScanStatus::Failed, format!("ZIP not inspected: {}", e))),
            ));
        }

        let mut archive = match zip::ZipArchive::new(std::io::Cursor::new(data)) {
            Ok(a) => a,
            Err(e) => {
                return Ok((
                    subs,
                    Some((
                        ScanStatus::Unsupported,
                        format!("Malformed ZIP container: {}", e),
                    )),
                ))
            }
        };

        let max_entries = tracker.limits().max_email_attachments;
        if archive.len() > max_entries {
            return Ok((
                subs,
                Some((
                    ScanStatus::Failed,
                    format!("ZIP has {} entries (limit {})", archive.len(), max_entries),
                )),
            ));
        }

        let cap = tracker.limits().max_email_attachment_size;
        let mut issue: Option<(ScanStatus, String)> = None;
        let raise = |issue: &mut Option<(ScanStatus, String)>, st: ScanStatus, msg: String| {
            let replace = match issue {
                None => true,
                Some((cur, _)) => *cur == ScanStatus::Unsupported && st == ScanStatus::Failed,
            };
            if replace {
                *issue = Some((st, msg));
            }
        };

        for i in 0..archive.len() {
            tracker.check_timeout()?;
            let mut file = match archive.by_index(i) {
                Ok(f) => f,
                Err(zip::result::ZipError::UnsupportedArchive(m)) => {
                    raise(
                        &mut issue,
                        ScanStatus::Unsupported,
                        format!("ZIP member {} not inspectable: {}", i, m),
                    );
                    continue;
                }
                Err(e) => {
                    raise(
                        &mut issue,
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
                raise(
                    &mut issue,
                    ScanStatus::Unsupported,
                    format!("Encrypted ZIP member: {}", label),
                );
                continue;
            }

            let declared = file.size();
            if let Err(e) = tracker.register_attachment(declared) {
                match e {
                    ScanError::Timeout { .. } => return Err(e),
                    ScanError::AttachmentLimitExceeded { .. }
                    | ScanError::ExtractedSizeLimitExceeded { .. } => {
                        raise(
                            &mut issue,
                            ScanStatus::Failed,
                            format!("ZIP extraction budget exhausted: {}", e),
                        );
                        break;
                    }
                    _ => {
                        raise(
                            &mut issue,
                            ScanStatus::Failed,
                            format!("ZIP member {} rejected: {}", label, e),
                        );
                        continue;
                    }
                }
            }

            // Never trust declared sizes: hard cap actual decompressed output.
            let mut buf = Vec::with_capacity(declared.min(cap).min(1 << 20) as usize);
            if let Err(e) = (&mut file)
                .take(cap.saturating_add(1))
                .read_to_end(&mut buf)
            {
                raise(
                    &mut issue,
                    ScanStatus::Failed,
                    format!("ZIP member {} extraction failed: {}", label, e),
                );
                continue;
            }
            if buf.len() as u64 > cap {
                raise(
                    &mut issue,
                    ScanStatus::Failed,
                    format!("ZIP member {} exceeds size limit", label),
                );
                continue;
            }
            if buf.len() as u64 > declared {
                if let Err(e) =
                    tracker.record_extracted_bytes((buf.len() as u64 - declared) as usize)
                {
                    raise(
                        &mut issue,
                        ScanStatus::Failed,
                        format!("ZIP extraction budget exhausted: {}", e),
                    );
                    break;
                }
            }
            drop(file);

            match self.scan_object(&buf, &label, None, tracker, depth) {
                Ok(r) => subs.push(r),
                Err(e @ ScanError::Timeout { .. }) => return Err(e),
                Err(e) => raise(
                    &mut issue,
                    ScanStatus::Failed,
                    format!("ZIP member {} scan failed: {}", label, e),
                ),
            }
        }
        Ok((subs, issue))
    }
}

enum ContainerKind {
    None,
    Zip,
    Unsupported(&'static str),
}

/// Content-based container classification (never trusts filenames).
fn classify_container(data: &[u8]) -> ContainerKind {
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        ContainerKind::Zip
    } else if data.starts_with(b"Rar!\x1a\x07") {
        ContainerKind::Unsupported("RAR")
    } else if data.starts_with(b"7z\xbc\xaf\x27\x1c") {
        ContainerKind::Unsupported("7-Zip")
    } else if data.starts_with(&[0x1f, 0x8b]) {
        ContainerKind::Unsupported("GZIP")
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

/// Helper checking if a byte slice contains a specific subslice.
fn bytes_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Validates RFC 2046 MIME boundary integrity.
fn validate_mime_boundaries(raw_bytes: &[u8], msg: &Message) -> Result<(), String> {
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

            let open_delim = format!("--{}", boundary);
            if !bytes_contains(raw_bytes, open_delim.as_bytes()) {
                return Err(format!(
                    "Malformed multipart MIME: boundary delimiter '--{}' not found in message",
                    boundary
                ));
            }

            let close_delim = format!("--{}--", boundary);
            if !bytes_contains(raw_bytes, close_delim.as_bytes()) {
                return Err(format!(
                    "Incomplete multipart MIME: missing closing boundary delimiter '--{}--'",
                    boundary
                ));
            }
        }
    }

    // 2. Check any parts that declare multipart sub-structures
    for part in msg.parts() {
        if let Some(ct) = part.content_type() {
            if ct.ctype().eq_ignore_ascii_case("multipart") {
                if let Some(b) = ct.attribute("boundary") {
                    if !b.is_empty() {
                        let close_delim = format!("--{}--", b);
                        if !bytes_contains(raw_bytes, close_delim.as_bytes()) {
                            return Err(format!(
                                "Incomplete multipart MIME: missing sub-part boundary delimiter '--{}--'",
                                b
                            ));
                        }
                    }
                }
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
}
