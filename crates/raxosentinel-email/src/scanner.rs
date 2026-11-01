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

        tracker.check_file_size(metadata.len())?;
        let bytes = std::fs::read(path).map_err(|e| ScanError::IoWithPath {
            path: path.to_path_buf(),
            source: e,
        })?;

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

        let sha256 = hash_bytes(raw_bytes);
        let detected_type = detect_type(raw_bytes);

        // Parse MIME message structure with limits
        let parser = MessageParser::new()
            .max_depth(tracker.limits().max_email_depth)
            .max_parts(tracker.limits().max_email_attachments + 10);

        let parsed = match parser.parse(raw_bytes) {
            Some(msg) => msg,
            None => {
                // If it's completely unparseable as MIME
                let duration_ms = tracker.elapsed_millis().saturating_sub(start_ms);
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
                    ScanStatus::Unsupported,
                    Vec::new(),
                    Vec::new(),
                    duration_ms,
                    Some("Malformed or corrupted MIME message format".to_string()),
                ));
            }
        };

        let mut threats: Vec<Threat> = Vec::new();
        let mut sub_reports: Vec<ScanReport> = Vec::new();

        // 1. Check raw email hash
        if let Some(hash_threat) = self.db.match_hash(&sha256) {
            threats.push(hash_threat.with_location("email_root"));
        }

        // 2. Scan email bodies (text and html)
        self.scan_bodies(&parsed, &mut threats);

        // 3. Scan attachments and embedded parts
        self.scan_attachments(&parsed, &mut threats, &mut sub_reports, tracker, depth)?;

        let has_threats =
            !threats.is_empty() || sub_reports.iter().any(|r| r.status == ScanStatus::Infected);

        let overall_status = if has_threats {
            ScanStatus::Infected
        } else {
            ScanStatus::Clean
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
            None,
        ))
    }

    fn scan_bodies(&self, msg: &Message, threats: &mut Vec<Threat>) {
        // Scan text bodies
        for (idx, text) in msg.text_bodies().enumerate() {
            let body_bytes = text.as_bytes();
            let body_threats = self.db.match_bytes(body_bytes);
            for t in body_threats {
                threats.push(t.with_location(format!("body:text/plain:part_{}", idx)));
            }
        }

        // Scan HTML bodies
        for (idx, html) in msg.html_bodies().enumerate() {
            let body_bytes = html.as_bytes();
            let body_threats = self.db.match_bytes(body_bytes);
            for t in body_threats {
                threats.push(t.with_location(format!("body:text/html:part_{}", idx)));
            }
        }
    }

    fn scan_attachments(
        &self,
        msg: &Message,
        threats: &mut Vec<Threat>,
        sub_reports: &mut Vec<ScanReport>,
        tracker: &mut ResourceTracker,
        depth: usize,
    ) -> Result<(), ScanError> {
        for (idx, attachment) in msg.attachments().enumerate() {
            let decoded_data = attachment.decoded();
            let attachment_size = decoded_data.len() as u64;

            // Enforce resource limits per attachment
            tracker.register_attachment(attachment_size)?;

            let filename = attachment
                .attachment_name()
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("attachment_{}", idx));

            let declared_mime = attachment
                .content_type()
                .map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("*")));

            let sub_report = self.scan_single_attachment(
                &filename,
                declared_mime.as_deref(),
                &attachment,
                &decoded_data,
                tracker,
                depth,
            )?;

            // If sub-target has threats, also roll them up to parent threat list with location tag
            for t in &sub_report.threats {
                threats.push(t.clone());
            }

            sub_reports.push(sub_report);
        }

        Ok(())
    }

    fn scan_single_attachment(
        &self,
        filename: &str,
        declared_mime: Option<&str>,
        part: &MessagePart,
        data: &[u8],
        tracker: &mut ResourceTracker,
        depth: usize,
    ) -> Result<ScanReport, ScanError> {
        let start_ms = tracker.elapsed_millis();
        let sha256 = hash_bytes(data);
        let detected_type = detect_type(data);

        // Check if this part is a nested email message
        if part.is_message() || detected_type.mime_type == "message/rfc822" {
            // Recursive scan with increased depth
            return self.scan_internal(data, Some(filename), tracker, depth + 1);
        }

        let mut part_threats: Vec<Threat> = Vec::new();

        // 1. Extension mismatch / disguised executable analysis
        if let Some(mismatch) = check_extension_mismatch(filename, &detected_type) {
            part_threats.push(mismatch);
        }

        // 2. Exact hash signature match
        if let Some(hash_threat) = self.db.match_hash(&sha256) {
            part_threats.push(hash_threat.with_location(format!("attachment:{}", filename)));
        }

        // 3. Byte pattern signature match
        let pattern_threats = self.db.match_bytes(data);
        for t in pattern_threats {
            part_threats.push(t.with_location(format!("attachment:{}", filename)));
        }

        let status = if !part_threats.is_empty() {
            ScanStatus::Infected
        } else {
            ScanStatus::Clean
        };

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
            part_threats,
            Vec::new(),
            duration_ms,
            None,
        ))
    }
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
        assert!(!report.threats.is_empty());
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
        assert!(report
            .threats
            .iter()
            .any(|t| t.name == "EICAR-Standard-Antivirus-Test-File"));
    }

    #[test]
    fn test_scan_multipart_disguised_executable_mismatch() {
        // Attachment named "invoice.pdf" containing a Windows PE header MZ ... PE\0\0
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
        // Set attachment limit to 1
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
    fn test_malformed_mime_handled_gracefully() {
        let malformed = b"\x00\x01\x02\x03\xff\xfe\x00";
        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);

        // Should return a report without panicking
        let report = scanner
            .scan_bytes(malformed, Some("bad.eml"), &mut tracker)
            .unwrap();
        assert!(report.status.is_unsupported() || report.status.is_clean());
    }
}
