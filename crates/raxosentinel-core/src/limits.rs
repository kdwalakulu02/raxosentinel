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

use crate::error::ScanError;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Configurable resource limits for malware and email scanning.
/// All limits protect the system from denial of service, memory exhaustion,
/// decompression bombs, and infinite recursive nesting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum file size scanned directly from disk or stream (bytes). Default: 50 MiB.
    pub max_file_size: u64,
    /// Maximum wall-clock scan duration per target (milliseconds). Default: 10,000 ms (10 s).
    pub max_scan_duration_ms: u64,
    /// Maximum MIME / nested message recursion depth. Default: 5.
    pub max_email_depth: usize,
    /// Maximum number of MIME attachments/parts expanded per scan. Default: 100.
    /// Only MIME parts spend this budget; other object kinds have their own.
    pub max_email_attachments: usize,
    /// Maximum size of a single extracted object (bytes). Default: 50 MiB.
    pub max_email_attachment_size: u64,
    /// Maximum cumulative extracted data across all parts/attachments (bytes). Default: 200 MiB.
    pub max_total_extracted_bytes: u64,
    /// Buffer size used for chunked streaming I/O (bytes). Default: 64 KiB.
    pub buffer_size: usize,
    /// Maximum archive members (ZIP, OOXML, ...) expanded per scan. Default: 2,000.
    #[serde(default = "default_archive_entries")]
    pub max_archive_entries: usize,
    /// Maximum PDF streams decoded per scan. Default: 10,000.
    #[serde(default = "default_pdf_streams")]
    pub max_pdf_streams: usize,
    /// Maximum GZIP members expanded per scan. Default: 64.
    #[serde(default = "default_gzip_members")]
    pub max_gzip_members: usize,
}

fn default_archive_entries() -> usize {
    2_000
}
fn default_pdf_streams() -> usize {
    10_000
}
fn default_gzip_members() -> usize {
    64
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_file_size: 50 * 1024 * 1024,              // 50 MiB
            max_scan_duration_ms: 10_000,                 // 10 seconds
            max_email_depth: 5,                           // 5 nested MIME levels
            max_email_attachments: 100,                   // 100 MIME parts
            max_email_attachment_size: 50 * 1024 * 1024,  // 50 MiB
            max_total_extracted_bytes: 200 * 1024 * 1024, // 200 MiB
            buffer_size: 64 * 1024,                       // 64 KiB
            max_archive_entries: default_archive_entries(),
            max_pdf_streams: default_pdf_streams(),
            max_gzip_members: default_gzip_members(),
        }
    }
}

/// Kinds of extracted objects; each kind has an independent count budget so that,
/// e.g., a many-page PDF never consumes the MIME attachment budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    ArchiveEntry,
    PdfStream,
    GzipMember,
}

impl ObjectKind {
    pub fn label(self) -> &'static str {
        match self {
            ObjectKind::ArchiveEntry => "archive member",
            ObjectKind::PdfStream => "PDF stream",
            ObjectKind::GzipMember => "GZIP member",
        }
    }
}

/// Tracks dynamic resource consumption during an active scan execution.
pub struct ResourceTracker {
    limits: ResourceLimits,
    start_time: Instant,
    total_bytes_read: u64,
    total_extracted_bytes: u64,
    attachment_count: usize,
    object_counts: [usize; 3],
}

impl ResourceTracker {
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            start_time: Instant::now(),
            total_bytes_read: 0,
            total_extracted_bytes: 0,
            attachment_count: 0,
            object_counts: [0; 3],
        }
    }

    /// Spends one unit of the per-kind object budget.
    pub fn register_object(&mut self, kind: ObjectKind) -> Result<(), ScanError> {
        self.check_timeout()?;
        let limit = match kind {
            ObjectKind::ArchiveEntry => self.limits.max_archive_entries,
            ObjectKind::PdfStream => self.limits.max_pdf_streams,
            ObjectKind::GzipMember => self.limits.max_gzip_members,
        };
        let count = &mut self.object_counts[kind as usize];
        if *count >= limit {
            return Err(ScanError::ObjectLimitExceeded {
                kind: kind.label(),
                limit,
            });
        }
        *count += 1;
        Ok(())
    }

    /// Extraction should stop (yielding a partial result) once 70% of the scan
    /// budget is spent, leaving time to finish and report what was inspected.
    pub fn soft_deadline_reached(&self) -> bool {
        self.start_time.elapsed().as_millis() as u64 >= self.limits.max_scan_duration_ms * 7 / 10
    }

    /// Bytes still available to a single extracted object.
    pub fn object_extraction_cap(&self) -> u64 {
        self.limits.max_email_attachment_size.min(
            self.limits
                .max_total_extracted_bytes
                .saturating_sub(self.total_extracted_bytes),
        )
    }

    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// Checks whether the maximum scan duration has elapsed.
    pub fn check_timeout(&self) -> Result<(), ScanError> {
        let elapsed = self.start_time.elapsed();
        let max_duration = Duration::from_millis(self.limits.max_scan_duration_ms);
        if elapsed > max_duration {
            return Err(ScanError::Timeout {
                duration_ms: elapsed.as_millis() as u64,
            });
        }
        Ok(())
    }

    /// Records newly read bytes and checks against max_file_size limit.
    pub fn record_bytes_read(&mut self, bytes: usize) -> Result<(), ScanError> {
        self.check_timeout()?;
        self.total_bytes_read = self.total_bytes_read.checked_add(bytes as u64).ok_or(
            ScanError::FileSizeLimitExceeded {
                limit: self.limits.max_file_size,
                actual: u64::MAX,
            },
        )?;

        if self.total_bytes_read > self.limits.max_file_size {
            return Err(ScanError::FileSizeLimitExceeded {
                limit: self.limits.max_file_size,
                actual: self.total_bytes_read,
            });
        }
        Ok(())
    }

    /// Resets stream byte counter before a new pass over the same target file.
    pub fn reset_bytes_read(&mut self) {
        self.total_bytes_read = 0;
    }

    /// Checks if a file with known size exceeds max_file_size limit.
    pub fn check_file_size(&self, size: u64) -> Result<(), ScanError> {
        if size > self.limits.max_file_size {
            return Err(ScanError::FileSizeLimitExceeded {
                limit: self.limits.max_file_size,
                actual: size,
            });
        }
        Ok(())
    }

    /// Checks nesting depth.
    pub fn check_depth(&self, depth: usize) -> Result<(), ScanError> {
        self.check_timeout()?;
        if depth > self.limits.max_email_depth {
            return Err(ScanError::DepthLimitExceeded {
                limit: self.limits.max_email_depth,
                current: depth,
            });
        }
        Ok(())
    }

    /// Registers a new attachment and enforces attachment count and individual size limits.
    pub fn register_attachment(&mut self, attachment_size: u64) -> Result<(), ScanError> {
        self.check_timeout()?;
        if self.attachment_count + 1 > self.limits.max_email_attachments {
            return Err(ScanError::AttachmentLimitExceeded {
                limit: self.limits.max_email_attachments,
            });
        }

        if attachment_size > self.limits.max_email_attachment_size {
            return Err(ScanError::FileSizeLimitExceeded {
                limit: self.limits.max_email_attachment_size,
                actual: attachment_size,
            });
        }

        self.record_extracted_bytes(attachment_size as usize)?;
        self.attachment_count += 1;
        Ok(())
    }

    /// Records newly extracted data (decompressed or decoded) and checks against cumulative limit.
    pub fn record_extracted_bytes(&mut self, bytes: usize) -> Result<(), ScanError> {
        self.check_timeout()?;
        self.total_extracted_bytes = self.total_extracted_bytes.checked_add(bytes as u64).ok_or(
            ScanError::ExtractedSizeLimitExceeded {
                limit: self.limits.max_total_extracted_bytes,
                current: u64::MAX,
            },
        )?;

        if self.total_extracted_bytes > self.limits.max_total_extracted_bytes {
            return Err(ScanError::ExtractedSizeLimitExceeded {
                limit: self.limits.max_total_extracted_bytes,
                current: self.total_extracted_bytes,
            });
        }
        Ok(())
    }

    pub fn elapsed_millis(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }

    pub fn total_bytes_read(&self) -> u64 {
        self.total_bytes_read
    }

    pub fn total_extracted_bytes(&self) -> u64 {
        self.total_extracted_bytes
    }

    pub fn attachment_count(&self) -> usize {
        self.attachment_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_size_limit_enforcement() {
        let limits = ResourceLimits {
            max_file_size: 100,
            ..Default::default()
        };
        let mut tracker = ResourceTracker::new(limits);
        assert!(tracker.record_bytes_read(50).is_ok());
        assert!(tracker.record_bytes_read(50).is_ok());
        assert!(tracker.record_bytes_read(1).is_err());
    }

    #[test]
    fn test_attachment_limits() {
        let limits = ResourceLimits {
            max_email_attachments: 2,
            max_email_attachment_size: 50,
            max_total_extracted_bytes: 80,
            ..Default::default()
        };
        let mut tracker = ResourceTracker::new(limits);
        assert!(tracker.register_attachment(30).is_ok());
        assert!(tracker.register_attachment(60).is_err()); // exceeds individual size
        assert!(tracker.register_attachment(30).is_ok()); // 2nd attachment
        assert!(tracker.register_attachment(10).is_err()); // exceeds max count
    }

    #[test]
    fn test_depth_limit() {
        let limits = ResourceLimits {
            max_email_depth: 3,
            ..Default::default()
        };
        let tracker = ResourceTracker::new(limits);
        assert!(tracker.check_depth(0).is_ok());
        assert!(tracker.check_depth(3).is_ok());
        assert!(tracker.check_depth(4).is_err());
    }
}
