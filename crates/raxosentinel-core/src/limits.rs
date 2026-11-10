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
    /// Maximum number of attachments permitted per message. Default: 30.
    pub max_email_attachments: usize,
    /// Maximum size of a single extracted attachment (bytes). Default: 25 MiB.
    pub max_email_attachment_size: u64,
    /// Maximum cumulative extracted data across all parts/attachments (bytes). Default: 100 MiB.
    pub max_total_extracted_bytes: u64,
    /// Buffer size used for chunked streaming I/O (bytes). Default: 64 KiB.
    pub buffer_size: usize,
    /// Largest extracted object held completely in memory for recursive inspection
    /// (bytes). Larger objects are inspected in streaming mode. Default: 25 MiB.
    #[serde(default = "default_max_buffered_object_bytes")]
    pub max_buffered_object_bytes: u64,
    /// Maximum decoded size of one object inspected in streaming mode (bytes).
    /// Default: 512 MiB.
    #[serde(default = "default_max_streamed_object_bytes")]
    pub max_streamed_object_bytes: u64,
    /// Maximum cumulative bytes inspected in streaming mode per scan (bytes).
    /// Streamed bytes are never retained, so this bounds work, not memory.
    /// Default: 1 GiB.
    #[serde(default = "default_max_total_streamed_bytes")]
    pub max_total_streamed_bytes: u64,
    /// Maximum archive members (ZIP/TAR/OLE entries, compressed members) per scan.
    /// Default: 10,000.
    #[serde(default = "default_max_archive_members")]
    pub max_archive_members: usize,
}

fn default_max_buffered_object_bytes() -> u64 {
    25 * 1024 * 1024
}
fn default_max_streamed_object_bytes() -> u64 {
    512 * 1024 * 1024
}
fn default_max_total_streamed_bytes() -> u64 {
    1024 * 1024 * 1024
}
fn default_max_archive_members() -> usize {
    10_000
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_file_size: 50 * 1024 * 1024,              // 50 MiB
            max_scan_duration_ms: 10_000,                 // 10 seconds
            max_email_depth: 5,                           // 5 nested MIME levels
            max_email_attachments: 30,                    // 30 attachments
            max_email_attachment_size: 25 * 1024 * 1024,  // 25 MiB
            max_total_extracted_bytes: 100 * 1024 * 1024, // 100 MiB
            buffer_size: 64 * 1024,                       // 64 KiB
            max_buffered_object_bytes: default_max_buffered_object_bytes(),
            max_streamed_object_bytes: default_max_streamed_object_bytes(),
            max_total_streamed_bytes: default_max_total_streamed_bytes(),
            max_archive_members: default_max_archive_members(),
        }
    }
}

/// Tracks dynamic resource consumption during an active scan execution.
pub struct ResourceTracker {
    limits: ResourceLimits,
    start_time: Instant,
    total_bytes_read: u64,
    total_extracted_bytes: u64,
    total_streamed_bytes: u64,
    attachment_count: usize,
    archive_members: usize,
}

impl ResourceTracker {
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            start_time: Instant::now(),
            total_bytes_read: 0,
            total_extracted_bytes: 0,
            total_streamed_bytes: 0,
            attachment_count: 0,
            archive_members: 0,
        }
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

    /// Timeout error carrying the elapsed scan time, for deadlines detected by
    /// components (such as YARA-X) that only know their remaining budget.
    pub fn timeout_error(&self) -> ScanError {
        ScanError::Timeout {
            duration_ms: self.start_time.elapsed().as_millis() as u64,
        }
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

    /// Registers an attachment whose content was streamed rather than buffered. It
    /// counts towards `max_email_attachments`; its bytes were already charged to the
    /// streamed-byte limits (`max_streamed_object_bytes`, `max_total_streamed_bytes`)
    /// and are not charged again to the extracted-bytes budget.
    pub fn register_streamed_attachment(&mut self) -> Result<(), ScanError> {
        self.check_timeout()?;
        if self.attachment_count + 1 > self.limits.max_email_attachments {
            return Err(ScanError::AttachmentLimitExceeded {
                limit: self.limits.max_email_attachments,
            });
        }
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

    /// Records bytes inspected in streaming mode (not retained) against the
    /// cumulative streamed-bytes budget.
    pub fn record_streamed_bytes(&mut self, bytes: usize) -> Result<(), ScanError> {
        self.check_timeout()?;
        self.total_streamed_bytes = self.total_streamed_bytes.saturating_add(bytes as u64);
        if self.total_streamed_bytes > self.limits.max_total_streamed_bytes {
            return Err(ScanError::ExtractedSizeLimitExceeded {
                limit: self.limits.max_total_streamed_bytes,
                current: self.total_streamed_bytes,
            });
        }
        Ok(())
    }

    /// Registers one archive member against the per-scan member limit.
    pub fn register_archive_member(&mut self) -> Result<(), ScanError> {
        self.check_timeout()?;
        if self.archive_members >= self.limits.max_archive_members {
            return Err(ScanError::AttachmentLimitExceeded {
                limit: self.limits.max_archive_members,
            });
        }
        self.archive_members += 1;
        Ok(())
    }

    /// Remaining whole-scan deadline.
    pub fn remaining(&self) -> Duration {
        Duration::from_millis(self.limits.max_scan_duration_ms)
            .saturating_sub(self.start_time.elapsed())
    }

    pub fn total_streamed_bytes(&self) -> u64 {
        self.total_streamed_bytes
    }

    pub fn archive_members(&self) -> usize {
        self.archive_members
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
    fn test_streamed_and_member_budgets() {
        let limits = ResourceLimits {
            max_total_streamed_bytes: 100,
            max_archive_members: 2,
            ..Default::default()
        };
        let mut tracker = ResourceTracker::new(limits);
        assert!(tracker.record_streamed_bytes(100).is_ok());
        assert!(tracker.record_streamed_bytes(1).is_err());
        assert_eq!(tracker.total_extracted_bytes(), 0);
        assert!(tracker.register_archive_member().is_ok());
        assert!(tracker.register_archive_member().is_ok());
        assert!(tracker.register_archive_member().is_err());
        assert_eq!(tracker.attachment_count(), 0);
        // Streamed attachments count but are not charged to the extracted budget.
        let mut tracker = ResourceTracker::new(ResourceLimits {
            max_email_attachments: 1,
            ..Default::default()
        });
        assert!(tracker.register_streamed_attachment().is_ok());
        assert_eq!(tracker.total_extracted_bytes(), 0);
        assert!(tracker.register_streamed_attachment().is_err());
        // Older serialized limits without the new fields still deserialize.
        let old = r#"{"max_file_size":1,"max_scan_duration_ms":1,"max_email_depth":1,
            "max_email_attachments":1,"max_email_attachment_size":1,
            "max_total_extracted_bytes":1,"buffer_size":1}"#;
        let parsed: ResourceLimits = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.max_archive_members, 10_000);
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
