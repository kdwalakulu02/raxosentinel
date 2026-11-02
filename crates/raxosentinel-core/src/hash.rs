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
use crate::limits::ResourceTracker;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Result of a bounded hash operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashResult {
    /// Lowercase hexadecimal representation of the SHA-256 digest
    pub sha256_hex: String,
    /// Total bytes processed
    pub bytes_processed: u64,
}

/// Computes SHA-256 across any `Read` stream using bounded memory allocations.
/// Enforces resource limits (max file size, timeout) via `ResourceTracker`.
pub fn hash_reader_bounded<R: Read>(
    reader: &mut R,
    tracker: &mut ResourceTracker,
) -> Result<HashResult, ScanError> {
    let mut hasher = Sha256::new();
    let buffer_size = tracker.limits().buffer_size;
    if buffer_size == 0 || buffer_size > 16 * 1024 * 1024 {
        return Err(ScanError::Internal("Invalid hashing buffer size".into()));
    }
    tracker.check_timeout()?;
    let mut buffer = vec![0u8; buffer_size];
    let mut total_bytes: u64 = 0;

    loop {
        tracker.check_timeout()?;
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            tracker.check_timeout()?;
            break;
        }

        tracker.record_bytes_read(n)?;
        total_bytes =
            total_bytes
                .checked_add(n as u64)
                .ok_or(ScanError::FileSizeLimitExceeded {
                    limit: tracker.limits().max_file_size,
                    actual: u64::MAX,
                })?;

        hasher.update(&buffer[..n]);
    }

    let digest = hasher.finalize();
    Ok(HashResult {
        sha256_hex: hex::encode(digest),
        bytes_processed: total_bytes,
    })
}

/// Convenience function to hash a file on disk with bounded memory and limits.
pub fn hash_file_bounded(
    path: &Path,
    tracker: &mut ResourceTracker,
) -> Result<HashResult, ScanError> {
    let file = File::open(path).map_err(|e| ScanError::IoWithPath {
        path: path.to_path_buf(),
        source: e,
    })?;

    // Pre-check file metadata size if accessible
    if let Ok(metadata) = file.metadata() {
        tracker.check_file_size(metadata.len())?;
    }

    let mut reader = std::io::BufReader::with_capacity(tracker.limits().buffer_size, file);
    hash_reader_bounded(&mut reader, tracker)
}

/// Computes SHA-256 of an in-memory byte slice.
pub fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::ResourceLimits;
    use std::io::Cursor;

    #[test]
    fn test_hash_empty_stream() {
        let data: &[u8] = b"";
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);
        let mut cursor = Cursor::new(data);
        let result = hash_reader_bounded(&mut cursor, &mut tracker).unwrap();

        // Standard SHA-256 of empty string
        assert_eq!(
            result.sha256_hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(result.bytes_processed, 0);
    }

    #[test]
    fn test_hash_known_value() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let limits = ResourceLimits::default();
        let mut tracker = ResourceTracker::new(limits);
        let mut cursor = Cursor::new(data);
        let result = hash_reader_bounded(&mut cursor, &mut tracker).unwrap();

        assert_eq!(
            result.sha256_hex,
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
        assert_eq!(result.bytes_processed, data.len() as u64);
    }

    #[test]
    fn invalid_stream_buffer_is_rejected() {
        let limits = ResourceLimits {
            buffer_size: 0,
            ..ResourceLimits::default()
        };
        let mut tracker = ResourceTracker::new(limits);
        assert!(hash_reader_bounded(&mut Cursor::new(b"not empty"), &mut tracker).is_err());
    }

    #[test]
    fn test_hash_exceeding_limit() {
        let data = vec![0x41u8; 1000];
        let limits = ResourceLimits {
            max_file_size: 500,
            buffer_size: 64,
            ..Default::default()
        };
        let mut tracker = ResourceTracker::new(limits);
        let mut cursor = Cursor::new(data);
        let result = hash_reader_bounded(&mut cursor, &mut tracker);
        assert!(result.is_err());
        match result.unwrap_err() {
            ScanError::FileSizeLimitExceeded { limit, actual } => {
                assert_eq!(limit, 500);
                assert!(actual > 500);
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }
}
