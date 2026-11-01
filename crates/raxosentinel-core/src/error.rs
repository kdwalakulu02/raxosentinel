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

use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("I/O error reading '{path}': {source}")]
    IoWithPath {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("File size limit exceeded: actual {actual} bytes exceeds limit of {limit} bytes")]
    FileSizeLimitExceeded { limit: u64, actual: u64 },

    #[error("Scan timeout reached after {duration_ms} ms")]
    Timeout { duration_ms: u64 },

    #[error("Nesting depth limit exceeded: depth {current} exceeds max allowed {limit}")]
    DepthLimitExceeded { limit: usize, current: usize },

    #[error("Attachment count limit exceeded: maximum allowed is {limit}")]
    AttachmentLimitExceeded { limit: usize },

    #[error(
        "Total extracted data limit exceeded: reached {current} bytes (limit is {limit} bytes)"
    )]
    ExtractedSizeLimitExceeded { limit: u64, current: u64 },

    #[error("Corrupted or malformed data: {0}")]
    CorruptedData(String),

    #[error("Invalid signature definition: {0}")]
    InvalidSignature(String),

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error("Internal scanner error: {0}")]
    Internal(String),
}

impl serde::Serialize for ScanError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
