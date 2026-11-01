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

use super::format::HashAlgorithm;

/// Errors that can occur during RSIDB parsing, building, validation, or loading.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DatabaseError {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("File is smaller than header size ({0} < {1})")]
    TruncatedHeader(usize, usize),

    #[error("Invalid magic bytes: expected {0:?}, got {1:?}")]
    InvalidMagic([u8; 8], [u8; 8]),

    #[error("Unsupported database version: {0} (supported: {1})")]
    UnsupportedVersion(u32, u32),

    #[error("Truncated database: expected {0} bytes, got {1} bytes")]
    TruncatedData(usize, usize),

    #[error("Trailing bytes in database: expected {0} bytes, got {1} bytes")]
    TrailingBytes(usize, usize),

    #[error("Unsorted records detected in algorithm {0:?} at index {1}")]
    UnsortedIndex(HashAlgorithm, usize),

    #[error("Invalid name ID {0} (total names: {1})")]
    InvalidNameId(u32, u32),

    #[error("Database integrity checksum mismatch: expected {0}, computed {1}")]
    CorruptedChecksum(String, String),

    #[error("Invalid UTF-8 in string table: {0}")]
    InvalidUtf8(String),

    #[error("Malformed record in import source line {0}: {1}")]
    MalformedImportRecord(usize, String),

    #[error("Unsupported wildcard file size in import source line {0}: '{1}'")]
    UnsupportedWildcardSize(usize, String),

    #[error("Unsupported hash length {0} in import source line {1}")]
    UnsupportedHashLength(usize, usize),

    #[error("Invalid query: {0}")]
    InvalidQuery(String),
}

impl From<std::io::Error> for DatabaseError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}
