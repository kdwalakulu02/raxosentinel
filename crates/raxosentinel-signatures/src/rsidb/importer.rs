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

use super::error::DatabaseError;
use super::format::{
    HashAlgorithm, RsidbHeader, FLAG_HAS_DIRECTORY, FLAG_NONE, HEADER_SIZE, PREFIX_BUCKET_COUNT,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::path::Path;

/// Ingested signature entry before compilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureEntry {
    pub alg: HashAlgorithm,
    pub digest: Vec<u8>,
    pub size: u64,
    pub name: String,
}

impl SignatureEntry {
    pub fn new(alg: HashAlgorithm, size: u64, digest: Vec<u8>, name: impl Into<String>) -> Self {
        Self {
            alg,
            digest,
            size,
            name: name.into(),
        }
    }
}

impl Ord for SignatureEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.alg
            .cmp(&other.alg)
            .then_with(|| self.digest.cmp(&other.digest))
            .then_with(|| self.size.cmp(&other.size))
            .then_with(|| self.name.cmp(&other.name))
    }
}

impl PartialOrd for SignatureEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Statistics collected during signature ingestion.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IngestionStats {
    pub accepted: usize,
    pub rejected: usize,
    pub ignored: usize,
    pub rejections_by_reason: HashMap<String, usize>,
}

impl IngestionStats {
    pub fn record_rejected(&mut self, reason: impl Into<String>) {
        self.rejected += 1;
        *self.rejections_by_reason.entry(reason.into()).or_insert(0) += 1;
    }
}

/// Ingests and parses text hash signature files.
pub struct SignatureImporter;

impl SignatureImporter {
    /// Ingests signatures from a string containing lines in `<hash>:<size>:<name>` format.
    pub fn parse_str(
        content: &str,
    ) -> Result<(Vec<SignatureEntry>, IngestionStats), DatabaseError> {
        let mut entries = Vec::new();
        let mut stats = IngestionStats::default();

        for (line_idx, line) in content.lines().enumerate() {
            let line_no = line_idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                stats.ignored += 1;
                continue;
            }

            let parts: Vec<&str> = trimmed.split(':').collect();
            if parts.len() != 3 {
                stats.record_rejected("Malformed line format: expected 3 colon-separated fields");
                return Err(DatabaseError::MalformedImportRecord(
                    line_no,
                    format!("expected 3 fields, got {}: '{}'", parts.len(), trimmed),
                ));
            }

            let hex_digest = parts[0].trim();
            let size_str = parts[1].trim();
            let name = parts[2].trim();

            if name.is_empty() {
                stats.record_rejected("Empty signature detection name");
                return Err(DatabaseError::MalformedImportRecord(
                    line_no,
                    "signature name cannot be empty".to_string(),
                ));
            }

            // Strict validation: wildcard sizes are explicitly rejected as unsupported
            if size_str == "*" || !size_str.chars().all(|c| c.is_ascii_digit()) {
                stats.record_rejected("Unsupported wildcard or non-numeric file size");
                return Err(DatabaseError::UnsupportedWildcardSize(
                    line_no,
                    size_str.to_string(),
                ));
            }

            let size = size_str.parse::<u64>().map_err(|_| {
                stats.record_rejected("File size overflow");
                DatabaseError::MalformedImportRecord(
                    line_no,
                    format!("file size overflow: '{}'", size_str),
                )
            })?;

            let digest = hex::decode(hex_digest).map_err(|e| {
                stats.record_rejected("Invalid hexadecimal hash characters");
                DatabaseError::MalformedImportRecord(
                    line_no,
                    format!("invalid hex digest '{}': {}", hex_digest, e),
                )
            })?;

            let alg = match HashAlgorithm::from_digest_len(digest.len()) {
                Some(a) => a,
                None => {
                    stats.record_rejected(format!(
                        "Unsupported hash length: {} bytes (expected 16, 20, or 32)",
                        digest.len()
                    ));
                    return Err(DatabaseError::UnsupportedHashLength(digest.len(), line_no));
                }
            };

            entries.push(SignatureEntry::new(alg, size, digest, name));
            stats.accepted += 1;
        }

        Ok((entries, stats))
    }

    /// Reads and parses an input signature file from disk.
    pub fn parse_file(path: &Path) -> Result<(Vec<SignatureEntry>, IngestionStats), DatabaseError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            DatabaseError::Io(format!(
                "Failed to read signature file {}: {}",
                path.display(),
                e
            ))
        })?;
        Self::parse_str(&content)
    }
}

/// Deterministic compiler for the RSIDB binary format.
pub struct RsidbCompiler {
    include_directory: bool,
    provenance_metadata: String,
}

impl Default for RsidbCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl RsidbCompiler {
    pub fn new() -> Self {
        Self {
            include_directory: true,
            provenance_metadata: String::from(
                "RaxoSentinel RSIDB Compiler v1.0 (GPL-2.0-or-later)",
            ),
        }
    }

    pub fn with_directory(mut self, enabled: bool) -> Self {
        self.include_directory = enabled;
        self
    }

    pub fn with_provenance(mut self, metadata: impl Into<String>) -> Self {
        self.provenance_metadata = metadata.into();
        self
    }

    /// Compiles a set of signature entries into a deterministic RSIDB binary buffer.
    pub fn compile(&self, mut entries: Vec<SignatureEntry>) -> Result<Vec<u8>, DatabaseError> {
        // Deterministic sorting of all records
        entries.sort();

        // Separate records by algorithm
        let mut md5_entries = Vec::new();
        let mut sha1_entries = Vec::new();
        let mut sha256_entries = Vec::new();

        for entry in entries {
            match entry.alg {
                HashAlgorithm::Md5 => md5_entries.push(entry),
                HashAlgorithm::Sha1 => sha1_entries.push(entry),
                HashAlgorithm::Sha256 => sha256_entries.push(entry),
            }
        }

        // Deduplicate and deterministically sort string table
        let mut unique_names = BTreeSet::new();
        for e in md5_entries
            .iter()
            .chain(&sha1_entries)
            .chain(&sha256_entries)
        {
            unique_names.insert(e.name.clone());
        }

        let sorted_names: Vec<String> = unique_names.into_iter().collect();
        let mut name_to_id = HashMap::with_capacity(sorted_names.len());
        let mut name_table_bytes = Vec::new();

        for (id, name) in sorted_names.iter().enumerate() {
            name_to_id.insert(name.as_str(), id as u32);
            let name_bytes = name.as_bytes();
            name_table_bytes.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            name_table_bytes.extend_from_slice(name_bytes);
        }

        // Output buffer starting after header
        let mut payload = Vec::new();

        // 1. MD5 records
        for e in &md5_entries {
            payload.extend_from_slice(&e.digest);
            payload.extend_from_slice(&e.size.to_le_bytes());
            let name_id = name_to_id[e.name.as_str()];
            payload.extend_from_slice(&name_id.to_le_bytes());
        }

        // 2. SHA-1 records
        for e in &sha1_entries {
            payload.extend_from_slice(&e.digest);
            payload.extend_from_slice(&e.size.to_le_bytes());
            let name_id = name_to_id[e.name.as_str()];
            payload.extend_from_slice(&name_id.to_le_bytes());
        }

        // 3. SHA-256 records
        for e in &sha256_entries {
            payload.extend_from_slice(&e.digest);
            payload.extend_from_slice(&e.size.to_le_bytes());
            let name_id = name_to_id[e.name.as_str()];
            payload.extend_from_slice(&name_id.to_le_bytes());
        }

        // 4. Name table
        payload.extend_from_slice(&name_table_bytes);

        // 5. Provenance metadata
        let prov_bytes = self.provenance_metadata.as_bytes();
        payload.extend_from_slice(prov_bytes);

        // 6. Optional Compact Lookup Directory
        let (dir_offset, dir_bytes, flags) = if self.include_directory {
            let offset = (HEADER_SIZE + payload.len()) as u64;
            let dir_start_len = payload.len();

            // Build directory for each algorithm: 65,537 u32 offsets
            Self::build_directory_into(&md5_entries, &mut payload);
            Self::build_directory_into(&sha1_entries, &mut payload);
            Self::build_directory_into(&sha256_entries, &mut payload);

            let total_dir_bytes = (payload.len() - dir_start_len) as u64;
            (offset, total_dir_bytes, FLAG_HAS_DIRECTORY)
        } else {
            (0, 0, FLAG_NONE)
        };

        // Compute SHA-256 checksum over the entire payload
        let checksum: [u8; 32] = Sha256::digest(&payload).into();

        // Construct Header
        let header = RsidbHeader::new(
            md5_entries.len() as u32,
            sha1_entries.len() as u32,
            sha256_entries.len() as u32,
            sorted_names.len() as u32,
            name_table_bytes.len() as u32,
            prov_bytes.len() as u32,
            flags,
            dir_offset,
            dir_bytes,
            checksum,
        );

        let mut output = Vec::with_capacity(HEADER_SIZE + payload.len());
        header
            .write_to(&mut output)
            .map_err(|e| DatabaseError::Io(e.to_string()))?;
        output.extend_from_slice(&payload);

        Ok(output)
    }

    /// Compiles entries and saves directly to a file on disk.
    pub fn compile_to_file(
        &self,
        entries: Vec<SignatureEntry>,
        dest: &Path,
    ) -> Result<(), DatabaseError> {
        let bytes = self.compile(entries)?;
        let mut file = std::fs::File::create(dest).map_err(|e| {
            DatabaseError::Io(format!(
                "Failed to create destination file {}: {}",
                dest.display(),
                e
            ))
        })?;
        file.write_all(&bytes)?;
        file.flush()?;
        Ok(())
    }

    fn build_directory_into(entries: &[SignatureEntry], out: &mut Vec<u8>) {
        // 65,537 u32 entries (PREFIX_BUCKET_COUNT + 1)
        // dir[p] stores the index of the first record where digest prefix (first 2 bytes) >= p.
        // dir[65536] = entries.len()
        let mut current_rec = 0;
        let total = entries.len();

        for prefix in 0..PREFIX_BUCKET_COUNT {
            let p_u16 = prefix as u16;
            while current_rec < total {
                let rec_prefix = ((entries[current_rec].digest[0] as u16) << 8)
                    | (entries[current_rec].digest[1] as u16);
                if rec_prefix >= p_u16 {
                    break;
                }
                current_rec += 1;
            }
            out.extend_from_slice(&(current_rec as u32).to_le_bytes());
        }
        // Final sentinel entry
        out.extend_from_slice(&(total as u32).to_le_bytes());
    }
}
