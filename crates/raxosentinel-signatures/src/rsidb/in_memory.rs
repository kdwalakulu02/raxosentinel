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
use super::format::{HashAlgorithm, RsidbHeader, HEADER_SIZE};
use super::importer::SignatureEntry;
use super::traits::RsidbIndex;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

/// In-memory hash-indexed RSIDB implementation.
///
/// Stores all digests, sizes, and detection names entirely within heap-allocated HashMaps.
/// Provides O(1) expected lookup performance at the expense of higher process memory and startup time.
#[derive(Debug, Clone)]
pub struct InMemoryIndex {
    records: HashMap<(HashAlgorithm, u64, Vec<u8>), Vec<String>>,
    counts: [usize; 3],
    name_count: usize,
    provenance: String,
}

impl InMemoryIndex {
    /// Constructs an in-memory index from a collection of raw signature entries.
    pub fn from_entries(entries: Vec<SignatureEntry>, provenance: impl Into<String>) -> Self {
        let mut records: HashMap<(HashAlgorithm, u64, Vec<u8>), Vec<String>> = HashMap::new();
        let mut counts = [0usize; 3];
        let mut names = BTreeSet::new();

        for e in entries {
            counts[e.alg.index()] += 1;
            names.insert(e.name.clone());
            records
                .entry((e.alg, e.size, e.digest))
                .or_default()
                .push(e.name);
        }

        Self {
            records,
            counts,
            name_count: names.len(),
            provenance: provenance.into(),
        }
    }

    /// Loads and validates an in-memory index from a compiled RSIDB binary buffer.
    pub fn from_bytes(slice: &[u8]) -> Result<Self, DatabaseError> {
        let header = RsidbHeader::read_from(slice)?;

        let md5_bytes = header.count_md5 as usize * HashAlgorithm::Md5.record_width();
        let sha1_bytes = header.count_sha1 as usize * HashAlgorithm::Sha1.record_width();
        let sha256_bytes = header.count_sha256 as usize * HashAlgorithm::Sha256.record_width();
        let records_bytes = md5_bytes + sha1_bytes + sha256_bytes;

        let expected_min_len = HEADER_SIZE
            + records_bytes
            + header.name_bytes as usize
            + header.provenance_bytes as usize
            + header.directory_bytes as usize;

        if slice.len() < expected_min_len {
            return Err(DatabaseError::TruncatedData(expected_min_len, slice.len()));
        }
        if slice.len() > expected_min_len {
            return Err(DatabaseError::TrailingBytes(expected_min_len, slice.len()));
        }

        // Verify SHA-256 payload checksum
        let computed_checksum: [u8; 32] = Sha256::digest(&slice[HEADER_SIZE..]).into();
        if computed_checksum != header.data_checksum {
            return Err(DatabaseError::CorruptedChecksum(
                hex::encode(header.data_checksum),
                hex::encode(computed_checksum),
            ));
        }

        // Parse Name Table
        let name_start = HEADER_SIZE + records_bytes;
        let name_end = name_start + header.name_bytes as usize;
        let mut names = Vec::with_capacity(header.name_count as usize);
        let mut pos = name_start;

        for _ in 0..header.name_count {
            if pos + 4 > name_end {
                return Err(DatabaseError::TruncatedData(pos + 4, slice.len()));
            }
            let len = u32::from_le_bytes(slice[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + len > name_end {
                return Err(DatabaseError::TruncatedData(pos + len, slice.len()));
            }
            let name_str = std::str::from_utf8(&slice[pos..pos + len])
                .map_err(|e| DatabaseError::InvalidUtf8(e.to_string()))?;
            names.push(name_str.to_string());
            pos += len;
        }

        if pos != name_end {
            return Err(DatabaseError::TrailingBytes(pos, name_end));
        }

        // Parse Provenance String
        let prov_start = name_end;
        let prov_end = prov_start + header.provenance_bytes as usize;
        let provenance = std::str::from_utf8(&slice[prov_start..prov_end])
            .map_err(|e| DatabaseError::InvalidUtf8(e.to_string()))?
            .to_string();

        // Populate Records
        let mut records: HashMap<(HashAlgorithm, u64, Vec<u8>), Vec<String>> =
            HashMap::with_capacity(header.total_records() as usize);
        let mut rec_pos = HEADER_SIZE;

        for &alg in &HashAlgorithm::ALL {
            let count = header.count_for(alg) as usize;
            let width = alg.record_width();
            let dlen = alg.digest_len();
            let mut prev_key: Option<(&[u8], u64)> = None;

            for idx in 0..count {
                let digest = &slice[rec_pos..rec_pos + dlen];
                let size = u64::from_le_bytes(
                    slice[rec_pos + dlen..rec_pos + dlen + 8]
                        .try_into()
                        .unwrap(),
                );
                let name_id = u32::from_le_bytes(
                    slice[rec_pos + dlen + 8..rec_pos + width]
                        .try_into()
                        .unwrap(),
                );

                if name_id >= header.name_count {
                    return Err(DatabaseError::InvalidNameId(name_id, header.name_count));
                }

                // Strict validation: verify sort order (digest, then size)
                let current_key = (digest, size);
                if let Some(prev) = prev_key {
                    if current_key < prev {
                        return Err(DatabaseError::UnsortedIndex(alg, idx));
                    }
                }
                prev_key = Some(current_key);

                records
                    .entry((alg, size, digest.to_vec()))
                    .or_default()
                    .push(names[name_id as usize].clone());

                rec_pos += width;
            }
        }

        Ok(Self {
            records,
            counts: [
                header.count_md5 as usize,
                header.count_sha1 as usize,
                header.count_sha256 as usize,
            ],
            name_count: names.len(),
            provenance,
        })
    }

    /// Reads and parses an in-memory index from a database file on disk.
    pub fn from_file(path: &Path) -> Result<Self, DatabaseError> {
        let bytes = std::fs::read(path).map_err(|e| {
            DatabaseError::Io(format!("Failed to read database {}: {}", path.display(), e))
        })?;
        Self::from_bytes(&bytes)
    }
}

impl RsidbIndex for InMemoryIndex {
    fn lookup(&self, alg: HashAlgorithm, size: u64, digest: &[u8]) -> Vec<String> {
        if digest.len() != alg.digest_len() {
            return Vec::new();
        }
        self.records
            .get(&(alg, size, digest.to_vec()))
            .cloned()
            .unwrap_or_default()
    }

    fn record_count(&self, alg: HashAlgorithm) -> usize {
        self.counts[alg.index()]
    }

    fn name_count(&self) -> usize {
        self.name_count
    }

    fn provenance(&self) -> &str {
        &self.provenance
    }
}
