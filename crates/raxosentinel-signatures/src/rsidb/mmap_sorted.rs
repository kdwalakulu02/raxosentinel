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
use super::traits::RsidbIndex;
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::path::Path;

enum Storage {
    Mmap(Mmap),
    Buffer(Vec<u8>),
}

impl Storage {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Mmap(m) => m,
            Self::Buffer(b) => b,
        }
    }
}

/// Memory-mapped sorted binary index for RSIDB.
///
/// Maps the database file directly into memory and performs O(log N) binary searches
/// over flat, contiguous record slices. Minimizes heap memory usage and delivers near-instant
/// startup times with zero deserialization overhead.
pub struct MmapSortedIndex {
    storage: Storage,
    header: RsidbHeader,
    offsets: [usize; 3],
    name_offsets: Vec<(usize, usize)>,
    provenance_range: (usize, usize),
}

impl MmapSortedIndex {
    /// Opens and validates a memory-mapped RSIDB index from a file path.
    pub fn from_file(path: &Path) -> Result<Self, DatabaseError> {
        let file = File::open(path).map_err(|e| {
            DatabaseError::Io(format!("Failed to open database {}: {}", path.display(), e))
        })?;
        let mmap = unsafe {
            Mmap::map(&file).map_err(|e| {
                DatabaseError::Io(format!("Failed to mmap database {}: {}", path.display(), e))
            })?
        };
        Self::from_storage(Storage::Mmap(mmap))
    }

    /// Loads and validates a sorted index from an in-memory byte buffer.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, DatabaseError> {
        Self::from_storage(Storage::Buffer(bytes))
    }

    fn from_storage(storage: Storage) -> Result<Self, DatabaseError> {
        let slice = storage.as_slice();
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

        let offsets = [
            HEADER_SIZE,
            HEADER_SIZE + md5_bytes,
            HEADER_SIZE + md5_bytes + sha1_bytes,
        ];

        // Parse and validate Name Table
        let name_start = HEADER_SIZE + records_bytes;
        let name_end = name_start + header.name_bytes as usize;
        let mut name_offsets = Vec::with_capacity(header.name_count as usize);
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
            // Validate UTF-8 compliance
            std::str::from_utf8(&slice[pos..pos + len])
                .map_err(|e| DatabaseError::InvalidUtf8(e.to_string()))?;
            name_offsets.push((pos, len));
            pos += len;
        }

        if pos != name_end {
            return Err(DatabaseError::TrailingBytes(pos, name_end));
        }

        // Validate Provenance String
        let prov_start = name_end;
        let prov_end = prov_start + header.provenance_bytes as usize;
        std::str::from_utf8(&slice[prov_start..prov_end])
            .map_err(|e| DatabaseError::InvalidUtf8(e.to_string()))?;

        // Strict validation: verify sorted keys and label IDs across all records
        for &alg in &HashAlgorithm::ALL {
            let count = header.count_for(alg) as usize;
            let base = offsets[alg.index()];
            let width = alg.record_width();
            let dlen = alg.digest_len();
            let mut prev_key: Option<(&[u8], u64)> = None;

            for i in 0..count {
                let rec_pos = base + i * width;
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

                let current_key = (digest, size);
                if let Some(prev) = prev_key {
                    if current_key < prev {
                        return Err(DatabaseError::UnsortedIndex(alg, i));
                    }
                }
                prev_key = Some(current_key);
            }
        }

        Ok(Self {
            storage,
            header,
            offsets,
            name_offsets,
            provenance_range: (prov_start, prov_end - prov_start),
        })
    }

    #[inline]
    fn get_record(&self, alg: HashAlgorithm, idx: usize) -> (&[u8], u64, u32) {
        let slice = self.storage.as_slice();
        let base = self.offsets[alg.index()];
        let width = alg.record_width();
        let dlen = alg.digest_len();
        let rec_pos = base + idx * width;

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

        (digest, size, name_id)
    }

    #[inline]
    fn get_name(&self, name_id: u32) -> &str {
        let (pos, len) = self.name_offsets[name_id as usize];
        unsafe { std::str::from_utf8_unchecked(&self.storage.as_slice()[pos..pos + len]) }
    }
}

impl RsidbIndex for MmapSortedIndex {
    fn lookup(&self, alg: HashAlgorithm, size: u64, digest: &[u8]) -> Vec<String> {
        let count = self.header.count_for(alg) as usize;
        if count == 0 || digest.len() != alg.digest_len() {
            return Vec::new();
        }

        let target_key = (digest, size);
        let mut lo = 0;
        let mut hi = count;

        // Binary search for the lower bound: first index where key >= target_key
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let (rec_digest, rec_size, _) = self.get_record(alg, mid);
            let candidate_key = (rec_digest, rec_size);

            if candidate_key < target_key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        // Collect all matching records (supporting multiple detection names for identical keys)
        let mut matches = Vec::new();
        while lo < count {
            let (rec_digest, rec_size, name_id) = self.get_record(alg, lo);
            if (rec_digest, rec_size) != target_key {
                break;
            }
            matches.push(self.get_name(name_id).to_string());
            lo += 1;
        }

        matches
    }

    fn record_count(&self, alg: HashAlgorithm) -> usize {
        self.header.count_for(alg) as usize
    }

    fn name_count(&self) -> usize {
        self.header.name_count as usize
    }

    fn provenance(&self) -> &str {
        let (pos, len) = self.provenance_range;
        unsafe { std::str::from_utf8_unchecked(&self.storage.as_slice()[pos..pos + len]) }
    }
}
