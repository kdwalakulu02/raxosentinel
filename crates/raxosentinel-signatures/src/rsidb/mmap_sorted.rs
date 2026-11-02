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
use super::format::{HashAlgorithm, RsidbHeader};
use super::traits::RsidbIndex;
use memmap2::Mmap;
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
        let layout = super::layout::validate(storage.as_slice())?;
        Ok(Self {
            storage,
            header: layout.header,
            offsets: layout.record_offsets,
            name_offsets: layout.name_offsets,
            provenance_range: layout.provenance_range,
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
        // Validated at load; checked again (cheap) so a file mutated after mapping cannot cause UB.
        std::str::from_utf8(&self.storage.as_slice()[pos..pos + len]).unwrap_or("<invalid-utf8>")
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
        // Validated at load; checked again (cheap) so a file mutated after mapping cannot cause UB.
        std::str::from_utf8(&self.storage.as_slice()[pos..pos + len]).unwrap_or("<invalid-utf8>")
    }
}
