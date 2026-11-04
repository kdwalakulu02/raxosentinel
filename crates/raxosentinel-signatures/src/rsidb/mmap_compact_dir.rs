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
use std::path::Path;

/// Validated sorted index backed by owned bytes. The historical type name is retained
/// for API compatibility; file-backed mappings are not used because external writes
/// or truncation cannot be ruled out for arbitrary input paths.
pub struct MmapCompactDirIndex {
    storage: Vec<u8>,
    header: RsidbHeader,
    record_offsets: [usize; 3],
    dir_offsets: [Option<usize>; 3],
    name_offsets: Vec<(usize, usize)>,
    provenance_range: (usize, usize),
}

impl MmapCompactDirIndex {
    /// Reads and validates an owned compact-directory index from a file.
    pub fn from_file(path: &Path) -> Result<Self, DatabaseError> {
        let bytes = std::fs::read(path).map_err(|e| {
            DatabaseError::Io(format!("Failed to read database {}: {}", path.display(), e))
        })?;
        Self::from_bytes(bytes)
    }

    /// Loads and validates an index from an owned byte buffer.
    pub fn from_bytes(storage: Vec<u8>) -> Result<Self, DatabaseError> {
        let layout = super::layout::validate(storage.as_slice())?;
        Ok(Self {
            storage,
            header: layout.header,
            record_offsets: layout.record_offsets,
            dir_offsets: layout.dir_offsets,
            name_offsets: layout.name_offsets,
            provenance_range: layout.provenance_range,
        })
    }

    #[inline]
    fn get_record(&self, alg: HashAlgorithm, idx: usize) -> (&[u8], u64, u32) {
        let slice = self.storage.as_slice();
        let base = self.record_offsets[alg.index()];
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

impl RsidbIndex for MmapCompactDirIndex {
    fn lookup(&self, alg: HashAlgorithm, size: u64, digest: &[u8]) -> Vec<String> {
        let count = self.header.count_for(alg) as usize;
        if count == 0 || digest.len() != alg.digest_len() {
            return Vec::new();
        }

        let target_key = (digest, size);

        // Determine search range: either from compact directory or full range fallback
        let (mut lo, mut hi) = if let Some(dir_base) = self.dir_offsets[alg.index()] {
            let slice = self.storage.as_slice();
            let prefix = ((digest[0] as usize) << 8) | (digest[1] as usize);
            let p_pos = dir_base + prefix * 4;

            let start_idx =
                u32::from_le_bytes(slice[p_pos..p_pos + 4].try_into().unwrap()) as usize;
            let end_idx =
                u32::from_le_bytes(slice[p_pos + 4..p_pos + 8].try_into().unwrap()) as usize;

            if start_idx >= end_idx {
                return Vec::new(); // Prefix bucket has zero records
            }
            (start_idx, end_idx.min(count))
        } else {
            (0, count)
        };

        // Binary search within narrowed bucket range
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

        // Collect all matching records
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
