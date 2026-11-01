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
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub trait RsidbIndex: Send + Sync {
    /// Look up all detection names matching (algorithm, file_size, digest).
    fn lookup(&self, alg: HashAlgorithm, size: u64, digest: &[u8]) -> Vec<String>;

    /// Check if there is any match for (algorithm, file_size, digest).
    fn has_match(&self, alg: HashAlgorithm, size: u64, digest: &[u8]) -> bool {
        !self.lookup(alg, size, digest).is_empty()
    }

    /// Scan a block of raw bytes against all supported algorithms present in the database.
    fn scan_raw_bytes(&self, data: &[u8]) -> Vec<String> {
        let size = data.len() as u64;
        let mut found = Vec::new();

        if self.record_count(HashAlgorithm::Md5) > 0 {
            let digest: [u8; 16] = Md5::digest(data).into();
            found.extend(self.lookup(HashAlgorithm::Md5, size, &digest));
        }

        if self.record_count(HashAlgorithm::Sha1) > 0 {
            let digest: [u8; 20] = Sha1::digest(data).into();
            found.extend(self.lookup(HashAlgorithm::Sha1, size, &digest));
        }

        if self.record_count(HashAlgorithm::Sha256) > 0 {
            let digest: [u8; 32] = Sha256::digest(data).into();
            found.extend(self.lookup(HashAlgorithm::Sha256, size, &digest));
        }

        found
    }

    /// Count of records for a specific algorithm.
    fn record_count(&self, alg: HashAlgorithm) -> usize;

    /// Total records across all algorithms.
    fn total_records(&self) -> usize {
        self.record_count(HashAlgorithm::Md5)
            + self.record_count(HashAlgorithm::Sha1)
            + self.record_count(HashAlgorithm::Sha256)
    }

    /// Total unique detection names.
    fn name_count(&self) -> usize;

    /// Database provenance metadata string.
    fn provenance(&self) -> &str;
}
