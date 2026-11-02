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

//! Shared, hardened structural validation for RSIDB images.
//!
//! The SHA-256 payload checksum only detects *accidental* corruption: anyone able to
//! modify a database file can also recompute the checksum. Every structural field is
//! therefore validated independently with checked arithmetic, so that a crafted file
//! (valid checksum, hostile header) can never cause out-of-bounds access, integer
//! overflow, huge allocations or silently incorrect lookups (false negatives).

use super::error::DatabaseError;
use super::format::{
    HashAlgorithm, RsidbHeader, FLAG_HAS_DIRECTORY, HEADER_SIZE, PREFIX_BUCKET_COUNT,
};
use sha2::{Digest, Sha256};

/// Maximum accepted length of a single detection name (bytes).
pub const MAX_NAME_LEN: usize = 1024;

/// Exact size of one per-algorithm prefix directory (65,537 little-endian u32 values).
pub const DIR_BYTES_PER_ALG: usize = (PREFIX_BUCKET_COUNT + 1) * 4;

/// Exact size of the complete prefix directory region (three algorithms).
pub const DIR_TOTAL_BYTES: usize = DIR_BYTES_PER_ALG * 3;

/// Fully validated byte layout of an RSIDB image.
#[derive(Debug, Clone)]
pub struct ValidatedLayout {
    pub header: RsidbHeader,
    pub record_offsets: [usize; 3],
    pub name_offsets: Vec<(usize, usize)>,
    pub provenance_range: (usize, usize),
    /// Start offsets of the validated per-algorithm prefix directories, if present.
    pub dir_offsets: [Option<usize>; 3],
}

fn layout_err(msg: impl Into<String>) -> DatabaseError {
    DatabaseError::InvalidLayout(msg.into())
}

fn add(a: usize, b: usize) -> Result<usize, DatabaseError> {
    a.checked_add(b)
        .ok_or_else(|| layout_err("size arithmetic overflow"))
}

fn mul(a: usize, b: usize) -> Result<usize, DatabaseError> {
    a.checked_mul(b)
        .ok_or_else(|| layout_err("size arithmetic overflow"))
}

#[inline]
fn read_u32(slice: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes([slice[pos], slice[pos + 1], slice[pos + 2], slice[pos + 3]])
}

/// Validates an entire RSIDB image. Must succeed before any lookup is performed.
pub fn validate(slice: &[u8]) -> Result<ValidatedLayout, DatabaseError> {
    let header = RsidbHeader::read_from(slice)?;

    if header.reserved != 0 {
        return Err(layout_err("reserved header field must be zero"));
    }
    if header.flags & !FLAG_HAS_DIRECTORY != 0 {
        return Err(layout_err(format!(
            "unknown header flags 0x{:08x}",
            header.flags
        )));
    }

    let md5_bytes = mul(header.count_md5 as usize, HashAlgorithm::Md5.record_width())?;
    let sha1_bytes = mul(
        header.count_sha1 as usize,
        HashAlgorithm::Sha1.record_width(),
    )?;
    let sha256_bytes = mul(
        header.count_sha256 as usize,
        HashAlgorithm::Sha256.record_width(),
    )?;
    let records_bytes = add(add(md5_bytes, sha1_bytes)?, sha256_bytes)?;

    let has_dir = header.flags & FLAG_HAS_DIRECTORY != 0;
    let dir_bytes = usize::try_from(header.directory_bytes)
        .map_err(|_| layout_err("directory_bytes does not fit in address space"))?;

    let name_start = add(HEADER_SIZE, records_bytes)?;
    let name_end = add(name_start, header.name_bytes as usize)?;
    let prov_end = add(name_end, header.provenance_bytes as usize)?;
    let expected_len = add(prov_end, dir_bytes)?;

    if slice.len() < expected_len {
        return Err(DatabaseError::TruncatedData(expected_len, slice.len()));
    }
    if slice.len() > expected_len {
        return Err(DatabaseError::TrailingBytes(expected_len, slice.len()));
    }

    // Directory region must be exactly where the format places it, with the exact size.
    if has_dir {
        if header.directory_offset != prov_end as u64 || dir_bytes != DIR_TOTAL_BYTES {
            return Err(layout_err(format!(
                "directory region mismatch: offset {} (expected {}), bytes {} (expected {})",
                header.directory_offset, prov_end, dir_bytes, DIR_TOTAL_BYTES
            )));
        }
    } else if header.directory_offset != 0 || dir_bytes != 0 {
        return Err(layout_err(
            "directory fields set without FLAG_HAS_DIRECTORY",
        ));
    }

    // Every name needs at least a 4-byte length prefix: bound the allocation by real data.
    let min_name_table = mul(header.name_count as usize, 4)?;
    if min_name_table > header.name_bytes as usize {
        return Err(layout_err(format!(
            "name_count {} cannot fit in name table of {} bytes",
            header.name_count, header.name_bytes
        )));
    }

    // Integrity checksum (detects accidental corruption only; not authentication).
    let computed: [u8; 32] = Sha256::digest(&slice[HEADER_SIZE..]).into();
    if computed != header.data_checksum {
        return Err(DatabaseError::CorruptedChecksum(
            hex::encode(header.data_checksum),
            hex::encode(computed),
        ));
    }

    let record_offsets = [
        HEADER_SIZE,
        HEADER_SIZE + md5_bytes,
        HEADER_SIZE + md5_bytes + sha1_bytes,
    ];

    // Name table
    let mut name_offsets = Vec::with_capacity(header.name_count as usize);
    let mut pos = name_start;
    for _ in 0..header.name_count {
        if name_end - pos < 4 {
            return Err(DatabaseError::TruncatedData(pos + 4, name_end));
        }
        let len = read_u32(slice, pos) as usize;
        pos += 4;
        if len > MAX_NAME_LEN {
            return Err(layout_err(format!(
                "detection name length {} exceeds {}",
                len, MAX_NAME_LEN
            )));
        }
        if name_end - pos < len {
            return Err(DatabaseError::TruncatedData(pos + len, name_end));
        }
        std::str::from_utf8(&slice[pos..pos + len])
            .map_err(|e| DatabaseError::InvalidUtf8(e.to_string()))?;
        name_offsets.push((pos, len));
        pos += len;
    }
    if pos != name_end {
        return Err(DatabaseError::TrailingBytes(pos, name_end));
    }

    std::str::from_utf8(&slice[name_end..prov_end])
        .map_err(|e| DatabaseError::InvalidUtf8(e.to_string()))?;

    // Records: sorted keys, valid name IDs.
    for &alg in &HashAlgorithm::ALL {
        let count = header.count_for(alg) as usize;
        let base = record_offsets[alg.index()];
        let width = alg.record_width();
        let dlen = alg.digest_len();
        let mut prev: Option<(&[u8], u64)> = None;
        for i in 0..count {
            let rec = base + i * width;
            let digest = &slice[rec..rec + dlen];
            let size = u64::from_le_bytes(slice[rec + dlen..rec + dlen + 8].try_into().unwrap());
            let name_id = read_u32(slice, rec + dlen + 8);
            if name_id >= header.name_count {
                return Err(DatabaseError::InvalidNameId(name_id, header.name_count));
            }
            let key = (digest, size);
            if let Some(p) = prev {
                if key < p {
                    return Err(DatabaseError::UnsortedIndex(alg, i));
                }
            }
            prev = Some(key);
        }
    }

    // Directory: must be monotonic, complete, and consistent with every record's prefix.
    // Without this, a crafted directory can steer lookups to empty buckets (false negatives).
    let mut dir_offsets = [None; 3];
    if has_dir {
        for &alg in &HashAlgorithm::ALL {
            let dir = prov_end + alg.index() * DIR_BYTES_PER_ALG;
            let count = header.count_for(alg) as usize;
            if read_u32(slice, dir) != 0 {
                return Err(layout_err(format!("{:?} directory must start at 0", alg)));
            }
            if read_u32(slice, dir + PREFIX_BUCKET_COUNT * 4) as usize != count {
                return Err(layout_err(format!(
                    "{:?} directory sentinel != record count",
                    alg
                )));
            }
            let mut last = 0u32;
            for p in 0..=PREFIX_BUCKET_COUNT {
                let v = read_u32(slice, dir + p * 4);
                if v < last {
                    return Err(layout_err(format!(
                        "{:?} directory not monotonic at {}",
                        alg, p
                    )));
                }
                last = v;
            }
            let base = record_offsets[alg.index()];
            let width = alg.record_width();
            for i in 0..count {
                let rec = base + i * width;
                let prefix = ((slice[rec] as usize) << 8) | slice[rec + 1] as usize;
                let lo = read_u32(slice, dir + prefix * 4) as usize;
                let hi = read_u32(slice, dir + (prefix + 1) * 4) as usize;
                if i < lo || i >= hi {
                    return Err(layout_err(format!(
                        "{:?} directory bucket {} inconsistent with record {}",
                        alg, prefix, i
                    )));
                }
            }
            dir_offsets[alg.index()] = Some(dir);
        }
    }

    Ok(ValidatedLayout {
        header,
        record_offsets,
        name_offsets,
        provenance_range: (name_end, prov_end - name_end),
        dir_offsets,
    })
}
