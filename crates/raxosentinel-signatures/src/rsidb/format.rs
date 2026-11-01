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
use std::io::{self, Write};

pub const RSIDB_MAGIC: &[u8; 8] = b"RSIDB001";
pub const RSIDB_CURRENT_VERSION: u32 = 1;
pub const HEADER_SIZE: usize = 92;

pub const FLAG_NONE: u32 = 0;
pub const FLAG_HAS_DIRECTORY: u32 = 1 << 0;

/// Number of prefix buckets for the compact 16-bit lookup directory (2^16 = 65,536).
pub const PREFIX_BUCKET_COUNT: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum HashAlgorithm {
    Md5 = 0,
    Sha1 = 1,
    Sha256 = 2,
}

impl HashAlgorithm {
    pub const ALL: [HashAlgorithm; 3] = [
        HashAlgorithm::Md5,
        HashAlgorithm::Sha1,
        HashAlgorithm::Sha256,
    ];

    #[inline]
    pub const fn index(self) -> usize {
        self as usize
    }

    #[inline]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    #[inline]
    pub const fn record_width(self) -> usize {
        8 + self.digest_len() + 4
    }

    pub fn from_digest_len(len: usize) -> Option<Self> {
        match len {
            16 => Some(Self::Md5),
            20 => Some(Self::Sha1),
            32 => Some(Self::Sha256),
            _ => None,
        }
    }
}

/// 88-byte fixed little-endian header of RSIDB files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsidbHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub flags: u32,
    pub count_md5: u32,
    pub count_sha1: u32,
    pub count_sha256: u32,
    pub name_count: u32,
    pub name_bytes: u32,
    pub provenance_bytes: u32,
    pub reserved: u32,
    pub directory_offset: u64,
    pub directory_bytes: u64,
    pub data_checksum: [u8; 32],
}

impl RsidbHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        count_md5: u32,
        count_sha1: u32,
        count_sha256: u32,
        name_count: u32,
        name_bytes: u32,
        provenance_bytes: u32,
        flags: u32,
        directory_offset: u64,
        directory_bytes: u64,
        data_checksum: [u8; 32],
    ) -> Self {
        Self {
            magic: *RSIDB_MAGIC,
            version: RSIDB_CURRENT_VERSION,
            flags,
            count_md5,
            count_sha1,
            count_sha256,
            name_count,
            name_bytes,
            provenance_bytes,
            reserved: 0,
            directory_offset,
            directory_bytes,
            data_checksum,
        }
    }

    pub fn count_for(&self, alg: HashAlgorithm) -> u32 {
        match alg {
            HashAlgorithm::Md5 => self.count_md5,
            HashAlgorithm::Sha1 => self.count_sha1,
            HashAlgorithm::Sha256 => self.count_sha256,
        }
    }

    pub fn total_records(&self) -> u64 {
        self.count_md5 as u64 + self.count_sha1 as u64 + self.count_sha256 as u64
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.magic)?;
        w.write_all(&self.version.to_le_bytes())?;
        w.write_all(&self.flags.to_le_bytes())?;
        w.write_all(&self.count_md5.to_le_bytes())?;
        w.write_all(&self.count_sha1.to_le_bytes())?;
        w.write_all(&self.count_sha256.to_le_bytes())?;
        w.write_all(&self.name_count.to_le_bytes())?;
        w.write_all(&self.name_bytes.to_le_bytes())?;
        w.write_all(&self.provenance_bytes.to_le_bytes())?;
        w.write_all(&self.reserved.to_le_bytes())?;
        w.write_all(&self.directory_offset.to_le_bytes())?;
        w.write_all(&self.directory_bytes.to_le_bytes())?;
        w.write_all(&self.data_checksum)?;
        Ok(())
    }

    pub fn read_from(slice: &[u8]) -> Result<Self, DatabaseError> {
        if slice.len() < HEADER_SIZE {
            return Err(DatabaseError::TruncatedHeader(slice.len(), HEADER_SIZE));
        }

        let mut magic = [0u8; 8];
        magic.copy_from_slice(&slice[0..8]);
        if &magic != RSIDB_MAGIC {
            return Err(DatabaseError::InvalidMagic(*RSIDB_MAGIC, magic));
        }

        let version = u32::from_le_bytes(slice[8..12].try_into().unwrap());
        if version != RSIDB_CURRENT_VERSION {
            return Err(DatabaseError::UnsupportedVersion(
                version,
                RSIDB_CURRENT_VERSION,
            ));
        }

        let flags = u32::from_le_bytes(slice[12..16].try_into().unwrap());
        let count_md5 = u32::from_le_bytes(slice[16..20].try_into().unwrap());
        let count_sha1 = u32::from_le_bytes(slice[20..24].try_into().unwrap());
        let count_sha256 = u32::from_le_bytes(slice[24..28].try_into().unwrap());
        let name_count = u32::from_le_bytes(slice[28..32].try_into().unwrap());
        let name_bytes = u32::from_le_bytes(slice[32..36].try_into().unwrap());
        let provenance_bytes = u32::from_le_bytes(slice[36..40].try_into().unwrap());
        let reserved = u32::from_le_bytes(slice[40..44].try_into().unwrap());
        let directory_offset = u64::from_le_bytes(slice[44..52].try_into().unwrap());
        let directory_bytes = u64::from_le_bytes(slice[52..60].try_into().unwrap());
        let mut data_checksum = [0u8; 32];
        data_checksum.copy_from_slice(&slice[60..92]); // wait! 60..92 is 32 bytes!

        Ok(Self {
            magic,
            version,
            flags,
            count_md5,
            count_sha1,
            count_sha256,
            name_count,
            name_bytes,
            provenance_bytes,
            reserved,
            directory_offset,
            directory_bytes,
            data_checksum,
        })
    }
}
