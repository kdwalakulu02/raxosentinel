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

pub mod crypto;
pub mod error;
pub mod format;
pub mod importer;
pub mod in_memory;
pub mod ingest;
pub mod layout;
pub mod lifecycle;
pub mod malwarebazaar;
pub mod mmap_compact_dir;
pub mod mmap_sorted;
pub mod public_release;
pub mod traits;

#[cfg(test)]
mod tests;

pub use error::DatabaseError;
pub use format::{HashAlgorithm, RsidbHeader, HEADER_SIZE};
pub use importer::{IngestionStats, RsidbCompiler, SignatureEntry, SignatureImporter};
pub use in_memory::InMemoryIndex;
pub use mmap_compact_dir::MmapCompactDirIndex;
pub use mmap_sorted::MmapSortedIndex;
pub use traits::RsidbIndex;
