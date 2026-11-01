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

pub mod error;
pub mod hash;
pub mod limits;
pub mod memory;
pub mod report;
pub mod status;
pub mod threat;

pub use error::ScanError;
pub use hash::{hash_bytes, hash_file_bounded, hash_reader_bounded, HashResult};
pub use limits::{ResourceLimits, ResourceTracker};
pub use memory::MemoryUsage;
pub use report::{ScanReport, TargetMetadata};
pub use status::ScanStatus;
pub use threat::{Severity, Threat, ThreatCategory};
