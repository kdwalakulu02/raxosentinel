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

use serde::{Deserialize, Serialize};

/// High-level scanning status.
///
/// NOTE: Clean represents that no threats were detected by current rules/signatures.
/// It is fundamentally NOT an assertion that the content is universally safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanStatus {
    /// No known threats were matched by active signatures.
    /// This is an absence of detection, not a guarantee of safety.
    Clean,
    /// One or more threats were identified.
    Infected,
    /// The input format or encoding is unsupported, encrypted, or cannot be parsed.
    Unsupported,
    /// Scanning could not complete due to an I/O error, resource limit, or corruption.
    Failed,
}

impl ScanStatus {
    pub fn is_clean(&self) -> bool {
        matches!(self, ScanStatus::Clean)
    }

    pub fn is_infected(&self) -> bool {
        matches!(self, ScanStatus::Infected)
    }

    pub fn is_unsupported(&self) -> bool {
        matches!(self, ScanStatus::Unsupported)
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, ScanStatus::Failed)
    }

    /// Exit code appropriate for CLI usage:
    /// 0 = Clean (No threats detected)
    /// 1 = Infected (Threat detected)
    /// 2 = Unsupported (Unsupported content)
    /// 3 = Failed (Scan failure / limit exceeded)
    pub fn exit_code(&self) -> i32 {
        match self {
            ScanStatus::Clean => 0,
            ScanStatus::Infected => 1,
            ScanStatus::Unsupported => 2,
            ScanStatus::Failed => 3,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            ScanStatus::Clean => "No threats detected by active rules (not a guarantee of safety)",
            ScanStatus::Infected => "Threat detected",
            ScanStatus::Unsupported => "Unsupported content format or structure",
            ScanStatus::Failed => "Scan aborted or failed",
        }
    }
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanStatus::Clean => write!(f, "CLEAN (no threats detected)"),
            ScanStatus::Infected => write!(f, "INFECTED"),
            ScanStatus::Unsupported => write!(f, "UNSUPPORTED"),
            ScanStatus::Failed => write!(f, "FAILED"),
        }
    }
}
