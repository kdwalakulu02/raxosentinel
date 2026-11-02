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

use crate::status::ScanStatus;
use crate::threat::Threat;
use serde::{Deserialize, Serialize};

/// Target metadata captured during scanning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetMetadata {
    pub path: Option<String>,
    pub file_name: Option<String>,
    pub file_size_bytes: u64,
    pub sha256: String,
    pub detected_mime: String,
    pub declared_mime: Option<String>,
}

/// Structured scan report adhering to RaxoSentinel specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanReport {
    /// Engine version
    pub engine_version: String,
    /// Target metadata
    pub target: TargetMetadata,
    /// Overall scan outcome
    pub status: ScanStatus,
    /// Explicit human-readable statement of what this result means
    pub status_description: String,
    /// Safety notice clarifying that Clean is not an absolute safety guarantee
    pub safety_disclaimer: String,
    /// All detected threats or anomalies
    pub threats: Vec<Threat>,
    /// Sub-target scan reports (e.g. extracted email attachments, nested MIME messages)
    pub sub_targets: Vec<ScanReport>,
    /// Elapsed scan duration in milliseconds
    pub scan_duration_ms: u64,
    /// Error description if status == Failed
    pub error: Option<String>,
}

impl ScanReport {
    pub fn new(
        target: TargetMetadata,
        status: ScanStatus,
        threats: Vec<Threat>,
        sub_targets: Vec<ScanReport>,
        scan_duration_ms: u64,
        error: Option<String>,
    ) -> Self {
        fn collect_detections<'a>(
            report: &'a ScanReport,
            found: &mut std::collections::HashSet<(&'a str, Option<&'a str>)>,
        ) {
            for threat in &report.threats {
                found.insert((&threat.name, threat.location.as_deref()));
            }
            for child in &report.sub_targets {
                collect_detections(child, found);
            }
        }
        let mut found = std::collections::HashSet::new();
        for threat in &threats {
            found.insert((threat.name.as_str(), threat.location.as_deref()));
        }
        for child in &sub_targets {
            collect_detections(child, &mut found);
        }
        let detected = found.len();
        let status_description = match status {
            ScanStatus::Clean => "No known threats detected by active signatures.".to_string(),
            ScanStatus::Infected => format!("Detected {} threat(s).", detected),
            ScanStatus::Unsupported => {
                "Content format is unsupported or could not be inspected.".to_string()
            }
            ScanStatus::Failed => {
                if let Some(ref err) = error {
                    format!("Scan failed: {}", err)
                } else {
                    "Scan could not be completed.".to_string()
                }
            }
        };

        let safety_disclaimer = if status == ScanStatus::Clean {
            "NOTICE: RaxoSentinel found no known threats in this file. This scan result reflects the coverage of current rules and is not an absolute guarantee that the file is safe or benign."
        } else {
            "NOTICE: Automated threat detection report."
        }.to_string();

        Self {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            target,
            status,
            status_description,
            safety_disclaimer,
            threats,
            sub_targets,
            scan_duration_ms,
            error,
        }
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}
