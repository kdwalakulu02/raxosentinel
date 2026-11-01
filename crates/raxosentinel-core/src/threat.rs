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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    TestSignature,
    Virus,
    Trojan,
    Worm,
    Ransomware,
    Exploit,
    Phishing,
    SuspiciousScript,
    MacroMalware,
    SuspiciousArchive,
    ExtensionMismatch,
    SuspiciousExecutable,
    Other(String),
}

impl std::fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatCategory::TestSignature => write!(f, "Test Signature"),
            ThreatCategory::Virus => write!(f, "Virus"),
            ThreatCategory::Trojan => write!(f, "Trojan"),
            ThreatCategory::Worm => write!(f, "Worm"),
            ThreatCategory::Ransomware => write!(f, "Ransomware"),
            ThreatCategory::Exploit => write!(f, "Exploit"),
            ThreatCategory::Phishing => write!(f, "Phishing"),
            ThreatCategory::SuspiciousScript => write!(f, "Suspicious Script"),
            ThreatCategory::MacroMalware => write!(f, "Macro Malware"),
            ThreatCategory::SuspiciousArchive => write!(f, "Suspicious Archive"),
            ThreatCategory::ExtensionMismatch => write!(f, "Extension Mismatch"),
            ThreatCategory::SuspiciousExecutable => write!(f, "Suspicious Executable"),
            ThreatCategory::Other(s) => write!(f, "Other: {}", s),
        }
    }
}

/// A detected security threat or anomaly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Threat {
    /// Canonical threat identifier (e.g. "EICAR-Standard-Antivirus-Test-File", "Trojan.Generic.Downloader")
    pub name: String,
    /// Categorization of the threat
    pub category: ThreatCategory,
    /// Assessed severity level
    pub severity: Severity,
    /// Human-readable explanation of why this was flagged
    pub description: String,
    /// Specific signature, hash rule or heuristic that triggered detection
    pub matched_by: String,
    /// Location inside the inspected artifact (e.g. byte offset, MIME part, attachment filename)
    pub location: Option<String>,
}

impl Threat {
    pub fn new(
        name: impl Into<String>,
        category: ThreatCategory,
        severity: Severity,
        description: impl Into<String>,
        matched_by: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            category,
            severity,
            description: description.into(),
            matched_by: matched_by.into(),
            location: None,
        }
    }

    pub fn with_location(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }
}
