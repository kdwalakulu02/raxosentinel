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

use raxosentinel_core::{Severity, Threat, ThreatCategory};
use serde::{Deserialize, Serialize};

/// Signature rule targeting a known exact SHA-256 hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashRule {
    pub name: String,
    pub sha256: String,
    pub category: ThreatCategory,
    pub severity: Severity,
    pub description: String,
}

impl HashRule {
    pub fn new(
        name: impl Into<String>,
        sha256: impl Into<String>,
        category: ThreatCategory,
        severity: Severity,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            sha256: sha256.into().to_lowercase(),
            category,
            severity,
            description: description.into(),
        }
    }

    pub fn to_threat(&self) -> Threat {
        Threat::new(
            &self.name,
            self.category.clone(),
            self.severity.clone(),
            &self.description,
            format!("sha256:{}", self.sha256),
        )
    }
}

/// Signature rule targeting a byte sequence pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternRule {
    pub name: String,
    #[serde(with = "serde_bytes_hex")]
    pub pattern: Vec<u8>,
    pub category: ThreatCategory,
    pub severity: Severity,
    pub description: String,
    /// If specified, pattern match must start at or after this byte offset
    pub min_offset: Option<usize>,
    /// If specified, pattern match must end at or before this byte offset
    pub max_offset: Option<usize>,
}

impl PatternRule {
    pub fn new(
        name: impl Into<String>,
        pattern: Vec<u8>,
        category: ThreatCategory,
        severity: Severity,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            pattern,
            category,
            severity,
            description: description.into(),
            min_offset: None,
            max_offset: None,
        }
    }

    pub fn with_offset_range(mut self, min: Option<usize>, max: Option<usize>) -> Self {
        self.min_offset = min;
        self.max_offset = max;
        self
    }

    pub fn to_threat(&self, matched_offset: usize) -> Threat {
        Threat::new(
            &self.name,
            self.category.clone(),
            self.severity.clone(),
            &self.description,
            format!("pattern_match at byte offset {}", matched_offset),
        )
        .with_location(format!(
            "offset: {:#x} ({})",
            matched_offset, matched_offset
        ))
    }
}

mod serde_bytes_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}
