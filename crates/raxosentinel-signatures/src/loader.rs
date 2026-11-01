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

use crate::database::SignatureDatabase;
use crate::models::{HashRule, PatternRule};
use raxosentinel_core::ScanError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// External rule set definition file structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleSetFile {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub hash_rules: Vec<HashRule>,
    #[serde(default)]
    pub pattern_rules: Vec<PatternRule>,
}

/// Loads signature rules from JSON string.
pub fn load_rules_from_str(json: &str, db: &mut SignatureDatabase) -> Result<(), ScanError> {
    let ruleset: RuleSetFile = serde_json::from_str(json)
        .map_err(|e| ScanError::InvalidSignature(format!("JSON parsing error: {}", e)))?;

    for rule in ruleset.hash_rules {
        if rule.sha256.len() != 64 || !rule.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ScanError::InvalidSignature(format!(
                "Invalid SHA-256 hash in rule '{}': '{}'",
                rule.name, rule.sha256
            )));
        }
        db.add_hash_rule(rule);
    }

    for rule in ruleset.pattern_rules {
        if rule.pattern.is_empty() {
            return Err(ScanError::InvalidSignature(format!(
                "Pattern in rule '{}' cannot be empty",
                rule.name
            )));
        }
        db.add_pattern_rule(rule);
    }

    db.compile()?;
    Ok(())
}

/// Loads signature rules from a JSON file path.
pub fn load_rules_from_file(path: &Path, db: &mut SignatureDatabase) -> Result<(), ScanError> {
    let content = fs::read_to_string(path).map_err(|e| ScanError::IoWithPath {
        path: path.to_path_buf(),
        source: e,
    })?;
    load_rules_from_str(&content, db)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_valid_rules() {
        let json = r#"{
            "description": "Custom test rules",
            "hash_rules": [
                {
                    "name": "Custom.Malware.Hash",
                    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "category": "trojan",
                    "severity": "critical",
                    "description": "Custom test hash"
                }
            ],
            "pattern_rules": [
                {
                    "name": "Custom.Malware.BytePattern",
                    "pattern": "48656c6c6f",
                    "category": "suspicious_script",
                    "severity": "medium",
                    "description": "Matches 'Hello' in hex"
                }
            ]
        }"#;

        let mut db = SignatureDatabase::new();
        assert!(load_rules_from_str(json, &mut db).is_ok());
        assert_eq!(db.hash_count(), 1);
        assert_eq!(db.pattern_count(), 1);

        let threats = db.match_bytes(b"Hello world");
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].name, "Custom.Malware.BytePattern");
    }

    #[test]
    fn test_load_invalid_hash() {
        let json = r#"{
            "hash_rules": [
                {
                    "name": "Bad.Hash",
                    "sha256": "invalid_length_or_chars",
                    "category": "trojan",
                    "severity": "critical",
                    "description": "Bad"
                }
            ]
        }"#;

        let mut db = SignatureDatabase::new();
        assert!(load_rules_from_str(json, &mut db).is_err());
    }
}
