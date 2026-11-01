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

/// Maximum allowable size for an external signature rule file (10 MiB).
pub const MAX_RULE_FILE_SIZE: u64 = 10 * 1024 * 1024;
/// Maximum number of total rules allowed in a single ruleset (50,000).
pub const MAX_RULE_COUNT: usize = 50_000;
/// Maximum pattern byte length allowed for a single pattern rule (1 MiB).
pub const MAX_PATTERN_LENGTH: usize = 1024 * 1024;
/// Maximum length for rule names (256 characters).
pub const MAX_NAME_LENGTH: usize = 256;

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

/// Loads signature rules from JSON string with strict bounds checking.
pub fn load_rules_from_str(json: &str, db: &mut SignatureDatabase) -> Result<(), ScanError> {
    if json.len() > MAX_RULE_FILE_SIZE as usize {
        return Err(ScanError::FileSizeLimitExceeded {
            limit: MAX_RULE_FILE_SIZE,
            actual: json.len() as u64,
        });
    }

    let ruleset: RuleSetFile = serde_json::from_str(json)
        .map_err(|e| ScanError::InvalidSignature(format!("JSON parsing error: {}", e)))?;

    let total_new_rules = ruleset.hash_rules.len() + ruleset.pattern_rules.len();
    if total_new_rules > MAX_RULE_COUNT {
        return Err(ScanError::InvalidSignature(format!(
            "Rule count {} exceeds maximum allowed limit of {}",
            total_new_rules, MAX_RULE_COUNT
        )));
    }

    for rule in ruleset.hash_rules {
        validate_rule_name(&rule.name)?;
        if rule.sha256.len() != 64 || !rule.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ScanError::InvalidSignature(format!(
                "Invalid SHA-256 hash in rule '{}': '{}'",
                rule.name, rule.sha256
            )));
        }
        db.add_hash_rule(rule);
    }

    for rule in ruleset.pattern_rules {
        validate_rule_name(&rule.name)?;
        if rule.pattern.is_empty() {
            return Err(ScanError::InvalidSignature(format!(
                "Pattern in rule '{}' cannot be empty",
                rule.name
            )));
        }
        if rule.pattern.len() > MAX_PATTERN_LENGTH {
            return Err(ScanError::InvalidSignature(format!(
                "Pattern in rule '{}' length {} exceeds maximum allowed length {}",
                rule.name,
                rule.pattern.len(),
                MAX_PATTERN_LENGTH
            )));
        }
        db.add_pattern_rule(rule);
    }

    db.compile()?;
    Ok(())
}

/// Loads signature rules from a JSON file path with file size enforcement.
pub fn load_rules_from_file(path: &Path, db: &mut SignatureDatabase) -> Result<(), ScanError> {
    let metadata = fs::metadata(path).map_err(|e| ScanError::IoWithPath {
        path: path.to_path_buf(),
        source: e,
    })?;

    if metadata.len() > MAX_RULE_FILE_SIZE {
        return Err(ScanError::FileSizeLimitExceeded {
            limit: MAX_RULE_FILE_SIZE,
            actual: metadata.len(),
        });
    }

    let content = fs::read_to_string(path).map_err(|e| ScanError::IoWithPath {
        path: path.to_path_buf(),
        source: e,
    })?;

    load_rules_from_str(&content, db)
}

fn validate_rule_name(name: &str) -> Result<(), ScanError> {
    if name.trim().is_empty() {
        return Err(ScanError::InvalidSignature(
            "Rule name cannot be empty".to_string(),
        ));
    }
    if name.len() > MAX_NAME_LENGTH {
        return Err(ScanError::InvalidSignature(format!(
            "Rule name length {} exceeds maximum limit of {}",
            name.len(),
            MAX_NAME_LENGTH
        )));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(ScanError::InvalidSignature(format!(
            "Rule name '{}' contains illegal control characters",
            name
        )));
    }
    Ok(())
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

    #[test]
    fn test_load_empty_rule_name_rejected() {
        let json = r#"{
            "pattern_rules": [
                {
                    "name": "   ",
                    "pattern": "4142",
                    "category": "trojan",
                    "severity": "high",
                    "description": "No name"
                }
            ]
        }"#;
        let mut db = SignatureDatabase::new();
        assert!(load_rules_from_str(json, &mut db).is_err());
    }

    #[test]
    fn test_load_oversized_pattern_rejected() {
        let huge_pattern = hex::encode(vec![0x41u8; MAX_PATTERN_LENGTH + 1]);
        let json = format!(
            r#"{{"pattern_rules": [{{"name": "Huge", "pattern": "{}", "category": "trojan", "severity": "high", "description": "Too big"}}]}}"#,
            huge_pattern
        );
        let mut db = SignatureDatabase::new();
        assert!(load_rules_from_str(&json, &mut db).is_err());
    }
}
