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

use crate::builtin::{default_hash_rules, default_pattern_rules};
use crate::models::{HashRule, PatternRule};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use raxosentinel_core::{ResourceTracker, ScanError, Threat};
use std::collections::HashMap;
use std::io::Read;

/// Compiled signature matching engine containing hash tables and pattern automata.
pub struct SignatureDatabase {
    hash_rules: HashMap<String, HashRule>,
    pattern_rules: Vec<PatternRule>,
    automaton: Option<AhoCorasick>,
    max_pattern_len: usize,
}

impl Default for SignatureDatabase {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl SignatureDatabase {
    /// Creates an empty signature database.
    pub fn new() -> Self {
        Self {
            hash_rules: HashMap::new(),
            pattern_rules: Vec::new(),
            automaton: None,
            max_pattern_len: 0,
        }
    }

    /// Creates a database loaded with standard built-in rules (EICAR, test rules, heuristics).
    pub fn with_defaults() -> Self {
        let mut db = Self::new();
        for rule in default_hash_rules() {
            db.add_hash_rule(rule);
        }
        for rule in default_pattern_rules() {
            db.add_pattern_rule(rule);
        }
        db.compile()
            .expect("Failed to compile default signature automaton");
        db
    }

    /// Adds a hash rule.
    pub fn add_hash_rule(&mut self, rule: HashRule) {
        self.hash_rules.insert(rule.sha256.to_lowercase(), rule);
    }

    /// Adds a byte-pattern rule. Requires calling `compile()` before scanning.
    pub fn add_pattern_rule(&mut self, rule: PatternRule) {
        if rule.pattern.len() > self.max_pattern_len {
            self.max_pattern_len = rule.pattern.len();
        }
        self.pattern_rules.push(rule);
        self.automaton = None; // Invalidate compiled state
    }

    /// Compiles pattern rules into an optimized Aho-Corasick automaton.
    pub fn compile(&mut self) -> Result<(), ScanError> {
        let patterns: Vec<&[u8]> = self
            .pattern_rules
            .iter()
            .map(|r| r.pattern.as_slice())
            .collect();
        if patterns.is_empty() {
            self.automaton = None;
            return Ok(());
        }

        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .build(&patterns)
            .map_err(|e| {
                ScanError::Internal(format!("Failed to build Aho-Corasick automaton: {}", e))
            })?;

        self.automaton = Some(ac);
        Ok(())
    }

    /// Matches a SHA-256 hash digest against known signatures.
    pub fn match_hash(&self, sha256_hex: &str) -> Option<Threat> {
        self.hash_rules
            .get(&sha256_hex.to_lowercase())
            .map(|r| r.to_threat())
    }

    /// Scans an in-memory byte slice against all compiled byte-pattern rules.
    pub fn match_bytes(&self, data: &[u8]) -> Vec<Threat> {
        let mut threats = Vec::new();
        let ac = match &self.automaton {
            Some(ac) => ac,
            None => return threats,
        };

        for mat in ac.find_iter(data) {
            let rule_idx = mat.pattern().as_usize();
            let rule = &self.pattern_rules[rule_idx];
            let start_offset = mat.start();

            // Validate offset boundaries if configured
            if let Some(min_off) = rule.min_offset {
                if start_offset < min_off {
                    continue;
                }
            }
            if let Some(max_off) = rule.max_offset {
                if mat.end() > max_off {
                    continue;
                }
            }

            threats.push(rule.to_threat(start_offset));
        }

        self.deduplicate_threats(threats)
    }

    /// Scans a streaming reader with bounded memory buffers while seamlessly preserving
    /// pattern matches that cross buffer boundaries.
    pub fn match_stream<R: Read>(
        &self,
        reader: &mut R,
        tracker: &mut ResourceTracker,
    ) -> Result<Vec<Threat>, ScanError> {
        let mut threats = Vec::new();
        let ac = match &self.automaton {
            Some(ac) => ac,
            None => return Ok(threats),
        };

        let chunk_size = tracker.limits().buffer_size;
        let overlap_size = self.max_pattern_len.saturating_sub(1);

        let mut read_buf = vec![0u8; chunk_size];
        let mut carry_buf = Vec::with_capacity(overlap_size);
        let mut stream_offset: usize = 0;

        loop {
            let n = reader.read(&mut read_buf)?;
            if n == 0 {
                break;
            }

            tracker.record_bytes_read(n)?;

            // Combine carry buffer from previous block with newly read data
            let combined = if carry_buf.is_empty() {
                &read_buf[..n]
            } else {
                let mut c = Vec::with_capacity(carry_buf.len() + n);
                c.extend_from_slice(&carry_buf);
                c.extend_from_slice(&read_buf[..n]);
                // We'll inspect via slice
                let base_offset = stream_offset - carry_buf.len();

                for mat in ac.find_iter(&c) {
                    let rule_idx = mat.pattern().as_usize();
                    let rule = &self.pattern_rules[rule_idx];
                    let abs_offset = base_offset + mat.start();

                    if let Some(min_off) = rule.min_offset {
                        if abs_offset < min_off {
                            continue;
                        }
                    }
                    if let Some(max_off) = rule.max_offset {
                        if base_offset + mat.end() > max_off {
                            continue;
                        }
                    }

                    threats.push(rule.to_threat(abs_offset));
                }

                // Update carry buffer for next iteration
                carry_buf.clear();
                let keep_start = c.len().saturating_sub(overlap_size);
                carry_buf.extend_from_slice(&c[keep_start..]);
                stream_offset += n;
                continue;
            };

            for mat in ac.find_iter(combined) {
                let rule_idx = mat.pattern().as_usize();
                let rule = &self.pattern_rules[rule_idx];
                let abs_offset = stream_offset + mat.start();

                if let Some(min_off) = rule.min_offset {
                    if abs_offset < min_off {
                        continue;
                    }
                }
                if let Some(max_off) = rule.max_offset {
                    if stream_offset + mat.end() > max_off {
                        continue;
                    }
                }

                threats.push(rule.to_threat(abs_offset));
            }

            carry_buf.clear();
            let keep_start = n.saturating_sub(overlap_size);
            carry_buf.extend_from_slice(&read_buf[keep_start..n]);
            stream_offset += n;
        }

        Ok(self.deduplicate_threats(threats))
    }

    fn deduplicate_threats(&self, threats: Vec<Threat>) -> Vec<Threat> {
        let mut deduped: Vec<Threat> = Vec::new();
        for threat in threats {
            if !deduped
                .iter()
                .any(|t| t.name == threat.name && t.location == threat.location)
            {
                deduped.push(threat);
            }
        }
        deduped
    }

    pub fn pattern_count(&self) -> usize {
        self.pattern_rules.len()
    }

    pub fn hash_count(&self) -> usize {
        self.hash_rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxosentinel_core::ResourceLimits;
    use std::io::Cursor;

    #[test]
    fn test_eicar_pattern_matching() {
        let db = SignatureDatabase::with_defaults();
        let eicar_content =
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let threats = db.match_bytes(eicar_content);
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].name, "EICAR-Standard-Antivirus-Test-File");
    }

    #[test]
    fn test_eicar_embedded_in_text() {
        let db = SignatureDatabase::with_defaults();
        let mut data = b"Hello world! This is a test file containing: ".to_vec();
        data.extend_from_slice(
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        );
        data.extend_from_slice(b" trailing safe text");

        let threats = db.match_bytes(&data);
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].name, "EICAR-Standard-Antivirus-Test-File");
    }

    #[test]
    fn test_stream_boundary_crossing() {
        let db = SignatureDatabase::with_defaults();
        let synthetic_pattern = b"RAXOSENTINEL-SYNTHETIC-TEST-SIGNATURE";

        // Create stream where pattern is split across buffer boundaries
        // Buffer size will be 32 bytes
        let mut stream_data = vec![b'A'; 20];
        stream_data.extend_from_slice(synthetic_pattern);
        stream_data.extend_from_slice(&[b'B'; 30]);

        let limits = ResourceLimits {
            buffer_size: 32,
            ..Default::default()
        };
        let mut tracker = ResourceTracker::new(limits);
        let mut cursor = Cursor::new(stream_data);

        let threats = db.match_stream(&mut cursor, &mut tracker).unwrap();
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].name, "Test.Synthetic.BytePattern");
    }

    #[test]
    fn test_eicar_exact_hash_match() {
        let db = SignatureDatabase::with_defaults();
        let sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        let threat = db.match_hash(sha);
        assert!(threat.is_some());
        assert_eq!(threat.unwrap().name, "EICAR-Standard-Antivirus-Test-File");
    }

    #[test]
    fn test_clean_input_no_detection() {
        let db = SignatureDatabase::with_defaults();
        let data = b"This is a perfectly benign text document with no malicious patterns.";
        let threats = db.match_bytes(data);
        assert!(threats.is_empty());
    }
}
