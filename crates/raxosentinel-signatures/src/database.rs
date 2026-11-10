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
use crate::rsidb::{HashAlgorithm, RsidbIndex};
use crate::yara::{YaraBlockScan, YaraEngine};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use raxosentinel_core::{ResourceTracker, ScanError, Severity, Threat, ThreatCategory};
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

const MAX_REPORTED_PATTERN_OFFSETS: usize = 32;

/// Compiled signature matching engine containing hash tables and pattern automata.
pub struct SignatureDatabase {
    hash_rules: HashMap<String, HashRule>,
    pattern_rules: Vec<PatternRule>,
    automaton: Option<AhoCorasick>,
    max_pattern_len: usize,
    /// Optional validated native RSIDB hash index (MD5/SHA-1/SHA-256 + size).
    rsidb: Option<Arc<dyn RsidbIndex>>,
    /// Optional compiled YARA-X rules from trusted local files.
    yara: Option<Arc<YaraEngine>>,
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
            rsidb: None,
            yara: None,
        }
    }

    /// Attaches a compiled YARA-X rule set.
    pub fn attach_yara(&mut self, engine: Arc<YaraEngine>) {
        self.yara = Some(engine);
    }

    /// Returns the attached YARA-X rule set, if any.
    pub fn yara(&self) -> Option<&Arc<YaraEngine>> {
        self.yara.as_ref()
    }

    /// Runs attached YARA-X rules over a complete in-memory object. Returns no
    /// threats when no rules are configured.
    pub fn match_yara(&self, data: &[u8], timeout: Duration) -> Result<Vec<Threat>, ScanError> {
        match &self.yara {
            Some(engine) => engine.scan(data, timeout),
            None => Ok(Vec::new()),
        }
    }

    /// Starts bounded-memory inspection of an object delivered in chunks.
    pub fn stream_matcher(&self) -> StreamMatcher<'_> {
        StreamMatcher::new(self)
    }

    /// Attaches a validated RSIDB index. Callers must only pass indexes produced by
    /// `MmapCompactDirIndex`/`MmapSortedIndex::from_file`, which fully validate on load.
    pub fn attach_rsidb(&mut self, index: Arc<dyn RsidbIndex>) {
        self.rsidb = Some(index);
    }

    /// Returns the attached RSIDB index, if any.
    pub fn rsidb(&self) -> Option<&Arc<dyn RsidbIndex>> {
        self.rsidb.as_ref()
    }

    /// Looks up a complete in-memory object in the attached RSIDB (exact hash + size).
    pub fn match_rsidb(&self, data: &[u8]) -> Vec<Threat> {
        let Some(index) = &self.rsidb else {
            return Vec::new();
        };
        Self::rsidb_threats(index.scan_raw_bytes(data), data.len() as u64)
    }

    fn rsidb_threats(mut names: Vec<String>, size: u64) -> Vec<Threat> {
        names.sort();
        names.dedup();
        names
            .into_iter()
            .map(|name| {
                let category = if name.contains("Test") || name.contains("EICAR") {
                    ThreatCategory::TestSignature
                } else {
                    ThreatCategory::Other("rsidb-hash".to_string())
                };
                let mut t = Threat::new(
                    &name,
                    category,
                    Severity::High,
                    "Exact hash+size match in RSIDB signature database",
                    format!("rsidb:size={}", size),
                );
                // Exact cryptographic hash matches are deterministic regardless of category.
                t.detection_type = raxosentinel_core::DetectionType::Deterministic;
                t
            })
            .collect()
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

    fn record_pattern_match(
        threats: &mut Vec<Threat>,
        counts: &mut [usize],
        index: usize,
        rule: &PatternRule,
        offset: usize,
    ) {
        let count = &mut counts[index];
        if *count < MAX_REPORTED_PATTERN_OFFSETS {
            threats.push(rule.to_threat(offset));
            *count += 1;
        } else if *count == MAX_REPORTED_PATTERN_OFFSETS {
            let mut notice = rule.to_threat(offset);
            notice.matched_by = "additional pattern offsets omitted".into();
            threats.push(notice);
            *count += 1;
        }
    }

    /// Scans an in-memory byte slice against all compiled byte-pattern rules.
    pub fn match_bytes(&self, data: &[u8]) -> Vec<Threat> {
        let mut threats = Vec::new();
        let ac = match &self.automaton {
            Some(ac) => ac,
            None => return threats,
        };

        let mut counts = vec![0usize; self.pattern_rules.len()];
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

            Self::record_pattern_match(&mut threats, &mut counts, rule_idx, rule, start_offset);
        }

        Self::deduplicate_threats(threats)
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
        if chunk_size == 0 || chunk_size > 16 * 1024 * 1024 {
            return Err(ScanError::Internal("Invalid stream buffer size".into()));
        }
        let overlap_size = self.max_pattern_len.saturating_sub(1);

        let mut read_buf = vec![0u8; chunk_size];
        let mut carry_buf = Vec::with_capacity(overlap_size);
        let mut stream_offset: usize = 0;
        let mut counts = vec![0usize; self.pattern_rules.len()];

        loop {
            tracker.check_timeout()?;
            let n = reader.read(&mut read_buf)?;
            if n == 0 {
                tracker.check_timeout()?;
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

                    Self::record_pattern_match(
                        &mut threats,
                        &mut counts,
                        rule_idx,
                        rule,
                        abs_offset,
                    );
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

                Self::record_pattern_match(&mut threats, &mut counts, rule_idx, rule, abs_offset);
            }

            carry_buf.clear();
            let keep_start = n.saturating_sub(overlap_size);
            carry_buf.extend_from_slice(&read_buf[keep_start..n]);
            stream_offset += n;
        }

        Ok(Self::deduplicate_threats(threats))
    }

    fn pattern_match_allowed(rule: &PatternRule, start: usize, end: usize) -> bool {
        if rule.min_offset.is_some_and(|min| start < min) {
            return false;
        }
        !rule.max_offset.is_some_and(|max| end > max)
    }

    pub fn deduplicate_threats(threats: Vec<Threat>) -> Vec<Threat> {
        let mut deduped: Vec<Threat> = Vec::new();
        for threat in threats {
            if let Some(existing) = deduped
                .iter_mut()
                .find(|t| t.name == threat.name && t.location == threat.location)
            {
                if !existing.matched_by.contains(&threat.matched_by) {
                    existing.matched_by = format!("{}; {}", existing.matched_by, threat.matched_by);
                }
            } else {
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

    const EICAR: &[u8] =
        br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    fn stream(db: &SignatureDatabase, data: &[u8], chunk: usize, complete: bool) -> StreamOutcome {
        let mut m = db.stream_matcher();
        for c in data.chunks(chunk) {
            m.update(c, Duration::from_secs(5)).unwrap();
        }
        m.finish(complete, Duration::from_secs(5)).unwrap()
    }

    #[test]
    fn stream_matcher_finds_patterns_across_every_boundary() {
        let db = SignatureDatabase::with_defaults();
        let mut data = vec![b'.'; 300];
        data.extend_from_slice(EICAR);
        data.extend(vec![b'.'; 300]);
        data.extend_from_slice(b"RAXOSENTINEL-SYNTHETIC-TEST-SIGNATURE");
        data.extend(vec![b'.'; 10]);
        let expected = db.match_bytes(&data);
        assert!(!expected.is_empty());
        for chunk in [1, 2, 3, 7, 16, 33, 64, 1000] {
            let out = stream(&db, &data, chunk, false);
            let names: Vec<_> = out.threats.iter().map(|t| (&t.name, &t.matched_by)).collect();
            let want: Vec<_> = expected.iter().map(|t| (&t.name, &t.matched_by)).collect();
            assert_eq!(names, want, "chunk {chunk}");
            assert!(out.sha256.is_none());
        }
    }

    #[test]
    fn stream_matcher_hash_lookup_only_when_complete() {
        let mut db = SignatureDatabase::with_defaults();
        let mut data = vec![0x5au8; 200_000];
        data[1000] = 1;
        let entries = vec![
            crate::rsidb::SignatureEntry::new(
                HashAlgorithm::Md5,
                data.len() as u64,
                <md5::Md5 as sha2::Digest>::digest(&data).to_vec(),
                "Streamed.Md5",
            ),
            crate::rsidb::SignatureEntry::new(
                HashAlgorithm::Sha256,
                data.len() as u64,
                <sha2::Sha256 as sha2::Digest>::digest(&data).to_vec(),
                "Streamed.Sha256",
            ),
        ];
        db.attach_rsidb(Arc::new(crate::rsidb::InMemoryIndex::from_entries(entries, "t")));
        let out = stream(&db, &data, 4096, true);
        let names: Vec<_> = out.threats.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["Streamed.Md5", "Streamed.Sha256"]);
        assert_eq!(out.bytes, data.len() as u64);
        assert_eq!(db.match_rsidb(&data).len(), 2);
        // A truncated (incomplete) object is never hash-compared.
        assert!(stream(&db, &data, 4096, false).threats.is_empty());
        // A prefix of the object, even if complete, has a different size/digest.
        assert!(stream(&db, &data[..199_999], 4096, true).threats.is_empty());
        // Builtin SHA-256 rule (EICAR) via streaming.
        let out = stream(&db, EICAR, 5, true);
        assert!(out.threats.iter().any(|t| t.matched_by.contains("sha256")
            || t.name.contains("EICAR")));
    }

    #[test]
    fn stream_matcher_runs_yara_blocks() {
        let mut db = SignatureDatabase::with_defaults();
        db.attach_yara(Arc::new(
            YaraEngine::from_source("t", "rule M { strings: $a = \"STREAM-YARA-MARK\" condition: $a }")
                .unwrap(),
        ));
        let mut data = vec![0u8; 3 * 1024 * 1024];
        data[2_000_000..2_000_016].copy_from_slice(b"STREAM-YARA-MARK");
        let out = stream(&db, &data, 256 * 1024, false);
        assert!(out.threats.iter().any(|t| t.name == "YARA:t.M"));
        assert!(db.match_yara(&data, Duration::from_secs(5)).unwrap().len() == 1);
    }

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

/// Result of a streamed inspection.
#[derive(Debug)]
pub struct StreamOutcome {
    pub threats: Vec<Threat>,
    /// SHA-256 of the complete object; `None` when the stream was incomplete.
    pub sha256: Option<String>,
    pub bytes: u64,
}

/// Bounded-memory matcher for objects delivered in chunks.
///
/// * Byte patterns: Aho-Corasick over each chunk plus a boundary window made of the
///   last `max_pattern_len - 1` bytes of the previous data, so a pattern split
///   across chunks is found exactly once and reported at its absolute offset.
/// * Exact hashes: MD5/SHA-1/SHA-256 are computed incrementally (only the
///   algorithms present in the RSIDB). Lookups are performed only when the caller
///   declares the object complete; a partial object is never hash-compared.
/// * YARA-X: optional block scan (see [`YaraBlockScan`] for block-mode limits).
pub struct StreamMatcher<'a> {
    db: &'a SignatureDatabase,
    md5: Option<md5::Md5>,
    sha1: Option<sha1::Sha1>,
    sha256: sha2::Sha256,
    carry: Vec<u8>,
    offset: usize,
    counts: Vec<usize>,
    threats: Vec<Threat>,
    yara: Option<YaraBlockScan<'a>>,
}

impl<'a> StreamMatcher<'a> {
    fn new(db: &'a SignatureDatabase) -> Self {
        use sha2::Digest;
        let has = |alg| db.rsidb.as_ref().is_some_and(|i| i.record_count(alg) > 0);
        Self {
            db,
            md5: has(HashAlgorithm::Md5).then(md5::Md5::new),
            sha1: has(HashAlgorithm::Sha1).then(sha1::Sha1::new),
            sha256: sha2::Sha256::new(),
            carry: Vec::with_capacity(db.max_pattern_len),
            offset: 0,
            counts: vec![0; db.pattern_rules.len()],
            threats: Vec::new(),
            yara: db.yara.as_ref().map(|y| y.block_scan()),
        }
    }

    /// Bytes consumed so far.
    pub fn bytes(&self) -> u64 {
        self.offset as u64
    }

    /// Consumes the next chunk. `remaining` is the scan's remaining deadline.
    pub fn update(&mut self, chunk: &[u8], remaining: Duration) -> Result<(), ScanError> {
        use sha2::Digest;
        if chunk.is_empty() {
            return Ok(());
        }
        if let Some(h) = &mut self.md5 {
            h.update(chunk);
        }
        if let Some(h) = &mut self.sha1 {
            h.update(chunk);
        }
        self.sha256.update(chunk);
        if let Some(ac) = &self.db.automaton {
            let rules = &self.db.pattern_rules;
            if !self.carry.is_empty() {
                let base = self.offset - self.carry.len();
                let mut window = Vec::with_capacity(self.carry.len() * 2);
                window.extend_from_slice(&self.carry);
                window.extend_from_slice(&chunk[..chunk.len().min(self.carry.len())]);
                for m in ac.find_overlapping_iter(&window) {
                    if m.start() >= self.carry.len() || m.end() <= self.carry.len() {
                        continue;
                    }
                    let idx = m.pattern().as_usize();
                    let (start, end) = (base + m.start(), base + m.end());
                    if SignatureDatabase::pattern_match_allowed(&rules[idx], start, end) {
                        SignatureDatabase::record_pattern_match(
                            &mut self.threats,
                            &mut self.counts,
                            idx,
                            &rules[idx],
                            start,
                        );
                    }
                }
            }
            for m in ac.find_overlapping_iter(chunk) {
                let idx = m.pattern().as_usize();
                let (start, end) = (self.offset + m.start(), self.offset + m.end());
                if SignatureDatabase::pattern_match_allowed(&rules[idx], start, end) {
                    SignatureDatabase::record_pattern_match(
                        &mut self.threats,
                        &mut self.counts,
                        idx,
                        &rules[idx],
                        start,
                    );
                }
            }
            let overlap = self.db.max_pattern_len.saturating_sub(1);
            if chunk.len() >= overlap {
                self.carry.clear();
                self.carry.extend_from_slice(&chunk[chunk.len() - overlap..]);
            } else {
                self.carry.extend_from_slice(chunk);
                let excess = self.carry.len().saturating_sub(overlap);
                self.carry.drain(..excess);
            }
        }
        self.offset += chunk.len();
        if let Some(y) = &mut self.yara {
            y.update(chunk, remaining)?;
        }
        Ok(())
    }

    /// Finishes the stream. Exact-hash lookups run only when `complete` is true.
    pub fn finish(self, complete: bool, remaining: Duration) -> Result<StreamOutcome, ScanError> {
        use sha2::Digest;
        let size = self.offset as u64;
        let mut threats = self.threats;
        if let Some(y) = self.yara {
            threats.extend(y.finish(remaining)?);
        }
        let mut sha256 = None;
        if complete {
            let sha: [u8; 32] = self.sha256.finalize().into();
            let hex = hex::encode(sha);
            if let Some(t) = self.db.match_hash(&hex) {
                threats.push(t);
            }
            if let Some(index) = &self.db.rsidb {
                let mut names = Vec::new();
                if let Some(h) = self.md5 {
                    let d: [u8; 16] = h.finalize().into();
                    names.extend(index.lookup(HashAlgorithm::Md5, size, &d));
                }
                if let Some(h) = self.sha1 {
                    let d: [u8; 20] = h.finalize().into();
                    names.extend(index.lookup(HashAlgorithm::Sha1, size, &d));
                }
                if index.record_count(HashAlgorithm::Sha256) > 0 {
                    names.extend(index.lookup(HashAlgorithm::Sha256, size, &sha));
                }
                threats.extend(SignatureDatabase::rsidb_threats(names, size));
            }
            sha256 = Some(hex);
        }
        Ok(StreamOutcome {
            threats: SignatureDatabase::deduplicate_threats(threats),
            sha256,
            bytes: size,
        })
    }
}
