// RaxoSentinel - Email and file malware scanning engine
// Copyright (C) 2026 RaxoSentinel Contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! Optional YARA-X rule engine.
//!
//! Rules are compiled once from trusted, locally supplied files. Nothing is ever
//! downloaded. `include` statements are disabled so a rule file cannot pull in
//! other files from the filesystem, and slow patterns/loops are rejected at
//! compile time. Matches are reported as ordinary [`Threat`]s named
//! `YARA:<namespace>.<rule>` and complement (never replace) RSIDB/pattern matching.

use raxosentinel_core::{DetectionType, ScanError, Severity, Threat, ThreatCategory};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Largest single rule file accepted.
pub const MAX_RULE_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Largest total rule source accepted.
pub const MAX_RULE_TOTAL_BYTES: u64 = 32 * 1024 * 1024;
/// Most rule files accepted from a directory.
pub const MAX_RULE_FILES: usize = 4096;
/// Per-pattern match cap applied to every scan (bounds match bookkeeping memory).
pub const MAX_MATCHES_PER_PATTERN: usize = 1_000;
/// Block size used when feeding streamed objects to the block scanner.
pub const YARA_BLOCK_BYTES: usize = 1024 * 1024;
/// Bytes of each previous block re-scanned with the next block so patterns up to
/// this length still match across block boundaries.
pub const YARA_BLOCK_OVERLAP: usize = 64 * 1024;

/// Error produced while loading or compiling YARA-X rules.
#[derive(Debug, thiserror::Error)]
pub enum YaraLoadError {
    #[error("YARA rule path '{path}': {message}")]
    Io { path: PathBuf, message: String },
    #[error("YARA rule source limit exceeded: {0}")]
    Limit(String),
    #[error("YARA rule compilation failed in '{origin}':\n{message}")]
    Compile { origin: String, message: String },
    #[error("no YARA rule files (*.yar, *.yara) found under '{0}'")]
    Empty(PathBuf),
}

/// Compiled, immutable YARA-X rule set.
pub struct YaraEngine {
    rules: yara_x::Rules,
    files: Vec<PathBuf>,
}

impl std::fmt::Debug for YaraEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YaraEngine")
            .field("rules", &self.rules.iter().len())
            .field("files", &self.files)
            .finish()
    }
}

fn new_compiler<'a>() -> yara_x::Compiler<'a> {
    let mut compiler = yara_x::Compiler::new();
    compiler
        .enable_includes(false)
        .error_on_slow_pattern(true)
        .error_on_slow_loop(true);
    compiler
}

fn namespace_for(path: &Path) -> String {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "rules".to_string());
    let ns: String = stem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    if ns.is_empty() {
        "rules".to_string()
    } else {
        ns
    }
}

fn collect_rule_files(path: &Path) -> Result<Vec<PathBuf>, YaraLoadError> {
    let io = |e: std::io::Error| YaraLoadError::Io {
        path: path.to_path_buf(),
        message: e.to_string(),
    };
    let meta = std::fs::metadata(path).map_err(io)?;
    if meta.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    if !meta.is_dir() {
        return Err(YaraLoadError::Io {
            path: path.to_path_buf(),
            message: "not a regular file or directory".into(),
        });
    }
    let mut files = Vec::new();
    for entry in std::fs::read_dir(path).map_err(io)? {
        let entry = entry.map_err(io)?;
        let p = entry.path();
        let is_rule = matches!(
            p.extension().and_then(|e| e.to_str()),
            Some("yar") | Some("yara")
        );
        if is_rule && entry.file_type().map_err(io)?.is_file() {
            files.push(p);
            if files.len() > MAX_RULE_FILES {
                return Err(YaraLoadError::Limit(format!(
                    "more than {MAX_RULE_FILES} rule files in '{}'",
                    path.display()
                )));
            }
        }
    }
    files.sort();
    if files.is_empty() {
        return Err(YaraLoadError::Empty(path.to_path_buf()));
    }
    Ok(files)
}

impl YaraEngine {
    /// Compiles every rule file named directly or found (non-recursively, `*.yar`/`*.yara`)
    /// in the given paths. Each file becomes its own namespace (its file stem). Any
    /// compile error fails the whole load: a partially loaded rule set is never used.
    pub fn from_paths(paths: &[PathBuf]) -> Result<Self, YaraLoadError> {
        let mut files = Vec::new();
        for p in paths {
            files.extend(collect_rule_files(p)?);
        }
        let mut compiler = new_compiler();
        let mut total = 0u64;
        for file in &files {
            let len = std::fs::metadata(file)
                .map_err(|e| YaraLoadError::Io {
                    path: file.clone(),
                    message: e.to_string(),
                })?
                .len();
            if len > MAX_RULE_FILE_BYTES {
                return Err(YaraLoadError::Limit(format!(
                    "'{}' is {len} bytes (max {MAX_RULE_FILE_BYTES})",
                    file.display()
                )));
            }
            total += len;
            if total > MAX_RULE_TOTAL_BYTES {
                return Err(YaraLoadError::Limit(format!(
                    "total rule source exceeds {MAX_RULE_TOTAL_BYTES} bytes"
                )));
            }
            let text = std::fs::read(file).map_err(|e| YaraLoadError::Io {
                path: file.clone(),
                message: e.to_string(),
            })?;
            let origin = file.display().to_string();
            compiler.new_namespace(&namespace_for(file));
            let src = yara_x::SourceCode::from(text.as_slice()).with_origin(origin.clone());
            if let Err(e) = compiler.add_source(src) {
                return Err(YaraLoadError::Compile {
                    origin,
                    message: e.to_string(),
                });
            }
        }
        Ok(Self {
            rules: compiler.build(),
            files,
        })
    }

    /// Compiles rules from an in-memory source (tests and tooling).
    pub fn from_source(namespace: &str, source: &str) -> Result<Self, YaraLoadError> {
        let mut compiler = new_compiler();
        compiler.new_namespace(namespace);
        compiler
            .add_source(source)
            .map_err(|e| YaraLoadError::Compile {
                origin: namespace.to_string(),
                message: e.to_string(),
            })?;
        Ok(Self {
            rules: compiler.build(),
            files: Vec::new(),
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rules.iter().len()
    }

    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// Full scan of a complete in-memory object (modules, `filesize` etc. available).
    pub fn scan(&self, data: &[u8], timeout: Duration) -> Result<Vec<Threat>, ScanError> {
        if timeout.is_zero() {
            return Err(timeout_error(timeout));
        }
        let mut scanner = yara_x::Scanner::new(&self.rules);
        scanner
            .set_timeout(timeout)
            .max_matches_per_pattern(MAX_MATCHES_PER_PATTERN);
        let results = scanner.scan(data).map_err(|e| map_scan_error(e, timeout))?;
        Ok(results
            .matching_rules()
            .map(|r| rule_threat(&r, "yara-x"))
            .collect())
    }

    /// Starts a block scan for an object too large to hold in memory.
    pub fn block_scan(&self) -> YaraBlockScan<'_> {
        let mut scanner = yara_x::blocks::Scanner::new(&self.rules);
        scanner.max_matches_per_pattern(MAX_MATCHES_PER_PATTERN);
        YaraBlockScan {
            scanner,
            pending: Vec::new(),
            pending_base: 0,
            scanned_any: false,
        }
    }
}

/// Incremental block scan. Data is accumulated into [`YARA_BLOCK_BYTES`] blocks and
/// each block is scanned together with the last [`YARA_BLOCK_OVERLAP`] bytes of the
/// previous one. Block mode has documented YARA-X limitations: modules are not
/// populated, `filesize`/`uintXX(offset)` are undefined, and patterns longer than
/// the overlap are not matched across block boundaries.
pub struct YaraBlockScan<'r> {
    scanner: yara_x::blocks::Scanner<'r>,
    pending: Vec<u8>,
    pending_base: usize,
    scanned_any: bool,
}

impl YaraBlockScan<'_> {
    pub fn update(&mut self, mut chunk: &[u8], deadline: Duration) -> Result<(), ScanError> {
        while !chunk.is_empty() {
            let room = YARA_BLOCK_BYTES + YARA_BLOCK_OVERLAP - self.pending.len();
            let take = room.min(chunk.len());
            self.pending.extend_from_slice(&chunk[..take]);
            chunk = &chunk[take..];
            if self.pending.len() == YARA_BLOCK_BYTES + YARA_BLOCK_OVERLAP {
                self.flush(deadline)?;
                let keep_from = self.pending.len() - YARA_BLOCK_OVERLAP;
                self.pending.drain(..keep_from);
                self.pending_base += keep_from;
            }
        }
        Ok(())
    }

    fn flush(&mut self, deadline: Duration) -> Result<(), ScanError> {
        if deadline.is_zero() {
            return Err(timeout_error(deadline));
        }
        self.scanner.set_timeout(deadline);
        self.scanner
            .scan(self.pending_base, &self.pending)
            .map_err(|e| map_scan_error(e, deadline))?;
        self.scanned_any = true;
        Ok(())
    }

    pub fn finish(mut self, deadline: Duration) -> Result<Vec<Threat>, ScanError> {
        // The tail is always scanned, even if it was partly scanned as overlap.
        if !self.pending.is_empty() || !self.scanned_any {
            self.flush(deadline)?;
        }
        let results = self
            .scanner
            .finish()
            .map_err(|e| map_scan_error(e, deadline))?;
        Ok(results
            .matching_rules()
            .map(|r| rule_threat(&r, "yara-x-blocks"))
            .collect())
    }
}

fn timeout_error(timeout: Duration) -> ScanError {
    ScanError::Timeout {
        duration_ms: timeout.as_millis() as u64,
    }
}

fn map_scan_error(e: yara_x::ScanError, timeout: Duration) -> ScanError {
    match e {
        yara_x::ScanError::Timeout => timeout_error(timeout),
        other => ScanError::Internal(format!("YARA-X scan failed: {other}")),
    }
}

fn meta_str(rule: &yara_x::Rule<'_, '_>, key: &str) -> Option<String> {
    rule.metadata().find_map(|(k, v)| match v {
        yara_x::MetaValue::String(s) if k == key => Some(s.to_string()),
        _ => None,
    })
}

fn rule_threat(rule: &yara_x::Rule<'_, '_>, mode: &str) -> Threat {
    let ns = rule.namespace();
    let id = rule.identifier();
    let qualified = if ns.is_empty() || ns == "default" {
        id.to_string()
    } else {
        format!("{ns}.{id}")
    };
    let severity = match meta_str(rule, "severity").as_deref() {
        Some("critical") => Severity::Critical,
        Some("high") => Severity::High,
        Some("low") => Severity::Low,
        Some("info") => Severity::Info,
        _ => Severity::Medium,
    };
    let detection_type = match meta_str(rule, "detection_type").as_deref() {
        Some("deterministic") => DetectionType::Deterministic,
        _ => DetectionType::Heuristic,
    };
    let description =
        meta_str(rule, "description").unwrap_or_else(|| "YARA-X rule match".to_string());
    Threat::new(
        format!("YARA:{qualified}"),
        ThreatCategory::Other("yara-rule".to_string()),
        severity,
        description,
        format!("{mode}:{qualified}"),
    )
    .with_detection_type(detection_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
rule TestMarker {
  meta:
    description = "Test marker"
    severity = "high"
    detection_type = "deterministic"
  strings:
    $a = "RAXO-YARA-TEST-MARKER"
  condition:
    $a
}
rule SizeAware {
  condition:
    filesize == 7 and uint8(0) == 0x41
}
"#;

    fn t() -> Duration {
        Duration::from_secs(5)
    }

    #[test]
    fn full_scan_match_and_nonmatch() {
        let e = YaraEngine::from_source("unit", RULES).unwrap();
        assert_eq!(e.rule_count(), 2);
        let hits = e.scan(b"xx RAXO-YARA-TEST-MARKER yy", t()).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "YARA:unit.TestMarker");
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].detection_type, DetectionType::Deterministic);
        assert!(e.scan(b"nothing here", t()).unwrap().is_empty());
        let size = e.scan(b"ABCDEFG", t()).unwrap();
        assert_eq!(size[0].name, "YARA:unit.SizeAware");
    }

    #[test]
    fn block_scan_matches_across_block_boundary() {
        let e = YaraEngine::from_source("unit", RULES).unwrap();
        let marker = b"RAXO-YARA-TEST-MARKER";
        let mut data = vec![b'.'; YARA_BLOCK_BYTES * 3];
        let at = YARA_BLOCK_BYTES + YARA_BLOCK_OVERLAP - 5;
        data[at..at + marker.len()].copy_from_slice(marker);
        let mut s = e.block_scan();
        for c in data.chunks(77_777) {
            s.update(c, t()).unwrap();
        }
        let hits = s.finish(t()).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched_by, "yara-x-blocks:unit.TestMarker");
        // filesize-dependent rules never match in block mode
        let mut s = e.block_scan();
        s.update(b"ABCDEFG", t()).unwrap();
        assert!(s.finish(t()).unwrap().is_empty());
    }

    #[test]
    fn malformed_and_unsafe_rules_are_rejected() {
        assert!(matches!(
            YaraEngine::from_source("bad", "rule x { condition: nope }"),
            Err(YaraLoadError::Compile { .. })
        ));
        assert!(YaraEngine::from_source("inc", "include \"/etc/passwd\"\nrule a { condition: true }")
            .is_err());
        // A pattern with no usable atoms is rejected as slow.
        assert!(
            YaraEngine::from_source("slow", "rule s { strings: $a = /.*/ condition: $a }")
                .is_err()
        );
    }

    #[test]
    fn zero_deadline_is_timeout() {
        let e = YaraEngine::from_source("unit", RULES).unwrap();
        assert!(matches!(
            e.scan(b"abc", Duration::ZERO),
            Err(ScanError::Timeout { .. })
        ));
    }

    #[test]
    fn loads_directory_and_reports_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            YaraEngine::from_paths(&[dir.path().to_path_buf()]),
            Err(YaraLoadError::Empty(_))
        ));
        std::fs::write(dir.path().join("my-rules.yar"), RULES).unwrap();
        std::fs::write(dir.path().join("ignored.txt"), "garbage").unwrap();
        let e = YaraEngine::from_paths(&[dir.path().to_path_buf()]).unwrap();
        assert_eq!(e.rule_count(), 2);
        let hits = e.scan(b"RAXO-YARA-TEST-MARKER", t()).unwrap();
        assert_eq!(hits[0].name, "YARA:my_rules.TestMarker");
        std::fs::write(dir.path().join("broken.yara"), "rule {").unwrap();
        let err = YaraEngine::from_paths(&[dir.path().to_path_buf()]).unwrap_err();
        assert!(err.to_string().contains("broken.yara"), "{err}");
    }
}
