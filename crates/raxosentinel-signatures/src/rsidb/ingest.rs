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

//! Threat-intelligence ingestion pipeline: approved local sources -> validated,
//! attributed, deduplicated indicators -> deterministic RSIDB build + manifest.
//!
//! Unlike the strict `SignatureImporter` (which aborts on the first bad line), this
//! pipeline rejects malformed records individually and reports every rejection.

use super::error::DatabaseError;
use super::format::HashAlgorithm;
use super::importer::{RsidbCompiler, SignatureEntry};
use super::layout::MAX_NAME_LEN;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Version of the build-manifest JSON schema.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
/// Maximum accepted input line length.
pub const MAX_LINE_LEN: usize = 4096;
/// Maximum number of rejection samples retained per source report.
const MAX_REJECTION_SAMPLES: usize = 100;

/// Redistribution terms declared by the operator for a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Redistribution {
    /// Redistribution in a public database is permitted.
    Allowed,
    /// Permitted with attribution (attribution is carried in the manifest).
    AllowedWithAttribution,
    /// Internal use only; must not appear in public builds.
    InternalOnly,
    /// Redistribution prohibited.
    Prohibited,
    /// Terms not yet reviewed. Treated as not redistributable.
    Unknown,
}

impl Redistribution {
    pub fn public_ok(self) -> bool {
        matches!(self, Self::Allowed | Self::AllowedWithAttribution)
    }
}

/// Input record syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorFormat {
    /// `hexhash:size:name` (ClamAV .hdb/.hsb compatible, no wildcards).
    HashSizeName,
    /// `hexhash,size,name` CSV (no quoting).
    Csv,
}

/// Operator-supplied description of an approved local indicator source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceManifest {
    /// Stable identifier, e.g. `raxo-internal-fixtures`.
    pub id: String,
    pub name: String,
    /// Where the data was obtained (URL or description). Informational only.
    pub origin: String,
    /// Upstream version / release identifier.
    pub version: String,
    /// RFC 3339 acquisition timestamp supplied by the operator.
    pub acquired_at: String,
    /// SPDX identifier or licence description.
    pub license: String,
    pub redistribution: Redistribution,
    /// Attribution text required by the source, if any.
    #[serde(default)]
    pub attribution: Option<String>,
    /// Must be explicitly `true`; unapproved sources are refused.
    pub approved: bool,
    pub format: IndicatorFormat,
    /// Indicator file path, relative to the source manifest file.
    pub path: String,
    /// Optional expected SHA-256 of the indicator file (pinning).
    #[serde(default)]
    pub sha256: Option<String>,
}

impl SourceManifest {
    /// Resolves and validates the indicator file path relative to `base_dir`.
    /// Rejects directory traversal (`..`), absolute paths, and paths escaping `base_dir`.
    pub fn resolve_path(
        &self,
        base_dir: &std::path::Path,
    ) -> Result<std::path::PathBuf, DatabaseError> {
        let p = std::path::Path::new(&self.path);
        if p.is_absolute() {
            return Err(DatabaseError::Policy(format!(
                "source '{}' path must be relative, got absolute: '{}'",
                self.id, self.path
            )));
        }
        for component in p.components() {
            match component {
                std::path::Component::ParentDir => {
                    return Err(DatabaseError::Policy(format!(
                        "source '{}' path traversal disallowed: '{}'",
                        self.id, self.path
                    )));
                }
                std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                    return Err(DatabaseError::Policy(format!(
                        "source '{}' path contains root/prefix: '{}'",
                        self.id, self.path
                    )));
                }
                _ => {}
            }
        }
        let full = base_dir.join(p);
        if let Ok(canon_base) = std::fs::canonicalize(base_dir) {
            if let Ok(canon_full) = std::fs::canonicalize(&full) {
                if !canon_full.starts_with(&canon_base) {
                    return Err(DatabaseError::Policy(format!(
                        "source '{}' path escapes base directory: '{}'",
                        self.id, self.path
                    )));
                }
            }
        }
        Ok(full)
    }
}

/// Build target: public builds only accept redistributable sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildProfile {
    Public,
    Internal,
}

/// Limits applied to every indicator.
#[derive(Debug, Clone)]
pub struct IngestLimits {
    pub min_file_size: u64,
    pub max_file_size: u64,
    pub max_records_per_source: usize,
}

impl Default for IngestLimits {
    fn default() -> Self {
        Self {
            min_file_size: 1,
            max_file_size: 512 * 1024 * 1024,
            max_records_per_source: 50_000_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rejection {
    pub line: usize,
    pub reason: String,
}

/// Per-source ingestion result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceReport {
    pub source_id: String,
    pub input_sha256: String,
    pub accepted: usize,
    pub rejected: usize,
    pub duplicates: usize,
    pub ignored_lines: usize,
    pub rejections_by_reason: BTreeMap<String, usize>,
    pub rejection_samples: Vec<Rejection>,
}

impl SourceReport {
    fn reject(&mut self, line: usize, reason: &str, detail: String) {
        self.rejected += 1;
        *self
            .rejections_by_reason
            .entry(reason.to_string())
            .or_insert(0) += 1;
        if self.rejection_samples.len() < MAX_REJECTION_SAMPLES {
            self.rejection_samples.push(Rejection {
                line,
                reason: format!("{}: {}", reason, detail),
            });
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceAttribution {
    #[serde(flatten)]
    pub source: SourceManifest,
    pub report: SourceReport,
}

/// Versioned manifest describing a deterministic RSIDB build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildManifest {
    pub schema_version: u32,
    pub db_format: String,
    pub db_version: String,
    pub built_at: String,
    pub profile: BuildProfile,
    pub min_engine_version: String,
    pub db_sha256: String,
    pub db_bytes: u64,
    pub records_md5: usize,
    pub records_sha1: usize,
    pub records_sha256: usize,
    pub unique_names: usize,
    pub total_accepted: usize,
    pub total_rejected: usize,
    pub total_duplicates: usize,
    pub sources: Vec<SourceAttribution>,
}

/// Accumulates indicators from multiple sources and produces a deterministic build.
pub struct IngestPipeline {
    profile: BuildProfile,
    limits: IngestLimits,
    /// Key: (alg, digest, size, name) -> contributing source ids.
    records: BTreeMap<(HashAlgorithm, Vec<u8>, u64, String), BTreeSet<String>>,
    sources: Vec<SourceAttribution>,
}

impl IngestPipeline {
    pub fn new(profile: BuildProfile) -> Self {
        Self::with_limits(profile, IngestLimits::default())
    }

    pub fn with_limits(profile: BuildProfile, limits: IngestLimits) -> Self {
        Self {
            profile,
            limits,
            records: BTreeMap::new(),
            sources: Vec::new(),
        }
    }

    /// Ingests one approved source. Policy violations (unapproved, licence not suitable
    /// for the build profile, pin mismatch, duplicate source id) refuse the whole source.
    pub fn add_source(
        &mut self,
        manifest: SourceManifest,
        content: &[u8],
    ) -> Result<SourceReport, DatabaseError> {
        if !manifest.approved {
            return Err(DatabaseError::Policy(format!(
                "source '{}' is not approved",
                manifest.id
            )));
        }
        if self.profile == BuildProfile::Public && !manifest.redistribution.public_ok() {
            return Err(DatabaseError::Policy(format!(
                "source '{}' redistribution={:?} not permitted in public builds",
                manifest.id, manifest.redistribution
            )));
        }
        if manifest.redistribution == Redistribution::AllowedWithAttribution
            && manifest
                .attribution
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
        {
            return Err(DatabaseError::Policy(format!(
                "source '{}' requires attribution text",
                manifest.id
            )));
        }
        if manifest.id.trim().is_empty() || self.sources.iter().any(|s| s.source.id == manifest.id)
        {
            return Err(DatabaseError::Policy(format!(
                "invalid or duplicate source id '{}'",
                manifest.id
            )));
        }
        let input_sha256 = hex::encode(Sha256::digest(content));
        if let Some(pin) = &manifest.sha256 {
            if !pin.eq_ignore_ascii_case(&input_sha256) {
                return Err(DatabaseError::Policy(format!(
                    "source '{}' sha256 pin mismatch (expected {}, got {})",
                    manifest.id, pin, input_sha256
                )));
            }
        }
        let text = std::str::from_utf8(content).map_err(|e| {
            DatabaseError::Policy(format!("source '{}' is not UTF-8: {}", manifest.id, e))
        })?;

        let mut report = SourceReport {
            source_id: manifest.id.clone(),
            input_sha256,
            ..Default::default()
        };
        let sep = match manifest.format {
            IndicatorFormat::HashSizeName => ':',
            IndicatorFormat::Csv => ',',
        };

        for (idx, raw) in text.lines().enumerate() {
            let line_no = idx + 1;
            if raw.len() > MAX_LINE_LEN {
                report.reject(line_no, "line_too_long", format!("{} bytes", raw.len()));
                continue;
            }
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                report.ignored_lines += 1;
                continue;
            }
            if report.accepted + report.duplicates >= self.limits.max_records_per_source {
                report.reject(
                    line_no,
                    "source_record_limit",
                    "remaining lines skipped".into(),
                );
                break;
            }
            match self.parse_record(line, sep) {
                Ok((alg, digest, size, name)) => {
                    let ids = self.records.entry((alg, digest, size, name)).or_default();
                    if ids.insert(manifest.id.clone()) && ids.len() == 1 {
                        report.accepted += 1;
                    } else {
                        report.duplicates += 1;
                    }
                }
                Err((reason, detail)) => report.reject(line_no, reason, detail),
            }
        }

        self.sources.push(SourceAttribution {
            source: manifest,
            report: report.clone(),
        });
        Ok(report)
    }

    #[allow(clippy::type_complexity)]
    fn parse_record(
        &self,
        line: &str,
        sep: char,
    ) -> Result<(HashAlgorithm, Vec<u8>, u64, String), (&'static str, String)> {
        // splitn(3): the name may contain the separator only for CSV-free formats; we
        // keep it simple and require exactly three fields.
        let parts: Vec<&str> = line.split(sep).collect();
        if parts.len() != 3 {
            return Err((
                "field_count",
                format!("expected 3 fields, got {}", parts.len()),
            ));
        }
        let (h, sz, name) = (parts[0].trim(), parts[1].trim(), parts[2].trim());

        if !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(("invalid_hex", h.chars().take(80).collect()));
        }
        let alg = match h.len() {
            32 => HashAlgorithm::Md5,
            40 => HashAlgorithm::Sha1,
            64 => HashAlgorithm::Sha256,
            n => return Err(("unsupported_hash_length", format!("{} hex chars", n))),
        };
        let digest = hex::decode(h).map_err(|e| ("invalid_hex", e.to_string()))?;
        if digest.iter().all(|&b| b == 0) {
            return Err(("null_digest", h.to_string()));
        }

        if sz.is_empty() || !sz.bytes().all(|b| b.is_ascii_digit()) {
            return Err(("invalid_size", sz.chars().take(40).collect()));
        }
        let size: u64 = sz.parse().map_err(|_| ("invalid_size", sz.to_string()))?;
        if size < self.limits.min_file_size || size > self.limits.max_file_size {
            return Err((
                "size_out_of_range",
                format!(
                    "{} not in [{}, {}]",
                    size, self.limits.min_file_size, self.limits.max_file_size
                ),
            ));
        }

        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(("invalid_name_length", format!("{} bytes", name.len())));
        }
        if name.chars().any(|c| c.is_control()) {
            return Err(("invalid_name_chars", "control characters".into()));
        }
        Ok((alg, digest, size, name.to_string()))
    }

    /// Produces the RSIDB image and manifest. Output is a pure function of the ingested
    /// inputs plus `db_version`/`built_at` (no wall-clock or random input).
    pub fn build(
        &self,
        db_version: &str,
        built_at: &str,
    ) -> Result<(Vec<u8>, BuildManifest), DatabaseError> {
        let mut entries = Vec::with_capacity(self.records.len());
        let mut counts = [0usize; 3];
        let mut names = BTreeSet::new();
        for (alg, digest, size, name) in self.records.keys() {
            counts[alg.index()] += 1;
            names.insert(name.as_str());
            entries.push(SignatureEntry::new(
                *alg,
                *size,
                digest.clone(),
                name.clone(),
            ));
        }

        let source_ids: Vec<String> = self
            .sources
            .iter()
            .map(|s| format!("{}@{}", s.source.id, s.source.version))
            .collect();
        let provenance = format!(
            "RSIDB db_version={} built_at={} profile={:?} sources=[{}]",
            db_version,
            built_at,
            self.profile,
            source_ids.join(",")
        );
        let bytes = RsidbCompiler::new()
            .with_provenance(provenance)
            .compile(entries)?;

        let total = |f: fn(&SourceReport) -> usize| self.sources.iter().map(|s| f(&s.report)).sum();
        let manifest = BuildManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            db_format: "RSIDB001".into(),
            db_version: db_version.into(),
            built_at: built_at.into(),
            profile: self.profile,
            min_engine_version: env!("CARGO_PKG_VERSION").into(),
            db_sha256: hex::encode(Sha256::digest(&bytes)),
            db_bytes: bytes.len() as u64,
            records_md5: counts[0],
            records_sha1: counts[1],
            records_sha256: counts[2],
            unique_names: names.len(),
            total_accepted: total(|r| r.accepted),
            total_rejected: total(|r| r.rejected),
            total_duplicates: total(|r| r.duplicates),
            sources: self.sources.clone(),
        };
        Ok((bytes, manifest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsidb::{MmapCompactDirIndex, RsidbIndex};

    fn src(id: &str, redistribution: Redistribution, format: IndicatorFormat) -> SourceManifest {
        SourceManifest {
            id: id.into(),
            name: id.into(),
            origin: "local test fixture".into(),
            version: "1".into(),
            acquired_at: "2026-11-02T00:00:00Z".into(),
            license: "CC0-1.0".into(),
            redistribution,
            attribution: None,
            approved: true,
            format,
            path: "x".into(),
            sha256: None,
        }
    }

    const EICAR_MD5: &str = "44d88612fea8a8f36de82e1278abb02f";
    const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    #[test]
    fn ingest_counts_rejects_dedups_and_is_deterministic() {
        let input = format!(
            "# comment\n{m}:68:Eicar-Test-Signature\n{m}:68:Eicar-Test-Signature\n{m}:68:Alt.Name\n\
             {s}:68:Eicar-Test-Signature\nzz:1:Bad\n{m}:*:Wild\n{m}:0:Zero\n{m}:68:\n{m}:68:a:b\n",
            m = EICAR_MD5,
            s = EICAR_SHA256
        );
        let mut p = IngestPipeline::new(BuildProfile::Public);
        let r = p
            .add_source(
                src("a", Redistribution::Allowed, IndicatorFormat::HashSizeName),
                input.as_bytes(),
            )
            .unwrap();
        assert_eq!(r.accepted, 3);
        assert_eq!(r.duplicates, 1);
        assert_eq!(r.rejected, 5);
        assert_eq!(r.ignored_lines, 1);

        // Second source contributes an overlapping record: counted as duplicate, attributed.
        let csv = format!("{},68,Eicar-Test-Signature\n", EICAR_MD5);
        let r2 = p
            .add_source(
                src("b", Redistribution::Allowed, IndicatorFormat::Csv),
                csv.as_bytes(),
            )
            .unwrap();
        assert_eq!((r2.accepted, r2.duplicates), (0, 1));

        let (bytes, manifest) = p.build("2026.11.02.1", "2026-11-02T00:00:00Z").unwrap();
        let (bytes2, manifest2) = p.build("2026.11.02.1", "2026-11-02T00:00:00Z").unwrap();
        assert_eq!(bytes, bytes2);
        assert_eq!(manifest, manifest2);
        assert_eq!(manifest.records_md5, 2);
        assert_eq!(manifest.records_sha256, 1);
        assert_eq!(manifest.total_rejected, 5);

        let idx = MmapCompactDirIndex::from_bytes(bytes).unwrap();
        let mut names = idx.lookup(HashAlgorithm::Md5, 68, &hex::decode(EICAR_MD5).unwrap());
        names.sort();
        assert_eq!(names, vec!["Alt.Name", "Eicar-Test-Signature"]);
    }

    #[test]
    fn policy_refuses_unapproved_and_non_redistributable_sources() {
        let mut p = IngestPipeline::new(BuildProfile::Public);
        let mut s = src("x", Redistribution::Allowed, IndicatorFormat::Csv);
        s.approved = false;
        assert!(matches!(
            p.add_source(s, b""),
            Err(DatabaseError::Policy(_))
        ));
        for r in [
            Redistribution::InternalOnly,
            Redistribution::Unknown,
            Redistribution::Prohibited,
        ] {
            assert!(p
                .add_source(src("y", r, IndicatorFormat::Csv), b"")
                .is_err());
        }
        let mut pinned = src("z", Redistribution::Allowed, IndicatorFormat::Csv);
        pinned.sha256 = Some("00".repeat(32));
        assert!(p.add_source(pinned, b"data").is_err());
        // Internal builds accept internal-only sources.
        let mut i = IngestPipeline::new(BuildProfile::Internal);
        assert!(i
            .add_source(
                src("y", Redistribution::InternalOnly, IndicatorFormat::Csv),
                b""
            )
            .is_ok());
    }
}
