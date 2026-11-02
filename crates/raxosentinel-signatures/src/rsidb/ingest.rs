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

/// Category of indicator source: genuine operational threat intelligence vs synthetic/harmless test fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Genuine operational threat intelligence (real-world observed malware hashes).
    Genuine,
    /// Synthetic or harmless test fixtures (EICAR, ClamAV test files, unit test vectors).
    #[default]
    SyntheticTest,
}

fn default_source_kind() -> SourceKind {
    SourceKind::SyntheticTest
}

/// Returns true if the digest corresponds to a known synthetic test string, test fixture, or standard preimage.
/// Known synthetic digests can NEVER be classified as genuine operational threat records.
pub fn is_known_synthetic_digest(digest: &[u8]) -> bool {
    const KNOWN_SYNTHETIC_HEX: &[&str] = &[
        // Standard EICAR Antivirus Test File
        "44d88612fea8a8f36de82e1278abb02f",         // EICAR MD5
        "131f95c51cc819465fa1797f6ccacf9d494aaaff", // EICAR SHA1
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", // EICAR SHA256
        // ClamAV official test executable (clam.exe)
        "71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495",
        // Empty string digests
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        // Common synthetic test preimages audited in Phase 2C
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", // sha256("abc")
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff213f0ffced94b21490a0", // sha256("abcd")
        "5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5", // sha256("123456")
        "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b", // sha256("1")
        "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35", // sha256("2")
        "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce", // sha256("3")
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", // sha256("test")
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", // sha256("hello")
        "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918", // sha256("admin")
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", // sha256("password")
    ];

    let hex_repr = hex::encode(digest);
    KNOWN_SYNTHETIC_HEX
        .iter()
        .any(|k| k.eq_ignore_ascii_case(&hex_repr))
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
    /// Kind of intelligence: genuine threat data vs synthetic test fixtures.
    #[serde(default = "default_source_kind")]
    pub kind: SourceKind,
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
    #[serde(default = "default_source_kind")]
    pub effective_kind: SourceKind,
    #[serde(default)]
    pub authenticity_status: String,
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
    pub genuine_records: usize,
    pub synthetic_records: usize,
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
    authorized_sources: BTreeSet<String>,
    authorize_all_dev: bool,
    verified_genuine_sources: BTreeSet<String>,
    revocations: BTreeSet<Vec<u8>>,
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
            authorized_sources: BTreeSet::new(),
            authorize_all_dev: false,
            verified_genuine_sources: BTreeSet::new(),
            revocations: BTreeSet::new(),
            records: BTreeMap::new(),
            sources: Vec::new(),
        }
    }

    /// Authorizes a source ID in the operator policy (prevents source self-approval).
    pub fn authorize_source(&mut self, source_id: impl Into<String>) -> &mut Self {
        self.authorized_sources.insert(source_id.into());
        self
    }

    /// Explicitly certifies an authorized source ID as an authentic, verified genuine threat intelligence provider.
    /// Without explicit operator verification, sources claiming to be genuine are demoted to SyntheticTest.
    pub fn verify_genuine_source(&mut self, source_id: impl Into<String>) -> &mut Self {
        self.verified_genuine_sources.insert(source_id.into());
        self
    }

    /// Explicitly certifies multiple source IDs as authentic, verified genuine threat providers.
    pub fn with_verified_genuine_sources(
        mut self,
        ids: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        for id in ids {
            self.verified_genuine_sources.insert(id.into());
        }
        self
    }

    /// Authorizes multiple source IDs.
    pub fn with_authorized_sources(
        mut self,
        ids: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        for id in ids {
            self.authorized_sources.insert(id.into());
        }
        self
    }

    /// Development / testing mode: permits all sources without explicit whitelist.
    pub fn authorize_all_for_testing(&mut self) -> &mut Self {
        self.authorize_all_dev = true;
        self
    }

    /// Revokes an indicator hash (MD5, SHA1, or SHA256 hex string).
    pub fn revoke_hash(&mut self, hex_hash: &str) -> Result<(), DatabaseError> {
        let clean = hex_hash.trim();
        let digest = hex::decode(clean).map_err(|e| {
            DatabaseError::Policy(format!("invalid revocation hex hash '{}': {}", clean, e))
        })?;
        self.revocations.insert(digest);
        Ok(())
    }

    /// Revokes multiple indicator hashes.
    pub fn revoke_hashes<'a>(
        &mut self,
        hex_hashes: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), DatabaseError> {
        for h in hex_hashes {
            self.revoke_hash(h)?;
        }
        Ok(())
    }

    /// Ingests one approved source. Policy violations (unapproved by manifest, unauthorized
    /// by operator trust policy, licence not suitable for the build profile, pin mismatch,
    /// duplicate source id) refuse the whole source.
    pub fn add_source(
        &mut self,
        manifest: SourceManifest,
        content: &[u8],
    ) -> Result<SourceReport, DatabaseError> {
        if !manifest.approved {
            return Err(DatabaseError::Policy(format!(
                "source '{}' is not approved in its manifest",
                manifest.id
            )));
        }
        if !self.authorize_all_dev && !self.authorized_sources.contains(&manifest.id) {
            return Err(DatabaseError::Policy(format!(
                "source '{}' is not authorized by operator policy (manifest self-approval is rejected)",
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

        let (effective_kind, authenticity_status) = if manifest.kind == SourceKind::Genuine {
            if !self.verified_genuine_sources.contains(&manifest.id) {
                (
                    SourceKind::SyntheticTest,
                    "unverified_operator_certification_missing".to_string(),
                )
            } else if manifest.sha256.is_none() {
                (
                    SourceKind::SyntheticTest,
                    "unverified_sha256_pin_missing".to_string(),
                )
            } else if manifest.origin.trim().is_empty()
                || manifest.version.trim().is_empty()
                || manifest.acquired_at.trim().is_empty()
            {
                (
                    SourceKind::SyntheticTest,
                    "unverified_provenance_metadata_incomplete".to_string(),
                )
            } else if !manifest.redistribution.public_ok() {
                (
                    SourceKind::SyntheticTest,
                    "unverified_redistribution_unauthorized".to_string(),
                )
            } else {
                (SourceKind::Genuine, "verified_genuine_provider".to_string())
            }
        } else {
            (
                SourceKind::SyntheticTest,
                "synthetic_test_source".to_string(),
            )
        };

        let mut report = SourceReport {
            source_id: manifest.id.clone(),
            input_sha256,
            effective_kind,
            authenticity_status,
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
                    if self.revocations.contains(&digest) {
                        report.reject(
                            line_no,
                            "revoked",
                            format!(
                                "indicator hash {} is revoked by policy",
                                hex::encode(&digest)
                            ),
                        );
                        continue;
                    }
                    if effective_kind == SourceKind::Genuine && is_known_synthetic_digest(&digest) {
                        report.reject(
                            line_no,
                            "synthetic_preimage_in_genuine_feed",
                            format!(
                                "indicator hash {} matches known synthetic test string; prohibited in genuine threat feed",
                                hex::encode(&digest)
                            ),
                        );
                        continue;
                    }
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
        let mut genuine_records = 0usize;
        let mut synthetic_records = 0usize;

        let effective_kinds: BTreeMap<String, SourceKind> = self
            .sources
            .iter()
            .map(|s| (s.source.id.clone(), s.report.effective_kind))
            .collect();

        for ((alg, digest, size, name), source_ids) in &self.records {
            counts[alg.index()] += 1;
            names.insert(name.as_str());
            entries.push(SignatureEntry::new(
                *alg,
                *size,
                digest.clone(),
                name.clone(),
            ));

            let has_genuine = source_ids
                .iter()
                .any(|id| effective_kinds.get(id).copied() == Some(SourceKind::Genuine));
            if has_genuine && !is_known_synthetic_digest(digest) {
                genuine_records += 1;
            } else {
                synthetic_records += 1;
            }
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
            genuine_records,
            synthetic_records,
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
            kind: SourceKind::SyntheticTest,
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
        p.authorize_all_for_testing();
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
        assert_eq!(manifest.synthetic_records, 3);
        assert_eq!(manifest.genuine_records, 0);
        assert_eq!(manifest.total_rejected, 5);

        let idx = MmapCompactDirIndex::from_bytes(bytes).unwrap();
        let mut names = idx.lookup(HashAlgorithm::Md5, 68, &hex::decode(EICAR_MD5).unwrap());
        names.sort();
        assert_eq!(names, vec!["Alt.Name", "Eicar-Test-Signature"]);
    }

    #[test]
    fn policy_refuses_unapproved_and_non_redistributable_sources() {
        let mut p = IngestPipeline::new(BuildProfile::Public);
        p.authorize_all_for_testing();
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
        i.authorize_all_for_testing();
        assert!(i
            .add_source(
                src("y", Redistribution::InternalOnly, IndicatorFormat::Csv),
                b""
            )
            .is_ok());
    }

    #[test]
    fn test_self_approval_vulnerability_blocked() {
        let mut p = IngestPipeline::new(BuildProfile::Public);
        // Manifest claims approved = true, but operator has NOT authorized "untrusted-rogue-source"
        let s = src(
            "untrusted-rogue-source",
            Redistribution::Allowed,
            IndicatorFormat::Csv,
        );
        let err = p.add_source(s, b"").unwrap_err();
        match err {
            DatabaseError::Policy(msg) => {
                assert!(msg.contains("not authorized by operator policy"));
                assert!(msg.contains("manifest self-approval is rejected"));
            }
            other => panic!("Expected policy error, got: {:?}", other),
        }

        // Once operator authorizes the source, it succeeds
        p.authorize_source("untrusted-rogue-source");
        assert!(p
            .add_source(
                src(
                    "untrusted-rogue-source",
                    Redistribution::Allowed,
                    IndicatorFormat::Csv
                ),
                b""
            )
            .is_ok());
    }

    #[test]
    fn test_revocation_and_genuine_breakdown() {
        let mut p = IngestPipeline::new(BuildProfile::Public);
        p.authorize_source("feed-genuine");
        p.verify_genuine_source("feed-genuine");

        // Revoke the EICAR MD5 hash
        p.revoke_hash(EICAR_MD5).unwrap();

        let sha256_threat = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let genuine_content = format!(
            "{}:1000:Win32.Trojan.GenuineThreat\n{}:68:Revoked.Eicar\n",
            sha256_threat, EICAR_MD5
        );

        let mut genuine_src = src(
            "feed-genuine",
            Redistribution::Allowed,
            IndicatorFormat::HashSizeName,
        );
        genuine_src.kind = SourceKind::Genuine;
        genuine_src.sha256 = Some(hex::encode(sha2::Sha256::digest(
            genuine_content.as_bytes(),
        )));

        let report = p
            .add_source(genuine_src, genuine_content.as_bytes())
            .unwrap();

        assert_eq!(report.accepted, 1);
        assert_eq!(report.rejected, 1);
        assert_eq!(report.rejections_by_reason.get("revoked"), Some(&1));

        let (_, manifest) = p.build("2026.11.02.1", "2026-11-02T00:00:00Z").unwrap();
        assert_eq!(manifest.genuine_records, 1);
        assert_eq!(manifest.synthetic_records, 0);
    }

    #[test]
    fn test_unverified_source_cannot_claim_genuine_status() {
        let mut p = IngestPipeline::new(BuildProfile::Public);
        // Operator authorizes source to ingest, but does NOT certify authenticity
        p.authorize_source("unverified-claims-feed");

        let content =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:1000:SomeThreat\n";
        let mut s = src(
            "unverified-claims-feed",
            Redistribution::Allowed,
            IndicatorFormat::HashSizeName,
        );
        s.kind = SourceKind::Genuine;
        s.sha256 = Some(hex::encode(sha2::Sha256::digest(content.as_bytes())));

        let report = p.add_source(s, content.as_bytes()).unwrap();
        assert_eq!(report.effective_kind, SourceKind::SyntheticTest);
        assert_eq!(
            report.authenticity_status,
            "unverified_operator_certification_missing"
        );
        assert_eq!(report.accepted, 1);

        let (_, manifest) = p.build("2026.11.02.1", "2026-11-02T00:00:00Z").unwrap();
        // Crucial: Must be 0 genuine records!
        assert_eq!(manifest.genuine_records, 0);
        assert_eq!(manifest.synthetic_records, 1);
    }

    #[test]
    fn test_synthetic_preimages_rejected_from_genuine_records() {
        let mut p = IngestPipeline::new(BuildProfile::Public);
        p.authorize_source("certified-feed");
        p.verify_genuine_source("certified-feed");

        // Input contains:
        // 1. sha256("abc") -> known synthetic preimage
        // 2. sha256("1") -> known synthetic preimage
        // 3. EICAR SHA256 -> known synthetic test vector
        // 4. real threat hash -> valid non-synthetic
        let real_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let abc_hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let one_hash = "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b";

        let content = format!(
            "{}:1000:Real.Threat\n{}:34816:FalselyClaimed.AgentTesla\n{}:409600:FalselyClaimed.GuLoader\n{}:68:Eicar\n",
            real_hash, abc_hash, one_hash, EICAR_SHA256
        );

        let mut s = src(
            "certified-feed",
            Redistribution::Allowed,
            IndicatorFormat::HashSizeName,
        );
        s.kind = SourceKind::Genuine;
        s.sha256 = Some(hex::encode(sha2::Sha256::digest(content.as_bytes())));

        let report = p.add_source(s, content.as_bytes()).unwrap();
        // 1 accepted real record, 3 synthetic preimages rejected
        assert_eq!(report.accepted, 1);
        assert_eq!(report.rejected, 3);
        assert_eq!(
            report
                .rejections_by_reason
                .get("synthetic_preimage_in_genuine_feed"),
            Some(&3)
        );

        let (_, manifest) = p.build("2026.11.02.1", "2026-11-02T00:00:00Z").unwrap();
        assert_eq!(manifest.genuine_records, 1);
        assert_eq!(manifest.synthetic_records, 0);
    }

    #[test]
    fn test_unpinned_source_cannot_claim_genuine_status() {
        let mut p = IngestPipeline::new(BuildProfile::Public);
        p.authorize_source("unpinned-feed");
        p.verify_genuine_source("unpinned-feed");

        let content =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:1000:Threat\n";
        let mut s = src(
            "unpinned-feed",
            Redistribution::Allowed,
            IndicatorFormat::HashSizeName,
        );
        s.kind = SourceKind::Genuine;
        s.sha256 = None; // Unpinned!

        let report = p.add_source(s, content.as_bytes()).unwrap();
        assert_eq!(report.effective_kind, SourceKind::SyntheticTest);
        assert_eq!(report.authenticity_status, "unverified_sha256_pin_missing");

        let (_, manifest) = p.build("2026.11.02.1", "2026-11-02T00:00:00Z").unwrap();
        assert_eq!(manifest.genuine_records, 0);
        assert_eq!(manifest.synthetic_records, 1);
    }
}
