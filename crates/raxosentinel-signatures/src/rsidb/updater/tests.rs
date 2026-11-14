// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! Comprehensive tests verifying all 13 mandatory failure and success scenarios for Phase 2D.7.

use super::*;
use crate::rsidb::malwarebazaar::private_store::unified::{
    publish_unified, UnifiedAssociations, UnifiedClaim, UnifiedIndicator, UnifiedRegistry,
    UnifiedSource,
};
use crate::rsidb::malwarebazaar::private_store::{self, multi::digest};
use crate::rsidb::updater::providers::clamav::{authenticate_cvd, parse_clamav_dns_txt};
use crate::rsidb::updater::status::STATUS_FILE;
use crate::rsidb::updater::traits::{
    AcquisitionResult, ExtractedIntelligence, IntelligenceProvider, ProviderState, RecordKey,
    UpdateCheckResult, UpdateError,
};
use crate::rsidb::{HashAlgorithm, RsidbIndex, SignatureEntry};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Helper to create a secure temporary private store root directory with 0700 permissions.
fn setup_private_root() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    temp
}

/// Helper to create a synthetic initial unified generation in a private root.
fn create_initial_generation(
    root: &Path,
    gen_name: &str,
    entries: Vec<SignatureEntry>,
    source_id: &str,
) {
    create_initial_generation_with_version(root, gen_name, entries, source_id, "v1.0");
}

/// Helper to create a synthetic initial unified generation with specified source version.
fn create_initial_generation_with_version(
    root: &Path,
    gen_name: &str,
    entries: Vec<SignatureEntry>,
    source_id: &str,
    version: &str,
) {
    let ev_json = if source_id == "clamav" && version.contains("daily-") {
        let daily_v: u64 = version
            .strip_prefix("daily-")
            .and_then(|s| s.parse().ok())
            .unwrap_or(28173);
        serde_json::json!({
            "version": version,
            "cvd_files": [
                {"file": "main.cvd", "version": 63},
                {"file": "daily.cvd", "version": daily_v}
            ]
        })
    } else if source_id == "clamav" && version.starts_with("main:") {
        serde_json::json!({
            "version": version,
            "cvd_files": [
                {"file": "main.cvd", "version": 63},
                {"file": "daily.cvd", "version": 28173}
            ]
        })
    } else {
        serde_json::json!({
            "version": version
        })
    };
    let ev_bytes = serde_json::to_vec(&ev_json).unwrap();
    let ev_sha256 = digest(&ev_bytes);

    let mut md5_count = 0;
    let mut sha1_count = 0;
    let mut sha256_count = 0;
    let mut indicators = Vec::new();

    for e in &entries {
        match e.alg {
            HashAlgorithm::Md5 => md5_count += 1,
            HashAlgorithm::Sha1 => sha1_count += 1,
            HashAlgorithm::Sha256 => sha256_count += 1,
        }
        indicators.push(UnifiedIndicator {
            alg: match e.alg {
                HashAlgorithm::Md5 => "md5".to_string(),
                HashAlgorithm::Sha1 => "sha1".to_string(),
                HashAlgorithm::Sha256 => "sha256".to_string(),
            },
            hash: hex::encode(&e.digest),
            size: e.size,
            name: e.name.clone(),
            claims: vec![UnifiedClaim {
                source_id: source_id.to_string(),
                size: e.size,
                family: e.name.clone(),
            }],
        });
    }

    let registry = UnifiedRegistry {
        version: 1,
        sources: vec![UnifiedSource {
            id: source_id.to_string(),
            name: format!("Source {}", source_id),
            provider: "TestProvider".to_string(),
            acquisition_method: "test".to_string(),
            acquired_unix_seconds: 1000,
            classification: "test".to_string(),
            provenance: "synthetic fixture".to_string(),
            redistribution: "test only".to_string(),
            enabled: true,
            indicator_count: entries.len(),
            evidence_sha256: ev_sha256,
            evidence_file: Some(format!("evidence-{}.json", source_id)),
        }],
        total_indicators: entries.len(),
        md5_count,
        sha1_count,
        sha256_count,
    };

    let associations = UnifiedAssociations {
        version: 1,
        total_indicators: entries.len(),
        indicators,
    };

    let evidence_files = vec![(format!("evidence-{}.json", source_id), ev_bytes)];

    publish_unified(
        root,
        gen_name,
        entries,
        registry,
        associations,
        evidence_files,
    )
    .unwrap();
    write_pointer(root, CURRENT_PTR, gen_name).unwrap();
}

/// Controllable mock provider for simulating various update scenarios.
#[derive(Clone, Debug)]
struct MockProvider {
    id: String,
    name: String,
    check_result: Result<UpdateCheckResult, String>,
    acquire_result: Result<AcquisitionResult, String>,
    extract_result: Result<ExtractedIntelligence, String>,
}

impl MockProvider {
    fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            name: format!("Mock {}", id),
            check_result: Ok(UpdateCheckResult {
                available: true,
                version: "v1".to_string(),
                details: "New indicators".to_string(),
            }),
            acquire_result: Ok(AcquisitionResult {
                source_id: id.to_string(),
                version: "v1".to_string(),
                timestamp: 12345,
                evidence_files: vec![(format!("evidence-{}.json", id), b"{\"ev\":1}".to_vec())],
                staging_path: None,
            }),
            extract_result: Ok(ExtractedIntelligence {
                source_info: UnifiedSource {
                    id: id.to_string(),
                    name: format!("Mock {}", id),
                    provider: "MockOrg".to_string(),
                    acquisition_method: "mock".to_string(),
                    acquired_unix_seconds: 12345,
                    classification: "test".to_string(),
                    provenance: "mock".to_string(),
                    redistribution: "mock".to_string(),
                    enabled: true,
                    indicator_count: 0,
                    evidence_sha256: digest(b"{\"ev\":1}"),
                    evidence_file: Some(format!("evidence-{}.json", id)),
                },
                entries: Vec::new(),
                claims: BTreeMap::new(),
                revocations: HashSet::new(),
                evidence_files: vec![(format!("evidence-{}.json", id), b"{\"ev\":1}".to_vec())],
                gross_records: 0,
                rejected_records: 0,
                duplicate_records: 0,
            }),
        }
    }

    fn with_entries(mut self, entries: Vec<SignatureEntry>) -> Self {
        let mut claims = BTreeMap::new();
        for e in &entries {
            let rkey = (e.alg, e.digest.clone(), e.size, e.name.clone());
            let mut s = BTreeSet::new();
            s.insert(UnifiedClaim {
                source_id: self.id.clone(),
                size: e.size,
                family: e.name.clone(),
            });
            claims.insert(rkey, s);
        }
        if let Ok(ref mut ext) = self.extract_result {
            ext.source_info.indicator_count = entries.len();
            ext.gross_records = entries.len();
            ext.duplicate_records = entries.len().saturating_sub(claims.len());
            ext.entries = entries;
            ext.claims = claims;
        }
        self
    }
}

impl IntelligenceProvider for MockProvider {
    fn id(&self) -> &str {
        &self.id
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn check_update(&self, _state: &ProviderState) -> Result<UpdateCheckResult, UpdateError> {
        self.check_result
            .clone()
            .map_err(|e| UpdateError::CheckFailed {
                provider: self.id.clone(),
                message: e,
            })
    }
    fn acquire_update(&self, _staging_dir: &Path) -> Result<AcquisitionResult, UpdateError> {
        self.acquire_result
            .clone()
            .map_err(|e| UpdateError::AcquisitionFailed {
                provider: self.id.clone(),
                message: e,
            })
    }
    fn extract_records(
        &self,
        _acquisition: &AcquisitionResult,
    ) -> Result<ExtractedIntelligence, UpdateError> {
        self.extract_result
            .clone()
            .map_err(|e| UpdateError::ExtractionFailed {
                provider: self.id.clone(),
                message: e,
            })
    }
}

// ============================================================================
// SCENARIO 1: A source publishing new indicators
// ============================================================================
#[test]
fn test_01_source_publishing_new_indicators() {
    let temp = setup_private_root();
    let root = temp.path();

    let initial_entry = SignatureEntry::new(
        HashAlgorithm::Sha256,
        100,
        vec![0x11; 32],
        "Threat.Initial".to_string(),
    );
    create_initial_generation(root, "gen-initial", vec![initial_entry.clone()], "src_a");

    let new_entry = SignatureEntry::new(
        HashAlgorithm::Sha256,
        200,
        vec![0x22; 32],
        "Threat.New".to_string(),
    );
    let provider =
        MockProvider::new("src_a").with_entries(vec![initial_entry.clone(), new_entry.clone()]);

    let engine = UpdateEngine::new(root).with_provider(Box::new(provider));
    let summary = engine.apply_update(false).unwrap().expect("update summary");

    assert_eq!(summary.total_indicators, 2);
    assert_eq!(summary.new_records, 1);
    assert_eq!(summary.verification_result, "PASS");

    // Verify active pointer was updated and both indicators match
    let active = read_pointer(root, CURRENT_PTR).unwrap();
    assert_ne!(active, "gen-initial");
    let (db, _) = private_store::load_timed(root, &active).unwrap();
    assert_eq!(db.total_records(), 2);
    assert_eq!(db.lookup(HashAlgorithm::Sha256, 100, &[0x11; 32]).len(), 1);
    assert_eq!(db.lookup(HashAlgorithm::Sha256, 200, &[0x22; 32]).len(), 1);
}

// ============================================================================
// SCENARIO 2: An unchanged source (skipped, no unnecessary DB generation)
// ============================================================================
#[test]
fn test_02_unchanged_source_skipped() {
    let temp = setup_private_root();
    let root = temp.path();

    let entry = SignatureEntry::new(
        HashAlgorithm::Sha256,
        100,
        vec![0x11; 32],
        "Threat.Initial".to_string(),
    );
    create_initial_generation(root, "gen-initial", vec![entry], "src_a");

    let mut provider = MockProvider::new("src_a");
    provider.check_result = Ok(UpdateCheckResult {
        available: false,
        version: "v1".to_string(),
        details: "No new indicators".to_string(),
    });

    let engine = UpdateEngine::new(root).with_provider(Box::new(provider));
    let res = engine.apply_update(false).unwrap();

    assert!(
        res.is_none(),
        "Unchanged source must not produce a new generation"
    );
    assert_eq!(read_pointer(root, CURRENT_PTR).unwrap(), "gen-initial");
}

// ============================================================================
// SCENARIO 3: Duplicate indicators
// ============================================================================
#[test]
fn test_03_duplicate_indicators_deduplicated() {
    let temp = setup_private_root();
    let root = temp.path();

    let entry = SignatureEntry::new(
        HashAlgorithm::Md5,
        500,
        vec![0xaa; 16],
        "Threat.Duplicate".to_string(),
    );
    let duplicate = entry.clone();

    let provider = MockProvider::new("src_a").with_entries(vec![entry, duplicate]);
    let engine = UpdateEngine::new(root).with_provider(Box::new(provider));

    let summary = engine.apply_update(true).unwrap().expect("summary");
    assert_eq!(summary.total_indicators, 1);
    assert_eq!(summary.deduplicated_records, 1);

    let active = read_pointer(root, CURRENT_PTR).unwrap();
    let (db, _) = private_store::load_timed(root, &active).unwrap();
    assert_eq!(db.total_records(), 1);
}

// ============================================================================
// SCENARIO 4: A revoked signature
// ============================================================================
#[test]
fn test_04_revoked_signature_removed() {
    let temp = setup_private_root();
    let root = temp.path();

    let good_entry = SignatureEntry::new(
        HashAlgorithm::Sha256,
        100,
        vec![0x11; 32],
        "Threat.Good".to_string(),
    );
    let revoked_entry = SignatureEntry::new(
        HashAlgorithm::Sha256,
        200,
        vec![0x22; 32],
        "Threat.FalsePositive".to_string(),
    );
    create_initial_generation(
        root,
        "gen-initial",
        vec![good_entry.clone(), revoked_entry.clone()],
        "src_a",
    );

    let mut provider = MockProvider::new("src_a").with_entries(vec![good_entry.clone()]);
    // Mark revoked_entry in revocations
    let revoked_key: RecordKey = (
        revoked_entry.alg,
        revoked_entry.digest.clone(),
        revoked_entry.size,
        revoked_entry.name.clone(),
    );
    if let Ok(ref mut ext) = provider.extract_result {
        ext.revocations.insert(revoked_key);
    }

    let engine = UpdateEngine::new(root)
        .with_provider(Box::new(provider))
        .with_anomaly_threshold(60.0);
    let summary = engine.apply_update(true).unwrap().expect("summary");

    assert_eq!(summary.total_indicators, 1);
    assert_eq!(summary.rejected_records, 1);

    let active = read_pointer(root, CURRENT_PTR).unwrap();
    let (db, _) = private_store::load_timed(root, &active).unwrap();
    assert_eq!(db.total_records(), 1);
    assert_eq!(db.lookup(HashAlgorithm::Sha256, 100, &[0x11; 32]).len(), 1);
    assert_eq!(db.lookup(HashAlgorithm::Sha256, 200, &[0x22; 32]).len(), 0);
}

// ============================================================================
// SCENARIO 5: A source removing an indicator still supported by another source
// ============================================================================
#[test]
fn test_05_source_removing_indicator_still_supported_by_another_source() {
    let temp = setup_private_root();
    let root = temp.path();

    // Shared indicator between Source A and Source B
    let shared_entry = SignatureEntry::new(
        HashAlgorithm::Sha256,
        300,
        vec![0x33; 32],
        "Threat.Shared".to_string(),
    );

    let mut claims = BTreeMap::new();
    let shared_key = (
        shared_entry.alg,
        shared_entry.digest.clone(),
        shared_entry.size,
        shared_entry.name.clone(),
    );
    let mut claims_set = BTreeSet::new();
    claims_set.insert(UnifiedClaim {
        source_id: "src_a".to_string(),
        size: 300,
        family: "Threat.Shared".to_string(),
    });
    claims_set.insert(UnifiedClaim {
        source_id: "src_b".to_string(),
        size: 300,
        family: "Threat.Shared".to_string(),
    });
    claims.insert(shared_key, claims_set);

    let ev_bytes = b"evidence".to_vec();
    let ev_sha256 = digest(&ev_bytes);
    let registry = UnifiedRegistry {
        version: 1,
        sources: vec![
            UnifiedSource {
                id: "src_a".to_string(),
                name: "Source A".to_string(),
                provider: "Test".to_string(),
                acquisition_method: "test".to_string(),
                acquired_unix_seconds: 1000,
                classification: "test".to_string(),
                provenance: "test".to_string(),
                redistribution: "test".to_string(),
                enabled: true,
                indicator_count: 1,
                evidence_sha256: ev_sha256.clone(),
                evidence_file: Some("evidence-src_a.json".to_string()),
            },
            UnifiedSource {
                id: "src_b".to_string(),
                name: "Source B".to_string(),
                provider: "Test".to_string(),
                acquisition_method: "test".to_string(),
                acquired_unix_seconds: 1000,
                classification: "test".to_string(),
                provenance: "test".to_string(),
                redistribution: "test".to_string(),
                enabled: true,
                indicator_count: 1,
                evidence_sha256: ev_sha256.clone(),
                evidence_file: Some("evidence-src_b.json".to_string()),
            },
        ],
        total_indicators: 1,
        md5_count: 0,
        sha1_count: 0,
        sha256_count: 1,
    };
    let associations = UnifiedAssociations {
        version: 1,
        total_indicators: 1,
        indicators: vec![UnifiedIndicator {
            alg: "sha256".to_string(),
            hash: hex::encode(&shared_entry.digest),
            size: 300,
            name: "Threat.Shared".to_string(),
            claims: vec![
                UnifiedClaim {
                    source_id: "src_a".to_string(),
                    size: 300,
                    family: "Threat.Shared".to_string(),
                },
                UnifiedClaim {
                    source_id: "src_b".to_string(),
                    size: 300,
                    family: "Threat.Shared".to_string(),
                },
            ],
        }],
    };
    publish_unified(
        root,
        "gen-initial",
        vec![shared_entry.clone()],
        registry,
        associations,
        vec![
            ("evidence-src_a.json".to_string(), ev_bytes.clone()),
            ("evidence-src_b.json".to_string(), ev_bytes),
        ],
    )
    .unwrap();
    write_pointer(root, CURRENT_PTR, "gen-initial").unwrap();

    // Now Source A updates and removes Threat.Shared (only publishes Threat.UniqueA)
    let unique_a = SignatureEntry::new(
        HashAlgorithm::Sha256,
        400,
        vec![0x44; 32],
        "Threat.UniqueA".to_string(),
    );
    let prov_a = MockProvider::new("src_a").with_entries(vec![unique_a.clone()]);

    let engine = UpdateEngine::new(root).with_provider(Box::new(prov_a));
    let summary = engine.apply_update(true).unwrap().expect("summary");

    // Both Threat.Shared (still claimed by src_b) and Threat.UniqueA must be present!
    assert_eq!(summary.total_indicators, 2);

    let active = read_pointer(root, CURRENT_PTR).unwrap();
    let (db, _) = private_store::load_timed(root, &active).unwrap();
    assert_eq!(db.total_records(), 2);
    assert_eq!(db.lookup(HashAlgorithm::Sha256, 300, &[0x33; 32]).len(), 1);
    assert_eq!(db.lookup(HashAlgorithm::Sha256, 400, &[0x44; 32]).len(), 1);
}

// ============================================================================
// SCENARIO 6: A corrupted source archive
// ============================================================================
#[test]
fn test_06_corrupted_source_archive_fails_closed() {
    let temp = setup_private_root();
    let root = temp.path();

    let entry = SignatureEntry::new(
        HashAlgorithm::Sha256,
        100,
        vec![0x11; 32],
        "Threat.Good".to_string(),
    );
    create_initial_generation(root, "gen-initial", vec![entry], "src_a");

    let mut provider = MockProvider::new("src_a");
    provider.extract_result = Err("Corrupted archive header in CVD/tar payload".to_string());

    let engine = UpdateEngine::new(root).with_provider(Box::new(provider));
    let res = engine.apply_update(true);

    assert!(res.is_err());
    assert_eq!(read_pointer(root, CURRENT_PTR).unwrap(), "gen-initial");
}

// ============================================================================
// SCENARIO 7: An interrupted download
// ============================================================================
#[test]
fn test_07_interrupted_download_fails_closed() {
    let temp = setup_private_root();
    let root = temp.path();

    let entry = SignatureEntry::new(
        HashAlgorithm::Sha256,
        100,
        vec![0x11; 32],
        "Threat.Good".to_string(),
    );
    create_initial_generation(root, "gen-initial", vec![entry], "src_a");

    let mut provider = MockProvider::new("src_a");
    provider.acquire_result = Err("Network connection reset mid-download".to_string());

    let engine = UpdateEngine::new(root).with_provider(Box::new(provider));
    let res = engine.apply_update(true);

    assert!(res.is_err());
    assert_eq!(read_pointer(root, CURRENT_PTR).unwrap(), "gen-initial");
    // Ensure no orphan staging directories remain
    let staging_count = fs::read_dir(root)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".update-staging")
        })
        .count();
    assert_eq!(staging_count, 0);
}

// ============================================================================
// SCENARIO 8: An interrupted database build
// ============================================================================
#[test]
fn test_08_interrupted_database_build_fails_closed() {
    let temp = setup_private_root();
    let root = temp.path();

    let entry = SignatureEntry::new(
        HashAlgorithm::Sha256,
        100,
        vec![0x11; 32],
        "Threat.Good".to_string(),
    );
    create_initial_generation(root, "gen-initial", vec![entry], "src_a");

    // Provide malformed entry that violates bounds
    let bad_entry = SignatureEntry::new(
        HashAlgorithm::Sha256,
        0,
        vec![0x99; 31], // Invalid length for SHA256 (31 instead of 32)
        "Threat.Bad".to_string(),
    );
    let provider = MockProvider::new("src_a").with_entries(vec![bad_entry]);

    let engine = UpdateEngine::new(root).with_provider(Box::new(provider));
    let res = engine.apply_update(true);

    assert!(res.is_err());
    assert_eq!(read_pointer(root, CURRENT_PTR).unwrap(), "gen-initial");
}

// ============================================================================
// SCENARIO 9: Two updater processes starting simultaneously
// ============================================================================
#[test]
fn test_09_two_updaters_simultaneous_lock_contention() {
    let temp = setup_private_root();
    let root = temp.path();

    let engine1 = UpdateEngine::new(root);
    let lock1 = engine1.acquire_lock();
    assert!(lock1.is_ok(), "First updater must acquire lock");

    let engine2 = UpdateEngine::new(root);
    let lock2 = engine2.acquire_lock();
    match lock2 {
        Err(UpdateError::LockContention) => {}
        other => panic!("Expected LockContention, got {:?}", other),
    }

    drop(lock1);
    let lock3 = engine2.acquire_lock();
    assert!(
        lock3.is_ok(),
        "Lock should be acquirable after first is dropped"
    );
}

// ============================================================================
// SCENARIO 10: Failure during activation
// ============================================================================
#[test]
fn test_10_failure_during_activation_fails_closed() {
    let temp = setup_private_root();
    let root = temp.path();

    let entry = SignatureEntry::new(
        HashAlgorithm::Sha256,
        100,
        vec![0x11; 32],
        "Threat.Good".to_string(),
    );
    create_initial_generation(root, "gen-initial", vec![entry], "src_a");

    // Test writing an invalid pointer fails without changing current pointer
    let res = write_pointer(root, CURRENT_PTR, "../traversal/attempt");
    assert!(res.is_err());
    assert_eq!(read_pointer(root, CURRENT_PTR).unwrap(), "gen-initial");
}

// ============================================================================
// SCENARIO 11: Successful rollback to the previous generation
// ============================================================================
#[test]
fn test_11_successful_rollback() {
    let temp = setup_private_root();
    let root = temp.path();

    let entry1 = SignatureEntry::new(
        HashAlgorithm::Sha256,
        100,
        vec![0x11; 32],
        "Threat.Gen1".to_string(),
    );
    create_initial_generation(root, "gen-1", vec![entry1.clone()], "src_a");

    let entry2 = SignatureEntry::new(
        HashAlgorithm::Sha256,
        200,
        vec![0x22; 32],
        "Threat.Gen2".to_string(),
    );
    let provider = MockProvider::new("src_a").with_entries(vec![entry1.clone(), entry2.clone()]);
    let engine = UpdateEngine::new(root).with_provider(Box::new(provider));
    engine.apply_update(true).unwrap();

    let gen2 = read_pointer(root, CURRENT_PTR).unwrap();
    assert_ne!(gen2, "gen-1");
    assert_eq!(read_pointer(root, PREVIOUS_PTR).unwrap(), "gen-1");

    // Invoke rollback
    let rolled_back_to = engine.rollback().unwrap();
    assert_eq!(rolled_back_to, "gen-1");
    assert_eq!(read_pointer(root, CURRENT_PTR).unwrap(), "gen-1");

    // Verify database at active generation only contains entry1
    let (db, _) = private_store::load_timed(root, "current").unwrap();
    assert_eq!(db.total_records(), 1);
    assert_eq!(db.lookup(HashAlgorithm::Sha256, 100, &[0x11; 32]).len(), 1);
    assert_eq!(db.lookup(HashAlgorithm::Sha256, 200, &[0x22; 32]).len(), 0);
}

// ============================================================================
// SCENARIO 12: Provider outage or rate limiting
// ============================================================================
#[test]
fn test_12_provider_outage_or_rate_limiting() {
    let temp = setup_private_root();
    let root = temp.path();

    let entry = SignatureEntry::new(
        HashAlgorithm::Sha256,
        100,
        vec![0x11; 32],
        "Threat.Good".to_string(),
    );
    create_initial_generation(root, "gen-initial", vec![entry], "src_a");

    let mut provider = MockProvider::new("src_a");
    provider.check_result = Err("HTTP 429 Too Many Requests (Rate limit reached)".to_string());

    let engine = UpdateEngine::new(root).with_provider(Box::new(provider));
    let res = engine.check_all();
    assert!(res.is_err());

    // Active generation remains untouched and functional
    assert_eq!(read_pointer(root, CURRENT_PTR).unwrap(), "gen-initial");
    let (db, _) = private_store::load_timed(root, "current").unwrap();
    assert_eq!(db.total_records(), 1);
}

// ============================================================================
// SCENARIO 13: A suspiciously large unexpected reduction in source records
// ============================================================================
#[test]
fn test_13_suspiciously_large_reduction_triggers_anomaly_review() {
    let temp = setup_private_root();
    let root = temp.path();

    // Baseline: 10 indicators
    let mut initial_entries = Vec::new();
    for i in 0..10u8 {
        initial_entries.push(SignatureEntry::new(
            HashAlgorithm::Sha256,
            100 + i as u64,
            vec![i; 32],
            format!("Threat.{}", i),
        ));
    }
    create_initial_generation(root, "gen-initial", initial_entries, "src_a");

    // Sudden drop to only 2 indicators (80% reduction, exceeding 20% threshold)
    let reduced_entries = vec![
        SignatureEntry::new(
            HashAlgorithm::Sha256,
            100,
            vec![0; 32],
            "Threat.0".to_string(),
        ),
        SignatureEntry::new(
            HashAlgorithm::Sha256,
            101,
            vec![1; 32],
            "Threat.1".to_string(),
        ),
    ];
    let provider = MockProvider::new("src_a").with_entries(reduced_entries);

    let engine = UpdateEngine::new(root)
        .with_provider(Box::new(provider))
        .with_anomaly_threshold(20.0);

    let res = engine.apply_update(true);
    match res {
        Err(UpdateError::SuspiciousReduction {
            drop_pct,
            threshold_pct,
            ..
        }) => {
            assert!(
                drop_pct > threshold_pct,
                "Drop percentage {} must exceed threshold {}",
                drop_pct,
                threshold_pct
            );
        }
        other => panic!("Expected SuspiciousReduction, got {:?}", other),
    }

    // Active generation is preserved; mass deletion blocked!
    assert_eq!(read_pointer(root, CURRENT_PTR).unwrap(), "gen-initial");
    let (db, _) = private_store::load_timed(root, "current").unwrap();
    assert_eq!(db.total_records(), 10);
}

// ============================================================================
// SCENARIO 14: Strict Accounting Invariant & Multi-Source Retained Indicators
// ============================================================================
#[test]
fn test_14_accounting_invariant_and_retained_records() {
    let temp = setup_private_root();
    let root = temp.path();

    // Baseline indicators:
    // Threat.A is shared by src_a and src_b
    // Threat.B is claimed by src_a only
    // Threat.C is claimed by src_b only
    let entry_a = SignatureEntry::new(
        HashAlgorithm::Sha256,
        100,
        vec![0xaa; 32],
        "Threat.SharedA".to_string(),
    );
    let entry_b = SignatureEntry::new(
        HashAlgorithm::Sha256,
        200,
        vec![0xbb; 32],
        "Threat.SrcAOnlyB".to_string(),
    );
    let entry_c = SignatureEntry::new(
        HashAlgorithm::Sha256,
        300,
        vec![0xcc; 32],
        "Threat.SrcBOnlyC".to_string(),
    );

    let _key_a = (
        entry_a.alg,
        entry_a.digest.clone(),
        entry_a.size,
        entry_a.name.clone(),
    );
    let key_b = (
        entry_b.alg,
        entry_b.digest.clone(),
        entry_b.size,
        entry_b.name.clone(),
    );
    let _key_c = (
        entry_c.alg,
        entry_c.digest.clone(),
        entry_c.size,
        entry_c.name.clone(),
    );

    let indicators = vec![
        UnifiedIndicator {
            alg: "sha256".to_string(),
            hash: hex::encode(&entry_a.digest),
            size: entry_a.size,
            name: entry_a.name.clone(),
            claims: vec![
                UnifiedClaim {
                    source_id: "src_a".to_string(),
                    size: 100,
                    family: "Threat.SharedA".to_string(),
                },
                UnifiedClaim {
                    source_id: "src_b".to_string(),
                    size: 100,
                    family: "Threat.SharedA".to_string(),
                },
            ],
        },
        UnifiedIndicator {
            alg: "sha256".to_string(),
            hash: hex::encode(&entry_b.digest),
            size: entry_b.size,
            name: entry_b.name.clone(),
            claims: vec![UnifiedClaim {
                source_id: "src_a".to_string(),
                size: 200,
                family: "Threat.SrcAOnlyB".to_string(),
            }],
        },
        UnifiedIndicator {
            alg: "sha256".to_string(),
            hash: hex::encode(&entry_c.digest),
            size: entry_c.size,
            name: entry_c.name.clone(),
            claims: vec![UnifiedClaim {
                source_id: "src_b".to_string(),
                size: 300,
                family: "Threat.SrcBOnlyC".to_string(),
            }],
        },
    ];

    let ev_bytes = b"evidence".to_vec();
    let registry = UnifiedRegistry {
        version: 1,
        sources: vec![
            UnifiedSource {
                id: "src_a".to_string(),
                name: "Source A".to_string(),
                provider: "Test".to_string(),
                acquisition_method: "test".to_string(),
                acquired_unix_seconds: 1000,
                classification: "test".to_string(),
                provenance: "test".to_string(),
                redistribution: "test".to_string(),
                enabled: true,
                indicator_count: 2,
                evidence_sha256: digest(&ev_bytes),
                evidence_file: Some("evidence-src_a.json".to_string()),
            },
            UnifiedSource {
                id: "src_b".to_string(),
                name: "Source B".to_string(),
                provider: "Test".to_string(),
                acquisition_method: "test".to_string(),
                acquired_unix_seconds: 1000,
                classification: "test".to_string(),
                provenance: "test".to_string(),
                redistribution: "test".to_string(),
                enabled: true,
                indicator_count: 2,
                evidence_sha256: digest(&ev_bytes),
                evidence_file: Some("evidence-src_b.json".to_string()),
            },
        ],
        total_indicators: 3,
        md5_count: 0,
        sha1_count: 0,
        sha256_count: 3,
    };
    let associations = UnifiedAssociations {
        version: 1,
        total_indicators: 3,
        indicators,
    };

    publish_unified(
        root,
        "gen-initial",
        vec![entry_a.clone(), entry_b.clone(), entry_c.clone()],
        registry,
        associations,
        vec![
            ("evidence-src_a.json".to_string(), ev_bytes.clone()),
            ("evidence-src_b.json".to_string(), ev_bytes),
        ],
    )
    .unwrap();
    write_pointer(root, CURRENT_PTR, "gen-initial").unwrap();

    // Now, src_a updates:
    // - Drops Threat.A (it was shared with src_b, so Threat.A is RETAINED via src_b)
    // - Revokes Threat.B (it was only in src_a, so Threat.B is REMOVED)
    // - Adds 2 new threats: Threat.D and Threat.E (GROSS NEW UNIQUE RECORDS)
    let entry_d = SignatureEntry::new(
        HashAlgorithm::Sha256,
        400,
        vec![0xdd; 32],
        "Threat.NewD".to_string(),
    );
    let entry_e = SignatureEntry::new(
        HashAlgorithm::Sha256,
        500,
        vec![0xee; 32],
        "Threat.NewE".to_string(),
    );

    let mut prov_a =
        MockProvider::new("src_a").with_entries(vec![entry_d.clone(), entry_e.clone()]);
    if let Ok(ref mut ext) = prov_a.extract_result {
        ext.revocations.insert(key_b);
        ext.gross_records = 3;
        ext.rejected_records = 1;
    }

    let engine = UpdateEngine::new(root)
        .with_provider(Box::new(prov_a))
        .with_anomaly_threshold(50.0);

    let summary = engine.apply_update(true).unwrap().expect("summary");

    // Independent Quantity Verification
    assert_eq!(summary.initial_indicators, 3, "Initial count must be 3");
    assert_eq!(
        summary.new_records, 2,
        "Gross new unique additions must be 2 (D and E)"
    );
    assert_eq!(
        summary.removed_records, 1,
        "Removed records must be 1 (B revoked)"
    );
    assert_eq!(
        summary.retained_records, 1,
        "Retained through another provider must be 1 (A retained via src_b)"
    );
    assert_eq!(
        summary.net_count_change, 1,
        "Net count change must be +1 (2 added - 1 removed)"
    );
    assert_eq!(
        summary.total_indicators, 4,
        "Final active count must be 4 (A, C, D, E)"
    );

    // Strict Accounting Invariant Verification:
    // Final count = Initial count + additions − removals
    assert_eq!(
        summary.total_indicators,
        summary.initial_indicators + summary.new_records - summary.removed_records,
        "Invariant: Final ({}) == Initial ({}) + Additions ({}) - Removals ({})",
        summary.total_indicators,
        summary.initial_indicators,
        summary.new_records,
        summary.removed_records
    );

    // Verify indicators in active database
    let active = read_pointer(root, CURRENT_PTR).unwrap();
    let (db, _) = private_store::load_timed(root, &active).unwrap();
    assert_eq!(db.total_records(), 4);
    assert_eq!(
        db.lookup(HashAlgorithm::Sha256, 100, &[0xaa; 32]).len(),
        1,
        "A retained"
    );
    assert_eq!(
        db.lookup(HashAlgorithm::Sha256, 200, &[0xbb; 32]).len(),
        0,
        "B removed"
    );
    assert_eq!(
        db.lookup(HashAlgorithm::Sha256, 300, &[0xcc; 32]).len(),
        1,
        "C retained"
    );
    assert_eq!(
        db.lookup(HashAlgorithm::Sha256, 400, &[0xdd; 32]).len(),
        1,
        "D added"
    );
    assert_eq!(
        db.lookup(HashAlgorithm::Sha256, 500, &[0xee; 32]).len(),
        1,
        "E added"
    );
}

// ============================================================================
// SCENARIO 15: Dual Database Independent Tracking & CVD Authentication
// ============================================================================
#[test]
fn test_15_clamav_dual_database_independent_tracking_and_authentication() {
    let cvd_dir = Path::new("/var/lib/clamav");
    if !cvd_dir.join("daily.cvd").exists() || !cvd_dir.join("main.cvd").exists() {
        return; // Skip if run in environment without local ClamAV installation
    }

    // 1. Authenticate both official CVD databases
    let daily_meta =
        authenticate_cvd(&cvd_dir.join("daily.cvd")).expect("daily.cvd authentication");
    assert_eq!(daily_meta.file_name, "daily.cvd");
    assert!(daily_meta.version > 0);
    assert!(daily_meta.verified, "Digital signature must be verified OK");

    let main_meta = authenticate_cvd(&cvd_dir.join("main.cvd")).expect("main.cvd authentication");
    assert_eq!(main_meta.file_name, "main.cvd");
    assert!(main_meta.version > 0);
    assert!(main_meta.verified, "Digital signature must be verified OK");

    // 2. Tampered CVD signature authentication failure (fail closed)
    let temp = setup_private_root();
    let corrupt_cvd = temp.path().join("daily-corrupt.cvd");
    let mut bytes = fs::read(cvd_dir.join("daily.cvd")).unwrap();
    // Tamper with data payload
    if bytes.len() > 1000 {
        bytes[1000] ^= 0xff;
    }
    fs::write(&corrupt_cvd, &bytes).unwrap();
    let auth_res = authenticate_cvd(&corrupt_cvd);
    assert!(
        auth_res.is_err(),
        "Tampered CVD must fail cryptographic authentication"
    );

    // 3. Independent tracking: unchanged vs changed
    let composite = format!("main:{},daily:{}", main_meta.version, daily_meta.version);
    // Authentication uses real CVDs; tracking must not depend on live DNS.
    let provider = ClamAvProvider::with_cvd_dir(cvd_dir).with_version(&composite);

    // State with same version -> available=false (no unnecessary build)
    let state_same = ProviderState {
        last_version: composite.clone(),
        ..Default::default()
    };
    let chk_same = provider.check_update(&state_same).unwrap();
    assert!(
        !chk_same.available,
        "Unchanged source must report available=false"
    );

    // State with changed daily version -> available=true
    let state_diff_daily = ProviderState {
        last_version: format!(
            "main:{},daily:{}",
            main_meta.version,
            daily_meta.version - 1
        ),
        ..Default::default()
    };
    let chk_daily = provider.check_update(&state_diff_daily).unwrap();
    assert!(
        chk_daily.available,
        "Changed daily must report available=true"
    );

    // State with changed main version -> available=true
    let state_diff_main = ProviderState {
        last_version: format!(
            "main:{},daily:{}",
            main_meta.version - 1,
            daily_meta.version
        ),
        ..Default::default()
    };
    let chk_main = provider.check_update(&state_diff_main).unwrap();
    assert!(
        chk_main.available,
        "Changed main must report available=true"
    );
}

// ============================================================================
// SCENARIO 16: ClamAV DNS TXT Record Parser
// ============================================================================
#[test]
fn test_16_clamav_dns_txt_query_parser() {
    let raw_record = "1.4.6:63:28173:1793768400:1:90:49192:339";
    let (main_v, daily_v) = parse_clamav_dns_txt(raw_record).expect("parsed TXT");
    assert_eq!(main_v, 63);
    assert_eq!(daily_v, 28173);

    // Invalid TXT record rejection
    assert!(parse_clamav_dns_txt("invalid").is_none());
    assert!(parse_clamav_dns_txt("1.4.6:notanumber:28173").is_none());
}

// ============================================================================
// SCENARIO 17: Scenario A & Scenario B — Update, Rollback Consistency & Reapply
// ============================================================================
#[test]
fn test_17_rollback_consistency_and_reapply_lifecycle() {
    let temp = setup_private_root();
    let root = temp.path();

    // Baseline: 3 indicators, source version "v1.0"
    let e1 = SignatureEntry::new(
        HashAlgorithm::Sha256,
        100,
        vec![0x11; 32],
        "Threat.1".to_string(),
    );
    let e2 = SignatureEntry::new(
        HashAlgorithm::Sha256,
        200,
        vec![0x22; 32],
        "Threat.2".to_string(),
    );
    let e3 = SignatureEntry::new(
        HashAlgorithm::Sha256,
        300,
        vec![0x33; 32],
        "Threat.3".to_string(),
    );

    create_initial_generation_with_version(
        root,
        "gen-baseline",
        vec![e1.clone(), e2.clone(), e3.clone()],
        "prov_a",
        "v1.0",
    );

    // 1. Initial State Check
    let status_init = UpdateStatus::load(root);
    assert_eq!(
        status_init.current_generation.as_deref(),
        Some("gen-baseline")
    );
    assert_eq!(status_init.previous_generation, None);
    assert_eq!(
        status_init.sources.get("prov_a").unwrap().indicator_count,
        3
    );
    assert_eq!(
        status_init.sources.get("prov_a").unwrap().active_version,
        "v1.0"
    );

    // 2. Apply controlled update:
    // +2 additions (e4, e5), -1 removal (e3 revoked), net change +1 (total: 4)
    let e4 = SignatureEntry::new(
        HashAlgorithm::Sha256,
        400,
        vec![0x44; 32],
        "Threat.4".to_string(),
    );
    let e5 = SignatureEntry::new(
        HashAlgorithm::Sha256,
        500,
        vec![0x55; 32],
        "Threat.5".to_string(),
    );
    let key3 = (e3.alg, e3.digest.clone(), e3.size, e3.name.clone());

    let mut prov = MockProvider::new("prov_a").with_entries(vec![
        e1.clone(),
        e2.clone(),
        e4.clone(),
        e5.clone(),
    ]);
    prov.check_result = Ok(UpdateCheckResult {
        available: true,
        version: "v2.0".to_string(),
        details: "Version 2.0 release".to_string(),
    });
    let ev_v2 = serde_json::to_vec(&serde_json::json!({"version": "v2.0"})).unwrap();
    prov.acquire_result = Ok(AcquisitionResult {
        source_id: "prov_a".to_string(),
        version: "v2.0".to_string(),
        timestamp: 2000,
        evidence_files: vec![("evidence-prov_a.json".to_string(), ev_v2.clone())],
        staging_path: None,
    });
    if let Ok(ref mut ext) = prov.extract_result {
        ext.revocations.insert(key3);
        ext.source_info.evidence_sha256 = digest(&ev_v2);
        ext.evidence_files = vec![("evidence-prov_a.json".to_string(), ev_v2)];
    }

    let engine = UpdateEngine::new(root).with_provider(Box::new(prov));
    let summary = engine.apply_update(false).unwrap().expect("update applied");
    assert_eq!(summary.initial_indicators, 3);
    assert_eq!(summary.new_records, 2);
    assert_eq!(summary.removed_records, 1);
    assert_eq!(summary.total_indicators, 4);

    let gen_updated = read_pointer(root, CURRENT_PTR).unwrap();
    assert_eq!(
        read_pointer(root, PREVIOUS_PTR).as_deref(),
        Some("gen-baseline")
    );

    // Check status after update
    let status_up = UpdateStatus::load(root);
    assert_eq!(
        status_up.current_generation.as_deref(),
        Some(gen_updated.as_str())
    );
    assert_eq!(
        status_up.previous_generation.as_deref(),
        Some("gen-baseline")
    );
    assert_eq!(status_up.sources.get("prov_a").unwrap().indicator_count, 4);
    assert_eq!(
        status_up.sources.get("prov_a").unwrap().active_version,
        "v2.0"
    );

    // 3. Execute rollback
    let rolled = engine.rollback().expect("rollback succeeded");
    assert_eq!(rolled, "gen-baseline");
    assert_eq!(read_pointer(root, CURRENT_PTR).unwrap(), "gen-baseline");
    assert_eq!(
        read_pointer(root, PREVIOUS_PTR).as_deref(),
        Some(gen_updated.as_str()),
        "Newer generation must remain recoverable in PREVIOUS_PTR"
    );

    // 4. Inspect every persisted state component after rollback:
    // (a) Active RSIDB load
    let (db, _) = private_store::load_timed(root, "current").unwrap();
    assert_eq!(
        db.total_records(),
        3,
        "Database must contain exactly 3 baseline indicators"
    );
    assert_eq!(db.lookup(HashAlgorithm::Sha256, 100, &[0x11; 32]).len(), 1);
    assert_eq!(
        db.lookup(HashAlgorithm::Sha256, 300, &[0x33; 32]).len(),
        1,
        "Revoked threat e3 must be restored"
    );
    assert_eq!(
        db.lookup(HashAlgorithm::Sha256, 400, &[0x44; 32]).len(),
        0,
        "Threat e4 must not exist in baseline"
    );

    // (b) Status reconciliation from active generation
    let status_rb = UpdateStatus::load(root);
    assert_eq!(
        status_rb.current_generation.as_deref(),
        Some("gen-baseline")
    );
    assert_eq!(
        status_rb.previous_generation.as_deref(),
        Some(gen_updated.as_str())
    );
    let src_rb = status_rb.sources.get("prov_a").unwrap();
    assert_eq!(
        src_rb.indicator_count, 3,
        "Indicator count must match baseline 3, not stale 4"
    );
    assert_eq!(
        src_rb.active_version, "v1.0",
        "Active version must match baseline v1.0, not stale v2.0"
    );
    assert_eq!(src_rb.source_version, "v1.0");

    // (c) Rollback summary verification
    let sum_rb = status_rb.last_summary.expect("rollback summary");
    assert_eq!(sum_rb.generation, "gen-baseline");
    assert_eq!(sum_rb.total_indicators, 3);
    assert_eq!(sum_rb.verification_result, "PASS (ROLLBACK)");

    // 5. Scenario B: Reapply after rollback!
    // Stale status must not prevent re-applying the update.
    let reapply_res = engine
        .apply_update(false)
        .unwrap()
        .expect("reapply update applied");
    assert_eq!(reapply_res.initial_indicators, 3);
    assert_eq!(reapply_res.total_indicators, 4);

    let gen_reapplied = read_pointer(root, CURRENT_PTR).unwrap();
    let (db2, _) = private_store::load_timed(root, &gen_reapplied).unwrap();
    assert_eq!(
        db2.total_records(),
        4,
        "Reapplied generation must return cleanly to 4 indicators without corruption"
    );
}

// ============================================================================
// SCENARIO 18: Scenario C — Restart Recovery & Self-Healing Metadata
// ============================================================================
#[test]
fn test_18_restart_recovery_and_stale_file_healing() {
    let temp = setup_private_root();
    let root = temp.path();

    let e1 = SignatureEntry::new(
        HashAlgorithm::Sha256,
        100,
        vec![0x11; 32],
        "Threat.1".to_string(),
    );
    create_initial_generation_with_version(root, "gen-baseline", vec![e1], "prov_a", "v1.0");

    // Simulate stale / corrupted update_status.json left from a pre-crash or aborted session
    // containing wrong generation and wrong versions
    let bogus_status = serde_json::json!({
        "current_generation": "phantom-generation-9999",
        "previous_generation": "phantom-prev-0000",
        "sources": {
            "prov_a": {
                "id": "prov_a",
                "name": "Mock prov_a",
                "source_version": "stale-v9.9",
                "active_version": "stale-v9.9",
                "indicator_count": 999999
            }
        },
        "last_summary": {
            "generation": "phantom-generation-9999",
            "total_indicators": 999999
        }
    });
    fs::write(
        root.join(STATUS_FILE),
        serde_json::to_vec(&bogus_status).unwrap(),
    )
    .unwrap();

    // Fresh process startup / restart
    let recovered_status = UpdateStatus::load(root);

    // Assert that active filesystem pointer and active generation authoritatively overrides the bogus file!
    assert_eq!(
        recovered_status.current_generation.as_deref(),
        Some("gen-baseline"),
        "Must heal to real active pointer"
    );
    assert_eq!(
        recovered_status.previous_generation, None,
        "Must heal previous pointer when none exists on disk"
    );
    let prov = recovered_status.sources.get("prov_a").unwrap();
    assert_eq!(
        prov.indicator_count, 1,
        "Must heal indicator count to actual active count (1)"
    );
    assert_eq!(
        prov.active_version, "v1.0",
        "Must heal active version to real baseline version"
    );
    assert_eq!(prov.source_version, "v1.0");
    assert_eq!(
        recovered_status.last_summary.unwrap().generation,
        "gen-baseline"
    );
}

// ============================================================================
// SCENARIO 19: Scenario D — Repeated Operations Lifecycle
// ============================================================================
#[test]
fn test_19_repeated_operations_lifecycle() {
    let temp = setup_private_root();
    let root = temp.path();

    let e1 = SignatureEntry::new(
        HashAlgorithm::Sha256,
        100,
        vec![0x11; 32],
        "Threat.1".to_string(),
    );
    create_initial_generation_with_version(root, "gen-0", vec![e1.clone()], "prov_a", "v0");

    let e2 = SignatureEntry::new(
        HashAlgorithm::Sha256,
        200,
        vec![0x22; 32],
        "Threat.2".to_string(),
    );
    let e3 = SignatureEntry::new(
        HashAlgorithm::Sha256,
        300,
        vec![0x33; 32],
        "Threat.3".to_string(),
    );

    // Cycle 1: Update to v1 (+e2, total: 2)
    let prov_v1 = MockProvider::new("prov_a").with_entries(vec![e1.clone(), e2.clone()]);
    let engine = UpdateEngine::new(root).with_provider(Box::new(prov_v1));
    let s1 = engine.apply_update(true).unwrap().unwrap();
    assert_eq!(s1.total_indicators, 2);

    // Cycle 1 Rollback: back to gen-0 (total: 1)
    let r1 = engine.rollback().unwrap();
    assert_eq!(r1, "gen-0");
    assert_eq!(
        UpdateStatus::load(root)
            .sources
            .get("prov_a")
            .unwrap()
            .indicator_count,
        1
    );

    // Cycle 2: Update to v1 again (+e2, total: 2)
    let s2 = engine.apply_update(true).unwrap().unwrap();
    assert_eq!(s2.total_indicators, 2);

    // Cycle 2 Rollback: back to gen-0 (total: 1)
    let r2 = engine.rollback().unwrap();
    assert_eq!(r2, "gen-0");
    assert_eq!(
        UpdateStatus::load(root)
            .sources
            .get("prov_a")
            .unwrap()
            .indicator_count,
        1
    );

    // Cycle 3: Legitimate update to v2 (+e2, +e3, total: 3)
    let prov_v2 = MockProvider::new("prov_a").with_entries(vec![e1, e2, e3]);
    let engine3 = UpdateEngine::new(root).with_provider(Box::new(prov_v2));
    let s3 = engine3.apply_update(true).unwrap().unwrap();
    assert_eq!(s3.total_indicators, 3);
    assert_eq!(
        UpdateStatus::load(root)
            .sources
            .get("prov_a")
            .unwrap()
            .indicator_count,
        3
    );
    let (db, _) = private_store::load_timed(root, "current").unwrap();
    assert_eq!(db.total_records(), 3);
}

// ============================================================================
// SCENARIO 20: Scenario E — Unchanged Official Sources Safe No-op
// ============================================================================
#[test]
fn test_20_unchanged_sources_safe_noop() {
    let temp = setup_private_root();
    let root = temp.path();

    let e1 = SignatureEntry::new(
        HashAlgorithm::Sha256,
        100,
        vec![0x11; 32],
        "Threat.1".to_string(),
    );
    create_initial_generation_with_version(
        root,
        "gen-stable",
        vec![e1.clone()],
        "clamav",
        "main:63,daily:28173",
    );

    let mut prov = MockProvider::new("clamav").with_entries(vec![e1]);
    prov.check_result = Ok(UpdateCheckResult {
        available: false,
        version: "main:63,daily:28173".to_string(),
        details: "ClamAV CVD unchanged".to_string(),
    });

    let engine = UpdateEngine::new(root).with_provider(Box::new(prov));

    // Check indicates no update available
    let checks = engine.check_all().unwrap();
    assert!(!checks.get("clamav").unwrap().available);

    // Apply is a strict no-op: returns Ok(None)
    let apply_res = engine.apply_update(false).unwrap();
    assert!(
        apply_res.is_none(),
        "Must return Ok(None) without recompiling"
    );

    // Ensure pointer is completely untouched
    assert_eq!(read_pointer(root, CURRENT_PTR).unwrap(), "gen-stable");
    assert_eq!(read_pointer(root, PREVIOUS_PTR), None);
}

// ============================================================================
// SCENARIO 21: Crash and Interruption Safety at All 7 Transaction Boundaries
// ============================================================================
#[test]
fn test_21_crash_and_interruption_safety_at_transaction_boundaries() {
    let temp = setup_private_root();
    let root = temp.path();

    let e1 = SignatureEntry::new(
        HashAlgorithm::Sha256,
        100,
        vec![0x11; 32],
        "Threat.Base".to_string(),
    );
    create_initial_generation_with_version(
        root,
        "gen-verified-base",
        vec![e1.clone()],
        "prov_a",
        "v1.0",
    );

    // Boundary 1: Crash after downloading source data
    // Leftover staging directories from interrupted download must never be loaded by scanner
    let leftover_staging = root.join(".update-staging-9999-1");
    fs::create_dir_all(&leftover_staging).unwrap();
    fs::write(
        leftover_staging.join("partial.bin"),
        b"corrupt partial download",
    )
    .unwrap();

    let (active_db, _) = private_store::load_timed(root, "current").unwrap();
    assert_eq!(
        active_db.total_records(),
        1,
        "Scanner strictly loads verified base"
    );
    assert_eq!(
        active_db
            .lookup(HashAlgorithm::Sha256, 100, &[0x11; 32])
            .len(),
        1
    );

    // Boundary 2: Crash during generation compilation
    // Leftover temporary compilation directory .gen.tmp must never be loaded
    let leftover_compilation = root.join(".phase2d7-unified-crashed.tmp");
    fs::create_dir_all(&leftover_compilation).unwrap();
    fs::write(
        leftover_compilation.join("database.rsidb"),
        b"corrupted half-written index",
    )
    .unwrap();

    let (active_db2, _) = private_store::load_timed(root, "current").unwrap();
    assert_eq!(
        active_db2.total_records(),
        1,
        "Interrupted compile does not affect active database"
    );

    // Boundary 3: Crash after compilation & verification but before pointer swap
    // Complete verified generation exists on disk, but pointer was not yet flipped
    let e2 = SignatureEntry::new(
        HashAlgorithm::Sha256,
        200,
        vec![0x22; 32],
        "Threat.New".to_string(),
    );
    let ev_v2 = serde_json::to_vec(&serde_json::json!({"version": "v2.0"})).unwrap();
    let reg2 = UnifiedRegistry {
        version: 1,
        sources: vec![UnifiedSource {
            id: "prov_a".to_string(),
            name: "Mock prov_a".to_string(),
            provider: "Test".to_string(),
            acquisition_method: "test".to_string(),
            acquired_unix_seconds: 2000,
            classification: "test".to_string(),
            provenance: "test".to_string(),
            redistribution: "test".to_string(),
            enabled: true,
            indicator_count: 2,
            evidence_sha256: digest(&ev_v2),
            evidence_file: Some("evidence-prov_a.json".to_string()),
        }],
        total_indicators: 2,
        md5_count: 0,
        sha1_count: 0,
        sha256_count: 2,
    };
    let assoc2 = UnifiedAssociations {
        version: 1,
        total_indicators: 2,
        indicators: vec![
            UnifiedIndicator {
                alg: "sha256".to_string(),
                hash: hex::encode(&e1.digest),
                size: e1.size,
                name: e1.name.clone(),
                claims: vec![UnifiedClaim {
                    source_id: "prov_a".to_string(),
                    size: e1.size,
                    family: e1.name.clone(),
                }],
            },
            UnifiedIndicator {
                alg: "sha256".to_string(),
                hash: hex::encode(&e2.digest),
                size: e2.size,
                name: e2.name.clone(),
                claims: vec![UnifiedClaim {
                    source_id: "prov_a".to_string(),
                    size: e2.size,
                    family: e2.name.clone(),
                }],
            },
        ],
    };
    publish_unified(
        root,
        "gen-verified-unactivated",
        vec![e1, e2],
        reg2,
        assoc2,
        vec![("evidence-prov_a.json".to_string(), ev_v2)],
    )
    .unwrap();

    let (active_db3, _) = private_store::load_timed(root, "current").unwrap();
    assert_eq!(
        active_db3.total_records(),
        1,
        "Scanner strictly respects current pointer; never exposes unactivated generation"
    );

    // Boundary 4: Atomic pointer activation
    // Invariant: pointer write is atomic via temp file + rename; never partial bytes
    write_pointer(root, CURRENT_PTR, "gen-verified-unactivated").unwrap();
    let (active_db4, _) = private_store::load_timed(root, "current").unwrap();
    assert_eq!(
        active_db4.total_records(),
        2,
        "Atomic activation successfully exposes verified generation"
    );

    // Boundary 5: Crash between pointer change and status persistence
    // Pointer changed to gen-verified-unactivated, but update_status.json has old data
    let mut stale_sources = BTreeMap::new();
    stale_sources.insert(
        "prov_a".to_string(),
        SourceStatus {
            id: "prov_a".to_string(),
            source_version: "v1.0".to_string(),
            indicator_count: 1,
            ..Default::default()
        },
    );
    let stale_status = UpdateStatus {
        current_generation: Some("gen-verified-base".to_string()),
        sources: stale_sources,
        ..Default::default()
    };
    stale_status.save(root).unwrap();

    // Process restarts and loads status: it immediately self-heals from active pointer and registry
    let healed = UpdateStatus::load(root);
    assert_eq!(
        healed.current_generation.as_deref(),
        Some("gen-verified-unactivated")
    );
    assert_eq!(healed.sources.get("prov_a").unwrap().indicator_count, 2);
    assert_eq!(healed.sources.get("prov_a").unwrap().active_version, "v2.0");

    // Boundary 6 & 7: Interruption recovery guarantees clean single generation, never mixed
    let clean_load = private_store::load(root, "current");
    assert!(
        clean_load.is_ok(),
        "Active database must always be 100% valid and verified"
    );
}

// ============================================================================
// SCENARIO 22: One failing provider does not block others; old generations pruned
// ============================================================================
#[test]
fn test_22_failing_provider_isolated_and_generations_pruned() {
    let temp = setup_private_root();
    let root = temp.path();

    let kept = SignatureEntry::new(
        HashAlgorithm::Sha256,
        100,
        vec![0x11; 32],
        "Threat.Kept".to_string(),
    );
    create_initial_generation(root, "gen-initial", vec![kept], "src_a");

    let failing = || {
        let mut p = MockProvider::new("src_a");
        p.check_result = Err("HTTP 429 Too Many Requests".to_string());
        p
    };

    // Only a failing provider: the run reports the error and changes nothing.
    let engine = UpdateEngine::new(root).with_provider(Box::new(failing()));
    assert!(engine.apply_update(false).is_err());
    assert_eq!(read_pointer(root, CURRENT_PTR).unwrap(), "gen-initial");

    let mut generations = Vec::new();
    for i in 0..3u8 {
        let fresh = SignatureEntry::new(
            HashAlgorithm::Sha256,
            200 + i as u64,
            vec![0x20 + i; 32],
            format!("Threat.New{i}"),
        );
        let engine = UpdateEngine::new(root)
            .with_provider(Box::new(failing()))
            .with_provider(Box::new(
                MockProvider::new("src_b").with_entries(vec![fresh]),
            ));
        let summary = engine
            .apply_update(true)
            .unwrap()
            .expect("src_b must update");
        assert_eq!(summary.total_indicators, 2);
        generations.push(read_pointer(root, CURRENT_PTR).unwrap());
    }

    let status = UpdateStatus::load(root);
    assert!(status.sources["src_a"].last_error.is_some());
    let (db, _) = private_store::load_timed(root, "current").unwrap();
    assert_eq!(db.total_records(), 2);

    assert!(!root.join("gen-initial").exists());
    assert!(!root.join(&generations[0]).exists());
    assert!(root.join(&generations[1]).exists());
    assert!(root.join(&generations[2]).exists());
    assert_eq!(read_pointer(root, PREVIOUS_PTR).unwrap(), generations[1]);
}
