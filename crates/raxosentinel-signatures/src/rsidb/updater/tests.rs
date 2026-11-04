// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! Comprehensive tests verifying all 13 mandatory failure and success scenarios for Phase 2D.7.

use super::*;
use crate::rsidb::malwarebazaar::private_store::unified::{
    publish_unified, UnifiedAssociations, UnifiedClaim, UnifiedIndicator, UnifiedRegistry,
    UnifiedSource,
};
use crate::rsidb::malwarebazaar::private_store::{self, multi::digest};
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
    let ev_bytes = b"initial test evidence".to_vec();
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
