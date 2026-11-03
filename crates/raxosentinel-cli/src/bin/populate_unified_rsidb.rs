// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! Tool to populate the unified RSIDB database with real malware intelligence:
//! merges existing MalwareBazaar indicators and official ClamAV whole-file hash intelligence.

use raxosentinel_signatures::rsidb::malwarebazaar::private_store::unified::{
    publish_unified, UnifiedAssociations, UnifiedClaim, UnifiedIndicator, UnifiedRegistry,
    UnifiedSource,
};
use raxosentinel_signatures::rsidb::{
    HashAlgorithm, MmapCompactDirIndex, RsidbIndex, SignatureEntry,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

fn get_process_rss_bytes() -> usize {
    if let Ok(content) = fs::read_to_string("/proc/self/status") {
        for line in content.lines() {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<usize>() {
                        return kb * 1024;
                    }
                }
            }
        }
    }
    0
}

fn main() {
    println!("=== RaxoSentinel Phase 2D.6 — Unified RSIDB Population ===");
    let args: Vec<String> = std::env::args().collect();

    let private_root = PathBuf::from(
        args.get(1)
            .cloned()
            .unwrap_or_else(|| "/home/vscode/raxosentinel-private-phase2d1".to_string()),
    );
    let mb_gen_name = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "phase2d4-refreshed-final".to_string());
    let clamav_dir = PathBuf::from(
        args.get(3)
            .cloned()
            .unwrap_or_else(|| "/home/vscode/clamav-unpack".to_string()),
    );
    let out_gen_name = args
        .get(4)
        .cloned()
        .unwrap_or_else(|| "phase2d6-unified".to_string());

    println!("Private root      : {}", private_root.display());
    println!("MalwareBazaar gen : {}", mb_gen_name);
    println!("ClamAV unpack dir : {}", clamav_dir.display());
    println!("Output generation : {}", out_gen_name);

    let start_time = Instant::now();

    // 1. Load ClamAV exclusions (FP and ignored signatures)
    let mut fp_hashes: HashSet<String> = HashSet::new();
    let fp_files = [
        clamav_dir.join("main/main.fp"),
        clamav_dir.join("main/main.sfp"),
        clamav_dir.join("daily/daily.fp"),
        clamav_dir.join("daily/daily.sfp"),
    ];
    for p in &fp_files {
        if p.exists() {
            if let Ok(content) = fs::read_to_string(p) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        let parts: Vec<&str> = trimmed.split(':').collect();
                        if !parts.is_empty() {
                            fp_hashes.insert(parts[0].to_ascii_lowercase());
                        }
                    }
                }
            }
        }
    }

    let mut ign_names: HashSet<String> = HashSet::new();
    let ign_files = [
        clamav_dir.join("daily/daily.ign"),
        clamav_dir.join("daily/daily.ign2"),
    ];
    for p in &ign_files {
        if p.exists() {
            if let Ok(content) = fs::read_to_string(p) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        let parts: Vec<&str> = trimmed.split(':').collect();
                        if parts.len() >= 3 {
                            ign_names.insert(parts[2].to_string());
                        } else {
                            ign_names.insert(parts[0].to_string());
                        }
                    }
                }
            }
        }
    }
    println!(
        "Loaded {} false-positive exclusion hashes and {} ignored signature names.",
        fp_hashes.len(),
        ign_names.len()
    );

    // 2. Count unsupported signature types
    let mut pe_section_hashes = 0usize;
    let mut byte_patterns = 0usize;
    let mut logical_signatures = 0usize;

    for sub in &["main", "daily"] {
        let dir = clamav_dir.join(sub);
        if let Ok(read_dir) = fs::read_dir(&dir) {
            for entry in read_dir.flatten() {
                let path = entry.path();
                let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                if matches!(ext, "mdb" | "msb" | "ndb" | "ndu" | "ldb" | "ldu") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        let count = content
                            .lines()
                            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                            .count();
                        match ext {
                            "mdb" | "msb" => pe_section_hashes += count,
                            "ndb" | "ndu" => byte_patterns += count,
                            "ldb" | "ldu" => logical_signatures += count,
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    println!("ClamAV unsupported signature types examined and rejected:");
    println!("  - PE section hashes (.mdb, .msb) : {}", pe_section_hashes);
    println!("  - Byte patterns     (.ndb, .ndu) : {}", byte_patterns);
    println!(
        "  - Logical signatures (.ldb, .ldu): {}",
        logical_signatures
    );
    let total_unsupported = pe_section_hashes + byte_patterns + logical_signatures;
    println!("  - Total unsupported signatures   : {}", total_unsupported);

    // 3. Ingest supported ClamAV whole-file hash signatures
    let hash_files = [
        clamav_dir.join("main/main.hdb"),
        clamav_dir.join("main/main.hsb"),
        clamav_dir.join("daily/daily.hdb"),
        clamav_dir.join("daily/daily.hsb"),
    ];

    let mut raw_clamav_lines = 0usize;
    let mut wildcard_rejected = 0usize;
    let mut fp_rejected = 0usize;
    let mut ign_rejected = 0usize;
    let mut malformed_rejected = 0usize;
    let mut clamav_duplicates = 0usize;

    let mut seen_clamav_records: HashSet<(HashAlgorithm, Vec<u8>, u64, String)> = HashSet::new();
    let mut clamav_entries: Vec<SignatureEntry> = Vec::with_capacity(600_000);
    let mut clamav_claims: BTreeMap<(HashAlgorithm, Vec<u8>, u64, String), BTreeSet<UnifiedClaim>> =
        BTreeMap::new();

    for file_path in &hash_files {
        println!(
            "Ingesting ClamAV signatures from {}...",
            file_path.display()
        );
        let content = fs::read_to_string(file_path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {e}", file_path.display()));
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            raw_clamav_lines += 1;

            let parts: Vec<&str> = trimmed.split(':').collect();
            if parts.len() != 3 && parts.len() != 4 {
                malformed_rejected += 1;
                continue;
            }

            let hex_digest = parts[0].trim().to_ascii_lowercase();
            let size_str = parts[1].trim();
            let name = parts[2].trim();

            if size_str == "*" || !size_str.chars().all(|c| c.is_ascii_digit()) {
                wildcard_rejected += 1;
                continue;
            }

            let size: u64 = match size_str.parse() {
                Ok(s) => s,
                Err(_) => {
                    malformed_rejected += 1;
                    continue;
                }
            };

            if fp_hashes.contains(&hex_digest) {
                fp_rejected += 1;
                continue;
            }

            if ign_names.contains(name) {
                ign_rejected += 1;
                continue;
            }

            let digest_bytes = match hex::decode(&hex_digest) {
                Ok(b) => b,
                Err(_) => {
                    malformed_rejected += 1;
                    continue;
                }
            };

            let alg = match digest_bytes.len() {
                16 => HashAlgorithm::Md5,
                20 => HashAlgorithm::Sha1,
                32 => HashAlgorithm::Sha256,
                _ => {
                    malformed_rejected += 1;
                    continue;
                }
            };

            let record_key = (alg, digest_bytes.clone(), size, name.to_string());
            let claim = UnifiedClaim {
                source_id: "clamav".to_string(),
                size,
                family: name.to_string(),
            };

            if seen_clamav_records.contains(&record_key) {
                clamav_duplicates += 1;
                if let Some(claims) = clamav_claims.get_mut(&record_key) {
                    claims.insert(claim);
                }
            } else {
                seen_clamav_records.insert(record_key.clone());
                clamav_entries.push(SignatureEntry::new(
                    alg,
                    size,
                    digest_bytes.clone(),
                    name.to_string(),
                ));
                let mut claims = BTreeSet::new();
                claims.insert(claim);
                clamav_claims.insert(record_key, claims);
            }
        }
    }

    let clamav_converted = clamav_entries.len();
    println!("ClamAV Ingestion Complete:");
    println!("  - Raw lines examined       : {}", raw_clamav_lines);
    println!("  - Wildcard sizes rejected  : {}", wildcard_rejected);
    println!("  - False-positives rejected : {}", fp_rejected);
    println!("  - Ignored names rejected   : {}", ign_rejected);
    println!("  - Malformed rejected       : {}", malformed_rejected);
    println!(
        "  - Total rejected           : {}",
        wildcard_rejected + fp_rejected + ign_rejected + malformed_rejected
    );
    println!("  - Duplicates removed       : {}", clamav_duplicates);
    println!("  - Successfully converted   : {}", clamav_converted);

    // 4. Ingest MalwareBazaar 104 genuine indicators
    let mb_gen_dir = private_root.join(&mb_gen_name);
    let mb_assoc_path = mb_gen_dir.join("associations.json");
    let mb_assoc_content = fs::read_to_string(&mb_assoc_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", mb_assoc_path.display()));
    let mb_json: serde_json::Value = serde_json::from_str(&mb_assoc_content).unwrap();

    let indicators_array = mb_json["indicators"].as_array().expect("indicators array");
    println!(
        "Loading existing genuine indicators from MalwareBazaar ({}, {} entries)...",
        mb_assoc_path.display(),
        indicators_array.len()
    );

    let mut mb_entries: Vec<SignatureEntry> = Vec::new();
    let mut mb_claims: BTreeMap<(HashAlgorithm, Vec<u8>, u64, String), BTreeSet<UnifiedClaim>> =
        BTreeMap::new();
    let mut overlap_with_clamav = 0usize;

    for ind in indicators_array {
        let sha256_hex = ind["sha256"].as_str().expect("sha256").to_ascii_lowercase();
        let digest_bytes = hex::decode(&sha256_hex).expect("valid hex");
        let claims_arr = ind["claims"].as_array().expect("claims");
        let first_claim = &claims_arr[0];
        let size = first_claim["size"].as_u64().expect("size");
        let family = first_claim["family"].as_str().unwrap_or("Unknown");
        let detection_name = format!("MalwareBazaar.{}", family);

        let record_key = (
            HashAlgorithm::Sha256,
            digest_bytes.clone(),
            size,
            detection_name.clone(),
        );
        let mut claims_set = BTreeSet::new();
        for c in claims_arr {
            claims_set.insert(UnifiedClaim {
                source_id: "malwarebazaar".to_string(),
                size: c["size"].as_u64().expect("size"),
                family: c["family"].as_str().unwrap_or("Unknown").to_string(),
            });
        }

        if seen_clamav_records.contains(&record_key) {
            overlap_with_clamav += 1;
            if let Some(existing_claims) = clamav_claims.get_mut(&record_key) {
                for c in claims_set {
                    existing_claims.insert(c);
                }
            }
        } else {
            mb_entries.push(SignatureEntry::new(
                HashAlgorithm::Sha256,
                size,
                digest_bytes.clone(),
                detection_name.clone(),
            ));
            mb_claims.insert(record_key, claims_set);
        }
    }
    let previous_real_count = indicators_array.len();
    println!(
        "Preserved {} genuine MalwareBazaar indicators (overlap with ClamAV: {}).",
        previous_real_count, overlap_with_clamav
    );

    // 5. Combine and deduplicate
    let mut combined_entries: Vec<SignatureEntry> =
        Vec::with_capacity(clamav_entries.len() + mb_entries.len());
    combined_entries.extend(clamav_entries);
    combined_entries.extend(mb_entries);

    combined_entries.sort();
    combined_entries.dedup();

    let final_unique_count = combined_entries.len();
    println!(
        "Combined unified entries: {} unique records.",
        final_unique_count
    );

    // Count by algorithm
    let mut md5_count = 0usize;
    let mut sha1_count = 0usize;
    let mut sha256_count = 0usize;
    for entry in &combined_entries {
        match entry.alg {
            HashAlgorithm::Md5 => md5_count += 1,
            HashAlgorithm::Sha1 => sha1_count += 1,
            HashAlgorithm::Sha256 => sha256_count += 1,
        }
    }
    println!("Algorithm Breakdown:");
    println!("  - MD5    : {}", md5_count);
    println!("  - SHA-1  : {}", sha1_count);
    println!("  - SHA-256: {}", sha256_count);

    // 6. Build Unified Associations
    let mut unified_indicators: Vec<UnifiedIndicator> = Vec::with_capacity(final_unique_count);
    for entry in &combined_entries {
        let record_key = (
            entry.alg,
            entry.digest.clone(),
            entry.size,
            entry.name.clone(),
        );
        let claims = if let Some(clam_claims) = clamav_claims.get(&record_key) {
            clam_claims.clone()
        } else if let Some(mb_claims_set) = mb_claims.get(&record_key) {
            mb_claims_set.clone()
        } else {
            let mut s = BTreeSet::new();
            s.insert(UnifiedClaim {
                source_id: "unknown".to_string(),
                size: entry.size,
                family: entry.name.clone(),
            });
            s
        };

        unified_indicators.push(UnifiedIndicator {
            alg: match entry.alg {
                HashAlgorithm::Md5 => "md5".to_string(),
                HashAlgorithm::Sha1 => "sha1".to_string(),
                HashAlgorithm::Sha256 => "sha256".to_string(),
            },
            hash: hex::encode(&entry.digest),
            size: entry.size,
            name: entry.name.clone(),
            claims: claims.into_iter().collect(),
        });
    }

    let unified_associations = UnifiedAssociations {
        version: 1,
        total_indicators: final_unique_count,
        indicators: unified_indicators,
    };

    // 7. Build Evidence Files and Sources
    let acq1_name = "acq-130bdc21a6f9cf66dbce4baf90722d4225ed73606ea4b9c2b94bfc2f08a41777.json";
    let acq2_name = "acq-7009a4d2894c668fe056658b41674308fdeec5a21f315897717eaf1bb4d9175e.json";
    let acq1_bytes = fs::read(mb_gen_dir.join(acq1_name))
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", acq1_name));
    let acq2_bytes = fs::read(mb_gen_dir.join(acq2_name))
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", acq2_name));

    let mb_evidence = serde_json::json!({
        "source": "malwarebazaar",
        "provider": "abuse.ch",
        "api_endpoint": "https://mb-api.abuse.ch/api/v1/",
        "license": "unverified; private research only",
        "acquisitions": [
            {
                "id": "130bdc21a6f9cf66dbce4baf90722d4225ed73606ea4b9c2b94bfc2f08a41777",
                "timestamp": 1793647920u64,
                "evidence_sha256": hex::encode(Sha256::digest(&acq1_bytes))
            },
            {
                "id": "7009a4d2894c668fe056658b41674308fdeec5a21f315897717eaf1bb4d9175e",
                "timestamp": 1793652171u64,
                "evidence_sha256": hex::encode(Sha256::digest(&acq2_bytes))
            }
        ],
        "indicator_count": previous_real_count
    });
    let mb_evidence_bytes = serde_json::to_vec_pretty(&mb_evidence).unwrap();
    let mb_evidence_sha256 = hex::encode(Sha256::digest(&mb_evidence_bytes));

    let clamav_evidence = serde_json::json!({
        "source": "official_clamav_distribution",
        "provider": "Cisco Talos",
        "license": "GPL-2.0-only",
        "redistribution": "unverified; private research only",
        "acquisition_timestamp": 1793725600u64,
        "cvd_files": [
            {
                "file": "main.cvd",
                "version": 63,
                "builder": "tomjudge",
                "sha256": "0b2182d229f46981ec8f535382222f7c9dfdd656b250ad47988b910a8d302365",
                "sigtool_verification": "OK"
            },
            {
                "file": "daily.cvd",
                "version": 28173,
                "builder": "svc.clamav-publisher",
                "sha256": "e1baff030ff150a60c7e76159a350d2bc33acef395a1139f4cac58937ab91e60",
                "sigtool_verification": "OK"
            },
            {
                "file": "bytecode.cvd",
                "version": 339,
                "sha256": "6d4aa01f219e988060fc419f495d07f27e0cdf1a2cccc065971da922c76f7ffb",
                "sigtool_verification": "OK"
            }
        ],
        "input_hash_files": [
            "main/main.hdb", "main/main.hsb", "daily/daily.hdb", "daily/daily.hsb"
        ],
        "raw_hash_lines_examined": raw_clamav_lines,
        "wildcard_rejected": wildcard_rejected,
        "false_positives_rejected": fp_rejected,
        "ignored_names_rejected": ign_rejected,
        "malformed_rejected": malformed_rejected,
        "duplicates_removed": clamav_duplicates,
        "converted_records": clamav_converted,
        "unsupported_pe_section_hashes": pe_section_hashes,
        "unsupported_byte_patterns": byte_patterns,
        "unsupported_logical_signatures": logical_signatures
    });
    let clamav_evidence_bytes = serde_json::to_vec_pretty(&clamav_evidence).unwrap();
    let clamav_evidence_sha256 = hex::encode(Sha256::digest(&clamav_evidence_bytes));

    let unified_registry = UnifiedRegistry {
        version: 1,
        sources: vec![
            UnifiedSource {
                id: "malwarebazaar".to_string(),
                name: "MalwareBazaar".to_string(),
                provider: "abuse.ch".to_string(),
                acquisition_method: "https://mb-api.abuse.ch/api/v1/".to_string(),
                acquired_unix_seconds: 1793652171,
                classification: "private research intelligence".to_string(),
                provenance: "locally consistent evidence; no provider signature".to_string(),
                redistribution: "unverified; private research only".to_string(),
                enabled: true,
                indicator_count: previous_real_count,
                evidence_sha256: mb_evidence_sha256,
                evidence_file: Some("evidence-malwarebazaar.json".to_string()),
            },
            UnifiedSource {
                id: "clamav".to_string(),
                name: "ClamAV".to_string(),
                provider: "Cisco Talos".to_string(),
                acquisition_method: "official_cvd_distribution".to_string(),
                acquired_unix_seconds: 1793725600,
                classification: "official antivirus signature feed".to_string(),
                provenance: "CVD digital signature verified; official sigtool extraction"
                    .to_string(),
                redistribution: "unverified; private research only (GPL-2.0-only)".to_string(),
                enabled: true,
                indicator_count: clamav_converted,
                evidence_sha256: clamav_evidence_sha256,
                evidence_file: Some("evidence-clamav.json".to_string()),
            },
        ],
        total_indicators: final_unique_count,
        md5_count,
        sha1_count,
        sha256_count,
    };

    let evidence_files = vec![
        ("evidence-malwarebazaar.json".to_string(), mb_evidence_bytes),
        (acq1_name.to_string(), acq1_bytes),
        (acq2_name.to_string(), acq2_bytes),
        ("evidence-clamav.json".to_string(), clamav_evidence_bytes),
    ];

    // 8. Publish the Unified Generation atomically
    println!(
        "Compiling and publishing unified generation '{}'...",
        out_gen_name
    );
    let pub_start = Instant::now();
    publish_unified(
        &private_root,
        &out_gen_name,
        combined_entries,
        unified_registry,
        unified_associations,
        evidence_files,
    )
    .unwrap_or_else(|e| panic!("Failed to publish unified generation: {e}"));
    println!(
        "Generation published successfully in {:.2}s.",
        pub_start.elapsed().as_secs_f64()
    );

    // 9. Benchmark & Verification
    let gen_dir = private_root.join(&out_gen_name);
    let db_path = gen_dir.join("database.rsidb");
    let db_metadata = fs::metadata(&db_path).expect("database metadata");
    let db_file_size = db_metadata.len();
    println!(
        "Unified RSIDB file size: {} bytes ({:.2} MB)",
        db_file_size,
        db_file_size as f64 / (1024.0 * 1024.0)
    );

    // RSS before loading
    let rss_before = get_process_rss_bytes();

    // Load timings
    let t_load = Instant::now();
    let index = MmapCompactDirIndex::from_file(&db_path)
        .unwrap_or_else(|e| panic!("Failed to load database: {e}"));
    let load_time_ms = t_load.elapsed().as_secs_f64() * 1000.0;

    // Verify verification through private_store::load
    println!("Verifying via private_store::load...");
    let t_verify = Instant::now();
    let (_sorted_index, timings) =
        raxosentinel_signatures::rsidb::malwarebazaar::private_store::load_timed(
            &private_root,
            &out_gen_name,
        )
        .expect("private_store::load_timed verification");
    let verify_time_ms = t_verify.elapsed().as_secs_f64() * 1000.0;
    println!(
        "Verification PASS: db_ms={:.2}, evidence_ms={:.2}, total_verify_ms={:.2}",
        timings.database.as_secs_f64() * 1000.0,
        timings.evidence.as_secs_f64() * 1000.0,
        verify_time_ms
    );

    // Test known MalwareBazaar test hashes
    println!("Testing known MalwareBazaar indicators...");
    let test_mb_hash = "01115ec4c22e47143b098212dcbaf18f7c5c22f072d2f8f67d8cf73e63b3e931";
    let test_mb_digest = hex::decode(test_mb_hash).unwrap();
    let mb_matches = index.lookup(HashAlgorithm::Sha256, 162732, &test_mb_digest);
    println!("  MB Lookup {}: matches={:?}", test_mb_hash, mb_matches);
    assert!(
        !mb_matches.is_empty(),
        "MalwareBazaar test hash must be detected"
    );

    // Test known ClamAV test hashes (EICAR MD5, SHA256)
    println!("Testing known ClamAV test hashes...");
    let eicar_md5 = "44d88612fea8a8f36de82e1278abb02f";
    let eicar_md5_digest = hex::decode(eicar_md5).unwrap();
    let eicar_md5_matches = index.lookup(HashAlgorithm::Md5, 68, &eicar_md5_digest);
    println!("  ClamAV EICAR MD5: matches={:?}", eicar_md5_matches);
    assert!(!eicar_md5_matches.is_empty(), "EICAR MD5 must be detected");

    let eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    let eicar_sha256_digest = hex::decode(eicar_sha256).unwrap();
    let eicar_sha256_matches = index.lookup(HashAlgorithm::Sha256, 68, &eicar_sha256_digest);
    println!("  ClamAV EICAR SHA256: matches={:?}", eicar_sha256_matches);
    assert!(
        !eicar_sha256_matches.is_empty(),
        "EICAR SHA256 must be detected"
    );

    // Test known ClamAV real malware MD5 hash
    let gaobot_md5 = "073f4d8002652bc1b303c50412e851e8";
    let gaobot_digest = hex::decode(gaobot_md5).unwrap();
    let gaobot_matches = index.lookup(HashAlgorithm::Md5, 139264, &gaobot_digest);
    println!(
        "  ClamAV Real Win.Worm.Gaobot-308: matches={:?}",
        gaobot_matches
    );
    assert!(
        !gaobot_matches.is_empty(),
        "Win.Worm.Gaobot-308 must be detected"
    );

    // Test known ClamAV SHA-1 hash
    let keylogger_sha1 = "0059ee2322c3301263c8006fd780d7fe95a30572";
    let keylogger_digest = hex::decode(keylogger_sha1).unwrap();
    let keylogger_matches = index.lookup(HashAlgorithm::Sha1, 1705472, &keylogger_digest);
    println!(
        "  ClamAV Real Win.Keylogger.Generic-7604980-0 SHA1: matches={:?}",
        keylogger_matches
    );
    assert!(
        !keylogger_matches.is_empty(),
        "Win.Keylogger.Generic-7604980-0 SHA1 must be detected"
    );

    // Test clean non-malicious file
    println!("Testing non-malicious input...");
    let clean_data = b"Hello, this is a completely harmless and benign text file for testing!";
    let clean_sha256 = Sha256::digest(clean_data);
    let clean_matches = index.lookup(
        HashAlgorithm::Sha256,
        clean_data.len() as u64,
        &clean_sha256,
    );
    println!("  Clean file lookup matches: {:?}", clean_matches);
    assert!(
        clean_matches.is_empty(),
        "Clean file must NOT match any threat"
    );

    // Lookup performance benchmark (100,000 queries)
    let num_queries = 100_000usize;
    println!(
        "Running lookup throughput benchmark ({} queries)...",
        num_queries
    );
    let mut latencies_ns = Vec::with_capacity(num_queries);
    let t_bench = Instant::now();

    for i in 0..num_queries {
        let q_start = Instant::now();
        if i % 2 == 0 {
            // Hit query
            let _ = index.lookup(HashAlgorithm::Md5, 139264, &gaobot_digest);
        } else {
            // Miss query
            let dummy = [(i & 0xff) as u8; 16];
            let _ = index.lookup(HashAlgorithm::Md5, 12345, &dummy);
        }
        latencies_ns.push(q_start.elapsed().as_nanos() as u64);
    }
    let total_bench_duration = t_bench.elapsed();
    let qps = num_queries as f64 / total_bench_duration.as_secs_f64();

    latencies_ns.sort_unstable();
    let p50 = latencies_ns[num_queries * 50 / 100];
    let p95 = latencies_ns[num_queries * 95 / 100];
    let p99 = latencies_ns[num_queries * 99 / 100];

    let rss_final = get_process_rss_bytes();
    let delta_rss_mb = (rss_final.saturating_sub(rss_before)) as f64 / (1024.0 * 1024.0);

    println!("\n=== BENCHMARK RESULTS ===");
    println!(
        "Total execution time  : {:.2}s",
        start_time.elapsed().as_secs_f64()
    );
    println!(
        "Database file size    : {} bytes ({:.2} MB)",
        db_file_size,
        db_file_size as f64 / (1024.0 * 1024.0)
    );
    println!("Initial load time     : {:.2} ms", load_time_ms);
    println!("Strict verify time    : {:.2} ms", verify_time_ms);
    println!("Lookup throughput     : {:.0} queries/sec", qps);
    println!(
        "p50 lookup latency    : {} ns ({:.3} µs)",
        p50,
        p50 as f64 / 1000.0
    );
    println!(
        "p95 lookup latency    : {} ns ({:.3} µs)",
        p95,
        p95 as f64 / 1000.0
    );
    println!(
        "p99 lookup latency    : {} ns ({:.3} µs)",
        p99,
        p99 as f64 / 1000.0
    );
    println!(
        "RSS before load       : {:.2} MB",
        rss_before as f64 / (1024.0 * 1024.0)
    );
    println!(
        "RSS after warm load   : {:.2} MB",
        rss_final as f64 / (1024.0 * 1024.0)
    );
    println!("Delta memory (RSS)    : {:.2} MB", delta_rss_mb);
    println!("=========================\n");
}
