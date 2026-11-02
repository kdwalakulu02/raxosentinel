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

use raxosentinel_core::{ResourceLimits, ResourceTracker, ScanStatus, ThreatCategory};
use raxosentinel_email::EmailScanner;
use raxosentinel_filetypes::{detect_file_type, detect_type, FileCategory};
use raxosentinel_signatures::rsidb::crypto;
use raxosentinel_signatures::rsidb::ingest::{
    BuildProfile, IndicatorFormat, IngestPipeline, Redistribution, SourceKind, SourceManifest,
};
use raxosentinel_signatures::rsidb::lifecycle::DbStore;
use raxosentinel_signatures::rsidb::{
    DatabaseError, HashAlgorithm, MmapCompactDirIndex, RsidbCompiler, RsidbIndex, SignatureEntry,
};
use raxosentinel_signatures::SignatureDatabase;
use sha2::Digest;
use std::io::Write;
use std::sync::Arc;
use tempfile::NamedTempFile;

#[test]
fn test_valid_file_headers_detection() {
    // 1. Valid PDF header
    let pdf_header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n";
    let ft_pdf = detect_type(pdf_header);
    assert_eq!(ft_pdf.mime_type, "application/pdf");
    assert_eq!(ft_pdf.category, FileCategory::Document);

    // 2. Valid ELF header
    let elf_header = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00";
    let ft_elf = detect_type(elf_header);
    assert_eq!(ft_elf.mime_type, "application/x-executable");
    assert!(ft_elf.is_executable);

    // 3. Valid GZIP header
    let gzip_header = b"\x1f\x8b\x08\x00\x00\x00\x00\x00";
    let ft_gzip = detect_type(gzip_header);
    assert_eq!(ft_gzip.mime_type, "application/gzip");
    assert!(ft_gzip.is_archive);

    // 4. Valid PNG header
    let png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
    let ft_png = detect_type(png_header);
    assert_eq!(ft_png.mime_type, "image/png");
}

#[test]
fn test_invalid_and_truncated_file_headers() {
    // Truncated PE header: MZ only with no PE offset
    let truncated_mz = b"MZ";
    let ft = detect_type(truncated_mz);
    assert_eq!(ft.mime_type, "application/x-dosexec");

    // Random noise header
    let random_noise = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22";
    let ft_noise = detect_type(random_noise);
    assert_eq!(ft_noise.category, FileCategory::Unknown);
    assert_eq!(ft_noise.mime_type, "application/octet-stream");

    // Truncated ELF header (only 2 bytes)
    let truncated_elf = b"\x7fE";
    let ft_trunc = detect_type(truncated_elf);
    assert_eq!(ft_trunc.category, FileCategory::Unknown);
}

#[test]
fn test_empty_and_truncated_files() {
    // 1. Completely empty file
    let mut empty_file = NamedTempFile::new().unwrap();
    empty_file.flush().unwrap();

    let ft = detect_file_type(empty_file.path()).unwrap();
    assert_eq!(ft.mime_type, "application/x-empty");

    // 2. 1-byte file
    let mut one_byte_file = NamedTempFile::new().unwrap();
    one_byte_file.write_all(b"A").unwrap();
    one_byte_file.flush().unwrap();

    let ft_one = detect_file_type(one_byte_file.path()).unwrap();
    assert_eq!(ft_one.mime_type, "text/plain");
}

#[test]
fn test_malformed_mime_messages() {
    let db = SignatureDatabase::with_defaults();
    let scanner = EmailScanner::new(&db);
    let limits = ResourceLimits::default();

    // 1. Missing header separator and incomplete lines
    let malformed_1 = b"From: user@test.com\r\nSubject: Truncated";
    let mut tracker1 = ResourceTracker::new(limits.clone());
    let report1 = scanner
        .scan_bytes(malformed_1, Some("malformed1.eml"), &mut tracker1)
        .unwrap();
    assert!(report1.status.is_clean() || report1.status.is_unsupported());

    // 2. Broken boundary in multipart
    let malformed_boundary = b"MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"EXPECTED_BOUNDARY\"\r\n\
\r\n\
--WRONG_BOUNDARY\r\n\
Content-Type: text/plain\r\n\
\r\n\
Content without proper closure";
    let mut tracker2 = ResourceTracker::new(limits.clone());
    let report2 = scanner
        .scan_bytes(malformed_boundary, Some("broken_bound.eml"), &mut tracker2)
        .unwrap();
    // Must complete safely without panic
    assert!(report2.status.is_clean() || report2.status.is_unsupported());

    // 3. Null bytes injected in MIME headers
    let null_injected =
        b"From: attacker\0@evil.com\r\nSubject: Test\r\n\r\nBody text\0with null bytes";
    let mut tracker3 = ResourceTracker::new(limits);
    let report3 = scanner
        .scan_bytes(null_injected, Some("nulls.eml"), &mut tracker3)
        .unwrap();
    assert!(report3.status.is_clean() || report3.status.is_unsupported());
}

#[test]
fn test_synthetic_signature_matching() {
    let db = SignatureDatabase::with_defaults();
    let limits = ResourceLimits::default();
    let mut tracker = ResourceTracker::new(limits);

    let synthetic_content = b"Prefix data [RAXOSENTINEL-SYNTHETIC-TEST-SIGNATURE] suffix data";
    let mut cursor = std::io::Cursor::new(synthetic_content);
    let threats = db.match_stream(&mut cursor, &mut tracker).unwrap();

    assert_eq!(threats.len(), 1);
    assert_eq!(threats[0].name, "Test.Synthetic.BytePattern");
    assert_eq!(threats[0].category, ThreatCategory::TestSignature);
}

#[test]
fn test_eicar_antivirus_test_string_detection() {
    let db = SignatureDatabase::with_defaults();
    let limits = ResourceLimits::default();
    let mut tracker = ResourceTracker::new(limits);

    // Exact standard EICAR string
    let eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let mut cursor = std::io::Cursor::new(eicar_bytes);
    let threats = db.match_stream(&mut cursor, &mut tracker).unwrap();

    assert_eq!(threats.len(), 1);
    assert_eq!(threats[0].name, "EICAR-Standard-Antivirus-Test-File");
}

#[test]
fn test_file_size_enforcement_aborts_early() {
    let limits = ResourceLimits {
        max_file_size: 1024, // 1 KiB
        ..Default::default()
    };
    let tracker = ResourceTracker::new(limits);

    // Attempting to check a 5 KiB file
    let check_result = tracker.check_file_size(5120);
    assert!(check_result.is_err());
}

const EICAR_BYTES: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const EICAR_MD5_HEX: &str = "44d88612fea8a8f36de82e1278abb02f";
const EICAR_SHA256_HEX: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

fn make_eicar_test_rsidb() -> Vec<u8> {
    let md5 = hex::decode(EICAR_MD5_HEX).unwrap();
    let sha256 = hex::decode(EICAR_SHA256_HEX).unwrap();
    let entries = vec![
        SignatureEntry::new(HashAlgorithm::Md5, 68, md5, "EICAR-RSIDB-MD5-Match"),
        SignatureEntry::new(
            HashAlgorithm::Sha256,
            68,
            sha256,
            "EICAR-RSIDB-SHA256-Match",
        ),
    ];
    RsidbCompiler::new()
        .with_provenance("RaxoSentinel E2E Test Suite")
        .compile(entries)
        .expect("compile RSIDB")
}

fn create_test_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, data) in entries {
            zip.start_file(*name, options).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap();
    }
    cursor.into_inner()
}

#[test]
fn test_e2e_scenario_1_and_2_ingest_pipeline_and_verification() {
    let mut pipeline = IngestPipeline::new(BuildProfile::Public);
    pipeline.authorize_source("approved-harmless-feed");
    let manifest = SourceManifest {
        id: "approved-harmless-feed".into(),
        name: "Harmless Threat Intelligence Feed".into(),
        origin: "https://example.com/indicators".into(),
        version: "2026.11.02".into(),
        acquired_at: "2026-11-02T00:00:00Z".into(),
        license: "GPL-2.0-or-later".into(),
        redistribution: Redistribution::Allowed,
        attribution: None,
        approved: true,
        kind: SourceKind::SyntheticTest,
        format: IndicatorFormat::HashSizeName,
        path: "feed.hdb".into(),
        sha256: None,
    };

    let content = format!(
        "# Valid indicators\n{}:68:EICAR-RSIDB-MD5-Match\n{}:68:EICAR-RSIDB-SHA256-Match\n",
        EICAR_MD5_HEX, EICAR_SHA256_HEX
    );

    let report = pipeline
        .add_source(manifest, content.as_bytes())
        .expect("ingest source");
    assert_eq!(report.accepted, 2);
    assert_eq!(report.rejected, 0);

    let (bytes, build_manifest) = pipeline
        .build("2026.11.02.1", "2026-11-02T00:00:00Z")
        .expect("build RSIDB");
    assert_eq!(build_manifest.records_md5, 1);
    assert_eq!(build_manifest.records_sha256, 1);
    assert_eq!(build_manifest.total_accepted, 2);

    let index = MmapCompactDirIndex::from_bytes(bytes).expect("verify database");
    assert_eq!(index.record_count(HashAlgorithm::Md5), 1);
    assert_eq!(index.record_count(HashAlgorithm::Sha256), 1);
    assert_eq!(index.name_count(), 2);
}

#[test]
fn test_e2e_scenario_3_and_4_rsidb_detects_eicar_in_raw_file() {
    let rsidb_bytes = make_eicar_test_rsidb();
    let index = MmapCompactDirIndex::from_bytes(rsidb_bytes).expect("load RSIDB");

    // Empty database without builtin rules: detection must come from RSIDB!
    let mut db = SignatureDatabase::new();
    db.attach_rsidb(Arc::new(index));

    let scanner = EmailScanner::new(&db);
    let mut tracker = ResourceTracker::new(ResourceLimits::default());

    let mut temp = NamedTempFile::new().unwrap();
    temp.write_all(EICAR_BYTES).unwrap();
    temp.flush().unwrap();

    let report = scanner
        .scan_file(temp.path(), &mut tracker)
        .expect("scan file");
    assert_eq!(report.status, ScanStatus::Infected);
    assert!(!report.threats.is_empty());
    assert!(report
        .threats
        .iter()
        .any(|t| t.matched_by.contains("rsidb")));
}

#[test]
fn test_e2e_scenario_5_rsidb_detects_eicar_in_base64_mime_attachment() {
    let rsidb_bytes = make_eicar_test_rsidb();
    let index = MmapCompactDirIndex::from_bytes(rsidb_bytes).expect("load RSIDB");

    let mut db = SignatureDatabase::new();
    db.attach_rsidb(Arc::new(index));
    let scanner = EmailScanner::new(&db);
    let mut tracker = ResourceTracker::new(ResourceLimits::default());

    let b64_eicar = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=";
    let email = format!(
        "From: test@example.com\r\n\
         To: recipient@example.com\r\n\
         Subject: Test with EICAR attachment\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"BOUNDARY-12345\"\r\n\
         \r\n\
         --BOUNDARY-12345\r\n\
         Content-Type: text/plain\r\n\
         \r\n\
         Please inspect the attached payload.\r\n\
         --BOUNDARY-12345\r\n\
         Content-Type: application/octet-stream; name=\"payload.com\"\r\n\
         Content-Disposition: attachment; filename=\"payload.com\"\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {}\r\n\
         --BOUNDARY-12345--\r\n",
        b64_eicar
    );

    let report = scanner
        .scan_bytes(email.as_bytes(), Some("email_eicar.eml"), &mut tracker)
        .expect("scan email");
    assert_eq!(report.status, ScanStatus::Infected);
    assert_eq!(report.sub_targets.len(), 1);
    assert_eq!(report.sub_targets[0].status, ScanStatus::Infected);
    assert!(report.threats.iter().any(|t| t.name.contains("EICAR-RSIDB")
        && t.location.as_deref().unwrap_or("").contains("payload.com")));
}

#[test]
fn test_e2e_scenario_6_rsidb_detects_eicar_inside_zip_attachment() {
    let rsidb_bytes = make_eicar_test_rsidb();
    let index = MmapCompactDirIndex::from_bytes(rsidb_bytes).expect("load RSIDB");

    let mut db = SignatureDatabase::new();
    db.attach_rsidb(Arc::new(index));
    let scanner = EmailScanner::new(&db);
    let mut tracker = ResourceTracker::new(ResourceLimits::default());

    let zip_bytes = create_test_zip(&[("harmless_eicar.txt", EICAR_BYTES)]);

    let report = scanner
        .scan_object(&zip_bytes, "archive.zip", None, &mut tracker, 0)
        .expect("scan zip");
    assert_eq!(report.status, ScanStatus::Infected);
    assert_eq!(report.sub_targets.len(), 1);
    assert_eq!(report.sub_targets[0].status, ScanStatus::Infected);
    assert!(report
        .threats
        .iter()
        .any(|t| t.name.contains("EICAR-RSIDB")));
}

#[test]
fn test_e2e_scenario_7_corrupt_database_rejection_no_silent_fallback() {
    let rsidb_bytes = make_eicar_test_rsidb();

    // 1. Truncated database rejected
    let truncated = &rsidb_bytes[..40];
    assert!(matches!(
        MmapCompactDirIndex::from_bytes(truncated.to_vec()),
        Err(DatabaseError::TruncatedHeader(..))
    ));

    // 2. Corrupted checksum rejected
    let mut corrupt = rsidb_bytes.clone();
    let n = corrupt.len();
    corrupt[n - 1] ^= 0xff;
    assert!(matches!(
        MmapCompactDirIndex::from_bytes(corrupt),
        Err(DatabaseError::CorruptedChecksum(..))
    ));

    // 3. Invalid magic rejected
    let mut bad_magic = rsidb_bytes;
    bad_magic[0..8].copy_from_slice(b"BADMAGIC");
    assert!(matches!(
        MmapCompactDirIndex::from_bytes(bad_magic),
        Err(DatabaseError::InvalidMagic(..))
    ));
}

#[test]
fn test_e2e_scenario_8_unsupported_or_encrypted_archive_verdict() {
    let db = SignatureDatabase::new();
    let scanner = EmailScanner::new(&db);
    let mut tracker = ResourceTracker::new(ResourceLimits::default());

    // 1. Encrypted ZIP member (bit 0 of general purpose flag set to 1 in local & central headers)
    let mut zip_bytes = create_test_zip(&[("secret.txt", b"secret data")]);
    let len = zip_bytes.len();
    for i in 0..len.saturating_sub(10) {
        if &zip_bytes[i..i + 4] == b"PK\x03\x04" {
            zip_bytes[i + 6] |= 0x01;
        } else if &zip_bytes[i..i + 4] == b"PK\x01\x02" {
            zip_bytes[i + 8] |= 0x01;
        }
    }
    let report = scanner
        .scan_object(&zip_bytes, "protected.zip", None, &mut tracker, 0)
        .expect("scan encrypted zip");
    assert_eq!(report.status, ScanStatus::Unsupported);
    assert!(
        report
            .error
            .as_deref()
            .unwrap_or("")
            .contains("Encrypted ZIP member")
            || report.status_description.contains("unsupported")
    );

    // 2. Unsupported archive container (RAR signature)
    let rar_header = b"Rar!\x1a\x07\x00\xcf\x90\x73";
    let report_rar = scanner
        .scan_object(rar_header, "sample.rar", None, &mut tracker, 0)
        .expect("scan rar container");
    assert_eq!(report_rar.status, ScanStatus::Unsupported);
}

#[test]
fn test_e2e_scenario_9_enforce_zip_limits() {
    let db = SignatureDatabase::new();
    let scanner = EmailScanner::new(&db);

    // 1. Enforce max entries limit (35 entries > default 30)
    let entries: Vec<(String, Vec<u8>)> = (0..35)
        .map(|i| (format!("file_{}.txt", i), b"content".to_vec()))
        .collect();
    let entry_refs: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    let zip_many = create_test_zip(&entry_refs);

    let mut tracker = ResourceTracker::new(ResourceLimits::default());
    let report = scanner
        .scan_object(&zip_many, "bomb.zip", None, &mut tracker, 0)
        .expect("scan entry count bomb");
    assert_eq!(report.status, ScanStatus::Failed);
    assert!(report.error.as_deref().unwrap_or("").contains("limit 30"));

    // 2. Enforce attachment size limit on single extracted member
    let tight_limits = ResourceLimits {
        max_email_attachment_size: 100, // 100 bytes max
        ..Default::default()
    };
    let mut tight_tracker = ResourceTracker::new(tight_limits);
    let large_member = vec![b'A'; 200];
    let zip_large = create_test_zip(&[("large.txt", &large_member)]);
    let report_large = scanner
        .scan_object(&zip_large, "large.zip", None, &mut tight_tracker, 0)
        .expect("scan oversized member");
    assert_eq!(report_large.status, ScanStatus::Failed);
}

#[test]
fn test_e2e_scenario_10_reject_manifest_directory_traversal() {
    let base = std::path::Path::new("/workspace/project/sources");

    let test_cases = [
        "../../etc/passwd",
        "/etc/shadow",
        "nested/../../escape",
        "../sibling/file.hdb",
    ];

    for bad_path in test_cases {
        let manifest = SourceManifest {
            id: "traversal-test".into(),
            name: "Traversal Test".into(),
            origin: "test".into(),
            version: "1.0".into(),
            acquired_at: "2026-11-02T00:00:00Z".into(),
            license: "GPL-2.0-or-later".into(),
            redistribution: Redistribution::Allowed,
            attribution: None,
            approved: true,
            kind: SourceKind::SyntheticTest,
            format: IndicatorFormat::HashSizeName,
            path: bad_path.into(),
            sha256: None,
        };

        let res = manifest.resolve_path(base);
        assert!(
            res.is_err(),
            "Path '{}' should have been rejected as directory traversal",
            bad_path
        );
        match res {
            Err(DatabaseError::Policy(msg)) => {
                assert!(
                    msg.contains("traversal") || msg.contains("relative") || msg.contains("escape")
                );
            }
            other => panic!("Unexpected error type for '{}': {:?}", bad_path, other),
        }
    }
}

#[test]
fn test_e2e_scenario_11_dbstore_install_rollback_and_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let store = DbStore::new(dir.path().join("store"));

    let db_v1 = make_eicar_test_rsidb();
    let db_v2 = {
        let md5 = hex::decode("0123456789abcdef0123456789abcdef").unwrap();
        let entries = vec![SignatureEntry::new(
            HashAlgorithm::Md5,
            10,
            md5,
            "Custom-Test-Signature-V2",
        )];
        RsidbCompiler::new().compile(entries).unwrap()
    };

    let p1 = dir.path().join("v1.rsidb");
    let p2 = dir.path().join("v2.rsidb");
    std::fs::write(&p1, &db_v1).unwrap();
    std::fs::write(&p2, &db_v2).unwrap();

    // 1. Install V1
    let r1 = store.install(&p1, None).expect("install v1");
    assert_eq!(store.current_release().unwrap(), r1);

    // 2. Install V2
    let r2 = store.install(&p2, None).expect("install v2");
    assert_eq!(store.current_release().unwrap(), r2);
    assert_eq!(store.previous_release().unwrap(), r1);

    // 3. Rollback to V1
    let rolled = store.rollback().expect("rollback to v1");
    assert_eq!(rolled, r1);
    assert_eq!(store.current_release().unwrap(), r1);
    assert_eq!(store.previous_release().unwrap(), r2);

    // Roll back to V2 again
    store.rollback().expect("rollback to v2");

    // 4. Corrupt active release on disk -> open_active() falls back to previous (V1)
    let active_path = store.release_path(&r2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&active_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let mut corrupt = std::fs::read(&active_path).unwrap();
    let len = corrupt.len();
    corrupt[len - 1] ^= 0xff;
    std::fs::write(&active_path, corrupt).unwrap();

    let active = store.open_active().expect("open active with fallback");
    assert!(active.fell_back);
    assert_eq!(active.release, r1);
}

#[test]
fn test_e2e_scenario_12_backward_compatibility_clean_and_defaults() {
    let mut db_with_rsidb = SignatureDatabase::with_defaults();
    let rsidb_bytes = make_eicar_test_rsidb();
    let index = MmapCompactDirIndex::from_bytes(rsidb_bytes).expect("load RSIDB");
    db_with_rsidb.attach_rsidb(Arc::new(index));

    let scanner_with_rsidb = EmailScanner::new(&db_with_rsidb);
    let mut tracker = ResourceTracker::new(ResourceLimits::default());

    // 1. Clean file reports Clean
    let clean_data = b"Hello, world! This is a completely benign text file.";
    let report_clean = scanner_with_rsidb
        .scan_object(clean_data, "clean.txt", None, &mut tracker, 0)
        .expect("scan clean");
    assert_eq!(report_clean.status, ScanStatus::Clean);
    assert!(report_clean.threats.is_empty());

    // 2. Default scanner without RSIDB detects built-in EICAR
    let db_default = SignatureDatabase::with_defaults();
    let scanner_default = EmailScanner::new(&db_default);
    let mut tracker2 = ResourceTracker::new(ResourceLimits::default());
    let report_eicar = scanner_default
        .scan_object(EICAR_BYTES, "eicar.com", None, &mut tracker2, 0)
        .expect("scan eicar with defaults");
    assert_eq!(report_eicar.status, ScanStatus::Infected);
}

fn make_test_tar_archive(name: &str, content: &[u8]) -> Vec<u8> {
    let mut tar = vec![0u8; 512];
    let name_bytes = name.as_bytes();
    tar[..name_bytes.len()].copy_from_slice(name_bytes);
    tar[100..108].copy_from_slice(b"0000644\0");
    tar[108..116].copy_from_slice(b"0000000\0");
    tar[116..124].copy_from_slice(b"0000000\0");
    let size_str = format!("{:011o}\0", content.len());
    tar[124..136].copy_from_slice(size_str.as_bytes());
    tar[136..148].copy_from_slice(b"00000000000\0");
    tar[156] = b'0';
    tar[257..263].copy_from_slice(b"ustar\0");
    tar[263..265].copy_from_slice(b"00");
    tar[148..156].copy_from_slice(b"        ");
    let chksum: u32 = tar.iter().map(|&b| b as u32).sum();
    let chksum_str = format!("{:06o}\0 ", chksum);
    tar[148..156].copy_from_slice(chksum_str.as_bytes());

    tar.extend_from_slice(content);
    let pad = (512 - (content.len() % 512)) % 512;
    tar.extend(vec![0u8; pad]);
    tar.extend(vec![0u8; 1024]);
    tar
}

#[test]
fn test_e2e_scenario_13_signed_release_verification_and_tamper_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let store = DbStore::new(dir.path().join("store"));

    // 1. Generate release signing keypair
    let (signing_key, verifying_key) = crypto::generate_keypair();
    let pubkey_file = dir.path().join("trusted.pub");
    crypto::save_verifying_key_to_file(&verifying_key, &pubkey_file).unwrap();

    // 2. Build release with verified test indicators
    let mut pipeline = IngestPipeline::new(BuildProfile::Public);
    pipeline.authorize_source("release-test-source");
    let manifest_src = SourceManifest {
        id: "release-test-source".into(),
        name: "Release Test Feed".into(),
        origin: "https://example.com/feed".into(),
        version: "2026.11.02".into(),
        acquired_at: "2026-11-02T00:00:00Z".into(),
        license: "CC0-1.0".into(),
        redistribution: Redistribution::Allowed,
        attribution: None,
        approved: true,
        kind: SourceKind::SyntheticTest,
        format: IndicatorFormat::HashSizeName,
        path: "feed.hdb".into(),
        sha256: None,
    };
    let feed_content = format!("{}:68:Test.Threat.HashMatch\n", EICAR_SHA256_HEX);
    pipeline
        .add_source(manifest_src, feed_content.as_bytes())
        .unwrap();

    let (db_bytes, build_manifest) = pipeline
        .build("2026.11.02.1", "2026-11-02T00:00:00Z")
        .unwrap();
    assert_eq!(build_manifest.genuine_records, 0);
    assert_eq!(build_manifest.synthetic_records, 1);

    let db_path = dir.path().join("release.rsidb");
    let manifest_path = dir.path().join("release.manifest.json");
    let sig_path = dir.path().join("release.sig");

    std::fs::write(&db_path, &db_bytes).unwrap();
    let manifest_json = serde_json::to_string_pretty(&build_manifest).unwrap();
    std::fs::write(&manifest_path, &manifest_json).unwrap();

    // Sign manifest bytes
    let sig = crypto::sign_bytes(manifest_json.as_bytes(), &signing_key);
    crypto::save_signature_to_file(&sig, &sig_path).unwrap();

    // 3. Install valid signed release
    let activated = store
        .install_release(
            &db_path,
            Some(&manifest_path),
            Some(&sig_path),
            Some(&verifying_key),
            false,
        )
        .expect("valid signed release installs");
    assert_eq!(store.current_release().unwrap(), activated);

    // 4. Tampered database content is rejected
    let tampered_db_path = dir.path().join("tampered.rsidb");
    let mut tampered_bytes = db_bytes.clone();
    let len = tampered_bytes.len();
    tampered_bytes[len - 5] ^= 0x55;
    std::fs::write(&tampered_db_path, &tampered_bytes).unwrap();

    let res_tampered_db = store.install_release(
        &tampered_db_path,
        Some(&manifest_path),
        Some(&sig_path),
        Some(&verifying_key),
        false,
    );
    assert!(
        res_tampered_db.is_err(),
        "Tampered database must be rejected"
    );

    // 5. Tampered manifest is rejected
    let tampered_manifest_path = dir.path().join("tampered.manifest.json");
    let tampered_manifest_json = manifest_json.replace("release-test-source", "tampered-source");
    assert_ne!(manifest_json, tampered_manifest_json);
    std::fs::write(&tampered_manifest_path, &tampered_manifest_json).unwrap();

    let res_tampered_manifest = store.install_release(
        &db_path,
        Some(&tampered_manifest_path),
        Some(&sig_path),
        Some(&verifying_key),
        false,
    );
    assert!(
        res_tampered_manifest.is_err(),
        "Tampered manifest must fail signature verification"
    );
}

#[test]
fn test_e2e_scenario_14_missing_or_incorrect_signing_key() {
    let dir = tempfile::tempdir().unwrap();
    let store = DbStore::new(dir.path().join("store"));

    let (sk1, _vk1) = crypto::generate_keypair();
    let (_sk2, vk2) = crypto::generate_keypair();

    let mut pipeline = IngestPipeline::new(BuildProfile::Public);
    pipeline.authorize_all_for_testing();
    let manifest_src = SourceManifest {
        id: "source-test".into(),
        name: "Test Feed".into(),
        origin: "test".into(),
        version: "1.0".into(),
        acquired_at: "2026-11-02T00:00:00Z".into(),
        license: "CC0-1.0".into(),
        redistribution: Redistribution::Allowed,
        attribution: None,
        approved: true,
        kind: SourceKind::SyntheticTest,
        format: IndicatorFormat::HashSizeName,
        path: "f.hdb".into(),
        sha256: None,
    };
    let content = format!("{}:68:Synthetic.Test.Sig\n", EICAR_MD5_HEX);
    pipeline
        .add_source(manifest_src, content.as_bytes())
        .unwrap();

    let (db_bytes, build_manifest) = pipeline.build("1.0", "2026-11-02T00:00:00Z").unwrap();
    let db_path = dir.path().join("db.rsidb");
    let manifest_path = dir.path().join("db.manifest.json");
    let sig_path = dir.path().join("db.sig");

    std::fs::write(&db_path, &db_bytes).unwrap();
    let manifest_json = serde_json::to_string(&build_manifest).unwrap();
    std::fs::write(&manifest_path, &manifest_json).unwrap();

    // Sign with SK1
    let sig = crypto::sign_bytes(manifest_json.as_bytes(), &sk1);
    crypto::save_signature_to_file(&sig, &sig_path).unwrap();

    // 1. Install with wrong public key (VK2) fails signature verification
    let res_wrong_key = store.install_release(
        &db_path,
        Some(&manifest_path),
        Some(&sig_path),
        Some(&vk2),
        false,
    );
    assert!(
        res_wrong_key.is_err(),
        "Wrong public key must fail signature verification"
    );

    // 2. Missing signature when unsigned not allowed fails
    let res_missing_sig =
        store.install_release(&db_path, Some(&manifest_path), None, Some(&vk2), false);
    assert!(
        res_missing_sig.is_err(),
        "Missing signature must be rejected"
    );

    // 3. Explicit --allow-unsigned allows installation without signatures
    let res_dev_mode = store.install_release(&db_path, Some(&manifest_path), None, None, true);
    assert!(
        res_dev_mode.is_ok(),
        "allow_unsigned=true must succeed in development workflow"
    );
}

#[test]
fn test_e2e_scenario_15_tar_archive_produces_unsupported_verdict() {
    let tar_bytes =
        make_test_tar_archive("embedded_payload.bin", b"Malware payload bytes inside tar");
    let db = SignatureDatabase::new();
    let scanner = EmailScanner::new(&db);
    let mut tracker = ResourceTracker::new(ResourceLimits::default());

    // 1. Direct TAR scan returns Unsupported
    let report = scanner
        .scan_object(
            &tar_bytes,
            "payload.tar",
            Some("application/x-tar"),
            &mut tracker,
            0,
        )
        .expect("scan tar");
    assert_eq!(report.status, ScanStatus::Unsupported);
    assert!(report
        .error
        .as_ref()
        .unwrap()
        .contains("TAR container cannot be extracted"));

    // 2. Truncated TAR scan returns Unsupported
    let trunc_tar = &tar_bytes[..200];
    let report_trunc = scanner
        .scan_object(
            trunc_tar,
            "damaged.tar",
            Some("application/x-tar"),
            &mut tracker,
            0,
        )
        .expect("scan truncated tar");
    assert_eq!(report_trunc.status, ScanStatus::Unsupported);
}

#[test]
fn test_e2e_scenario_16_malformed_records_and_accurate_signature_counts() {
    let mut pipeline = IngestPipeline::new(BuildProfile::Public);
    pipeline.authorize_source("mixed-feed");

    let source = SourceManifest {
        id: "mixed-feed".into(),
        name: "Mixed Feed".into(),
        origin: "test".into(),
        version: "1.0".into(),
        acquired_at: "2026-11-02T00:00:00Z".into(),
        license: "CC0-1.0".into(),
        redistribution: Redistribution::Allowed,
        attribution: None,
        approved: true,
        kind: SourceKind::SyntheticTest,
        format: IndicatorFormat::HashSizeName,
        path: "mixed.hdb".into(),
        sha256: None,
    };

    let sha1_hex = "0123456789abcdef0123456789abcdef01234567";
    let content = format!(
        "# Feed with mixed valid and malformed records\n\
         {}:68:Threat.Eicar.MD5\n\
         {}:100:Threat.SHA1\n\
         {}:68:Threat.Eicar.SHA256\n\
         not_a_hex:10:BadHex\n\
         {}:0:ZeroSize\n\
         invalid_line_without_colons\n",
        EICAR_MD5_HEX, sha1_hex, EICAR_SHA256_HEX, EICAR_MD5_HEX
    );

    let report = pipeline.add_source(source, content.as_bytes()).unwrap();
    assert_eq!(report.accepted, 3);
    assert_eq!(report.rejected, 3);
    assert_eq!(report.ignored_lines, 1);

    let (_, manifest) = pipeline
        .build("2026.11.02.1", "2026-11-02T00:00:00Z")
        .unwrap();
    assert_eq!(manifest.records_md5, 1);
    assert_eq!(manifest.records_sha1, 1);
    assert_eq!(manifest.records_sha256, 1);
    assert_eq!(manifest.genuine_records, 0);
    assert_eq!(manifest.synthetic_records, 3);
    assert_eq!(manifest.total_accepted, 3);
    assert_eq!(manifest.total_rejected, 3);
}

#[test]
fn test_e2e_scenario_17_unauthorized_source_self_approval_blocked() {
    let mut pipeline = IngestPipeline::new(BuildProfile::Public);
    let rogue = SourceManifest {
        id: "rogue-source".into(),
        name: "Rogue Self-Approved Feed".into(),
        origin: "https://evil.example.com".into(),
        version: "1.0".into(),
        acquired_at: "2026-11-02T00:00:00Z".into(),
        license: "GPL-2.0-or-later".into(),
        redistribution: Redistribution::Allowed,
        attribution: None,
        approved: true, // attempts self-approval
        kind: SourceKind::Genuine,
        format: IndicatorFormat::HashSizeName,
        path: "rogue.hdb".into(),
        sha256: None,
    };

    let err = pipeline.add_source(rogue, b"").unwrap_err();
    match err {
        DatabaseError::Policy(msg) => {
            assert!(msg.contains("not authorized by operator policy"));
            assert!(msg.contains("manifest self-approval is rejected"));
        }
        other => panic!("Expected policy refusal, got {:?}", other),
    }
}

#[test]
fn test_e2e_scenario_18_genuine_integrity_guarantees() {
    let mut pipeline = IngestPipeline::new(BuildProfile::Public);

    // 1. Unverified source declaring genuine is demoted to synthetic
    pipeline.authorize_source("unverified-feed");
    let unverified_manifest = SourceManifest {
        id: "unverified-feed".into(),
        name: "Unverified Feed".into(),
        origin: "https://example.com/unverified".into(),
        version: "1.0".into(),
        acquired_at: "2026-11-02T00:00:00Z".into(),
        license: "CC0-1.0".into(),
        redistribution: Redistribution::Allowed,
        attribution: None,
        approved: true,
        kind: SourceKind::Genuine, // Falsely declares genuine
        format: IndicatorFormat::HashSizeName,
        path: "feed.hdb".into(),
        sha256: None, // Unpinned
    };
    let unverified_content =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:1024:Trojan.Generic\n";
    let report1 = pipeline
        .add_source(unverified_manifest, unverified_content.as_bytes())
        .unwrap();
    assert_eq!(report1.effective_kind, SourceKind::SyntheticTest);
    assert_eq!(
        report1.authenticity_status,
        "unverified_operator_certification_missing"
    );

    // 2. Verified genuine source with synthetic preimages has preimages rejected
    pipeline.authorize_source("verified-feed");
    pipeline.verify_genuine_source("verified-feed");

    let abc_preimage_hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let verified_content = format!(
        "# Pinned verified genuine feed with attempted synthetic inclusion\n\
         {}:34816:FalselyClaimed.AgentTesla\n\
         {}:68:FalselyClaimed.Eicar\n\
         fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210:2048:Real.Operational.Threat\n",
        abc_preimage_hash, EICAR_SHA256_HEX
    );
    let verified_sha256 = hex::encode(sha2::Sha256::digest(verified_content.as_bytes()));

    let verified_manifest = SourceManifest {
        id: "verified-feed".into(),
        name: "Verified Operational Feed".into(),
        origin: "https://example.com/verified".into(),
        version: "2026.11.02".into(),
        acquired_at: "2026-11-02T00:00:00Z".into(),
        license: "CC0-1.0".into(),
        redistribution: Redistribution::Allowed,
        attribution: None,
        approved: true,
        kind: SourceKind::Genuine,
        format: IndicatorFormat::HashSizeName,
        path: "verified.hdb".into(),
        sha256: Some(verified_sha256),
    };

    let report2 = pipeline
        .add_source(verified_manifest, verified_content.as_bytes())
        .unwrap();
    assert_eq!(report2.effective_kind, SourceKind::Genuine);
    assert_eq!(report2.authenticity_status, "verified_genuine_provider");
    // 2 synthetic preimages rejected, 1 real threat accepted
    assert_eq!(report2.accepted, 1);
    assert_eq!(report2.rejected, 2);
    assert_eq!(
        report2
            .rejections_by_reason
            .get("synthetic_preimage_in_genuine_feed"),
        Some(&2)
    );

    // 3. Build verifies strict genuine vs synthetic counts
    let (_, manifest) = pipeline
        .build("2026.11.02.1", "2026-11-02T00:00:00Z")
        .unwrap();
    assert_eq!(manifest.genuine_records, 1);
    assert_eq!(manifest.synthetic_records, 1); // 1 from unverified source
    assert_eq!(manifest.total_accepted, 2);
}
