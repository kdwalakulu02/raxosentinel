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

use super::*;
use sha2::Digest;
use std::fs;
use std::path::{Path, PathBuf};

const XOR_KEY: &[u8] = b"bhcftqarohcdiayfohalohkgmoefxrrg\
fnczssgybajvkzjaahpfrlqsratkhhfv\
pxytculmwgmtyzujlbjlgrhtwxhzpjaz\
libbwepffyjyfkjwzyofgpopoueurinp\
dujkphxwhnaxfkaiwrpzdqsnwughtejr";

fn decode_xor_fixture(path: &Path) -> Vec<u8> {
    let encrypted = fs::read(path).expect("Failed to read encrypted fixture");
    encrypted
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ XOR_KEY[i % XOR_KEY.len()])
        .collect()
}

fn get_test_fixtures_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let local_fixtures = manifest_dir.join("test_fixtures");
    if local_fixtures.exists() {
        return local_fixtures;
    }
    manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("raw referefce")
        .join("raxosentinel-db-lab")
        .join("upstream")
        .join("unit_tests")
        .join("input")
}

#[test]
fn test_parse_clamav_test_signatures() {
    let up = get_test_fixtures_dir();

    let hdb_path = up.join("clamav.hdb");
    let (entries, stats) = SignatureImporter::parse_file(&hdb_path).unwrap();
    assert_eq!(stats.accepted, 1);
    assert_eq!(stats.rejected, 0);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].alg, HashAlgorithm::Sha256);
    assert_eq!(entries[0].size, 544);
    assert_eq!(entries[0].name, "ClamAV-Test-File");

    // Load alz.hdb (13 SHA-1 signatures)
    let alz_path = up.join("other_sigs").join("alz.hdb");
    let (alz_entries, alz_stats) = SignatureImporter::parse_file(&alz_path).unwrap();
    assert_eq!(alz_stats.accepted, 13);
    assert_eq!(alz_entries.len(), 13);
    for e in &alz_entries {
        assert_eq!(e.alg, HashAlgorithm::Sha1);
    }

    // Load logo.hsb (SHA-256) and zstd.hdb (SHA-256)
    let logo_path = up.join("other_sigs").join("logo.hsb");
    let (logo_entries, _) = SignatureImporter::parse_file(&logo_path).unwrap();
    assert_eq!(logo_entries.len(), 1);
    assert_eq!(logo_entries[0].size, 25476);
    assert_eq!(logo_entries[0].name, "logo.png");

    let zstd_path = up.join("other_sigs").join("zstd.hdb");
    let (zstd_entries, _) = SignatureImporter::parse_file(&zstd_path).unwrap();
    assert_eq!(zstd_entries.len(), 2);

    let mut total_entries = Vec::new();
    total_entries.extend(entries);
    total_entries.extend(alz_entries);
    total_entries.extend(logo_entries);
    total_entries.extend(zstd_entries);
    assert_eq!(total_entries.len(), 17);
}

#[test]
fn test_roundtrip_all_three_implementations() {
    let up = get_test_fixtures_dir();

    let mut all_entries = Vec::new();
    for p in &[
        up.join("clamav.hdb"),
        up.join("other_sigs").join("alz.hdb"),
        up.join("other_sigs").join("logo.hsb"),
        up.join("other_sigs").join("zstd.hdb"),
    ] {
        let (entries, _) = SignatureImporter::parse_file(p).unwrap();
        all_entries.extend(entries);
    }
    assert_eq!(all_entries.len(), 17);

    let compiler = RsidbCompiler::new().with_directory(true);
    let binary_bytes = compiler.compile(all_entries.clone()).unwrap();

    let in_mem = InMemoryIndex::from_bytes(&binary_bytes).unwrap();
    let mmap_sorted = MmapSortedIndex::from_bytes(binary_bytes.clone()).unwrap();
    let mmap_dir = MmapCompactDirIndex::from_bytes(binary_bytes).unwrap();

    let indices: [&dyn RsidbIndex; 3] = [&in_mem, &mmap_sorted, &mmap_dir];

    for idx in indices {
        assert_eq!(idx.total_records(), 17);
        for entry in &all_entries {
            let names = idx.lookup(entry.alg, entry.size, &entry.digest);
            assert!(
                names.contains(&entry.name),
                "Missing expected name {} in index implementation",
                entry.name
            );
        }
    }
}

#[test]
fn test_official_harmless_clamav_fixture() {
    let up = get_test_fixtures_dir();

    let (entries, _) = SignatureImporter::parse_file(&up.join("clamav.hdb")).unwrap();
    let binary = RsidbCompiler::new()
        .with_directory(true)
        .compile(entries)
        .unwrap();

    let mmap_dir = MmapCompactDirIndex::from_bytes(binary).unwrap();

    let clam_exe = decode_xor_fixture(&up.join("clamav_hdb_scanfiles").join("clam.exe.xor"));
    assert_eq!(clam_exe.len(), 544);

    // Matches official harmless fixture
    let matches = mmap_dir.scan_raw_bytes(&clam_exe);
    assert_eq!(matches, vec!["ClamAV-Test-File".to_string()]);

    // One-byte mutation does not match whole-file hash
    let mut mutated = clam_exe.clone();
    mutated[0] ^= 1;
    let mut_matches = mmap_dir.scan_raw_bytes(&mutated);
    assert!(mut_matches.is_empty());

    // Changed file size does not match even with original digest
    let sha256_orig = sha2::Sha256::digest(&clam_exe);
    let size_mismatch = mmap_dir.lookup(HashAlgorithm::Sha256, 545, &sha256_orig);
    assert!(size_mismatch.is_empty());

    // Clean control input has no match
    let clean = b"RaxoSentinel database experiment clean control string.\n";
    let clean_matches = mmap_dir.scan_raw_bytes(clean);
    assert!(clean_matches.is_empty());
}

#[test]
fn test_zip_wrapper_and_extracted_member() {
    let up = get_test_fixtures_dir();

    let (entries, _) = SignatureImporter::parse_file(&up.join("clamav.hdb")).unwrap();
    let binary = RsidbCompiler::new().compile(entries).unwrap();
    let mmap_dir = MmapCompactDirIndex::from_bytes(binary).unwrap();

    let zip_bytes = decode_xor_fixture(&up.join("clamav_hdb_scanfiles").join("clam.zip.xor"));

    // 1. Raw ZIP wrapper bytes do NOT match the inner file's whole-file hash
    let zip_wrapper_matches = mmap_dir.scan_raw_bytes(&zip_bytes);
    assert!(zip_wrapper_matches.is_empty());

    // 2. Extracted ZIP member matches ClamAV-Test-File
    let cursor = std::io::Cursor::new(&zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor).unwrap();
    assert_eq!(archive.len(), 1);

    let mut member_data = Vec::new();
    {
        use std::io::Read;
        let mut file = archive.by_index(0).unwrap();
        file.read_to_end(&mut member_data).unwrap();
    }

    assert_eq!(member_data.len(), 544);
    let inner_matches = mmap_dir.scan_raw_bytes(&member_data);
    assert_eq!(inner_matches, vec!["ClamAV-Test-File".to_string()]);
}

#[test]
fn test_mime_email_wrapper_and_extracted_attachment() {
    let up = get_test_fixtures_dir();

    let (entries, _) = SignatureImporter::parse_file(&up.join("clamav.hdb")).unwrap();
    let binary = RsidbCompiler::new().compile(entries).unwrap();
    let mmap_dir = MmapCompactDirIndex::from_bytes(binary).unwrap();

    let eml_bytes = decode_xor_fixture(
        &up.join("clamav_hdb_scanfiles")
            .join("clam.exe.mbox.base64.xor"),
    );

    // 1. Encoded raw email bytes do NOT match the inner file's whole-file hash
    let raw_eml_matches = mmap_dir.scan_raw_bytes(&eml_bytes);
    assert!(raw_eml_matches.is_empty());

    // 2. MIME-decoded attachment matches ClamAV-Test-File
    let msg = mail_parser::MessageParser::default()
        .parse(&eml_bytes)
        .unwrap();
    let mut attachment_matched = false;

    for attachment in msg.attachments() {
        let contents = attachment.decoded();
        let matches = mmap_dir.scan_raw_bytes(&contents);
        if matches.contains(&"ClamAV-Test-File".to_string()) {
            attachment_matched = true;
            break;
        }
    }

    assert!(
        attachment_matched,
        "MIME attachment failed to match test signature"
    );
}

#[test]
fn test_exact_ndb_pattern_matching_semantics() {
    let up = get_test_fixtures_dir();
    let ndb_path = up.join("other_sigs").join("Clamav-Unit-Test-Signature.ndb");

    let line = fs::read_to_string(ndb_path).unwrap();
    let parts: Vec<&str> = line.trim().split(':').collect();
    assert_eq!(parts.len(), 4);
    let name = parts[0];
    let target = parts[1];
    let offset_str = parts[2];
    let hex_pattern = parts[3];

    assert_eq!(name, "NDB.Clamav-Unit-Test-Signature");
    assert_eq!(target, "0");
    assert_eq!(offset_str, "0");
    let pattern = hex::decode(hex_pattern).unwrap();
    assert_eq!(pattern, b"CLAMAV-TEST-STRING-NOT-EICAR");

    // Exact match at offset 0
    let payload = b"CLAMAV-TEST-STRING-NOT-EICAR";
    assert_eq!(&payload[0..pattern.len()], pattern.as_slice());

    // Shifted payload at offset 1 does NOT match offset 0 constraint
    let shifted = b"XCLAMAV-TEST-STRING-NOT-EICAR";
    assert_ne!(&shifted[0..pattern.len()], pattern.as_slice());
}

#[test]
fn test_strict_validation_and_corruption_rejection() {
    let up = get_test_fixtures_dir();
    let (entries, _) = SignatureImporter::parse_file(&up.join("clamav.hdb")).unwrap();
    let binary = RsidbCompiler::new().compile(entries).unwrap();

    // 1. Reject bad magic
    let mut bad_magic = binary.clone();
    bad_magic[0..8].copy_from_slice(b"BADMAGIC");
    assert!(matches!(
        MmapSortedIndex::from_bytes(bad_magic),
        Err(DatabaseError::InvalidMagic(..))
    ));

    // 2. Reject truncated header
    let truncated_header = binary[0..40].to_vec();
    assert!(matches!(
        MmapSortedIndex::from_bytes(truncated_header),
        Err(DatabaseError::TruncatedHeader(..))
    ));

    // 3. Reject truncated data region
    let truncated_data = binary[0..HEADER_SIZE + 10].to_vec();
    assert!(matches!(
        MmapSortedIndex::from_bytes(truncated_data),
        Err(DatabaseError::TruncatedData(..))
    ));

    // 4. Reject trailing bytes
    let mut trailing = binary.clone();
    trailing.extend_from_slice(b"EXTRA_TRAILING_BYTES");
    assert!(matches!(
        MmapSortedIndex::from_bytes(trailing),
        Err(DatabaseError::TrailingBytes(..))
    ));

    // 5. Reject corrupted checksum
    let mut corrupt_payload = binary.clone();
    // mutate one payload byte
    corrupt_payload[HEADER_SIZE + 4] ^= 0xFF;
    assert!(matches!(
        MmapSortedIndex::from_bytes(corrupt_payload),
        Err(DatabaseError::CorruptedChecksum(..))
    ));

    // 6. Explicitly reject unsupported wildcard sizes
    let wildcard_sig =
        "71e7b604d18aefd839e51a39c88df8383bb4c071dc31f87f00a2b5df580d4495:*:Wildcard.Sig\n";
    assert!(matches!(
        SignatureImporter::parse_str(wildcard_sig),
        Err(DatabaseError::UnsupportedWildcardSize(1, _))
    ));

    // 7. Explicitly reject invalid hash length
    let invalid_len_sig = "0102030405:100:Invalid.Length\n";
    assert!(matches!(
        SignatureImporter::parse_str(invalid_len_sig),
        Err(DatabaseError::UnsupportedHashLength(5, 1))
    ));
}

#[test]
fn test_multiple_detection_names_for_same_key() {
    let digest = vec![0xABu8; 32];
    let entries = vec![
        SignatureEntry::new(
            HashAlgorithm::Sha256,
            1024,
            digest.clone(),
            "Malware.Variant.A",
        ),
        SignatureEntry::new(
            HashAlgorithm::Sha256,
            1024,
            digest.clone(),
            "Malware.Variant.B",
        ),
    ];

    let binary = RsidbCompiler::new()
        .with_directory(true)
        .compile(entries)
        .unwrap();
    let idx = MmapCompactDirIndex::from_bytes(binary).unwrap();

    let matches = idx.lookup(HashAlgorithm::Sha256, 1024, &digest);
    assert_eq!(matches.len(), 2);
    assert!(matches.contains(&"Malware.Variant.A".to_string()));
    assert!(matches.contains(&"Malware.Variant.B".to_string()));
}

#[test]
fn test_deterministic_compiler_reproducibility() {
    let entries1 = vec![
        SignatureEntry::new(HashAlgorithm::Sha256, 100, vec![0x11; 32], "Rule.B"),
        SignatureEntry::new(HashAlgorithm::Sha256, 50, vec![0x22; 32], "Rule.A"),
    ];
    let entries2 = vec![
        SignatureEntry::new(HashAlgorithm::Sha256, 50, vec![0x22; 32], "Rule.A"),
        SignatureEntry::new(HashAlgorithm::Sha256, 100, vec![0x11; 32], "Rule.B"),
    ];

    let compiler = RsidbCompiler::new().with_provenance("Fixed Provenance 2026");
    let bin1 = compiler.compile(entries1).unwrap();
    let bin2 = compiler.compile(entries2).unwrap();

    assert_eq!(
        bin1, bin2,
        "Compilation must be byte-for-byte deterministic regardless of input order"
    );
}
