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

use raxosentinel_core::{ResourceLimits, ResourceTracker, ThreatCategory};
use raxosentinel_email::EmailScanner;
use raxosentinel_filetypes::{detect_file_type, detect_type, FileCategory};
use raxosentinel_signatures::SignatureDatabase;
use std::io::Write;
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
