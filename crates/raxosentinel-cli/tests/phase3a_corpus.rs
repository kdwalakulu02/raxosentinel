// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! Harmless generated file corpus, exercised through the actual scanner CLI.
use raxosentinel_core::{ResourceLimits, ResourceTracker, ScanStatus};
use raxosentinel_email::EmailScanner;
use raxosentinel_signatures::{
    rsidb::{HashAlgorithm, RsidbCompiler, SignatureEntry},
    SignatureDatabase,
};
use sha2::{Digest, Sha256};
use std::{
    io::{Cursor, Write},
    path::Path,
    process::Command,
};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

const PAYLOAD: &[u8] = b"RaxoSentinel harmless synthetic signature fixture 3A";
fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    for (name, data) in entries {
        out.start_file(*name, opts).unwrap();
        out.write_all(data).unwrap();
    }
    out.finish().unwrap().into_inner()
}
fn pdf_fixture() -> Vec<u8> {
    let mut bytes = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::new();
    for object in [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] >>\nendobj\n",
    ] {
        offsets.push(bytes.len());
        bytes.extend_from_slice(object.as_bytes());
    }
    let xref = bytes.len();
    bytes.extend_from_slice(b"xref\n0 4\n0000000000 65535 f \n");
    for offset in offsets {
        bytes.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    bytes.extend_from_slice(
        format!("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    bytes
}
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if c.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
fn run(file: &Path, db: &Path, args: &[&str]) -> (i32, serde_json::Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .arg("scan")
        .arg(file)
        .args(["--json", "--db"])
        .arg(db)
        .args(args)
        .output()
        .unwrap();
    (
        output.status.code().unwrap(),
        serde_json::from_slice(&output.stdout).expect("structured scan report"),
    )
}
#[test]
fn real_files_nested_archives_mime_and_limits() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let digest = Sha256::digest(PAYLOAD);
    let database = RsidbCompiler::new()
        .with_directory(false)
        .compile(vec![SignatureEntry::new(
            HashAlgorithm::Sha256,
            PAYLOAD.len() as u64,
            digest.to_vec(),
            "SyntheticFixture.3A",
        )])
        .unwrap();
    let db = dir.join("test.rsidb");
    std::fs::write(&db, database).unwrap();
    let hit = dir.join("fixture.txt");
    std::fs::write(&hit, PAYLOAD).unwrap();
    let (code, report) = run(&hit, &db, &[]);
    assert_eq!(code, 1);
    assert_eq!(report["status"], "DETECTED");
    assert_eq!(report["target"]["sha256"], hex::encode(digest));
    assert!(report.to_string().contains("SyntheticFixture.3A"));
    let clean = dir.join("ordinary.txt");
    std::fs::write(&clean, b"Ordinary harmless text.\n").unwrap();
    assert_eq!(run(&clean, &db, &[]).1["status"], "CLEAN");
    let pdf = dir.join("document.pdf");
    std::fs::write(&pdf, pdf_fixture()).unwrap();
    assert_eq!(run(&pdf, &db, &[]).1["status"], "CLEAN");
    // Generated 1x1 RGBA PNG and 8x8 grayscale JPEG; no malware content.
    let png = dir.join("pixel.png");
    std::fs::write(&png,hex::decode("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c63f8cfc0f01f00050001ff89993d1d0000000049454e44ae426082").unwrap()).unwrap();
    assert_eq!(run(&png, &db, &[]).1["status"], "CLEAN");
    let jpeg = dir.join("image.jpg");
    std::fs::write(
        &jpeg,
        hex::decode("ffd8ffdb00430001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101ffc0000b080008000801011100ffc40026000100000000000000000000000000000000100100000000000000000000000000000000ffda0008010100003f003fffd9").unwrap(),
    )
    .unwrap();
    assert_eq!(run(&jpeg, &db, &[]).1["status"], "CLEAN");
    let archive = dir.join("fixture.zip");
    std::fs::write(&archive, zip(&[("payload.txt", PAYLOAD)])).unwrap();
    assert_eq!(run(&archive, &db, &[]).1["status"], "DETECTED");
    let inner = zip(&[("payload.txt", PAYLOAD)]);
    let nested = dir.join("nested.zip");
    std::fs::write(&nested, zip(&[("inner.zip", &inner)])).unwrap();
    let nested_report = run(&nested, &db, &[]).1;
    assert_eq!(nested_report["status"], "DETECTED");
    assert_ne!(nested_report["status_description"], "Detected 0 threat(s).");
    let human = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .arg("scan")
        .arg(&nested)
        .arg("--db")
        .arg(&db)
        .output()
        .unwrap();
    assert_eq!(human.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&human.stdout).contains("SyntheticFixture.3A"));
    let mail = dir.join("message.eml");
    let message=format!("From: a@example.invalid\r\nTo: b@example.invalid\r\nSubject: harmless fixture\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"RAXO\"\r\n\r\n--RAXO\r\nContent-Type: text/plain\r\n\r\nhello\r\n--RAXO\r\nContent-Type: application/octet-stream; name=\"payload.txt\"\r\nContent-Disposition: attachment; filename=\"payload.txt\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--RAXO--\r\n",base64(PAYLOAD));
    std::fs::write(&mail, &message).unwrap();
    assert_eq!(run(&mail, &db, &[]).1["status"], "DETECTED");
    let nested_mail = dir.join("nested.eml");
    let message_zip = message
        .replace("payload.txt", "inner.zip")
        .replace(&base64(PAYLOAD), &base64(&inner));
    std::fs::write(&nested_mail, message_zip).unwrap();
    assert_eq!(run(&nested_mail, &db, &[]).1["status"], "DETECTED");
    let disguised_mail = dir.join("disguised.eml");
    let disguised = message.replace("payload.txt", "photo.jpg").replace(
        &base64(PAYLOAD),
        &base64(b"MZ\x00\x00synthetic executable header"),
    );
    std::fs::write(&disguised_mail, disguised).unwrap();
    assert_ne!(run(&disguised_mail, &db, &[]).1["status"], "CLEAN");
    let misleading = dir.join("photo.txt");
    std::fs::write(&misleading, b"MZ\x00\x00synthetic executable header").unwrap();
    assert_ne!(run(&misleading, &db, &[]).1["status"], "CLEAN");
    let corrupt = dir.join("broken.zip");
    std::fs::write(&corrupt, b"truncated zip file").unwrap();
    assert_eq!(run(&corrupt, &db, &[]).1["status"], "UNSCANNED");
    let missing = dir.join("missing.txt");
    assert_eq!(run(&missing, &db, &[]).1["status"], "ERROR");
    assert_eq!(run(&clean, &db, &["--max-size", "1"]).1["status"], "ERROR");
    assert_ne!(
        run(&nested, &db, &["--max-depth", "0"]).1["status"],
        "CLEAN"
    );
    let names: Vec<String> = (0..31).map(|i| format!("file{i}.txt")).collect();
    let many: Vec<(&str, &[u8])> = names.iter().map(|s| (s.as_str(), &b"x"[..])).collect();
    let many_path = dir.join("many.zip");
    std::fs::write(&many_path, zip(&many)).unwrap();
    assert_eq!(run(&many_path, &db, &[]).1["status"], "ERROR");
    let zeros = vec![0u8; 26 * 1024 * 1024];
    let bomb = dir.join("compressed.zip");
    std::fs::write(&bomb, zip(&[("zero.bin", &zeros)])).unwrap();
    assert_eq!(run(&bomb, &db, &[]).1["status"], "ERROR");
    let limits = ResourceLimits {
        max_total_extracted_bytes: 4,
        ..Default::default()
    };
    let mut tracker = ResourceTracker::new(limits);
    let database = SignatureDatabase::new();
    let archive = zip(&[("data.txt", b"more than four bytes")]);
    let report = EmailScanner::new(&database)
        .scan_object(&archive, "limit.zip", None, &mut tracker, 0)
        .unwrap();
    assert_eq!(report.status, ScanStatus::Failed);
    let limits = ResourceLimits {
        max_scan_duration_ms: 0,
        ..Default::default()
    };
    let mut tracker = ResourceTracker::new(limits);
    std::thread::sleep(std::time::Duration::from_millis(2));
    assert!(EmailScanner::new(&database)
        .scan_object(b"benign", "file.txt", None, &mut tracker, 0)
        .is_err());
}
