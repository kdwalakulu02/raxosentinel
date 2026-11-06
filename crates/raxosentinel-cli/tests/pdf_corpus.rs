#![cfg(target_os = "linux")]
//! Runs every fixture in `tests/pdf-corpus/MANIFEST.tsv` through the supervised worker
//! and requires the recorded verdict. Fixture hashes are checked so a regenerated
//! corpus cannot silently change what is being tested.
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Command;

#[test]
fn pdf_regression_corpus_verdicts() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/pdf-corpus");
    let manifest = std::fs::read_to_string(root.join("MANIFEST.tsv")).unwrap();
    let mut failures = Vec::new();
    let mut count = 0usize;
    for line in manifest
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let fields: Vec<&str> = line.split('\t').collect();
        let (name, expected, sha256) = (fields[0], fields[1], fields[5]);
        let path = root.join("fixtures").join(name);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            sha256,
            "{name}: fixture differs from MANIFEST.tsv"
        );
        let output = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
            .arg("scan")
            .arg(&path)
            .args(["--supervised", "--json"])
            .output()
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|e| panic!("{name}: invalid JSON envelope: {e}"));
        let status = report["status"].as_str().unwrap_or_default();
        if status != expected {
            failures.push(format!(
                "{name}: expected {expected}, got {status} ({})",
                report["error"]
            ));
        }
        count += 1;
    }
    assert!(count >= 40, "corpus unexpectedly small: {count}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
