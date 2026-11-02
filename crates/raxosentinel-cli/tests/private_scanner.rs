// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
use raxosentinel_signatures::rsidb::malwarebazaar::private_store;
use sha2::{Digest, Sha256};
use std::{os::unix::fs::PermissionsExt, process::Command};

#[test]
fn scanner_requires_private_evidence_and_never_scans_after_failure() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = root.path().join("synthetic.txt");
    let content = b"synthetic scanner fixture only";
    std::fs::write(&target, content).unwrap();
    let response = serde_json::json!({"query_status":"ok", "data":[{"sha256_hash":hex::encode(Sha256::digest(content)), "file_size":content.len(), "first_seen":"2024-02-29 00:00:00", "signature":"SyntheticFixture"}]}).to_string();
    private_store::publish(root.path(), "synthetic", response.as_bytes(), 1).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
            .arg("scan")
            .arg(&target)
            .arg("--private-db-root")
            .arg(root.path())
            .arg("--private-generation")
            .arg("synthetic")
            .output()
            .unwrap()
    };
    let listing = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .args(["db", "sources", "--root"])
        .arg(root.path())
        .args(["--generation", "synthetic"])
        .output()
        .unwrap();
    assert!(listing.status.success());
    assert!(String::from_utf8_lossy(&listing.stdout).contains("malwarebazaar"));
    let digest = hex::encode(Sha256::digest(content));
    let indicator = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .args(["db", "indicator", "--root"])
        .arg(root.path())
        .args(["--generation", "synthetic", &digest])
        .output()
        .unwrap();
    assert!(indicator.status.success());
    assert!(String::from_utf8_lossy(&indicator.stdout).contains("SyntheticFixture"));
    let good = run();
    assert_ne!(
        good.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    assert!(String::from_utf8_lossy(&good.stdout).contains("MalwareBazaar.SyntheticFixture"));
    private_store::publish(root.path(), "replacement", response.as_bytes(), 2).unwrap();
    let refresh = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .args(["db", "refresh-private-source", "--root"])
        .arg(root.path())
        .args([
            "--input",
            "synthetic",
            "--replacement",
            "replacement",
            "--output",
            "history",
            "--source",
            "malwarebazaar",
        ])
        .output()
        .unwrap();
    assert!(
        refresh.status.success(),
        "{}",
        String::from_utf8_lossy(&refresh.stderr)
    );
    let history = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .args(["db", "sources", "--root"])
        .arg(root.path())
        .args(["--generation", "history"])
        .output()
        .unwrap();
    assert!(history.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert_eq!(
        parsed["sources"][0]["acquisitions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let comparison = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .args(["db", "compare-private", "--root"])
        .arg(root.path())
        .args(["--before", "synthetic", "--after", "history"])
        .output()
        .unwrap();
    assert!(comparison.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&comparison.stdout).unwrap();
    assert_eq!(parsed["acquisitions_added"].as_array().unwrap().len(), 1);
    std::fs::write(root.path().join("history/registry.json"), b"corrupt").unwrap();
    let history_scan = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .arg("scan")
        .arg(&target)
        .arg("--private-db-root")
        .arg(root.path())
        .args(["--private-generation", "history"])
        .output()
        .unwrap();
    assert_eq!(history_scan.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&history_scan.stderr).contains("private database rejected"));
    std::fs::remove_file(root.path().join("synthetic/database.rsidb.evidence")).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
        .args(["db", "sources", "--root"])
        .arg(root.path())
        .args(["--generation", "synthetic"])
        .output()
        .unwrap();
    assert_eq!(rejected.status.code(), Some(3));
    let bad = run();
    assert_eq!(bad.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("private database rejected"));
}
