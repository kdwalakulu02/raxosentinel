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
    let good = run();
    assert_ne!(
        good.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    assert!(String::from_utf8_lossy(&good.stdout).contains("MalwareBazaar.SyntheticFixture"));
    std::fs::remove_file(root.path().join("synthetic/database.rsidb.evidence")).unwrap();
    let bad = run();
    assert_eq!(bad.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("private database rejected"));
}
