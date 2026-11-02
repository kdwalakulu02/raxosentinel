// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
use ed25519_dalek::SigningKey;
use raxosentinel_signatures::rsidb::{
    public_release::{self, Artifact, Manifest, Source},
    HashAlgorithm, RsidbCompiler, SignatureEntry,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn signed_public_scanner_rejects_tampered_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let release = dir.path().join("release");
    let state = dir.path().join("state");
    for p in [&release, &state] {
        std::fs::create_dir(p).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let content = b"synthetic signed release scanner fixture";
    let db = RsidbCompiler::new()
        .with_directory(false)
        .compile(vec![SignatureEntry::new(
            HashAlgorithm::Sha256,
            content.len() as u64,
            Sha256::digest(content).to_vec(),
            "SyntheticFixture",
        )])
        .unwrap();
    let artifacts: BTreeMap<String, Vec<u8>> = BTreeMap::from([
        ("database.rsidb".into(), db),
        ("registry.json".into(), b"synthetic registry".to_vec()),
        (
            "associations.json".into(),
            b"synthetic associations".to_vec(),
        ),
    ]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let manifest = Manifest {
        format: 1,
        database_version: "1.0.0".into(),
        release_id: "fixture".into(),
        release_number: 1,
        created_unix: now - 1,
        expires_unix: now + 600,
        artifacts: artifacts
            .iter()
            .map(|(n, v)| Artifact {
                name: n.clone(),
                sha256: hex::encode(Sha256::digest(v)),
                bytes: v.len() as u64,
            })
            .collect(),
        sources: vec![Source {
            id: "synthetic_test".into(),
            provenance: "synthetic fixture".into(),
            classification: "synthetic".into(),
            redistribution: "permitted".into(),
        }],
        minimum_scanner: "0.1.0".into(),
        previous_manifest_sha256: None,
        key_id: hex::encode(Sha256::digest(key.verifying_key().as_bytes())),
        algorithm: "ed25519".into(),
    };
    let (manifest, sig) = public_release::sign(&manifest, &key).unwrap();
    let save = |name: &str, data: &[u8]| {
        let p = release.join(name);
        std::fs::write(&p, data).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    };
    for (name, data) in &artifacts {
        save(name, data);
    }
    save("manifest.json", &manifest);
    save("manifest.sig", &sig);
    let reviewer = SigningKey::generate(&mut rand::rngs::OsRng);
    let (approval, approval_signature) =
        public_release::approve(&manifest, now + 300, &reviewer).unwrap();
    save("approval.json", &approval);
    save("approval.sig", &approval_signature);
    let approval_public = dir.path().join("approval.key");
    std::fs::write(
        &approval_public,
        hex::encode(reviewer.verifying_key().as_bytes()),
    )
    .unwrap();
    public_release::local::initialize(&state).unwrap();
    let public = dir.path().join("public.key");
    std::fs::write(&public, hex::encode(key.verifying_key().as_bytes())).unwrap();
    let target = dir.path().join("target.txt");
    std::fs::write(&target, content).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
            .arg("scan")
            .arg(&target)
            .arg("--public-release")
            .arg(&release)
            .arg("--public-key")
            .arg(&public)
            .arg("--public-approval-key")
            .arg(&approval_public)
            .arg("--public-state")
            .arg(&state)
            .output()
            .unwrap()
    };
    let good = run();
    assert_ne!(good.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&good.stdout).contains("SyntheticFixture"));
    let mut edited: Manifest = serde_json::from_slice(&manifest).unwrap();
    edited.sources[0].provenance = "locally edited approval claim".into();
    let (edited_manifest, edited_signature) = public_release::sign(&edited, &key).unwrap();
    save("manifest.json", &edited_manifest);
    save("manifest.sig", &edited_signature);
    assert_eq!(run().status.code(), Some(3));
    save("manifest.json", &manifest);
    save("manifest.sig", &sig);
    std::fs::write(
        &approval_public,
        hex::encode(key.verifying_key().as_bytes()),
    )
    .unwrap();
    assert_eq!(run().status.code(), Some(3));
    std::fs::write(
        &approval_public,
        hex::encode(reviewer.verifying_key().as_bytes()),
    )
    .unwrap();
    save("approval.sig", &[0u8; 64]);
    let missing_approval = run();
    assert_eq!(missing_approval.status.code(), Some(3));
    save("approval.sig", &approval_signature);
    save("associations.json", b"tampered");
    let bad = run();
    assert_eq!(bad.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("signed public release rejected"));
}
