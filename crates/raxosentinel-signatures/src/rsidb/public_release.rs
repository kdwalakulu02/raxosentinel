// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded signed-release prototype. This module is not a TUF client or updater.
use super::{MmapSortedIndex, RsidbIndex};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const DOMAIN: &[u8] = b"RaxoSentinel public release v1\0";
const MAX_MANIFEST: usize = 1024 * 1024;
const MAX_ARTIFACTS: usize = 32;
const MAX_ARTIFACT: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: String,
    pub provenance: String,
    pub classification: String,
    pub redistribution: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: u32,
    pub database_version: String,
    pub release_id: String,
    pub release_number: u64,
    pub created_unix: u64,
    pub expires_unix: u64,
    pub artifacts: Vec<Artifact>,
    pub sources: Vec<Source>,
    pub minimum_scanner: String,
    pub previous_manifest_sha256: Option<String>,
    pub key_id: String,
    pub algorithm: String,
}
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
        && s != "."
        && s != ".."
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn version(s: &str) -> Result<[u64; 3], String> {
    let parts: Vec<_> = s.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid version".into());
    }
    let mut out = [0; 3];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty()
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|x| x.is_ascii_digit())
        {
            return Err("invalid version".into());
        }
        out[i] = part.parse().map_err(|_| "invalid version")?;
    }
    Ok(out)
}
fn validate(m: &Manifest) -> Result<(), String> {
    if m.format != 1
        || m.algorithm != "ed25519"
        || !valid_name(&m.database_version)
        || !valid_name(&m.release_id)
        || !digest(&m.key_id)
        || m.release_number == 0
        || m.created_unix >= m.expires_unix
        || m.artifacts.is_empty()
        || m.artifacts.len() > MAX_ARTIFACTS
        || m.sources.is_empty()
        || m.sources.len() > 64
    {
        return Err("invalid release manifest".into());
    }
    version(&m.minimum_scanner)?;
    if m.previous_manifest_sha256
        .as_deref()
        .is_some_and(|x| !digest(x))
    {
        return Err("invalid previous manifest digest".into());
    }
    let total: u64 = m
        .artifacts
        .iter()
        .try_fold(0u64, |sum, a| sum.checked_add(a.bytes))
        .ok_or("artifact size overflow")?;
    if total > 128 * 1024 * 1024 {
        return Err("release exceeds total artifact size limit".into());
    }
    let mut seen = BTreeSet::new();
    for a in &m.artifacts {
        if !valid_name(&a.name)
            || !digest(&a.sha256)
            || a.bytes > MAX_ARTIFACT as u64
            || !seen.insert(&a.name)
        {
            return Err("invalid artifact declaration".into());
        }
    }
    if !seen.contains(&"database.rsidb".to_string()) {
        return Err("missing database declaration".into());
    }
    let mut sources = BTreeSet::new();
    for s in &m.sources {
        if !valid_name(&s.id)
            || !sources.insert(&s.id)
            || s.provenance.is_empty()
            || s.provenance.len() > 256
            || s.classification.is_empty()
            || s.classification.len() > 256
            || s.redistribution != "permitted"
            || s.id.eq_ignore_ascii_case("malwarebazaar")
            || s.classification == "private research intelligence"
        {
            return Err("source redistribution permission not established".into());
        }
    }
    Ok(())
}
/// Signing takes a supplied in-memory key and produces no key files.
pub fn sign(m: &Manifest, key: &SigningKey) -> Result<(Vec<u8>, [u8; 64]), String> {
    validate(m)?;
    if m.key_id != hex::encode(Sha256::digest(key.verifying_key().as_bytes())) {
        return Err("signing key ID mismatch".into());
    }
    let bytes = serde_json::to_vec(m).map_err(|e| e.to_string())?;
    let mut signed = DOMAIN.to_vec();
    signed.extend_from_slice(&bytes);
    Ok((bytes, key.sign(&signed).to_bytes()))
}
// Cryptographic and structural verification only; independent approval is checked
// separately before the public loader returns an index.
fn verify(
    manifest: &[u8],
    signature: &[u8],
    trusted: &BTreeMap<String, VerifyingKey>,
    artifacts: &BTreeMap<String, Vec<u8>>,
    now: u64,
    highest: u64,
    scanner_version: &str,
) -> Result<(Manifest, MmapSortedIndex), String> {
    if manifest.len() > MAX_MANIFEST {
        return Err("manifest too large".into());
    }
    let m: Manifest = serde_json::from_slice(manifest).map_err(|_| "invalid manifest")?;
    validate(&m)?;
    if serde_json::to_vec(&m).map_err(|_| "invalid manifest")? != manifest {
        return Err("non-canonical manifest".into());
    }
    let key = trusted.get(&m.key_id).ok_or("unknown signing key")?;
    if m.key_id != hex::encode(Sha256::digest(key.as_bytes())) {
        return Err("trusted key ID mismatch".into());
    }
    let sig = Signature::from_slice(signature).map_err(|_| "invalid signature")?;
    let mut signed = DOMAIN.to_vec();
    signed.extend_from_slice(manifest);
    key.verify_strict(&signed, &sig)
        .map_err(|_| "invalid signature")?;
    if now < m.created_unix || now >= m.expires_unix {
        return Err("release not currently valid".into());
    }
    if m.release_number < highest {
        return Err("release rollback rejected".into());
    }
    if version(scanner_version)? < version(&m.minimum_scanner)? {
        return Err("incompatible scanner version".into());
    }
    if artifacts.len() != m.artifacts.len() {
        return Err("artifact set mismatch".into());
    }
    for artifact in &m.artifacts {
        let data = artifacts.get(&artifact.name).ok_or("missing artifact")?;
        if data.len() > MAX_ARTIFACT
            || data.len() as u64 != artifact.bytes
            || hex::encode(Sha256::digest(data)) != artifact.sha256
        {
            return Err("artifact integrity mismatch".into());
        }
    }
    let data = artifacts
        .get("database.rsidb")
        .ok_or("missing database")?
        .clone();
    let db = MmapSortedIndex::from_bytes(data).map_err(|_| "invalid database format")?;
    // Touch the validated index before returning it to the caller.
    let _ = db.total_records();
    Ok((m, db))
}

/// An independently signed approval for one exact release manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub format: u32,
    pub manifest_sha256: String,
    pub reviewer_key_id: String,
    pub decision: String,
    pub expires_unix: u64,
}
const APPROVAL_DOMAIN: &[u8] = b"RaxoSentinel independent release approval v1\0";
/// Sign a release approval using an independently trusted reviewer key.
pub fn approve(
    manifest: &[u8],
    expires_unix: u64,
    reviewer: &SigningKey,
) -> Result<(Vec<u8>, [u8; 64]), String> {
    let parsed: Manifest = serde_json::from_slice(manifest).map_err(|_| "Invalid manifest")?;
    validate(&parsed)?;
    if serde_json::to_vec(&parsed).map_err(|_| "Invalid manifest")? != manifest {
        return Err("Non-canonical manifest".into());
    }
    let key_id = hex::encode(Sha256::digest(reviewer.verifying_key().as_bytes()));
    if key_id == parsed.key_id {
        return Err("Reviewer key must differ from release key".into());
    }
    let approval = Approval {
        format: 1,
        manifest_sha256: hex::encode(Sha256::digest(manifest)),
        reviewer_key_id: key_id,
        decision: "approved".into(),
        expires_unix,
    };
    let bytes = serde_json::to_vec(&approval).map_err(|e| e.to_string())?;
    let mut signed = APPROVAL_DOMAIN.to_vec();
    signed.extend_from_slice(&bytes);
    Ok((bytes, reviewer.sign(&signed).to_bytes()))
}
fn verify_approval(
    manifest: &[u8],
    approval: &[u8],
    signature: &[u8],
    reviewer: &VerifyingKey,
    release_key: &VerifyingKey,
    now: u64,
) -> Result<(), String> {
    if approval.len() > MAX_MANIFEST || reviewer == release_key {
        return Err("Invalid independent approval".into());
    }
    let value: Approval =
        serde_json::from_slice(approval).map_err(|_| "Invalid independent approval")?;
    if serde_json::to_vec(&value).map_err(|_| "Invalid independent approval")? != approval
        || value.format != 1
        || value.decision != "approved"
        || value.expires_unix <= now
        || value.reviewer_key_id != hex::encode(Sha256::digest(reviewer.as_bytes()))
        || value.manifest_sha256 != hex::encode(Sha256::digest(manifest))
    {
        return Err("Invalid independent approval".into());
    }
    let sig = Signature::from_slice(signature).map_err(|_| "Invalid approval signature")?;
    let mut signed = APPROVAL_DOMAIN.to_vec();
    signed.extend_from_slice(approval);
    reviewer
        .verify_strict(&signed, &sig)
        .map_err(|_| "Invalid approval signature".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsidb::{HashAlgorithm, RsidbCompiler, SignatureEntry};
    fn fixture() -> (SigningKey, Manifest, BTreeMap<String, Vec<u8>>) {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let db = RsidbCompiler::new()
            .with_directory(false)
            .compile(vec![SignatureEntry::new(
                HashAlgorithm::Sha256,
                42,
                vec![0xaa; 32],
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
        let files = artifacts
            .iter()
            .map(|(name, data)| Artifact {
                name: name.clone(),
                sha256: hex::encode(Sha256::digest(data)),
                bytes: data.len() as u64,
            })
            .collect();
        let manifest = Manifest {
            format: 1,
            database_version: "1.0.0".into(),
            release_id: "fixture".into(),
            release_number: 3,
            created_unix: 100,
            expires_unix: 200,
            artifacts: files,
            sources: vec![Source {
                id: "synthetic_test".into(),
                provenance: "synthetic fixture only".into(),
                classification: "synthetic".into(),
                redistribution: "permitted".into(),
            }],
            minimum_scanner: "0.1.0".into(),
            previous_manifest_sha256: None,
            key_id: hex::encode(Sha256::digest(key.verifying_key().as_bytes())),
            algorithm: "ed25519".into(),
        };
        (key, manifest, artifacts)
    }
    #[test]
    fn signed_release_rejects_tampering_missing_artifacts_and_unknown_keys() {
        let (key, manifest, artifacts) = fixture();
        let (bytes, signature) = sign(&manifest, &key).unwrap();
        assert!(approve(&bytes, 200, &key).is_err());
        let reviewer = SigningKey::generate(&mut rand::rngs::OsRng);
        let (approval, approval_sig) = approve(&bytes, 200, &reviewer).unwrap();
        assert!(verify_approval(
            &bytes,
            &approval,
            &approval_sig,
            &reviewer.verifying_key(),
            &key.verifying_key(),
            150
        )
        .is_ok());
        let mut altered = approval_sig;
        altered[0] ^= 1;
        assert!(verify_approval(
            &bytes,
            &approval,
            &altered,
            &reviewer.verifying_key(),
            &key.verifying_key(),
            150
        )
        .is_err());
        let trusted = BTreeMap::from([(manifest.key_id.clone(), key.verifying_key())]);
        let check = |data: &BTreeMap<String, Vec<u8>>| {
            verify(&bytes, &signature, &trusted, data, 150, 2, "0.1.0")
        };
        assert!(check(&artifacts).is_ok());
        for name in ["database.rsidb", "registry.json", "associations.json"] {
            let mut changed = artifacts.clone();
            changed.get_mut(name).unwrap()[0] ^= 1;
            assert!(check(&changed).is_err());
        }
        let mut missing = artifacts.clone();
        missing.remove("registry.json");
        assert!(check(&missing).is_err());
        let mut changed = bytes.clone();
        let n = changed.len();
        changed[n - 2] ^= 1;
        assert!(verify(&changed, &signature, &trusted, &artifacts, 150, 2, "0.1.0").is_err());
        let mut bad = signature;
        bad[0] ^= 1;
        assert!(verify(&bytes, &bad, &trusted, &artifacts, 150, 2, "0.1.0").is_err());
        assert!(verify(
            &bytes,
            &signature,
            &BTreeMap::new(),
            &artifacts,
            150,
            2,
            "0.1.0"
        )
        .is_err());
        assert!(verify(&bytes, &signature, &trusted, &artifacts, 150, 4, "0.1.0").is_err());
        assert!(verify(&bytes, &signature, &trusted, &artifacts, 200, 2, "0.1.0").is_err());
        assert!(verify(&bytes, &signature, &trusted, &artifacts, 150, 2, "0.0.1").is_err());
    }
    #[test]
    fn scanner_loader_persists_sequence_and_rejects_rollbacks() {
        use std::{
            os::unix::fs::PermissionsExt,
            time::{SystemTime, UNIX_EPOCH},
        };
        let release = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        for dir in [release.path(), state.path()] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let (key, mut manifest, artifacts) = fixture();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        manifest.created_unix = now - 1;
        manifest.expires_unix = now + 600;
        let save = |name: &str, bytes: &[u8]| {
            let p = release.path().join(name);
            std::fs::write(&p, bytes).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        for (name, data) in &artifacts {
            save(name, data);
        }
        let (bytes, sig) = sign(&manifest, &key).unwrap();
        save("manifest.json", &bytes);
        save("manifest.sig", &sig);
        let reviewer = SigningKey::generate(&mut rand::rngs::OsRng);
        let (approval, approval_signature) = approve(&bytes, now + 300, &reviewer).unwrap();
        save("approval.json", &approval);
        save("approval.sig", &approval_signature);
        assert!(local::load(
            release.path(),
            state.path(),
            key.verifying_key(),
            reviewer.verifying_key(),
            "0.1.0"
        )
        .is_err());
        local::initialize(state.path()).unwrap();
        assert!(local::initialize(state.path()).is_err());
        assert!(local::load(
            release.path(),
            state.path(),
            key.verifying_key(),
            reviewer.verifying_key(),
            "0.1.0"
        )
        .is_ok());
        save("associations.json", b"tampered");
        assert!(local::load(
            release.path(),
            state.path(),
            key.verifying_key(),
            reviewer.verifying_key(),
            "0.1.0"
        )
        .is_err());
        save("associations.json", &artifacts["associations.json"]);
        manifest.release_number = 2;
        let (old, sig) = sign(&manifest, &key).unwrap();
        save("manifest.json", &old);
        save("manifest.sig", &sig);
        assert!(local::load(
            release.path(),
            state.path(),
            key.verifying_key(),
            reviewer.verifying_key(),
            "0.1.0"
        )
        .is_err());
    }
    #[test]
    fn refuses_unknown_redistribution_and_signed_invalid_database() {
        let (key, mut manifest, mut artifacts) = fixture();
        manifest.sources[0].redistribution = "unknown".into();
        assert!(sign(&manifest, &key).is_err());
        manifest.sources[0].redistribution = "permitted".into();
        manifest.sources[0].id = "malwarebazaar".into();
        assert!(sign(&manifest, &key).is_err());
        manifest.sources[0].id = "synthetic_test".into();
        manifest.sources[0].redistribution = "permitted".into();
        artifacts.insert("database.rsidb".into(), b"not a database".to_vec());
        let file = manifest
            .artifacts
            .iter_mut()
            .find(|f| f.name == "database.rsidb")
            .unwrap();
        file.bytes = 14;
        file.sha256 = hex::encode(Sha256::digest(b"not a database"));
        let (bytes, signature) = sign(&manifest, &key).unwrap();
        let trusted = BTreeMap::from([(manifest.key_id.clone(), key.verifying_key())]);
        assert!(verify(&bytes, &signature, &trusted, &artifacts, 150, 0, "0.1.0").is_err());
    }
}

/// Public release loading helpers for an owner-controlled prototype store.
pub mod local {
    use super::*;
    use crate::rsidb::malwarebazaar::private_store::{check, openat, readat, root};
    use std::{
        ffi::CString,
        io::{Read, Write},
        os::fd::AsRawFd,
        path::Path,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };
    const STATE: &str = "public-release-state";
    const LOCK: &str = "public-release-lock";
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    fn locked(dir: &std::fs::File) -> Result<std::fs::File, String> {
        let file = openat(dir.as_raw_fd(), LOCK, libc::O_RDWR | libc::O_CREAT, 0o600)?;
        check(&file, false)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err("Cannot lock release state".into());
        }
        Ok(file)
    }
    /// Explicitly establish fresh local rollback state; never silently resets existing state.
    pub fn initialize(state_root: &Path) -> Result<(), String> {
        let dir = root(state_root)?;
        let _guard = locked(&dir)?;
        let mut f = openat(
            dir.as_raw_fd(),
            STATE,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        f.write_all(&[0u8; 40])
            .and_then(|_| f.sync_all())
            .map_err(|e| e.to_string())?;
        dir.sync_all().map_err(|e| e.to_string())
    }
    /// Load all release files exactly once, verify them and persist the highest accepted sequence.
    /// Both directories must be owner-controlled 0700, with 0600 regular single-link files.
    pub fn load(
        release_root: &Path,
        state_root: &Path,
        key: VerifyingKey,
        reviewer: VerifyingKey,
        scanner_version: &str,
    ) -> Result<MmapSortedIndex, String> {
        let dir = root(release_root)?;
        let state_dir = root(state_root)?;
        let _guard = locked(&state_dir)?;
        let mut state = Vec::new();
        let state_file = openat(
            state_dir.as_raw_fd(),
            STATE,
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        )?;
        check(&state_file, false)?;
        state_file
            .take(41)
            .read_to_end(&mut state)
            .map_err(|e| e.to_string())?;
        if state.len() != 40 {
            return Err("Invalid or uninitialized trusted release state".into());
        }
        let high = u64::from_le_bytes(state[..8].try_into().map_err(|_| "Invalid state")?);
        let bytes = readat(dir.as_raw_fd(), "manifest.json", MAX_MANIFEST as u64)?;
        let signature_file = readat(dir.as_raw_fd(), "manifest.sig", 129)?;
        let signature = if signature_file.len() == 64 {
            signature_file
        } else {
            let text = std::str::from_utf8(&signature_file)
                .map_err(|_| "Invalid signature encoding")?
                .trim();
            if text.len() != 128 {
                return Err("Invalid signature encoding".into());
            }
            hex::decode(text).map_err(|_| "Invalid signature encoding")?
        };
        let parsed: Manifest = serde_json::from_slice(&bytes).map_err(|_| "invalid manifest")?;
        validate(&parsed)?;
        let mut files = BTreeMap::new();
        for artifact in &parsed.artifacts {
            files.insert(
                artifact.name.clone(),
                readat(dir.as_raw_fd(), &artifact.name, MAX_ARTIFACT as u64)?,
            );
        }
        let key_id = hex::encode(Sha256::digest(key.as_bytes()));
        let trusted = BTreeMap::from([(key_id, key)]);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "Invalid system clock")?
            .as_secs();
        let (manifest, db) = verify(
            &bytes,
            &signature,
            &trusted,
            &files,
            now,
            high,
            scanner_version,
        )?;
        let approval = readat(dir.as_raw_fd(), "approval.json", MAX_MANIFEST as u64)?;
        let approval_signature = readat(dir.as_raw_fd(), "approval.sig", 64)?;
        let release_key = trusted.values().next().ok_or("Missing release key")?;
        verify_approval(
            &bytes,
            &approval,
            &approval_signature,
            &reviewer,
            release_key,
            now,
        )?;
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        if manifest.release_number == high && high != 0 && state[8..] != hash {
            return Err("Release sequence equivocation rejected".into());
        }
        if manifest.release_number > high
            && high != 0
            && manifest.previous_manifest_sha256.as_deref()
                != Some(hex::encode(&state[8..]).as_str())
        {
            return Err("Previous manifest digest mismatch".into());
        }
        if manifest.release_number > high {
            let filename = format!(
                ".public-release-state-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            let mut f = openat(
                state_dir.as_raw_fd(),
                &filename,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )?;
            let result = (|| {
                f.write_all(&manifest.release_number.to_le_bytes())
                    .and_then(|_| f.write_all(&hash))
                    .and_then(|_| f.sync_all())
                    .map_err(|e| e.to_string())?;
                let source = CString::new(filename.as_str()).map_err(|_| "Invalid state name")?;
                let destination = CString::new(STATE).map_err(|_| "Invalid state name")?;
                if unsafe {
                    libc::renameat(
                        state_dir.as_raw_fd(),
                        source.as_ptr(),
                        state_dir.as_raw_fd(),
                        destination.as_ptr(),
                    )
                } != 0
                {
                    return Err("Cannot publish release state".into());
                }
                state_dir
                    .sync_all()
                    .map_err(|e| format!("Release state sync failed: {e}"))
            })();
            if result.is_err() {
                if let Ok(path) = CString::new(filename) {
                    unsafe {
                        libc::unlinkat(state_dir.as_raw_fd(), path.as_ptr(), 0);
                    }
                }
            }
            result?;
        }
        Ok(db)
    }
}
