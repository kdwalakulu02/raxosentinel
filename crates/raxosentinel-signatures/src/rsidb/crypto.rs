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

//! Cryptographic release signing and verification using Ed25519.
//!
//! Release artifacts:
//! - `<name>.rsidb`: binary database
//! - `<name>.manifest.json`: JSON manifest describing contents & SHA-256
//! - `<name>.sig`: Ed25519 signature of the manifest bytes
//!
//! Verification ensures that:
//! 1. The manifest is signed by a trusted Ed25519 public key.
//! 2. The database file matches the `db_sha256` recorded in the signed manifest.
//! 3. The database binary conforms to the RSIDB structural and checksum specification.
//!
//! Private signing keys are never stored in the database or committed to version control.

use super::error::DatabaseError;
use super::ingest::BuildManifest;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Generates a new random Ed25519 keypair for offline release signing.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut rng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Saves an Ed25519 private signing key to a file as a hex string with restricted permissions (0600 on Unix).
pub fn save_signing_key_to_file(key: &SigningKey, path: &Path) -> Result<(), DatabaseError> {
    let hex_key = hex::encode(key.to_bytes());
    fs::write(path, format!("{}\n", hex_key))
        .map_err(|e| DatabaseError::Io(format!("failed to write signing key: {}", e)))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Loads an Ed25519 private signing key from a file (accepts hex string or 32 raw bytes).
pub fn load_signing_key_from_file(path: &Path) -> Result<SigningKey, DatabaseError> {
    let bytes = fs::read(path)
        .map_err(|e| DatabaseError::Io(format!("failed to read signing key: {}", e)))?;
    let key_bytes = parse_32_bytes(&bytes, "signing key")?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

/// Saves an Ed25519 public verification key to a file as a hex string.
pub fn save_verifying_key_to_file(key: &VerifyingKey, path: &Path) -> Result<(), DatabaseError> {
    let hex_key = hex::encode(key.to_bytes());
    fs::write(path, format!("{}\n", hex_key))
        .map_err(|e| DatabaseError::Io(format!("failed to write verifying key: {}", e)))?;
    Ok(())
}

/// Loads an Ed25519 public verification key from a file (accepts hex string or 32 raw bytes).
pub fn load_verifying_key_from_file(path: &Path) -> Result<VerifyingKey, DatabaseError> {
    let bytes = fs::read(path)
        .map_err(|e| DatabaseError::Io(format!("failed to read verifying key: {}", e)))?;
    let key_bytes = parse_32_bytes(&bytes, "verifying key")?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| DatabaseError::Policy(format!("invalid Ed25519 public key: {}", e)))
}

/// Signs arbitrary data bytes using an Ed25519 signing key.
pub fn sign_bytes(data: &[u8], key: &SigningKey) -> Signature {
    key.sign(data)
}

/// Verifies that `signature` is valid for `data` under `key`.
pub fn verify_signature(
    data: &[u8],
    signature: &Signature,
    key: &VerifyingKey,
) -> Result<(), DatabaseError> {
    key.verify(data, signature)
        .map_err(|e| DatabaseError::Policy(format!("Ed25519 signature verification failed: {}", e)))
}

/// Saves an Ed25519 signature to a file as a hex string.
pub fn save_signature_to_file(sig: &Signature, path: &Path) -> Result<(), DatabaseError> {
    let hex_sig = hex::encode(sig.to_bytes());
    fs::write(path, format!("{}\n", hex_sig))
        .map_err(|e| DatabaseError::Io(format!("failed to write signature file: {}", e)))?;
    Ok(())
}

/// Loads an Ed25519 signature from a file (accepts hex string or 64 raw bytes).
pub fn load_signature_from_file(path: &Path) -> Result<Signature, DatabaseError> {
    let bytes = fs::read(path)
        .map_err(|e| DatabaseError::Io(format!("failed to read signature file: {}", e)))?;
    let sig_bytes = parse_64_bytes(&bytes, "signature")?;
    Ok(Signature::from_bytes(&sig_bytes))
}

/// Fully validates a release package:
/// 1. Verifies manifest signature against `trusted_key`.
/// 2. Parses and validates `BuildManifest`.
/// 3. Computes SHA-256 of `db_bytes` and verifies it matches `manifest.db_sha256`.
pub fn verify_release_package(
    manifest_bytes: &[u8],
    signature: &Signature,
    trusted_key: &VerifyingKey,
    db_bytes: &[u8],
) -> Result<BuildManifest, DatabaseError> {
    // 1. Verify cryptographic signature of manifest
    verify_signature(manifest_bytes, signature, trusted_key)?;

    // 2. Parse BuildManifest
    let manifest: BuildManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|e| DatabaseError::Policy(format!("release manifest JSON is invalid: {}", e)))?;

    // 3. Compute database SHA-256 and match against manifest
    let actual_sha256 = hex::encode(Sha256::digest(db_bytes));
    if !actual_sha256.eq_ignore_ascii_case(&manifest.db_sha256) {
        return Err(DatabaseError::Policy(format!(
            "database SHA-256 mismatch: candidate is {} but signed manifest specifies {}",
            actual_sha256, manifest.db_sha256
        )));
    }

    if db_bytes.len() as u64 != manifest.db_bytes {
        return Err(DatabaseError::Policy(format!(
            "database byte size mismatch: candidate is {} bytes but signed manifest specifies {}",
            db_bytes.len(),
            manifest.db_bytes
        )));
    }

    Ok(manifest)
}

fn parse_32_bytes(raw: &[u8], label: &str) -> Result<[u8; 32], DatabaseError> {
    let s = std::str::from_utf8(raw).map(|s| s.trim()).unwrap_or("");
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        let vec = hex::decode(s)
            .map_err(|e| DatabaseError::Policy(format!("invalid hex in {}: {}", label, e)))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&vec);
        return Ok(arr);
    }
    if raw.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(raw);
        return Ok(arr);
    }
    Err(DatabaseError::Policy(format!(
        "invalid {} length: expected 32 raw bytes or 64 hex characters, got {} bytes",
        label,
        raw.len()
    )))
}

fn parse_64_bytes(raw: &[u8], label: &str) -> Result<[u8; 64], DatabaseError> {
    let s = std::str::from_utf8(raw).map(|s| s.trim()).unwrap_or("");
    if s.len() == 128 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        let vec = hex::decode(s)
            .map_err(|e| DatabaseError::Policy(format!("invalid hex in {}: {}", label, e)))?;
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&vec);
        return Ok(arr);
    }
    if raw.len() == 64 {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(raw);
        return Ok(arr);
    }
    Err(DatabaseError::Policy(format!(
        "invalid {} length: expected 64 raw bytes or 128 hex characters, got {} bytes",
        label,
        raw.len()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_signing_and_verification_roundtrip() {
        let (sk, vk) = generate_keypair();
        let payload = b"RaxoSentinel release manifest content";
        let sig = sign_bytes(payload, &sk);

        // Verification with valid key succeeds
        assert!(verify_signature(payload, &sig, &vk).is_ok());

        // Verification of tampered payload fails
        let mut tampered = payload.to_vec();
        tampered[0] ^= 0x01;
        assert!(verify_signature(&tampered, &sig, &vk).is_err());

        // Verification with wrong key fails
        let (_, wrong_vk) = generate_keypair();
        assert!(verify_signature(payload, &sig, &wrong_vk).is_err());
    }

    #[test]
    fn test_key_and_signature_file_serialization() {
        let dir = tempfile::tempdir().unwrap();
        let sk_path = dir.path().join("dev.key");
        let vk_path = dir.path().join("dev.pub");
        let sig_path = dir.path().join("release.sig");

        let (sk, vk) = generate_keypair();
        save_signing_key_to_file(&sk, &sk_path).unwrap();
        save_verifying_key_to_file(&vk, &vk_path).unwrap();

        let loaded_sk = load_signing_key_from_file(&sk_path).unwrap();
        let loaded_vk = load_verifying_key_from_file(&vk_path).unwrap();

        assert_eq!(sk.to_bytes(), loaded_sk.to_bytes());
        assert_eq!(vk.to_bytes(), loaded_vk.to_bytes());

        let payload = b"manifest bytes to sign";
        let sig = sign_bytes(payload, &loaded_sk);
        save_signature_to_file(&sig, &sig_path).unwrap();
        let loaded_sig = load_signature_from_file(&sig_path).unwrap();

        assert_eq!(sig.to_bytes(), loaded_sig.to_bytes());
        assert!(verify_signature(payload, &loaded_sig, &loaded_vk).is_ok());
    }
}
