// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! Offline prototype signer. Run only in an approved signing environment.
use ed25519_dalek::SigningKey;
use raxosentinel_signatures::rsidb::public_release::{sign, Manifest};
use std::io::Read;
fn main() {
    if let Err(error) = run() {
        eprintln!("Signing failed: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 2 {
        return Err("Usage: public_release_signer CANONICAL_MANIFEST < RAW_32_BYTE_KEY".into());
    }
    let bytes = std::fs::read(&args[1]).map_err(|_| "Cannot read manifest")?;
    if bytes.len() > 1024 * 1024 {
        return Err("Manifest too large".into());
    }
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| "Invalid manifest")?;
    let mut key_bytes = [0u8; 32];
    let mut input = std::io::stdin().lock();
    input
        .read_exact(&mut key_bytes)
        .map_err(|_| "Expected 32 key bytes")?;
    let mut extra = [0u8; 1];
    if input.read(&mut extra).map_err(|_| "Cannot read key")? != 0 {
        key_bytes.fill(0);
        return Err("Expected exactly 32 key bytes".into());
    }
    let key = SigningKey::from_bytes(&key_bytes);
    key_bytes.fill(0);
    let (canonical, signature) = sign(&manifest, &key)?;
    if canonical != bytes {
        return Err("Manifest is not canonical".into());
    }
    println!("{}", hex::encode(signature));
    Ok(())
}
