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

//! Minimal local database lifecycle: verified install, atomic activation,
//! last-known-good retention, rollback and automatic fallback on corruption.
//!
//! Store layout (`root/`):
//! ```text
//! releases/<sha256>.rsidb   immutable, content-addressed, read-only (0444)
//! current                   pointer file: "<sha256>.rsidb\n"  (atomically replaced)
//! previous                  pointer file: last known-good release
//! ```
//! Pointer files are replaced via write-temp + fsync + rename, which is atomic on POSIX
//! filesystems. Release files are never modified in place, so an already-mapped
//! database is never mutated underneath a running scanner.
//!
//! NOT YET IMPLEMENTED: cryptographic authentication of releases (see HANDOFF_GEMINI.md).
//! The SHA-256 pin in `install` only protects against corruption when the expected digest
//! comes from a trusted channel.

use super::crypto;
use super::error::DatabaseError;
use super::ingest::BuildManifest;
use super::mmap_compact_dir::MmapCompactDirIndex;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct DbStore {
    root: PathBuf,
}

/// Result of opening the active database.
pub struct ActiveDb {
    pub index: MmapCompactDirIndex,
    pub release: String,
    /// True when `current` failed validation and `previous` was used instead.
    pub fell_back: bool,
    pub fallback_reason: Option<String>,
}

fn io(ctx: &str, e: std::io::Error) -> DatabaseError {
    DatabaseError::Io(format!("{}: {}", ctx, e))
}

impl DbStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn releases(&self) -> PathBuf {
        self.root.join("releases")
    }

    fn read_pointer(&self, name: &str) -> Option<String> {
        let ptr_path = self.root.join(name);
        if let Ok(meta) = fs::symlink_metadata(&ptr_path) {
            if meta.file_type().is_symlink() {
                return None;
            }
        }
        let s = fs::read_to_string(ptr_path).ok()?;
        let s = s.trim().to_string();
        // Only accept content-addressed names: prevents path traversal via pointer files.
        let valid = s.len() == 64 + 6
            && s.ends_with(".rsidb")
            && s[..64]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
        valid.then_some(s)
    }

    fn write_pointer(&self, name: &str, release: &str) -> Result<(), DatabaseError> {
        let ptr_path = self.root.join(name);
        if let Ok(meta) = fs::symlink_metadata(&ptr_path) {
            if meta.file_type().is_symlink() {
                fs::remove_file(&ptr_path).map_err(|e| io("remove symlink pointer", e))?;
            }
        }
        let tmp = self.root.join(format!(".{}.tmp", name));
        {
            let mut f = fs::File::create(&tmp).map_err(|e| io("create pointer", e))?;
            f.write_all(format!("{}\n", release).as_bytes())
                .map_err(|e| io("write pointer", e))?;
            f.sync_all().map_err(|e| io("sync pointer", e))?;
        }
        fs::rename(&tmp, self.root.join(name)).map_err(|e| io("rename pointer", e))?;
        if let Ok(d) = fs::File::open(&self.root) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    pub fn current_release(&self) -> Option<String> {
        self.read_pointer("current")
    }

    pub fn previous_release(&self) -> Option<String> {
        self.read_pointer("previous")
    }

    pub fn release_path(&self, release: &str) -> PathBuf {
        self.releases().join(release)
    }

    /// Verifies and installs an authenticated or development release into the database store.
    ///
    /// For signed releases (`allow_unsigned == false`):
    /// - Requires `manifest_path`, `signature_path`, and `trusted_pubkey`.
    /// - Verifies the Ed25519 signature on the release manifest.
    /// - Verifies that the candidate database SHA-256 matches the signed manifest `db_sha256`.
    /// - Verifies the candidate database binary format and checksums.
    ///
    /// For unsigned releases (`allow_unsigned == true`):
    /// - Explicitly permits local development testing without Ed25519 signatures.
    /// - Still validates the candidate database binary structure and optional SHA-256 pin.
    ///
    /// Installation is atomic (write-temp -> fsync -> rename) and non-destructive.
    /// The previously active release is preserved in `previous` for instant rollback.
    pub fn install_release(
        &self,
        candidate_db: &Path,
        manifest_path: Option<&Path>,
        signature_path: Option<&Path>,
        trusted_pubkey: Option<&VerifyingKey>,
        allow_unsigned: bool,
    ) -> Result<String, DatabaseError> {
        let db_bytes = fs::read(candidate_db).map_err(|e| io("read candidate database", e))?;
        let digest = hex::encode(Sha256::digest(&db_bytes));

        let mut manifest_raw: Option<Vec<u8>> = None;
        let mut sig_raw: Option<Vec<u8>> = None;

        if !allow_unsigned {
            let m_path = manifest_path.ok_or_else(|| {
                DatabaseError::Policy(
                    "release manifest (.manifest.json) required for signed release installation"
                        .into(),
                )
            })?;
            let s_path = signature_path.ok_or_else(|| {
                DatabaseError::Policy(
                    "release signature (.sig) required for signed release installation".into(),
                )
            })?;
            let pubkey = trusted_pubkey.ok_or_else(|| {
                DatabaseError::Policy(
                    "trusted public key required for signed release verification".into(),
                )
            })?;

            let m_bytes = fs::read(m_path).map_err(|e| io("read release manifest", e))?;
            let sig = crypto::load_signature_from_file(s_path)?;

            let _manifest = crypto::verify_release_package(&m_bytes, &sig, pubkey, &db_bytes)?;
            manifest_raw = Some(m_bytes);
            sig_raw = Some(fs::read(s_path).map_err(|e| io("read signature file", e))?);
        } else {
            // Unsigned development mode: optionally read and cross-check manifest if provided
            if let Some(m_path) = manifest_path {
                if let Ok(m_bytes) = fs::read(m_path) {
                    if let Ok(m) = serde_json::from_slice::<BuildManifest>(&m_bytes) {
                        if !digest.eq_ignore_ascii_case(&m.db_sha256) {
                            return Err(DatabaseError::Policy(format!(
                                "candidate database sha256 {} does not match manifest {}",
                                digest, m.db_sha256
                            )));
                        }
                        manifest_raw = Some(m_bytes);
                    }
                }
            }
        }

        // Validate RSIDB binary format
        MmapCompactDirIndex::from_bytes(db_bytes.clone())?;

        fs::create_dir_all(self.releases()).map_err(|e| io("create store", e))?;
        let release = format!("{}.rsidb", digest);
        let dest = self.release_path(&release);
        if let Ok(meta) = fs::symlink_metadata(&dest) {
            if meta.file_type().is_symlink() {
                return Err(DatabaseError::Policy(format!(
                    "release destination cannot be a symlink: {}",
                    dest.display()
                )));
            }
        }
        if !dest.exists() {
            let tmp = self.releases().join(format!(".{}.tmp", digest));
            {
                let mut f = fs::File::create(&tmp).map_err(|e| io("create release", e))?;
                f.write_all(&db_bytes).map_err(|e| io("write release", e))?;
                f.sync_all().map_err(|e| io("sync release", e))?;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o444));
            }
            fs::rename(&tmp, &dest).map_err(|e| io("rename release", e))?;
        }

        // Store manifest and signature in releases/ alongside database for auditability
        if let Some(m_bytes) = manifest_raw {
            let m_dest = self.releases().join(format!("{}.manifest.json", digest));
            let _ = fs::write(m_dest, m_bytes);
        }
        if let Some(s_bytes) = sig_raw {
            let s_dest = self.releases().join(format!("{}.sig", digest));
            let _ = fs::write(s_dest, s_bytes);
        }

        // Re-verify what is actually on disk before activation.
        MmapCompactDirIndex::from_file(&dest)?;

        if let Some(cur) = self.current_release() {
            if cur != release {
                self.write_pointer("previous", &cur)?;
            }
        }
        self.write_pointer("current", &release)?;
        Ok(release)
    }

    /// Verifies `candidate` (structure, checksum and optional trusted SHA-256 pin), copies
    /// it into the store, re-verifies the stored copy and atomically activates it.
    /// The previously active release becomes `previous` (last known good).
    pub fn install(
        &self,
        candidate: &Path,
        expected_sha256: Option<&str>,
    ) -> Result<String, DatabaseError> {
        let bytes = fs::read(candidate).map_err(|e| io("read candidate", e))?;
        let digest = hex::encode(Sha256::digest(&bytes));
        if let Some(exp) = expected_sha256 {
            if !exp.eq_ignore_ascii_case(&digest) {
                return Err(DatabaseError::Policy(format!(
                    "candidate sha256 {} does not match expected {}",
                    digest, exp
                )));
            }
        }
        self.install_release(candidate, None, None, None, true)
    }

    /// Swaps `current` and `previous`. Fails if no valid previous release exists.
    pub fn rollback(&self) -> Result<String, DatabaseError> {
        let prev = self
            .previous_release()
            .ok_or_else(|| DatabaseError::Policy("no previous release to roll back to".into()))?;
        MmapCompactDirIndex::from_file(&self.release_path(&prev))?;
        if let Some(cur) = self.current_release() {
            self.write_pointer("previous", &cur)?;
        }
        self.write_pointer("current", &prev)?;
        Ok(prev)
    }

    /// Opens and fully validates `current`; on failure falls back to `previous`.
    /// Never returns an unvalidated database.
    pub fn open_active(&self) -> Result<ActiveDb, DatabaseError> {
        let reason;
        if let Some(cur) = self.current_release() {
            match MmapCompactDirIndex::from_file(&self.release_path(&cur)) {
                Ok(index) => {
                    return Ok(ActiveDb {
                        index,
                        release: cur,
                        fell_back: false,
                        fallback_reason: None,
                    })
                }
                Err(e) => reason = Some(format!("current release {} invalid: {}", cur, e)),
            }
        } else {
            reason = Some("no valid current pointer".to_string());
        }
        if let Some(prev) = self.previous_release() {
            let index = MmapCompactDirIndex::from_file(&self.release_path(&prev))?;
            return Ok(ActiveDb {
                index,
                release: prev,
                fell_back: true,
                fallback_reason: reason,
            });
        }
        Err(DatabaseError::Policy(format!(
            "no valid database available: {}",
            reason.unwrap_or_default()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsidb::{HashAlgorithm, RsidbCompiler, RsidbIndex, SignatureEntry};

    fn db(name: &str) -> Vec<u8> {
        RsidbCompiler::new()
            .compile(vec![SignatureEntry::new(
                HashAlgorithm::Md5,
                10,
                vec![7u8; 16],
                name,
            )])
            .unwrap()
    }

    #[test]
    fn install_rollback_and_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let store = DbStore::new(dir.path().join("store"));
        let a = dir.path().join("a.rsidb");
        let b = dir.path().join("b.rsidb");
        fs::write(&a, db("A")).unwrap();
        fs::write(&b, db("B")).unwrap();

        let ra = store.install(&a, None).unwrap();
        let rb = store.install(&b, None).unwrap();
        assert_eq!(store.current_release().unwrap(), rb);
        assert_eq!(store.previous_release().unwrap(), ra);
        assert_eq!(
            store
                .open_active()
                .unwrap()
                .index
                .lookup(HashAlgorithm::Md5, 10, &[7u8; 16]),
            vec!["B"]
        );

        // Corrupt candidate is rejected and does not change activation.
        let bad = dir.path().join("bad.rsidb");
        let mut bytes = db("C");
        let n = bytes.len();
        bytes[n - 1] ^= 0xff;
        fs::write(&bad, bytes).unwrap();
        assert!(store.install(&bad, None).is_err());
        assert!(store.install(&a, Some(&"0".repeat(64))).is_err());
        assert_eq!(store.current_release().unwrap(), rb);

        // Rollback.
        assert_eq!(store.rollback().unwrap(), ra);
        assert_eq!(store.current_release().unwrap(), ra);
        store.rollback().unwrap();

        // Corrupt the active release on disk: open_active falls back to last known good.
        let p = store.release_path(&rb);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let mut cur = fs::read(&p).unwrap();
        let n = cur.len();
        cur[n - 1] ^= 0xff;
        fs::write(&p, cur).unwrap();
        let active = store.open_active().unwrap();
        assert!(active.fell_back);
        assert_eq!(active.release, ra);

        // Pointer traversal attempt is ignored.
        fs::write(dir.path().join("store/current"), "../../etc/passwd\n").unwrap();
        assert!(store.current_release().is_none());
    }
}
