// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! Native RSIDB automated update engine implementing the end-to-end reconciliation pipeline.

use crate::rsidb::malwarebazaar::private_store;
use crate::rsidb::malwarebazaar::private_store::unified::{
    self, publish_unified, UnifiedAssociations, UnifiedClaim, UnifiedIndicator, UnifiedRegistry,
    UnifiedSource,
};
use crate::rsidb::updater::status::{SourceStatus, UpdateStatus, UpdateSummary};
use crate::rsidb::updater::traits::{
    ExtractedIntelligence, IntelligenceProvider, ProviderState, RecordKey, UpdateCheckResult,
    UpdateError,
};
use crate::rsidb::{HashAlgorithm, RsidbIndex, SignatureEntry};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);

pub const LOCK_FILE: &str = "updater.lock";
pub const CURRENT_PTR: &str = "current";
pub const PREVIOUS_PTR: &str = "previous";
pub const DEFAULT_ANOMALY_THRESHOLD_PCT: f64 = 20.0;

/// RAII lock guard holding flock on updater.lock.
#[derive(Debug)]
pub struct UpdateLockGuard {
    file: File,
}

impl Drop for UpdateLockGuard {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Read a pointer file containing a generation name.
pub fn read_pointer(root: &Path, name: &str) -> Option<String> {
    let ptr_path = root.join(name);
    if let Ok(meta) = fs::symlink_metadata(&ptr_path) {
        if meta.file_type().is_symlink() {
            return None;
        }
    }
    let s = fs::read_to_string(ptr_path).ok()?;
    let trimmed = s.trim().to_string();
    if !trimmed.is_empty()
        && trimmed.len() <= 120
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Some(trimmed)
    } else {
        None
    }
}

/// Atomically write a pointer file via temporary file + sync + rename.
pub fn write_pointer(root: &Path, name: &str, target_generation: &str) -> Result<(), UpdateError> {
    if target_generation.is_empty()
        || target_generation.len() > 120
        || !target_generation
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(UpdateError::ActivationFailed(format!(
            "Invalid generation name for pointer '{}': '{}'",
            name, target_generation
        )));
    }

    let ptr_path = root.join(name);
    let tmp_path = root.join(format!(".{}.tmp-{}", name, std::process::id()));

    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| {
                UpdateError::ActivationFailed(format!("Failed to create pointer temp file: {e}"))
            })?;

        f.write_all(format!("{}\n", target_generation).as_bytes())
            .map_err(|e| UpdateError::ActivationFailed(format!("Failed to write pointer: {e}")))?;
        f.sync_all().map_err(|e| {
            UpdateError::ActivationFailed(format!("Failed to sync pointer temp file: {e}"))
        })?;
    }

    fs::rename(&tmp_path, &ptr_path).map_err(|e| {
        UpdateError::ActivationFailed(format!("Failed to atomically rename pointer: {e}"))
    })?;

    // Sync root directory
    if let Ok(root_file) = File::open(root) {
        let _ = root_file.sync_all();
    }

    Ok(())
}

/// Engine coordinating automated multi-source intelligence updates into ONE RSIDB.
pub struct UpdateEngine {
    pub root: PathBuf,
    pub providers: Vec<Box<dyn IntelligenceProvider>>,
    pub anomaly_threshold_pct: f64,
}

impl UpdateEngine {
    /// Create a new UpdateEngine for the specified private storage root.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            providers: Vec::new(),
            anomaly_threshold_pct: DEFAULT_ANOMALY_THRESHOLD_PCT,
        }
    }

    /// Register an intelligence provider adapter.
    pub fn with_provider(mut self, provider: Box<dyn IntelligenceProvider>) -> Self {
        self.providers.push(provider);
        self
    }

    /// Set the safety anomaly threshold percentage (maximum allowed indicator drop before trigger).
    pub fn with_anomaly_threshold(mut self, threshold_pct: f64) -> Self {
        self.anomaly_threshold_pct = threshold_pct;
        self
    }

    /// Acquire the exclusive process-level advisory lock on the storage root.
    pub fn acquire_lock(&self) -> Result<UpdateLockGuard, UpdateError> {
        let lock_path = self.root.join(LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| {
                UpdateError::Io(format!(
                    "Failed to open lockfile {}: {e}",
                    lock_path.display()
                ))
            })?;

        let res = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if res != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EWOULDBLOCK)
                || err.raw_os_error() == Some(libc::EAGAIN)
            {
                return Err(UpdateError::LockContention);
            }
            return Err(UpdateError::Io(format!(
                "flock failed on {}: {err}",
                lock_path.display()
            )));
        }

        Ok(UpdateLockGuard { file })
    }

    /// Resolve the active generation name, initializing the `current` pointer if needed.
    pub fn resolve_active_generation(&self) -> Option<String> {
        if let Some(cur) = read_pointer(&self.root, CURRENT_PTR) {
            return Some(cur);
        }

        // Auto-discover existing unified generations
        let candidates = ["phase2d6-unified", "phase2d4-refreshed-final"];
        for c in &candidates {
            if self.root.join(c).join("database.rsidb").exists() {
                let _ = write_pointer(&self.root, CURRENT_PTR, c);
                return Some(c.to_string());
            }
        }

        None
    }

    /// Check all registered providers for available intelligence updates without modifying state.
    pub fn check_all(&self) -> Result<BTreeMap<String, UpdateCheckResult>, UpdateError> {
        let mut status = UpdateStatus::load(&self.root);
        let mut results = BTreeMap::new();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for provider in &self.providers {
            let p_state = status
                .sources
                .get(provider.id())
                .map(|s| ProviderState {
                    last_check_timestamp: s.last_check_timestamp,
                    last_import_timestamp: s.last_import_timestamp,
                    last_version: s.source_version.clone(),
                    indicator_count: s.indicator_count,
                    extra: BTreeMap::new(),
                })
                .unwrap_or_default();

            match provider.check_update(&p_state) {
                Ok(chk) => {
                    let entry = status
                        .sources
                        .entry(provider.id().to_string())
                        .or_insert_with(|| SourceStatus {
                            id: provider.id().to_string(),
                            name: provider.name().to_string(),
                            ..Default::default()
                        });
                    entry.last_check_timestamp = now;
                    entry.latest_upstream_version = chk.version.clone();
                    entry.last_error = None;
                    results.insert(provider.id().to_string(), chk);
                }
                Err(e) => {
                    let entry = status
                        .sources
                        .entry(provider.id().to_string())
                        .or_insert_with(|| SourceStatus {
                            id: provider.id().to_string(),
                            name: provider.name().to_string(),
                            ..Default::default()
                        });
                    entry.last_check_timestamp = now;
                    entry.last_error = Some(e.to_string());
                    return Err(e);
                }
            }
        }

        let _ = status.save(&self.root);
        Ok(results)
    }

    /// Run the full automated update pipeline:
    /// CHECK -> ACQUIRE -> VERIFY -> NORMALIZE -> VALIDATE -> RECONCILE -> BUILD -> VERIFY -> ACTIVATE
    pub fn apply_update(&self, force: bool) -> Result<Option<UpdateSummary>, UpdateError> {
        let _lock = self.acquire_lock()?;
        let start_time = Instant::now();

        let mut status = UpdateStatus::load(&self.root);
        let active_gen = self.resolve_active_generation();
        status.current_generation = active_gen.clone();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        status.last_run_timestamp = now;

        // 1. Check all providers
        let mut updates_to_run: Vec<(&Box<dyn IntelligenceProvider>, UpdateCheckResult)> =
            Vec::new();
        for provider in &self.providers {
            let p_state = status
                .sources
                .get(provider.id())
                .map(|s| ProviderState {
                    last_check_timestamp: s.last_check_timestamp,
                    last_import_timestamp: s.last_import_timestamp,
                    last_version: s.source_version.clone(),
                    indicator_count: s.indicator_count,
                    extra: BTreeMap::new(),
                })
                .unwrap_or_default();

            let chk = provider.check_update(&p_state)?;
            let src_entry = status
                .sources
                .entry(provider.id().to_string())
                .or_insert_with(|| SourceStatus {
                    id: provider.id().to_string(),
                    name: provider.name().to_string(),
                    ..Default::default()
                });
            src_entry.last_check_timestamp = now;
            src_entry.latest_upstream_version = chk.version.clone();
            src_entry.last_error = None;

            if chk.available || force {
                updates_to_run.push((provider, chk));
            }
        }

        if updates_to_run.is_empty() {
            let _ = status.save(&self.root);
            return Ok(None);
        }

        // 2. Create isolated staging workspace
        let seq = STAGING_SEQ.fetch_add(1, Ordering::Relaxed);
        let staging_name = format!(".update-staging-{}-{}", std::process::id(), seq);
        let staging_dir = self.root.join(&staging_name);
        fs::create_dir_all(&staging_dir).map_err(|e| {
            UpdateError::StagingError(format!(
                "Failed to create staging dir {}: {e}",
                staging_dir.display()
            ))
        })?;

        // Guard to ensure staging cleanup on error
        struct StagingCleanup<'a>(&'a Path);
        impl<'a> Drop for StagingCleanup<'a> {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(self.0);
            }
        }
        let _staging_guard = StagingCleanup(&staging_dir);

        // 3. Acquire and extract intelligence from updated providers
        let mut extracted_by_source: BTreeMap<String, ExtractedIntelligence> = BTreeMap::new();
        for (provider, _chk) in &updates_to_run {
            let prov_staging = staging_dir.join(provider.id());
            fs::create_dir_all(&prov_staging).map_err(|e| {
                UpdateError::StagingError(format!("Failed to create provider staging: {e}"))
            })?;

            let acq = provider.acquire_update(&prov_staging)?;
            let ext = provider.extract_records(&acq)?;
            extracted_by_source.insert(provider.id().to_string(), ext);
        }

        // 4. Load baseline from existing generation (if available)
        let mut existing_claims_by_record: BTreeMap<RecordKey, BTreeSet<UnifiedClaim>> =
            BTreeMap::new();
        let mut existing_sources: BTreeMap<String, UnifiedSource> = BTreeMap::new();
        let mut existing_evidence: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut previous_total_count = 0usize;

        if let Some(ref cur_gen) = active_gen {
            let (reg, assoc) = unified::inspect(&self.root, cur_gen).map_err(|e| {
                UpdateError::DatabaseVerificationFailed(
                    cur_gen.clone(),
                    format!("Failed to load baseline active generation: {e}"),
                )
            })?;
            previous_total_count = assoc.indicators.len();
            for s in reg.sources {
                existing_sources.insert(s.id.clone(), s);
            }
            for ind in assoc.indicators {
                let alg = match ind.alg.as_str() {
                    "md5" => HashAlgorithm::Md5,
                    "sha1" => HashAlgorithm::Sha1,
                    "sha256" => HashAlgorithm::Sha256,
                    _ => continue,
                };
                let digest = match hex::decode(&ind.hash) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                let rkey: RecordKey = (alg, digest, ind.size, ind.name.clone());
                let mut claim_set = BTreeSet::new();
                for c in ind.claims {
                    claim_set.insert(c);
                }
                existing_claims_by_record.insert(rkey, claim_set);
            }

            // Preserve existing evidence files from previous generation directory
            let cur_gen_dir = self.root.join(cur_gen);
            if let Ok(entries) = fs::read_dir(&cur_gen_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(fname) = path.file_name().and_then(|f| f.to_str()) {
                        if fname.starts_with("evidence-") || fname.starts_with("acq-") {
                            if let Ok(bytes) = fs::read(&path) {
                                existing_evidence.insert(fname.to_string(), bytes);
                            }
                        }
                    }
                }
            }
        }

        // 5. Reconcile records across sources
        // Gather all active revocations from updated sources
        let mut all_revocations: HashSet<RecordKey> = HashSet::new();
        for ext in extracted_by_source.values() {
            all_revocations.extend(ext.revocations.iter().cloned());
        }

        // Build new claims map
        let mut reconciled_claims: BTreeMap<RecordKey, BTreeSet<UnifiedClaim>> = BTreeMap::new();

        // (a) First, retain claims from sources that were NOT updated in this run
        for (rkey, claims) in &existing_claims_by_record {
            if all_revocations.contains(rkey) {
                continue;
            }
            let mut retained = BTreeSet::new();
            for c in claims {
                if !extracted_by_source.contains_key(&c.source_id) {
                    retained.insert(c.clone());
                }
            }
            if !retained.is_empty() {
                reconciled_claims.insert(rkey.clone(), retained);
            }
        }

        // (b) Next, incorporate newly extracted claims
        for (src_id, ext) in &extracted_by_source {
            for (rkey, claims) in &ext.claims {
                if all_revocations.contains(rkey) {
                    continue;
                }
                reconciled_claims
                    .entry(rkey.clone())
                    .or_default()
                    .extend(claims.iter().cloned());
            }

            // Update source info and evidence
            existing_sources.insert(src_id.clone(), ext.source_info.clone());
            for (ev_name, ev_bytes) in &ext.evidence_files {
                existing_evidence.insert(ev_name.clone(), ev_bytes.clone());
            }
        }

        // 6. Anomaly / Mass Deletion Check
        let new_total_count = reconciled_claims.len();
        if previous_total_count > 0 && new_total_count < previous_total_count {
            let drop_pct = ((previous_total_count - new_total_count) as f64
                / previous_total_count as f64)
                * 100.0;
            if drop_pct > self.anomaly_threshold_pct {
                return Err(UpdateError::SuspiciousReduction {
                    source_name: "all_sources_reconciled".to_string(),
                    previous: previous_total_count,
                    current: new_total_count,
                    drop_pct,
                    threshold_pct: self.anomaly_threshold_pct,
                });
            }
        }

        // 7. Compile unified SignatureEntry list and deduplicate
        let mut gross_records_acquired = 0usize;
        let mut total_provider_rejected = 0usize;
        let mut provider_duplicates = 0usize;
        for ext in extracted_by_source.values() {
            gross_records_acquired += ext.gross_records;
            total_provider_rejected += ext.rejected_records;
            if ext.duplicate_records > 0 {
                provider_duplicates += ext.duplicate_records;
            } else {
                provider_duplicates += ext.entries.len().saturating_sub(ext.claims.len());
            }
        }

        let mut entries: Vec<SignatureEntry> = Vec::with_capacity(reconciled_claims.len());
        let mut unified_indicators: Vec<UnifiedIndicator> =
            Vec::with_capacity(reconciled_claims.len());
        let mut md5_count = 0usize;
        let mut sha1_count = 0usize;
        let mut sha256_count = 0usize;

        for (rkey, claims) in &reconciled_claims {
            let (alg, digest, size, name) = rkey;
            entries.push(SignatureEntry::new(
                *alg,
                *size,
                digest.clone(),
                name.clone(),
            ));
            match alg {
                HashAlgorithm::Md5 => md5_count += 1,
                HashAlgorithm::Sha1 => sha1_count += 1,
                HashAlgorithm::Sha256 => sha256_count += 1,
            }

            unified_indicators.push(UnifiedIndicator {
                alg: match alg {
                    HashAlgorithm::Md5 => "md5".to_string(),
                    HashAlgorithm::Sha1 => "sha1".to_string(),
                    HashAlgorithm::Sha256 => "sha256".to_string(),
                },
                hash: hex::encode(digest),
                size: *size,
                name: name.clone(),
                claims: claims.iter().cloned().collect(),
            });
        }

        entries.sort();
        let pre_dedup = entries.len();
        entries.dedup();
        let cross_source_dedup = pre_dedup.saturating_sub(entries.len());
        let deduplicated_count = provider_duplicates + cross_source_dedup;

        let final_count = entries.len();
        let unified_associations = UnifiedAssociations {
            version: 1,
            total_indicators: final_count,
            indicators: unified_indicators,
        };

        // Build UnifiedRegistry
        let mut source_list: Vec<UnifiedSource> = existing_sources.into_values().collect();
        source_list.sort_by(|a, b| a.id.cmp(&b.id));

        let unified_registry = UnifiedRegistry {
            version: 1,
            sources: source_list,
            total_indicators: final_count,
            md5_count,
            sha1_count,
            sha256_count,
        };

        let evidence_files: Vec<(String, Vec<u8>)> = existing_evidence.into_iter().collect();

        // 8. Generate unique immutable generation name
        let gen_name = format!("phase2d7-unified-{}-{}", now, seq);

        // Publish unified generation atomically
        publish_unified(
            &self.root,
            &gen_name,
            entries,
            unified_registry,
            unified_associations,
            evidence_files,
        )
        .map_err(|e| UpdateError::DatabaseVerificationFailed(gen_name.clone(), e))?;

        // 9. Strict database verification before activation
        let (verified_db, _timings) = private_store::load_timed(&self.root, &gen_name)
            .map_err(|e| UpdateError::DatabaseVerificationFailed(gen_name.clone(), e))?;

        // Spot-check indicator lookups
        if verified_db.total_records() != final_count {
            return Err(UpdateError::DatabaseVerificationFailed(
                gen_name,
                format!(
                    "Record count mismatch: expected {}, got {}",
                    final_count,
                    verified_db.total_records()
                ),
            ));
        }

        // Test non-malicious input (clean file must not match)
        let clean_buf = b"benign clean test data";
        let clean_digest = Sha256::digest(clean_buf);
        let matches =
            verified_db.lookup(HashAlgorithm::Sha256, clean_buf.len() as u64, &clean_digest);
        if !matches.is_empty() {
            return Err(UpdateError::DatabaseVerificationFailed(
                gen_name,
                "Clean test buffer unexpectedly triggered threat detection".to_string(),
            ));
        }

        // 10. Atomic Pointer Activation
        if let Some(ref old) = active_gen {
            write_pointer(&self.root, PREVIOUS_PTR, old)?;
        }
        write_pointer(&self.root, CURRENT_PTR, &gen_name)?;

        // Update provider statuses
        for (provider, chk) in &updates_to_run {
            if let Some(ext) = extracted_by_source.get(provider.id()) {
                let s_entry = status.sources.entry(provider.id().to_string()).or_default();
                s_entry.id = provider.id().to_string();
                s_entry.name = provider.name().to_string();
                s_entry.active_version = chk.version.clone();
                s_entry.source_version = chk.version.clone();
                s_entry.latest_upstream_version = chk.version.clone();
                s_entry.indicator_count = ext.entries.len();
                s_entry.last_import_timestamp = now;
                s_entry.last_error = None;
            }
        }

        // Strict independent accounting of additions, removals, and retentions
        let new_records = reconciled_claims
            .keys()
            .filter(|k| !existing_claims_by_record.contains_key(*k))
            .count();

        let removed_records = existing_claims_by_record
            .keys()
            .filter(|k| !reconciled_claims.contains_key(*k))
            .count();

        let retained_records = existing_claims_by_record
            .iter()
            .filter(|(k, old_claims)| {
                if !reconciled_claims.contains_key(*k) {
                    return false;
                }
                let had_updating_source = old_claims
                    .iter()
                    .any(|c| extracted_by_source.contains_key(&c.source_id));
                if !had_updating_source {
                    return false;
                }
                let new_claims = &reconciled_claims[*k];
                let has_updating_source_now = new_claims
                    .iter()
                    .any(|c| extracted_by_source.contains_key(&c.source_id));
                !has_updating_source_now
            })
            .count();

        let net_count_change = (final_count as i64) - (previous_total_count as i64);

        // Strict invariant enforcement: Final count = Initial count + additions − removals
        let expected_final = previous_total_count + new_records - removed_records;
        if final_count != expected_final {
            return Err(UpdateError::VerificationFailed {
                provider: "engine".to_string(),
                message: format!(
                    "Accounting invariant violated: final ({}) != initial ({}) + additions ({}) - removals ({})",
                    final_count, previous_total_count, new_records, removed_records
                ),
            });
        }

        let effective_gross = if gross_records_acquired > 0 {
            gross_records_acquired
        } else {
            final_count + deduplicated_count + total_provider_rejected
        };

        let effective_rejected = if total_provider_rejected > 0 {
            total_provider_rejected
        } else {
            all_revocations.len()
        };

        let summary = UpdateSummary {
            generation: gen_name.clone(),
            initial_indicators: previous_total_count,
            total_indicators: final_count,
            gross_records_acquired: effective_gross,
            new_records,
            removed_records,
            retained_records,
            deduplicated_records: deduplicated_count,
            rejected_records: effective_rejected,
            net_count_change,
            verification_result: "PASS".to_string(),
            duration_ms: start_time.elapsed().as_millis() as u64,
        };

        status.current_generation = Some(gen_name);
        status.previous_generation = active_gen;
        status.last_summary = Some(summary.clone());
        status.last_error = None;
        let _ = status.save(&self.root);

        Ok(Some(summary))
    }

    /// Roll back the active database to the previous known-good generation.
    pub fn rollback(&self) -> Result<String, UpdateError> {
        let _lock = self.acquire_lock()?;
        let rollback_start = Instant::now();
        let prev_gen = read_pointer(&self.root, PREVIOUS_PTR).ok_or_else(|| {
            UpdateError::RollbackFailed("No previous generation pointer found".to_string())
        })?;

        let old_current = read_pointer(&self.root, CURRENT_PTR);
        if let Some(ref cur) = old_current {
            if cur == &prev_gen {
                return Err(UpdateError::RollbackFailed(format!(
                    "Cyclic rollback target: previous generation equals current generation '{}'",
                    prev_gen
                )));
            }
        }

        // Strict verification of the previous generation before activating it
        private_store::load(&self.root, &prev_gen).map_err(|e| {
            UpdateError::RollbackFailed(format!(
                "Previous generation '{}' failed verification: {e}",
                prev_gen
            ))
        })?;

        let old_total = old_current
            .as_deref()
            .and_then(|g| unified::inspect(&self.root, g).ok())
            .map(|(r, _)| r.total_indicators)
            .unwrap_or(0);

        let (prev_reg, _) = unified::inspect(&self.root, &prev_gen).map_err(|e| {
            UpdateError::RollbackFailed(format!(
                "Failed to inspect target rollback generation: {e}"
            ))
        })?;
        let prev_total = prev_reg.total_indicators;

        write_pointer(&self.root, CURRENT_PTR, &prev_gen)?;
        if let Some(ref old) = old_current {
            if old != &prev_gen {
                let _ = write_pointer(&self.root, PREVIOUS_PTR, old);
            }
        }

        // Authoritatively derive status and source metadata from the active generation (prev_gen)
        let mut status = UpdateStatus::load(&self.root);
        status.current_generation = Some(prev_gen.clone());
        status.previous_generation = old_current;

        let removed_from_old = old_total.saturating_sub(prev_total);
        let added_to_prev = prev_total.saturating_sub(old_total);
        let net_change = (prev_total as i64) - (old_total as i64);

        status.last_summary = Some(UpdateSummary {
            generation: prev_gen.clone(),
            initial_indicators: old_total,
            total_indicators: prev_total,
            gross_records_acquired: 0,
            new_records: added_to_prev,
            removed_records: removed_from_old,
            retained_records: 0,
            deduplicated_records: 0,
            rejected_records: 0,
            net_count_change: net_change,
            verification_result: "PASS (ROLLBACK)".to_string(),
            duration_ms: rollback_start.elapsed().as_millis() as u64,
        });

        status.save(&self.root).map_err(|e| {
            UpdateError::Io(format!(
                "Failed to persist update_status.json after rollback: {e}"
            ))
        })?;

        Ok(prev_gen)
    }
}
