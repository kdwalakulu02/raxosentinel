// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! Shared abstractions for automated multi-source intelligence updates.

use crate::rsidb::malwarebazaar::private_store::unified::{UnifiedClaim, UnifiedSource};
use crate::rsidb::{HashAlgorithm, SignatureEntry};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

/// Record identification key: (Algorithm, Digest bytes, File size constraint, Detection name).
pub type RecordKey = (HashAlgorithm, Vec<u8>, u64, String);

/// Errors that can occur during the intelligence update lifecycle.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("Provider '{provider}' check failed: {message}")]
    CheckFailed { provider: String, message: String },

    #[error("Provider '{provider}' acquisition failed: {message}")]
    AcquisitionFailed { provider: String, message: String },

    #[error("Provider '{provider}' verification failed: {message}")]
    VerificationFailed { provider: String, message: String },

    #[error("Extraction failed for provider '{provider}': {message}")]
    ExtractionFailed { provider: String, message: String },

    #[error("Lock contention: another updater instance is actively holding the update lock")]
    LockContention,

    #[error("Suspicious reduction detected for source '{source_name}': dropped from {previous} to {current} indicators ({drop_pct:.1}% drop exceeds {threshold_pct:.1}% safety threshold)")]
    SuspiciousReduction {
        source_name: String,
        previous: usize,
        current: usize,
        drop_pct: f64,
        threshold_pct: f64,
    },

    #[error("Database verification failed for generation '{0}': {1}")]
    DatabaseVerificationFailed(String, String),

    #[error("Atomic activation failed: {0}")]
    ActivationFailed(String),

    #[error("Rollback failed: {0}")]
    RollbackFailed(String),

    #[error("Staging directory error: {0}")]
    StagingError(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("General updater error: {0}")]
    Other(String),
}

/// Recorded state for a single intelligence provider across runs.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderState {
    pub last_check_timestamp: u64,
    pub last_import_timestamp: u64,
    pub last_version: String,
    pub indicator_count: usize,
    #[serde(default)]
    pub extra: BTreeMap<String, String>,
}

/// Result of checking whether new intelligence is available from a provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateCheckResult {
    pub available: bool,
    pub version: String,
    pub details: String,
}

/// Result of acquiring intelligence artifacts into private staging.
#[derive(Clone, Debug)]
pub struct AcquisitionResult {
    pub source_id: String,
    pub version: String,
    pub timestamp: u64,
    pub evidence_files: Vec<(String, Vec<u8>)>,
    pub staging_path: Option<PathBuf>,
}

/// Normalized intelligence extracted and validated from acquired source data.
#[derive(Clone, Debug)]
pub struct ExtractedIntelligence {
    pub source_info: UnifiedSource,
    pub entries: Vec<SignatureEntry>,
    pub claims: BTreeMap<RecordKey, BTreeSet<UnifiedClaim>>,
    pub revocations: HashSet<RecordKey>,
    pub evidence_files: Vec<(String, Vec<u8>)>,
}

/// Shared trait implemented by every intelligence provider adapter.
pub trait IntelligenceProvider: Send + Sync {
    /// Unique machine identifier (e.g. "clamav", "malwarebazaar").
    fn id(&self) -> &str;

    /// Human-readable provider name (e.g. "ClamAV", "MalwareBazaar").
    fn name(&self) -> &str;

    /// Check if new intelligence is available without performing full extraction.
    fn check_update(&self, state: &ProviderState) -> Result<UpdateCheckResult, UpdateError>;

    /// Acquire intelligence into the designated private staging directory.
    fn acquire_update(&self, staging_dir: &Path) -> Result<AcquisitionResult, UpdateError>;

    /// Extract, validate, and normalize records into native RSIDB entries.
    fn extract_records(
        &self,
        acquisition: &AcquisitionResult,
    ) -> Result<ExtractedIntelligence, UpdateError>;
}
