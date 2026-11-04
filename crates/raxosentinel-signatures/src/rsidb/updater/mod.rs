// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! Automated intelligence update pipeline for native RSIDB generations.

pub mod engine;
pub mod providers;
pub mod status;
pub mod traits;

#[cfg(test)]
pub mod tests;

pub use engine::{read_pointer, write_pointer, UpdateEngine, CURRENT_PTR, PREVIOUS_PTR};
pub use providers::{ClamAvProvider, MalwareBazaarProvider};
pub use status::{SourceStatus, UpdateStatus, UpdateSummary};
pub use traits::{
    AcquisitionResult, ExtractedIntelligence, IntelligenceProvider, ProviderState, RecordKey,
    UpdateCheckResult, UpdateError,
};
