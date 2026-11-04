// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! Persistent state and status reporting for automated intelligence updates.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

pub const STATUS_FILE: &str = "update_status.json";

/// Summary of metrics from the most recent database update run.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct UpdateSummary {
    pub generation: String,
    pub total_indicators: usize,
    pub new_records: usize,
    pub removed_records: usize,
    pub deduplicated_records: usize,
    pub rejected_records: usize,
    pub verification_result: String,
    pub duration_ms: u64,
}

/// Status for an individual intelligence source provider.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceStatus {
    pub id: String,
    pub name: String,
    pub last_check_timestamp: u64,
    pub last_import_timestamp: u64,
    pub source_version: String,
    pub indicator_count: usize,
    pub last_error: Option<String>,
}

/// Root status document maintained in the private intelligence store.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct UpdateStatus {
    pub current_generation: Option<String>,
    pub previous_generation: Option<String>,
    pub last_run_timestamp: u64,
    pub last_error: Option<String>,
    pub sources: BTreeMap<String, SourceStatus>,
    pub last_summary: Option<UpdateSummary>,
}

impl UpdateStatus {
    /// Load the status file from the private store root, or return default.
    pub fn load(root: &Path) -> Self {
        let path = root.join(STATUS_FILE);
        let mut status = if path.exists() {
            if let Ok(bytes) = fs::read(&path) {
                serde_json::from_slice::<UpdateStatus>(&bytes).unwrap_or_default()
            } else {
                Self::default()
            }
        } else {
            Self::default()
        };

        if status.current_generation.is_none() {
            let current_ptr = root.join("current");
            if current_ptr.exists() {
                if let Ok(s) = fs::read_to_string(&current_ptr) {
                    let gen = s.trim().to_string();
                    if !gen.is_empty() {
                        status.current_generation = Some(gen);
                    }
                }
            }
        }

        if status.previous_generation.is_none() {
            let prev_ptr = root.join("previous");
            if prev_ptr.exists() {
                if let Ok(s) = fs::read_to_string(&prev_ptr) {
                    let gen = s.trim().to_string();
                    if !gen.is_empty() {
                        status.previous_generation = Some(gen);
                    }
                }
            }
        }

        status
    }

    /// Atomically persist status into the private store root.
    pub fn save(&self, root: &Path) -> Result<(), String> {
        let path = root.join(STATUS_FILE);
        let tmp = root.join(format!(".{}.tmp", STATUS_FILE));
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        {
            let mut f = fs::File::create(&tmp)
                .map_err(|e| format!("Failed to create {}: {e}", tmp.display()))?;
            f.write_all(&bytes)
                .map_err(|e| format!("Failed to write {}: {e}", tmp.display()))?;
            f.sync_all()
                .map_err(|e| format!("Failed to sync {}: {e}", tmp.display()))?;
        }
        fs::rename(&tmp, &path).map_err(|e| format!("Failed to rename status file: {e}"))?;
        Ok(())
    }

    /// Format status report into human-readable text consistent with project reporting style.
    pub fn format_display(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "================================================================================\n",
        );
        out.push_str(
            "                   RAXOSENTINEL INTELLIGENCE UPDATE STATUS                      \n",
        );
        out.push_str(
            "================================================================================\n",
        );
        out.push_str(&format!(
            "Current RSIDB Generation : {}\n",
            self.current_generation.as_deref().unwrap_or("none")
        ));
        out.push_str(&format!(
            "Previous Generation      : {}\n",
            self.previous_generation.as_deref().unwrap_or("none")
        ));
        out.push_str(&format!(
            "Last Update Run (UTC)    : {}\n",
            if self.last_run_timestamp > 0 {
                self.last_run_timestamp.to_string()
            } else {
                "never".to_string()
            }
        ));
        if let Some(ref err) = self.last_error {
            out.push_str(&format!("Last Execution Error     : {}\n", err));
        }

        if let Some(ref sum) = self.last_summary {
            out.push_str("--------------------------------------------------------------------------------\n");
            out.push_str("LAST UPDATE METRICS:\n");
            out.push_str(&format!("  Target Generation      : {}\n", sum.generation));
            out.push_str(&format!(
                "  Total Unique Records   : {}\n",
                sum.total_indicators
            ));
            out.push_str(&format!("  New Records Added      : {}\n", sum.new_records));
            out.push_str(&format!(
                "  Removed Records        : {}\n",
                sum.removed_records
            ));
            out.push_str(&format!(
                "  Deduplicated Records   : {}\n",
                sum.deduplicated_records
            ));
            out.push_str(&format!(
                "  Rejected/Excluded      : {}\n",
                sum.rejected_records
            ));
            out.push_str(&format!(
                "  Verification Status    : {}\n",
                sum.verification_result
            ));
            out.push_str(&format!(
                "  Pipeline Duration      : {} ms\n",
                sum.duration_ms
            ));
        }

        out.push_str(
            "--------------------------------------------------------------------------------\n",
        );
        out.push_str("CONFIGURED INTELLIGENCE SOURCES:\n");
        if self.sources.is_empty() {
            out.push_str("  (No sources registered)\n");
        } else {
            for (id, s) in &self.sources {
                out.push_str(&format!("  Source: {} [{}]\n", s.name, id));
                out.push_str(&format!(
                    "    Source Version       : {}\n",
                    s.source_version
                ));
                out.push_str(&format!(
                    "    Indicators Tracked   : {}\n",
                    s.indicator_count
                ));
                out.push_str(&format!(
                    "    Last Check (Unix)    : {}\n",
                    s.last_check_timestamp
                ));
                out.push_str(&format!(
                    "    Last Import (Unix)   : {}\n",
                    s.last_import_timestamp
                ));
                if let Some(ref err) = s.last_error {
                    out.push_str(&format!("    Last Error           : {}\n", err));
                }
            }
        }
        out.push_str(
            "================================================================================\n",
        );
        out
    }
}
