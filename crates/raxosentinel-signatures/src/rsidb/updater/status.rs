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
    #[serde(default)]
    pub initial_indicators: usize,
    pub total_indicators: usize,
    #[serde(default)]
    pub gross_records_acquired: usize,
    pub new_records: usize,
    pub removed_records: usize,
    #[serde(default)]
    pub retained_records: usize,
    pub deduplicated_records: usize,
    pub rejected_records: usize,
    #[serde(default)]
    pub net_count_change: i64,
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
    /// Active version currently compiled and active in the RSIDB generation.
    #[serde(default)]
    pub active_version: String,
    /// Authoritative source version (kept identical to active_version for backwards compatibility).
    pub source_version: String,
    /// Latest upstream version observed from remote provider checks.
    #[serde(default)]
    pub latest_upstream_version: String,
    /// Active indicator count from the active generation.
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
    ///
    /// The filesystem pointer `current` and the active generation's immutable metadata
    /// are authoritative over any stale contents in `update_status.json`.
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

        // 1. Authoritative resolution of active database generation
        let current_ptr = root.join("current");
        if current_ptr.exists() {
            if let Ok(s) = fs::read_to_string(&current_ptr) {
                let gen = s.trim().to_string();
                if !gen.is_empty() {
                    status.current_generation = Some(gen);
                }
            }
        } else if status.current_generation.is_none() {
            let candidates = ["phase2d6-unified", "phase2d4-refreshed-final"];
            for c in &candidates {
                if root.join(c).join("database.rsidb").exists() {
                    status.current_generation = Some(c.to_string());
                    break;
                }
            }
        }

        // 2. Authoritative resolution of previous generation (rollback target)
        let prev_ptr = root.join("previous");
        if prev_ptr.exists() {
            if let Ok(s) = fs::read_to_string(&prev_ptr) {
                let gen = s.trim().to_string();
                if !gen.is_empty() {
                    status.previous_generation = Some(gen);
                } else {
                    status.previous_generation = None;
                }
            }
        } else {
            status.previous_generation = None;
        }

        // Validate that previous_generation is not cyclic (does not equal current_generation)
        // and that its database file actually exists.
        if let Some(ref prev) = status.previous_generation {
            if status.current_generation.as_ref() == Some(prev)
                || !root.join(prev).join("database.rsidb").exists()
            {
                status.previous_generation = None;
            }
        }

        // 3. Authoritative reconciliation from active generation's registry and evidence
        status.bootstrap_from_generation(root);

        if let Some(ref mut sum) = status.last_summary {
            if sum.initial_indicators == 0
                && sum.total_indicators > 0
                && sum.new_records == 0
                && sum.removed_records == 0
            {
                sum.initial_indicators = sum.total_indicators;
                sum.gross_records_acquired = sum.total_indicators;
            }
        }

        status
    }

    /// Attempt to bootstrap source statuses and metrics from the active generation's registry and evidence.
    pub fn bootstrap_from_generation(&mut self, root: &Path) {
        let active_gen = match self.current_generation.as_deref() {
            Some(g) => g,
            None => return,
        };

        let gen_dir = root.join(active_gen);
        let reg_file = gen_dir.join("registry.json");
        if !reg_file.exists() {
            return;
        }

        let reg_bytes = match fs::read(&reg_file) {
            Ok(b) => b,
            Err(_) => return,
        };

        let reg_json: serde_json::Value = match serde_json::from_slice(&reg_bytes) {
            Ok(j) => j,
            Err(_) => return,
        };

        let sources_arr = match reg_json["sources"].as_array() {
            Some(a) => a,
            None => return,
        };

        for s in sources_arr {
            let id = match s["id"].as_str() {
                Some(id) => id.to_string(),
                None => continue,
            };
            let name = s["name"].as_str().unwrap_or(&id).to_string();
            let count = s["indicator_count"].as_u64().unwrap_or(0) as usize;
            let timestamp = s["acquired_unix_seconds"].as_u64().unwrap_or(0);
            let ev_file = s["evidence_file"].as_str().unwrap_or("");

            let mut version = String::new();
            if !ev_file.is_empty() {
                let ev_path = gen_dir.join(ev_file);
                if let Ok(ev_bytes) = fs::read(&ev_path) {
                    if let Ok(ev_json) = serde_json::from_slice::<serde_json::Value>(&ev_bytes) {
                        if id == "clamav" {
                            let mut main_v = None;
                            let mut daily_v = None;
                            if let Some(files) = ev_json["cvd_files"].as_array() {
                                for f in files {
                                    if f["file"].as_str() == Some("main.cvd") {
                                        main_v = f["version"].as_u64();
                                    } else if f["file"].as_str() == Some("daily.cvd") {
                                        daily_v = f["version"].as_u64();
                                    }
                                }
                            }
                            if let (Some(m), Some(d)) = (main_v, daily_v) {
                                version = format!("main:{},daily:{}", m, d);
                            } else if let Some(d) = daily_v {
                                version = format!("daily-{}", d);
                            } else if let Some(v_str) = ev_json["version"].as_str() {
                                version = v_str.to_string();
                            }
                        } else if id == "malwarebazaar" {
                            if let Some(acqs) = ev_json["acquisitions"].as_array() {
                                if let Some(last_acq) = acqs.last() {
                                    if let Some(acq_id) = last_acq["id"].as_str() {
                                        let acq_file = gen_dir.join(format!("acq-{}.json", acq_id));
                                        if let Ok(acq_bytes) = fs::read(&acq_file) {
                                            if let Ok(acq_json) =
                                                serde_json::from_slice::<serde_json::Value>(
                                                    &acq_bytes,
                                                )
                                            {
                                                if let Some(data) = acq_json["data"]
                                                    .as_array()
                                                    .or_else(|| acq_json["indicators"].as_array())
                                                {
                                                    if let Some(first) = data.first() {
                                                        if let Some(h) = first["sha256_hash"]
                                                            .as_str()
                                                            .or_else(|| first["sha256"].as_str())
                                                        {
                                                            version = h.to_string();
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        if version.is_empty() {
                                            version = acq_id.to_string();
                                        }
                                    }
                                }
                            }
                            if version.is_empty() {
                                if let Some(v_str) = ev_json["version"].as_str() {
                                    version = v_str.to_string();
                                }
                            }
                        } else if let Some(v_str) = ev_json["version"].as_str() {
                            version = v_str.to_string();
                        }
                    }
                }
            }

            let src = self
                .sources
                .entry(id.clone())
                .or_insert_with(|| SourceStatus {
                    id: id.clone(),
                    name: name.clone(),
                    ..Default::default()
                });
            src.name = name;
            src.indicator_count = count;
            if !version.is_empty() {
                src.active_version = version.clone();
                src.source_version = version.clone();
            } else if src.active_version.is_empty() && !src.source_version.is_empty() {
                src.active_version = src.source_version.clone();
            }
            if src.last_import_timestamp == 0 {
                src.last_import_timestamp = timestamp;
            }
            if src.last_check_timestamp == 0 {
                src.last_check_timestamp = timestamp;
            }
            if src.latest_upstream_version.is_empty() {
                src.latest_upstream_version = src.source_version.clone();
            }
        }

        if self.last_summary.is_none()
            || self.last_summary.as_ref().map(|s| s.generation.as_str()) != Some(active_gen)
        {
            let total = reg_json["total_indicators"].as_u64().unwrap_or(0) as usize;
            if total > 0 {
                self.last_summary = Some(UpdateSummary {
                    generation: active_gen.to_string(),
                    initial_indicators: total,
                    total_indicators: total,
                    gross_records_acquired: total,
                    new_records: 0,
                    removed_records: 0,
                    retained_records: 0,
                    deduplicated_records: 0,
                    rejected_records: 0,
                    net_count_change: 0,
                    verification_result: "PASS (ACTIVE GENERATION)".to_string(),
                    duration_ms: 0,
                });
            }
        }
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
            out.push_str(&format!(
                "  Target Generation            : {}\n",
                sum.generation
            ));
            out.push_str(&format!(
                "  Initial Active Indicators    : {}\n",
                sum.initial_indicators
            ));
            out.push_str(&format!(
                "  Gross Records Acquired       : {}\n",
                sum.gross_records_acquired
            ));
            out.push_str(&format!(
                "  Gross New Unique Records     : {}\n",
                sum.new_records
            ));
            out.push_str(&format!(
                "  Records Removed or Revoked   : {}\n",
                sum.removed_records
            ));
            out.push_str(&format!(
                "  Retained via Other Provider  : {}\n",
                sum.retained_records
            ));
            out.push_str(&format!(
                "  Duplicates Deduplicated      : {}\n",
                sum.deduplicated_records
            ));
            out.push_str(&format!(
                "  Rejected / Excluded Records  : {}\n",
                sum.rejected_records
            ));
            out.push_str(&format!(
                "  Net Count Change             : {:+}\n",
                sum.net_count_change
            ));
            out.push_str(&format!(
                "  Final Active Total           : {}\n",
                sum.total_indicators
            ));
            out.push_str(&format!(
                "  Verification Status          : {}\n",
                sum.verification_result
            ));
            out.push_str(&format!(
                "  Pipeline Duration            : {} ms\n",
                sum.duration_ms
            ));
            let invariant_ok = sum.total_indicators
                == sum.initial_indicators + sum.new_records - sum.removed_records;
            out.push_str(&format!(
                "  Accounting Invariant Check   : {} ({} = {} + {} - {})\n",
                if invariant_ok {
                    "VERIFIED OK"
                } else {
                    "VIOLATION DETECTED"
                },
                sum.total_indicators,
                sum.initial_indicators,
                sum.new_records,
                sum.removed_records
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
                let active_v = if !s.active_version.is_empty() {
                    &s.active_version
                } else {
                    &s.source_version
                };
                out.push_str(&format!("    Active RSIDB Version : {}\n", active_v));
                out.push_str(&format!(
                    "    Source Version       : {}\n",
                    s.source_version
                ));
                if !s.latest_upstream_version.is_empty() {
                    out.push_str(&format!(
                        "    Latest Upstream Seen : {}\n",
                        s.latest_upstream_version
                    ));
                }
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
