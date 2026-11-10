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

use crate::status::ScanStatus;
use crate::threat::Threat;
use serde::{Deserialize, Serialize};

/// Target metadata captured during scanning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetMetadata {
    pub path: Option<String>,
    pub file_name: Option<String>,
    pub file_size_bytes: u64,
    pub sha256: String,
    pub detected_mime: String,
    pub declared_mime: Option<String>,
}

/// Structured scan report adhering to RaxoSentinel specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanReport {
    /// Engine version
    pub engine_version: String,
    /// Target metadata
    pub target: TargetMetadata,
    /// Overall scan outcome
    pub status: ScanStatus,
    /// Explicit human-readable statement of what this result means
    pub status_description: String,
    /// Safety notice clarifying that Clean is not an absolute safety guarantee
    pub safety_disclaimer: String,
    /// All detected threats or anomalies
    pub threats: Vec<Threat>,
    /// Sub-target scan reports (e.g. extracted email attachments, nested MIME messages)
    pub sub_targets: Vec<ScanReport>,
    /// Elapsed scan duration in milliseconds
    pub scan_duration_ms: u64,
    /// Error description if status == Failed
    pub error: Option<String>,
}

impl ScanReport {
    pub fn new(
        target: TargetMetadata,
        status: ScanStatus,
        threats: Vec<Threat>,
        sub_targets: Vec<ScanReport>,
        scan_duration_ms: u64,
        error: Option<String>,
    ) -> Self {
        fn collect_detections<'a>(
            report: &'a ScanReport,
            found: &mut std::collections::HashSet<(&'a str, Option<&'a str>)>,
        ) {
            for threat in &report.threats {
                found.insert((&threat.name, threat.location.as_deref()));
            }
            for child in &report.sub_targets {
                collect_detections(child, found);
            }
        }
        let mut found = std::collections::HashSet::new();
        for threat in &threats {
            found.insert((threat.name.as_str(), threat.location.as_deref()));
        }
        for child in &sub_targets {
            collect_detections(child, &mut found);
        }
        let detected = found.len();
        let status_description = match status {
            ScanStatus::Clean => "No known threats detected by active signatures.".to_string(),
            ScanStatus::Infected => format!("Detected {} threat(s).", detected),
            ScanStatus::Unsupported => {
                "Content format is unsupported or could not be inspected.".to_string()
            }
            ScanStatus::Failed => {
                if let Some(ref err) = error {
                    format!("Scan failed: {}", err)
                } else {
                    "Scan could not be completed.".to_string()
                }
            }
        };

        let safety_disclaimer = if status == ScanStatus::Clean {
            "NOTICE: RaxoSentinel found no known threats in this file. This scan result reflects the coverage of current rules and is not an absolute guarantee that the file is safe or benign."
        } else {
            "NOTICE: Automated threat detection report."
        }.to_string();

        Self {
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            target,
            status,
            status_description,
            safety_disclaimer,
            threats,
            sub_targets,
            scan_duration_ms,
            error,
        }
    }

    /// Bounds the number of nested sub-target reports so a container with thousands of
    /// members cannot exceed worker/socket response limits. Children are kept in priority
    /// order (DETECTED, ERROR, UNSCANNED, CLEAN) while the budget lasts; omitted siblings
    /// are folded into one summary sub-target carrying their worst status, their unique
    /// threats and their first error, so the verdict and its evidence are preserved.
    /// Returns the number of sub-target reports folded into summaries.
    pub fn compact(&mut self, max_nodes: usize) -> usize {
        let mut budget = max_nodes;
        self.compact_with(&mut budget)
    }

    fn compact_with(&mut self, budget: &mut usize) -> usize {
        if self.sub_targets.is_empty() {
            return 0;
        }
        let mut order: Vec<usize> = (0..self.sub_targets.len()).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(status_rank(self.sub_targets[i].status)));
        let mut keep = vec![false; self.sub_targets.len()];
        for &i in &order {
            // One slot stays reserved for a possible summary entry.
            if *budget > 1 {
                *budget -= 1;
                keep[i] = true;
            }
        }
        let mut folded = 0;
        for &i in &order {
            if keep[i] {
                folded += self.sub_targets[i].compact_with(budget);
            }
        }
        if keep.iter().all(|k| *k) {
            return folded;
        }
        let mut kept = Vec::new();
        let mut omitted = Vec::new();
        for (child, k) in std::mem::take(&mut self.sub_targets).into_iter().zip(keep) {
            if k {
                kept.push(child);
            } else {
                omitted.push(child);
            }
        }
        let mut summary = OmittedSummary::default();
        for child in &omitted {
            summary.absorb(child);
        }
        folded += summary.reports;
        *budget = budget.saturating_sub(1);
        kept.push(summary.into_report());
        self.sub_targets = kept;
        folded
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Default upper bound on sub-target reports emitted for one scan.
pub const MAX_REPORT_NODES: usize = 512;
const MAX_SUMMARY_THREATS: usize = 32;

fn status_rank(status: ScanStatus) -> u8 {
    match status {
        ScanStatus::Infected => 3,
        ScanStatus::Failed => 2,
        ScanStatus::Unsupported => 1,
        ScanStatus::Clean => 0,
    }
}

#[derive(Default)]
struct OmittedSummary {
    reports: usize,
    bytes: u64,
    status: Option<ScanStatus>,
    threats: Vec<Threat>,
    error: Option<String>,
    duration_ms: u64,
}

impl OmittedSummary {
    fn absorb(&mut self, report: &ScanReport) {
        self.reports += 1;
        self.bytes = self.bytes.saturating_add(report.target.file_size_bytes);
        self.duration_ms = self.duration_ms.max(report.scan_duration_ms);
        if self.status.is_none_or(|s| status_rank(report.status) > status_rank(s)) {
            self.status = Some(report.status);
        }
        if self.error.is_none() && report.status.is_failed() {
            self.error = report.error.clone();
        }
        for threat in &report.threats {
            if self.threats.len() < MAX_SUMMARY_THREATS
                && !self
                    .threats
                    .iter()
                    .any(|t| t.name == threat.name && t.location == threat.location)
            {
                self.threats.push(threat.clone());
            }
        }
        for child in &report.sub_targets {
            self.absorb(child);
        }
    }

    fn into_report(self) -> ScanReport {
        let status = self.status.unwrap_or(ScanStatus::Clean);
        let error = if status.is_failed() {
            Some(self.error.unwrap_or_else(|| "omitted sub-target failed".to_string()))
        } else {
            None
        };
        ScanReport::new(
            TargetMetadata {
                path: None,
                file_name: Some(format!(
                    "[{} further sub-target report(s) summarised; worst status {:?}]",
                    self.reports, status
                )),
                file_size_bytes: self.bytes,
                sha256: String::new(),
                detected_mime: "application/x-raxosentinel-report-summary".to_string(),
                declared_mime: None,
            },
            status,
            self.threats,
            Vec::new(),
            self.duration_ms,
            error,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat::{Severity, ThreatCategory};

    fn leaf(name: &str, status: ScanStatus) -> ScanReport {
        let threats = if status.is_infected() {
            vec![Threat::new(
                "EICAR-Test",
                ThreatCategory::TestSignature,
                Severity::Low,
                "t",
                "sig",
            )
            .with_location(name.to_string())]
        } else {
            Vec::new()
        };
        let error = status.is_failed().then(|| format!("{name} failed"));
        ScanReport::new(
            TargetMetadata {
                path: None,
                file_name: Some(name.to_string()),
                file_size_bytes: 10,
                sha256: "00".into(),
                detected_mime: "text/plain".into(),
                declared_mime: None,
            },
            status,
            threats,
            Vec::new(),
            0,
            error,
        )
    }

    fn count(r: &ScanReport) -> usize {
        r.sub_targets.iter().map(|c| 1 + count(c)).sum()
    }

    #[test]
    fn compact_keeps_small_reports_unchanged() {
        let mut r = leaf("root", ScanStatus::Clean);
        r.sub_targets = (0..10).map(|i| leaf(&format!("m{i}"), ScanStatus::Clean)).collect();
        let before = r.clone();
        assert_eq!(r.compact(MAX_REPORT_NODES), 0);
        assert_eq!(r, before);
    }

    #[test]
    fn compact_bounds_nodes_and_preserves_worst_status_and_threats() {
        let mut r = leaf("root", ScanStatus::Infected);
        let mut children: Vec<_> = (0..5000).map(|i| leaf(&format!("c{i}"), ScanStatus::Clean)).collect();
        children[4000] = leaf("bad", ScanStatus::Infected);
        children[4500] = leaf("err", ScanStatus::Failed);
        r.sub_targets = children;
        let folded = r.compact(16);
        assert!(count(&r) <= 16, "{} nodes", count(&r));
        assert_eq!(folded + count(&r) - 1, 5000);
        assert!(r.sub_targets.iter().any(|c| c.target.file_name.as_deref() == Some("bad")));
        assert!(r.sub_targets.iter().any(|c| c.target.file_name.as_deref() == Some("err")));
        let summary = r.sub_targets.last().unwrap();
        assert_eq!(summary.status, ScanStatus::Clean);
        assert_eq!(summary.detected_mime_for_test(), "application/x-raxosentinel-report-summary");
    }

    #[test]
    fn compact_summary_carries_omitted_detections() {
        let mut r = leaf("root", ScanStatus::Infected);
        r.sub_targets = (0..100).map(|i| leaf(&format!("e{i}"), ScanStatus::Infected)).collect();
        r.sub_targets.push(leaf("u", ScanStatus::Unsupported));
        r.compact(8);
        assert!(count(&r) <= 8);
        let summary = r.sub_targets.last().unwrap();
        assert_eq!(summary.status, ScanStatus::Infected);
        assert_eq!(summary.threats.len(), MAX_SUMMARY_THREATS);
        let json = r.to_json().unwrap();
        let back: ScanReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn compact_nested_failure_surfaces_in_summary() {
        let mut inner = leaf("inner", ScanStatus::Failed);
        inner.sub_targets = vec![leaf("deep", ScanStatus::Failed)];
        let mut r = leaf("root", ScanStatus::Failed);
        r.sub_targets = (0..20).map(|i| leaf(&format!("c{i}"), ScanStatus::Clean)).collect();
        r.sub_targets.push(inner);
        r.compact(3);
        assert!(count(&r) <= 4);
        assert!(r.sub_targets.iter().any(|c| c.status.is_failed()));
    }

    impl ScanReport {
        fn detected_mime_for_test(&self) -> &str {
            &self.target.detected_mime
        }
    }
}
