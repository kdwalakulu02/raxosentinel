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

use serde::{Deserialize, Serialize};
use std::fs;

/// Process memory usage statistics.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct MemoryUsage {
    /// Current resident set size (RSS) in kibibytes (KiB)
    pub current_rss_kib: u64,
    /// Peak resident set size (High Water Mark / VmHWM) in kibibytes (KiB)
    pub peak_rss_kib: u64,
    /// Current virtual memory size (VmSize) in kibibytes (KiB)
    pub virtual_size_kib: u64,
}

impl MemoryUsage {
    /// Captures current memory usage from Linux /proc/self/status if available.
    pub fn capture() -> Self {
        let mut usage = Self::default();

        if let Ok(content) = fs::read_to_string("/proc/self/status") {
            for line in content.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    if let Some(val) = parse_kib_value(rest) {
                        usage.current_rss_kib = val;
                    }
                } else if let Some(rest) = line.strip_prefix("VmHWM:") {
                    if let Some(val) = parse_kib_value(rest) {
                        usage.peak_rss_kib = val;
                    }
                } else if let Some(rest) = line.strip_prefix("VmSize:") {
                    if let Some(val) = parse_kib_value(rest) {
                        usage.virtual_size_kib = val;
                    }
                }
            }
        }

        usage
    }

    pub fn current_rss_mb(&self) -> f64 {
        self.current_rss_kib as f64 / 1024.0
    }

    pub fn peak_rss_mb(&self) -> f64 {
        self.peak_rss_kib as f64 / 1024.0
    }
}

fn parse_kib_value(s: &str) -> Option<u64> {
    let s = s.trim();
    let num_part = s.split_whitespace().next()?;
    num_part.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_capture() {
        let mem = MemoryUsage::capture();
        // Check that memory values and helpers are accessible
        let _ = mem.current_rss_mb();
        let _ = mem.peak_rss_mb();
    }
}
