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

use raxosentinel_signatures::rsidb::malwarebazaar::private_store::{self, LoadTimings};
use raxosentinel_signatures::rsidb::updater::read_pointer;
use raxosentinel_signatures::rsidb::{MmapSortedIndex, RsidbIndex};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fmt;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Measure current process resident set size (RSS) in bytes via /proc/self/statm.
pub fn current_resident_memory_bytes() -> u64 {
    let statm_str = match std::fs::read_to_string("/proc/self/statm") {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let mut parts = statm_str.split_whitespace();
    // 2nd field is resident set size in pages
    let _total_pages = parts.next();
    let rss_pages: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size = if page_size > 0 {
        page_size as u64
    } else {
        4096
    };
    rss_pages.saturating_mul(page_size)
}

/// An immutable, verified in-memory representation of an active RSIDB generation.
pub struct ActiveDatabaseHandle {
    root: PathBuf,
    generation: String,
    index: Arc<MmapSortedIndex>,
    total_indicators: usize,
    loaded_at: Instant,
    load_timings: LoadTimings,
    active_scans: Arc<AtomicUsize>,
}

impl fmt::Debug for ActiveDatabaseHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActiveDatabaseHandle")
            .field("root", &self.root)
            .field("generation", &self.generation)
            .field("total_indicators", &self.total_indicators)
            .field("loaded_at", &self.loaded_at)
            .field("load_timings", &self.load_timings)
            .field("active_scans", &self.active_scans.load(Ordering::SeqCst))
            .finish()
    }
}

impl ActiveDatabaseHandle {
    pub fn new(
        root: PathBuf,
        generation: String,
        index: MmapSortedIndex,
        load_timings: LoadTimings,
    ) -> Self {
        let total_indicators = index.total_records();
        Self {
            root,
            generation,
            index: Arc::new(index),
            total_indicators,
            loaded_at: Instant::now(),
            load_timings,
            active_scans: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn generation(&self) -> &str {
        &self.generation
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn index(&self) -> &Arc<MmapSortedIndex> {
        &self.index
    }

    pub fn total_indicators(&self) -> usize {
        self.total_indicators
    }

    pub fn loaded_at(&self) -> Instant {
        self.loaded_at
    }

    pub fn load_timings(&self) -> &LoadTimings {
        &self.load_timings
    }

    pub fn active_scans(&self) -> usize {
        self.active_scans.load(Ordering::SeqCst)
    }
}

/// RAII pin guard pinning a scan to a verified RSIDB generation.
#[derive(Clone)]
pub struct PinnedDatabaseHandle {
    handle: Arc<ActiveDatabaseHandle>,
}

impl fmt::Debug for PinnedDatabaseHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedDatabaseHandle")
            .field("generation", &self.handle.generation())
            .field("total_indicators", &self.handle.total_indicators())
            .finish()
    }
}

impl PinnedDatabaseHandle {
    pub fn new(handle: Arc<ActiveDatabaseHandle>) -> Self {
        handle.active_scans.fetch_add(1, Ordering::SeqCst);
        Self { handle }
    }

    pub fn generation(&self) -> &str {
        self.handle.generation()
    }

    pub fn handle(&self) -> &Arc<ActiveDatabaseHandle> {
        &self.handle
    }
}

impl Drop for PinnedDatabaseHandle {
    fn drop(&mut self) {
        self.handle.active_scans.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Deref for PinnedDatabaseHandle {
    type Target = ActiveDatabaseHandle;
    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

/// Performance telemetry recorded during a successful hot reload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadMetrics {
    pub generation: String,
    pub previous_generation: Option<String>,
    pub load_time_ms: f64,
    pub switch_latency_micros: u64,
    pub total_indicators: usize,
    pub resident_memory_bytes: u64,
    pub timestamp_unix_secs: u64,
}

/// Manages active database generation lifecycle, live hot reload, and inotify monitoring.
pub struct DatabaseManager {
    root: PathBuf,
    active: Arc<RwLock<Arc<ActiveDatabaseHandle>>>,
    degraded: Arc<AtomicBool>,
    last_error: Arc<RwLock<Option<String>>>,
    reload_lock: Arc<Mutex<()>>,
    reload_history: Arc<RwLock<Vec<ReloadMetrics>>>,
    stop_signal: Arc<AtomicBool>,
    monitor_thread: Mutex<Option<thread::JoinHandle<()>>>,
}

impl DatabaseManager {
    /// Initialize database manager and load the initial verified generation.
    pub fn new(root: PathBuf, initial_generation: Option<String>) -> Result<Self, String> {
        let generation = match initial_generation {
            Some(g) => g,
            None => private_store::resolve_generation(&root, "current")
                .map_err(|e| format!("Cannot resolve active database generation: {e}"))?,
        };

        // Check for incomplete staging directories
        match private_store::incomplete(&root) {
            Ok(entries) if !entries.is_empty() => {
                return Err(format!(
                    "Incomplete private staging entries require inspection: {}",
                    entries.join(", ")
                ));
            }
            Ok(_) => {}
            Err(e) => {
                return Err(format!("Private database recovery inspection failed: {e}"));
            }
        }

        let (index, timings) = private_store::load_timed(&root, &generation)
            .map_err(|e| format!("Private database verification failed for '{generation}': {e}"))?;

        let handle = Arc::new(ActiveDatabaseHandle::new(
            root.clone(),
            generation.clone(),
            index,
            timings,
        ));

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let initial_metrics = ReloadMetrics {
            generation,
            previous_generation: None,
            load_time_ms: handle.load_timings.total.as_secs_f64() * 1000.0,
            switch_latency_micros: 0,
            total_indicators: handle.total_indicators,
            resident_memory_bytes: current_resident_memory_bytes(),
            timestamp_unix_secs: now_unix,
        };

        Ok(Self {
            root,
            active: Arc::new(RwLock::new(handle)),
            degraded: Arc::new(AtomicBool::new(false)),
            last_error: Arc::new(RwLock::new(None)),
            reload_lock: Arc::new(Mutex::new(())),
            reload_history: Arc::new(RwLock::new(vec![initial_metrics])),
            stop_signal: Arc::new(AtomicBool::new(false)),
            monitor_thread: Mutex::new(None),
        })
    }

    /// Root directory path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Retrieve the currently active database handle.
    pub fn get_active(&self) -> Arc<ActiveDatabaseHandle> {
        self.active.read().unwrap().clone()
    }

    /// Pin the currently active generation for an in-flight scan.
    pub fn pin_active(&self) -> PinnedDatabaseHandle {
        PinnedDatabaseHandle::new(self.get_active())
    }

    /// Whether the database freshness is degraded due to a failed reload attempt.
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::SeqCst)
    }

    /// Last recorded reload error, if any.
    pub fn last_error(&self) -> Option<String> {
        self.last_error.read().unwrap().clone()
    }

    /// Telemetry history of reload events.
    pub fn reload_history(&self) -> Vec<ReloadMetrics> {
        self.reload_history.read().unwrap().clone()
    }

    /// Check if active generation pointer changed; if so, verify and atomically hot reload.
    ///
    /// Ensures strictly at most two generations in memory simultaneously.
    pub fn check_and_reload(&self) -> Result<bool, String> {
        // Serialise reload attempts so multiple threads or events never race
        let _guard = match self.reload_lock.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let target_gen = match read_pointer(&self.root, "current") {
            Some(g) => g,
            None => {
                self.degraded.store(true, Ordering::SeqCst);
                let err_msg = "Malformed or missing 'current' generation pointer".to_string();
                *self.last_error.write().unwrap() = Some(err_msg.clone());
                tracing::warn!("{}", err_msg);
                return Ok(false);
            }
        };

        let current_active = self.get_active();
        if target_gen == current_active.generation() {
            // Pointer has not changed
            return Ok(false);
        }

        // Validate generation directory name
        if target_gen.starts_with('.') {
            self.degraded.store(true, Ordering::SeqCst);
            let err_msg = format!(
                "Candidate generation name '{}' starts with '.' and is rejected as incomplete staging",
                target_gen
            );
            *self.last_error.write().unwrap() = Some(err_msg.clone());
            tracing::warn!("{}", err_msg);
            return Ok(false);
        }

        // Check for incomplete staging directories
        if let Ok(entries) = private_store::incomplete(&self.root) {
            if entries.iter().any(|e| e == &target_gen) {
                self.degraded.store(true, Ordering::SeqCst);
                let err_msg = format!(
                    "Candidate generation '{}' is marked as incomplete staging",
                    target_gen
                );
                *self.last_error.write().unwrap() = Some(err_msg.clone());
                tracing::warn!("{}", err_msg);
                return Ok(false);
            }
        }

        tracing::info!(
            "Hot reload detected candidate generation '{}' (current active: '{}')",
            target_gen,
            current_active.generation()
        );

        // Verify candidate generation integrity before adopting
        let (candidate_index, timings) = match private_store::load_timed(&self.root, &target_gen) {
            Ok(pair) => pair,
            Err(e) => {
                self.degraded.store(true, Ordering::SeqCst);
                let err_msg = format!(
                    "Candidate generation '{}' verification failed: {}. Retaining active generation '{}'",
                    target_gen,
                    e,
                    current_active.generation()
                );
                *self.last_error.write().unwrap() = Some(err_msg.clone());
                tracing::error!("{}", err_msg);
                return Ok(false);
            }
        };

        // Switch to candidate atomically
        let switch_start = Instant::now();
        let prev_generation = current_active.generation().to_string();
        let new_handle = Arc::new(ActiveDatabaseHandle::new(
            self.root.clone(),
            target_gen.clone(),
            candidate_index,
            timings,
        ));

        {
            let mut write_guard = self.active.write().unwrap();
            *write_guard = new_handle.clone();
        }
        let switch_latency = switch_start.elapsed();

        // Freshness restored
        self.degraded.store(false, Ordering::SeqCst);
        *self.last_error.write().unwrap() = None;

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let metrics = ReloadMetrics {
            generation: target_gen.clone(),
            previous_generation: Some(prev_generation.clone()),
            load_time_ms: new_handle.load_timings.total.as_secs_f64() * 1000.0,
            switch_latency_micros: switch_latency.as_micros() as u64,
            total_indicators: new_handle.total_indicators,
            resident_memory_bytes: current_resident_memory_bytes(),
            timestamp_unix_secs: now_unix,
        };

        self.reload_history.write().unwrap().push(metrics);

        tracing::info!(
            "Hot reload successful: switched from '{}' to '{}' ({} indicators, load time: {:.2}ms, switch latency: {:?})",
            prev_generation,
            target_gen,
            new_handle.total_indicators,
            new_handle.load_timings.total.as_secs_f64() * 1000.0,
            switch_latency
        );

        Ok(true)
    }

    /// Start background filesystem monitor (inotify with bounded 100ms polling fallback).
    pub fn start_monitor(self: &Arc<Self>) -> Result<(), String> {
        let mut thread_guard = self.monitor_thread.lock().unwrap();
        if thread_guard.is_some() {
            return Ok(());
        }

        let root_c_str = CString::new(self.root.to_string_lossy().as_bytes())
            .map_err(|e| format!("Invalid root path: {e}"))?;

        // Initialize inotify instance
        let inotify_fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        let inotify_wd = if inotify_fd >= 0 {
            let mask = libc::IN_MOVED_TO
                | libc::IN_CLOSE_WRITE
                | libc::IN_ATTRIB
                | libc::IN_CREATE
                | libc::IN_DELETE;
            let wd = unsafe { libc::inotify_add_watch(inotify_fd, root_c_str.as_ptr(), mask) };
            if wd < 0 {
                unsafe {
                    libc::close(inotify_fd);
                }
                -1
            } else {
                wd
            }
        } else {
            -1
        };

        let db_manager = Arc::clone(self);
        let handle = thread::Builder::new()
            .name("rsidb-monitor".into())
            .spawn(move || {
                let mut buf = [0u8; 4096];
                while !db_manager.stop_signal.load(Ordering::SeqCst) {
                    if inotify_fd >= 0 {
                        let mut pfd = libc::pollfd {
                            fd: inotify_fd,
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        // Bounded 100ms poll timeout
                        let ret = unsafe { libc::poll(&mut pfd, 1, 100) };
                        if ret > 0 && (pfd.revents & libc::POLLIN) != 0 {
                            // Drain inotify buffer
                            loop {
                                let n = unsafe {
                                    libc::read(
                                        inotify_fd,
                                        buf.as_mut_ptr() as *mut libc::c_void,
                                        buf.len(),
                                    )
                                };
                                if n <= 0 {
                                    break;
                                }
                            }
                        }
                    } else {
                        thread::sleep(Duration::from_millis(100));
                    }

                    if db_manager.stop_signal.load(Ordering::SeqCst) {
                        break;
                    }

                    let _ = db_manager.check_and_reload();
                }

                if inotify_fd >= 0 {
                    if inotify_wd >= 0 {
                        unsafe {
                            libc::inotify_rm_watch(inotify_fd, inotify_wd);
                        }
                    }
                    unsafe {
                        libc::close(inotify_fd);
                    }
                }
            })
            .map_err(|e| format!("Failed to spawn database monitor thread: {e}"))?;

        *thread_guard = Some(handle);
        Ok(())
    }

    /// Terminate and join the background filesystem monitor thread.
    pub fn stop_monitor(&self) {
        self.stop_signal.store(true, Ordering::SeqCst);
        let mut thread_guard = self.monitor_thread.lock().unwrap();
        if let Some(handle) = thread_guard.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for DatabaseManager {
    fn drop(&mut self) {
        self.stop_monitor();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxosentinel_signatures::rsidb::updater::write_pointer;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;

    fn setup_test_gen(root: &Path, name: &str, sigs: &[&[u8]]) {
        std::fs::create_dir_all(root).unwrap();
        let _ = std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700));
        let entries: Vec<serde_json::Value> = sigs
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let h = hex::encode(Sha256::digest(s));
                serde_json::json!({
                    "sha256_hash": h,
                    "file_size": s.len(),
                    "first_seen": "2024-02-29 00:00:00",
                    "signature": format!("TestSig_{i}")
                })
            })
            .collect();
        let response = serde_json::json!({
            "query_status": "ok",
            "data": entries
        })
        .to_string();
        private_store::publish(root, name, response.as_bytes(), 1).unwrap();
    }

    #[test]
    fn test_hot_reload_unit_active_handle_and_pinning() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("db_root");
        setup_test_gen(&root, "gen1", &[b"signature_one"]);
        write_pointer(&root, "current", "gen1").unwrap();

        let mgr = DatabaseManager::new(root.clone(), None).unwrap();
        assert_eq!(mgr.get_active().generation(), "gen1");
        assert_eq!(mgr.get_active().total_indicators(), 1);
        assert_eq!(mgr.get_active().active_scans(), 0);

        let pin1 = mgr.pin_active();
        assert_eq!(mgr.get_active().active_scans(), 1);
        let pin2 = mgr.pin_active();
        assert_eq!(mgr.get_active().active_scans(), 2);
        drop(pin1);
        assert_eq!(mgr.get_active().active_scans(), 1);
        drop(pin2);
        assert_eq!(mgr.get_active().active_scans(), 0);
    }

    #[test]
    fn test_hot_reload_unit_successful_transition_and_telemetry() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("db_root");
        setup_test_gen(&root, "gen1", &[b"signature_one"]);
        write_pointer(&root, "current", "gen1").unwrap();

        let mgr = DatabaseManager::new(root.clone(), None).unwrap();
        assert_eq!(mgr.get_active().generation(), "gen1");

        // Publish gen2 with two indicators
        setup_test_gen(&root, "gen2", &[b"signature_one", b"signature_two"]);
        write_pointer(&root, "current", "gen2").unwrap();

        let changed = mgr.check_and_reload().unwrap();
        assert!(changed, "Must report reload change");
        assert_eq!(mgr.get_active().generation(), "gen2");
        assert_eq!(mgr.get_active().total_indicators(), 2);
        assert!(!mgr.is_degraded());

        let history = mgr.reload_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[1].generation, "gen2");
        assert_eq!(history[1].previous_generation.as_deref(), Some("gen1"));
        assert_eq!(history[1].total_indicators, 2);
        assert!(history[1].load_time_ms >= 0.0);
    }

    #[test]
    fn test_hot_reload_unit_rejection_of_corrupt_and_missing_and_staging() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("db_root");
        setup_test_gen(&root, "gen1", &[b"signature_one"]);
        write_pointer(&root, "current", "gen1").unwrap();

        let mgr = DatabaseManager::new(root.clone(), None).unwrap();
        assert_eq!(mgr.get_active().generation(), "gen1");

        // 1. Missing generation
        write_pointer(&root, "current", "gen_missing").unwrap();
        let changed = mgr.check_and_reload().unwrap();
        assert!(!changed);
        assert_eq!(mgr.get_active().generation(), "gen1");
        assert!(mgr.is_degraded());
        assert!(mgr.last_error().unwrap().contains("verification failed"));

        // 2. Incomplete staging generation manually written to current pointer
        std::fs::write(root.join("current"), ".staging-incomplete\n").unwrap();
        let changed = mgr.check_and_reload().unwrap();
        assert!(!changed);
        assert_eq!(mgr.get_active().generation(), "gen1");
        assert!(mgr.is_degraded());

        // 3. Malformed pointer with invalid characters
        std::fs::write(root.join("current"), "invalid/traversal\n").unwrap();
        let changed = mgr.check_and_reload().unwrap();
        assert!(!changed);
        assert_eq!(mgr.get_active().generation(), "gen1");
        assert!(mgr.is_degraded());

        // 3. Corrupt generation
        let corrupt_dir = root.join("gen_corrupt");
        std::fs::create_dir_all(&corrupt_dir).unwrap();
        std::fs::write(
            corrupt_dir.join("database.rsidb"),
            b"corrupted garbage bytes",
        )
        .unwrap();
        write_pointer(&root, "current", "gen_corrupt").unwrap();
        let changed = mgr.check_and_reload().unwrap();
        assert!(!changed);
        assert_eq!(mgr.get_active().generation(), "gen1");
        assert!(mgr.is_degraded());

        // 4. Restore valid generation
        setup_test_gen(&root, "gen2", &[b"signature_two"]);
        write_pointer(&root, "current", "gen2").unwrap();
        let changed = mgr.check_and_reload().unwrap();
        assert!(changed);
        assert_eq!(mgr.get_active().generation(), "gen2");
        assert!(!mgr.is_degraded());
        assert!(mgr.last_error().is_none());
    }

    #[test]
    fn test_hot_reload_unit_resident_memory_helper() {
        let mem = current_resident_memory_bytes();
        assert!(mem > 0, "Resident memory should be non-zero on Linux");
    }

    #[test]
    fn test_hot_reload_authentic_dataset_benchmark() {
        let auth_path =
            Path::new("/home/vscode/raxosentinel-private-phase2d1/phase2d6-unified/database.rsidb");
        if !auth_path.exists() {
            return;
        }
        let rss_before = current_resident_memory_bytes();
        let mgr = DatabaseManager::new(
            PathBuf::from("/home/vscode/raxosentinel-private-phase2d1"),
            Some("phase2d6-unified".into()),
        )
        .unwrap();
        let active = mgr.get_active();
        let rss_after = current_resident_memory_bytes();

        println!("=== AUTHENTIC DATASET LOAD BENCHMARK ===");
        println!("Generation Name       : {}", active.generation());
        println!("Total Indicators      : {}", active.total_indicators());
        println!(
            "Database Load Time    : {:.2} ms",
            active.load_timings().database.as_secs_f64() * 1000.0
        );
        println!(
            "Evidence Load Time    : {:.2} ms",
            active.load_timings().evidence.as_secs_f64() * 1000.0
        );
        println!(
            "Total Load Time       : {:.2} ms",
            active.load_timings().total.as_secs_f64() * 1000.0
        );
        println!(
            "Resident Memory Before: {:.2} MB",
            (rss_before as f64) / 1024.0 / 1024.0
        );
        println!(
            "Resident Memory After : {:.2} MB",
            (rss_after as f64) / 1024.0 / 1024.0
        );
        println!(
            "Net Memory Delta      : {:.2} MB",
            ((rss_after.saturating_sub(rss_before)) as f64) / 1024.0 / 1024.0
        );

        assert_eq!(active.total_indicators(), 542_057);
    }
}
