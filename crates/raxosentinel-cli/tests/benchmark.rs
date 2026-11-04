#![cfg(target_os = "linux")]

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

use raxosentinel_signatures::rsidb::malwarebazaar::private_store;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn setup_private_db(dir: &Path) -> (PathBuf, &'static str) {
    let db_root = dir.join("db_root");
    std::fs::create_dir_all(&db_root).unwrap();
    std::fs::set_permissions(&db_root, std::fs::Permissions::from_mode(0o700)).unwrap();

    let sig_content = b"synthetic private signature";
    let hash = hex::encode(Sha256::digest(sig_content));
    let response = serde_json::json!({
        "query_status": "ok",
        "data": [{
            "sha256_hash": hash,
            "file_size": sig_content.len(),
            "first_seen": "2024-02-29 00:00:00",
            "signature": "SyntheticFixture"
        }]
    })
    .to_string();

    private_store::publish(&db_root, "fixture", response.as_bytes(), 1).unwrap();
    (db_root, "fixture")
}

fn create_synthetic_file(path: &Path, size_bytes: usize) {
    let mut file = File::create(path).unwrap();
    let chunk = [0x5au8; 65536];
    let mut remaining = size_bytes;
    while remaining > 0 {
        let n = remaining.min(chunk.len());
        file.write_all(&chunk[..n]).unwrap();
        remaining -= n;
    }
    file.sync_all().unwrap();
}

fn read_proc_rss_kib(pid: u32) -> Option<u64> {
    let path = format!("/proc/{pid}/status");
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn read_cpu_ticks() -> Option<(u64, u64)> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let first_line = stat.lines().next()?;
    if !first_line.starts_with("cpu ") {
        return None;
    }
    let parts: Vec<u64> = first_line
        .split_whitespace()
        .skip(1)
        .filter_map(|s| s.parse().ok())
        .collect();
    if parts.len() >= 4 {
        let idle = parts[3];
        let total: u64 = parts.iter().sum();
        let busy = total.saturating_sub(idle);
        Some((busy, total))
    } else {
        None
    }
}

struct RunningCoordinator {
    child: Child,
    socket: PathBuf,
}

impl RunningCoordinator {
    fn start(
        socket: &Path,
        db_root: &Path,
        generation: &str,
        extra_args: &[&str],
    ) -> (Self, Duration) {
        let parent = socket.parent().unwrap_or_else(|| Path::new("."));
        let _ = std::fs::create_dir_all(parent);
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));

        let start = Instant::now();
        let mut child = Command::new(env!("CARGO_BIN_EXE_raxosentinel"))
            .arg("serve")
            .arg("--socket")
            .arg(socket)
            .arg("--private-db-root")
            .arg(db_root)
            .arg("--private-generation")
            .arg(generation)
            .args(extra_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn serve");

        let stdout = child.stdout.take().expect("piped stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read ready");
        let startup_duration = start.elapsed();
        assert!(line.contains("RAXOSENTINEL_COORDINATOR_READY"));

        (
            Self {
                child,
                socket: socket.to_path_buf(),
            },
            startup_duration,
        )
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for RunningCoordinator {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

fn median_and_p95(mut list: Vec<Duration>) -> (Duration, Duration) {
    if list.is_empty() {
        return (Duration::ZERO, Duration::ZERO);
    }
    list.sort();
    let median = list[list.len() / 2];
    let p95_idx = ((list.len() as f64 * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(list.len() - 1);
    let p95 = list[p95_idx];
    (median, p95)
}

#[test]
#[ignore]
fn run_phase_3b3_measurements() {
    println!("\n================================================================================");
    println!("RaxoSentinel Phase 3B.3 Performance & Bounded Concurrency Benchmarks");
    println!("System: Linux 6.8.0-1064-azure x86_64, 2 vCPUs (AMD EPYC 7763 64-Core Processor)");
    println!("================================================================================");

    let temp_dir = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_private_db(temp_dir.path());
    let exe = env!("CARGO_BIN_EXE_raxosentinel");

    // 1. Prepare synthetic test files (1 MB, 10 MB, 50 MB)
    let file_1mb = temp_dir.path().join("1mb.bin");
    create_synthetic_file(&file_1mb, 1_048_576);

    let file_10mb = temp_dir.path().join("10mb.bin");
    create_synthetic_file(&file_10mb, 10_485_760);

    let file_50mb = temp_dir.path().join("50mb.bin");
    create_synthetic_file(&file_50mb, 52_428_800);

    let empty_file = temp_dir.path().join("empty.bin");
    create_synthetic_file(&empty_file, 0);

    // 2. Measure worker peak RSS (VmHWM) per file size
    println!("\n[1] Per-Worker Peak RSS (VmHWM sampled externally every 1ms)");
    let sample_targets = [
        ("1 MB", &file_1mb),
        ("10 MB", &file_10mb),
        ("50 MB", &file_50mb),
    ];
    let mut worker_peak_rss_map = std::collections::BTreeMap::new();

    for (label, path) in &sample_targets {
        let mut child = Command::new(exe)
            .args([
                "scan",
                path.to_str().unwrap(),
                "--worker-internal",
                "--private-db-root",
                db_root.to_str().unwrap(),
                "--private-generation",
                gen,
            ])
            .stdin(File::open(path).unwrap())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let pid = child.id();
        let status_path = format!("/proc/{pid}/status");
        let mut peak_rss = 0u64;

        loop {
            if let Ok(content) = std::fs::read_to_string(&status_path) {
                for line in content.lines() {
                    if let Some(rest) = line.strip_prefix("VmHWM:") {
                        if let Some(val) = rest
                            .split_whitespace()
                            .next()
                            .and_then(|s| s.parse::<u64>().ok())
                        {
                            peak_rss = peak_rss.max(val);
                        }
                    }
                }
            }
            if child.try_wait().unwrap().is_some() {
                if let Ok(content) = std::fs::read_to_string(&status_path) {
                    for line in content.lines() {
                        if let Some(rest) = line.strip_prefix("VmHWM:") {
                            if let Some(val) = rest
                                .split_whitespace()
                                .next()
                                .and_then(|s| s.parse::<u64>().ok())
                            {
                                peak_rss = peak_rss.max(val);
                            }
                        }
                    }
                }
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        worker_peak_rss_map.insert(*label, peak_rss);
        println!(
            "    Target {:<6}: Worker peak RSS = {} KiB ({:.2} MiB)",
            label,
            peak_rss,
            peak_rss as f64 / 1024.0
        );
    }

    // 3. Concurrency Comparison: 1 Worker vs 2 Workers vs 4 Workers
    let worker_configs = [1usize, 2, 4];
    let workloads = [
        ("1 MB", &file_1mb, 1_048_576u64, 16usize),
        ("10 MB", &file_10mb, 10_485_760u64, 8usize),
        ("50 MB", &file_50mb, 52_428_800u64, 4usize),
    ];

    println!("\n[2] Concurrency Scaling Benchmarks (1, 2, and 4 Workers)");
    println!("+---------+-------------+---------+------------+------------+-----------+-------------+------------+");
    println!("| Workers | Target Size | Reqs/s  | Median Lat | p95 Lat    | Coord RSS | Snapshots   | CPU Util % |");
    println!("+---------+-------------+---------+------------+------------+-----------+-------------+------------+");

    for &w in &worker_configs {
        let sock = temp_dir.path().join(format!("sock_dir/bench_{w}w.sock"));
        let w_arg = format!("--max-workers={w}");
        let p_arg = format!("--max-pending={}", w * 4);
        let snap_arg = format!("--max-total-snapshot-bytes={}", 500 * 1024 * 1024);

        let (coord, _) =
            RunningCoordinator::start(&sock, &db_root, gen, &[&w_arg, &p_arg, &snap_arg]);
        std::thread::sleep(Duration::from_millis(20));

        let coord_rss = read_proc_rss_kib(coord.pid()).unwrap_or(0);

        for (label, path, file_bytes, total_reqs) in &workloads {
            // Warmup
            let _ = Command::new(exe)
                .args([
                    "client",
                    "--socket",
                    sock.to_str().unwrap(),
                    path.to_str().unwrap(),
                    "--json",
                ])
                .output();

            let cpu_before = read_cpu_ticks();
            let start = Instant::now();

            let reqs_per_worker = (*total_reqs) / w;
            let actual_total = reqs_per_worker * w;
            let latencies = Arc::new(std::sync::Mutex::new(Vec::with_capacity(actual_total)));

            let mut threads = Vec::new();
            for _ in 0..w {
                let lats_clone = Arc::clone(&latencies);
                let sock_path = sock.clone();
                let target_path = (*path).clone();
                let exe_str = exe.to_string();

                threads.push(std::thread::spawn(move || {
                    for _ in 0..reqs_per_worker {
                        let t0 = Instant::now();
                        let _ = Command::new(&exe_str)
                            .args([
                                "client",
                                "--socket",
                                sock_path.to_str().unwrap(),
                                target_path.to_str().unwrap(),
                                "--json",
                            ])
                            .output();
                        let el = t0.elapsed();
                        lats_clone.lock().unwrap().push(el);
                    }
                }));
            }

            for t in threads {
                let _ = t.join();
            }

            let total_wall = start.elapsed();
            let cpu_after = read_cpu_ticks();

            let cpu_util = match (cpu_before, cpu_after) {
                (Some((b0, t0)), Some((b1, t1))) if t1 > t0 => {
                    let b_delta = b1.saturating_sub(b0) as f64;
                    let t_delta = (t1 - t0) as f64;
                    (b_delta / t_delta) * 100.0
                }
                _ => 0.0,
            };

            let all_lats = Arc::try_unwrap(latencies).unwrap().into_inner().unwrap();
            let (med_lat, p95_lat) = median_and_p95(all_lats);
            let rps = actual_total as f64 / total_wall.as_secs_f64();
            let max_snap_inflight_mb = (w as u64 * *file_bytes) as f64 / (1024.0 * 1024.0);

            println!(
                "| {:<7} | {:<11} | {:>7.2} | {:>7.2} ms | {:>7.2} ms | {:>5.1} MiB | {:>5.1} MiB in-fl| {:>9.1}% |",
                w,
                label,
                rps,
                med_lat.as_secs_f64() * 1000.0,
                p95_lat.as_secs_f64() * 1000.0,
                coord_rss as f64 / 1024.0,
                max_snap_inflight_mb,
                cpu_util,
            );
        }
        println!("+---------+-------------+---------+------------+------------+-----------+-------------+------------+");
        drop(coord);
    }

    // 4. Overload & Queue Saturation Latency
    println!("\n[3] Queue Saturation & Immediate BUSY Response");
    let overload_sock = temp_dir.path().join("sock_dir/bench_overload.sock");
    let (overload_coord, _) = RunningCoordinator::start(
        &overload_sock,
        &db_root,
        gen,
        &["--max-workers=1", "--max-pending=1"],
    );

    // Occupy worker with 50 MB scan
    let osock1 = overload_sock.clone();
    let f50 = file_50mb.clone();
    let h1 = std::thread::spawn(move || {
        Command::new(exe)
            .args([
                "client",
                "--socket",
                osock1.to_str().unwrap(),
                f50.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap()
    });

    std::thread::sleep(Duration::from_millis(25));

    // Occupy single pending queue slot
    let osock2 = overload_sock.clone();
    let f10 = file_10mb.clone();
    let h2 = std::thread::spawn(move || {
        Command::new(exe)
            .args([
                "client",
                "--socket",
                osock2.to_str().unwrap(),
                f10.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap()
    });

    std::thread::sleep(Duration::from_millis(20));

    // Measure immediate BUSY response latency for 3rd request
    let t0 = Instant::now();
    let out3 = Command::new(exe)
        .args([
            "client",
            "--socket",
            overload_sock.to_str().unwrap(),
            empty_file.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    let busy_latency = t0.elapsed();

    let json3: serde_json::Value = serde_json::from_slice(&out3.stdout).unwrap_or_default();
    println!("    BUSY status returned:     {}", json3["status"]);
    println!(
        "    BUSY rejection latency:   {:.3} ms",
        busy_latency.as_secs_f64() * 1000.0
    );
    assert_eq!(out3.status.code().unwrap(), 3);
    assert_eq!(json3["status"], "BUSY");

    let _ = h1.join();
    let _ = h2.join();
    drop(overload_coord);

    // 5. Worker Timeout & Recovery Time
    println!("\n[4] Worker Timeout & Recovery Time");
    let timeout_sock = temp_dir.path().join("sock_dir/bench_timeout.sock");
    let (timeout_coord, _) =
        RunningCoordinator::start(&timeout_sock, &db_root, gen, &["--worker-timeout-ms=20"]);

    let t0 = Instant::now();
    let hang_out = Command::new(exe)
        .args([
            "client",
            "--socket",
            timeout_sock.to_str().unwrap(),
            file_50mb.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    let timeout_elapsed = t0.elapsed();
    assert_eq!(hang_out.status.code().unwrap(), 3);

    let t1 = Instant::now();
    let rec_out = Command::new(exe)
        .args([
            "client",
            "--socket",
            timeout_sock.to_str().unwrap(),
            empty_file.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    let recovery_elapsed = t1.elapsed();
    assert_eq!(rec_out.status.code().unwrap(), 0);

    println!("    Configured timeout:       20 ms (on 50 MB scan)");
    println!(
        "    Timeout abort latency:    {:.2} ms",
        timeout_elapsed.as_secs_f64() * 1000.0
    );
    println!(
        "    Subsequent recovery scan: {:.2} ms",
        recovery_elapsed.as_secs_f64() * 1000.0
    );

    drop(timeout_coord);

    println!("\n================================================================================");
    println!("Phase 3B.3 Measurements successfully completed.");
    println!("================================================================================");
}
