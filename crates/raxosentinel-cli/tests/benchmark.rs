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
use std::time::{Duration, Instant};

const WARMUP_RUNS: usize = 2;
const BENCH_RUNS: usize = 5;

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

fn median_duration(mut list: Vec<Duration>) -> Duration {
    list.sort();
    list[list.len() / 2]
}

#[test]
#[ignore]
fn run_phase_3b2_measurements() {
    println!("\n============================================================");
    println!("RaxoSentinel Phase 3B.2 Performance & Resource Measurements");
    println!("============================================================");

    let temp_dir = tempfile::tempdir().unwrap();
    let (db_root, gen) = setup_private_db(temp_dir.path());

    // Prepare synthetic test files
    let empty_file = temp_dir.path().join("empty.bin");
    create_synthetic_file(&empty_file, 0);

    let file_1mb = temp_dir.path().join("1mb.bin");
    create_synthetic_file(&file_1mb, 1_048_576);

    let file_10mb = temp_dir.path().join("10mb.bin");
    create_synthetic_file(&file_10mb, 10_485_760);

    let file_50mb = temp_dir.path().join("50mb.bin");
    create_synthetic_file(&file_50mb, 52_428_800);

    // -----------------------------------------------------------------------
    // 1. Coordinator Startup & DB Verification Time + Idle RSS
    // -----------------------------------------------------------------------
    let mut startup_times = Vec::new();
    let mut idle_rss_samples = Vec::new();

    for i in 0..BENCH_RUNS {
        let sock = temp_dir.path().join(format!("sock_dir/start_{i}.sock"));
        let (coord, duration) = RunningCoordinator::start(&sock, &db_root, gen, &[]);
        startup_times.push(duration);
        std::thread::sleep(Duration::from_millis(15));
        if let Some(rss) = read_proc_rss_kib(coord.pid()) {
            idle_rss_samples.push(rss);
        }
    }

    let median_startup = median_duration(startup_times);
    let median_idle_rss = if !idle_rss_samples.is_empty() {
        idle_rss_samples.sort();
        idle_rss_samples[idle_rss_samples.len() / 2]
    } else {
        0
    };

    println!("\n[1] Coordinator Startup & Base Resources");
    println!(
        "    Startup + DB verification: {:.2} ms",
        median_startup.as_secs_f64() * 1000.0
    );
    println!(
        "    Idle coordinator RSS:      {} KiB ({:.2} MiB)",
        median_idle_rss,
        median_idle_rss as f64 / 1024.0
    );

    // Start persistent coordinator for socket benchmarks
    let socket_path = temp_dir.path().join("sock_dir/bench_coord.sock");
    let (coord, _) = RunningCoordinator::start(&socket_path, &db_root, gen, &[]);

    // -----------------------------------------------------------------------
    // 2. Latency & Throughput: Direct CLI vs Supervised CLI vs Local Socket
    // -----------------------------------------------------------------------
    let exe = env!("CARGO_BIN_EXE_raxosentinel");
    let test_targets = [
        ("Empty (0 B)", &empty_file, 0usize),
        ("1 MB", &file_1mb, 1_048_576),
        ("10 MB", &file_10mb, 10_485_760),
    ];

    println!("\n[2] Scan Latency and Sequential Throughput");
    println!("+---------------+-----------------+--------------------+--------------------+");
    println!("| Target Size   | Direct CLI (ms) | Supervised CLI(ms) | Socket Client (ms) |");
    println!("+---------------+-----------------+--------------------+--------------------+");

    for (label, path, bytes) in &test_targets {
        // Warmup
        for _ in 0..WARMUP_RUNS {
            let _ = Command::new(exe)
                .args([
                    "scan",
                    path.to_str().unwrap(),
                    "--json",
                    "--private-db-root",
                    db_root.to_str().unwrap(),
                    "--private-generation",
                    gen,
                ])
                .output();
            let _ = Command::new(exe)
                .args([
                    "scan",
                    path.to_str().unwrap(),
                    "--supervised",
                    "--json",
                    "--private-db-root",
                    db_root.to_str().unwrap(),
                    "--private-generation",
                    gen,
                ])
                .output();
            let _ = Command::new(exe)
                .args([
                    "client",
                    "--socket",
                    socket_path.to_str().unwrap(),
                    path.to_str().unwrap(),
                    "--json",
                ])
                .output();
        }

        // Direct runs
        let mut direct_times = Vec::new();
        for _ in 0..BENCH_RUNS {
            let t0 = Instant::now();
            let _ = Command::new(exe)
                .args([
                    "scan",
                    path.to_str().unwrap(),
                    "--json",
                    "--private-db-root",
                    db_root.to_str().unwrap(),
                    "--private-generation",
                    gen,
                ])
                .output();
            direct_times.push(t0.elapsed());
        }

        // Supervised runs
        let mut sup_times = Vec::new();
        for _ in 0..BENCH_RUNS {
            let t0 = Instant::now();
            let _ = Command::new(exe)
                .args([
                    "scan",
                    path.to_str().unwrap(),
                    "--supervised",
                    "--json",
                    "--private-db-root",
                    db_root.to_str().unwrap(),
                    "--private-generation",
                    gen,
                ])
                .output();
            sup_times.push(t0.elapsed());
        }

        // Socket client runs
        let mut sock_times = Vec::new();
        for _ in 0..BENCH_RUNS {
            let t0 = Instant::now();
            let _ = Command::new(exe)
                .args([
                    "client",
                    "--socket",
                    socket_path.to_str().unwrap(),
                    path.to_str().unwrap(),
                    "--json",
                ])
                .output();
            sock_times.push(t0.elapsed());
        }

        let med_dir = median_duration(direct_times);
        let med_sup = median_duration(sup_times);
        let med_sock = median_duration(sock_times);

        let mb_s = |d: Duration| {
            if *bytes == 0 {
                0.0
            } else {
                (*bytes as f64 / (1024.0 * 1024.0)) / d.as_secs_f64()
            }
        };

        if *bytes > 0 {
            println!(
                "| {:<13} | {:>7.2} ms ({:>4.1}MB/s)| {:>7.2} ms ({:>4.1}MB/s)| {:>7.2} ms ({:>4.1}MB/s)|",
                label,
                med_dir.as_secs_f64() * 1000.0,
                mb_s(med_dir),
                med_sup.as_secs_f64() * 1000.0,
                mb_s(med_sup),
                med_sock.as_secs_f64() * 1000.0,
                mb_s(med_sock),
            );
        } else {
            println!(
                "| {:<13} | {:>15.2} ms | {:>18.2} ms | {:>18.2} ms |",
                label,
                med_dir.as_secs_f64() * 1000.0,
                med_sup.as_secs_f64() * 1000.0,
                med_sock.as_secs_f64() * 1000.0,
            );
        }
    }
    println!("+---------------+-----------------+--------------------+--------------------+");

    // -----------------------------------------------------------------------
    // 3. Worker Peak RSS & Sampling
    // -----------------------------------------------------------------------
    println!("\n[3] Worker Peak RSS (VmHWM sampled externally every 1ms)");
    let sample_targets = [
        ("1 MB", &file_1mb),
        ("10 MB", &file_10mb),
        ("50 MB", &file_50mb),
    ];

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

        println!(
            "    Target {:<6}: Worker peak RSS = {} KiB ({:.2} MiB)",
            label,
            peak_rss,
            peak_rss as f64 / 1024.0
        );
    }

    // -----------------------------------------------------------------------
    // 4. Overload Response Behavior
    // -----------------------------------------------------------------------
    println!("\n[4] Overload Response Behavior");
    let overload_sock = temp_dir.path().join("sock_dir/overload.sock");
    let (overload_coord, _) =
        RunningCoordinator::start(&overload_sock, &db_root, gen, &["--max-pending=1"]);

    // Submit a 50 MB file to keep worker busy for ~250ms
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

    std::thread::sleep(Duration::from_millis(20));

    // Submit a 10 MB file to fill the single pending slot
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

    std::thread::sleep(Duration::from_millis(15));

    // Measure immediate BUSY response latency for the 3rd request
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

    // -----------------------------------------------------------------------
    // 5. Worker Timeout and Recovery Time
    // -----------------------------------------------------------------------
    println!("\n[5] Worker Timeout & Recovery Time");
    let timeout_sock = temp_dir.path().join("sock_dir/timeout.sock");
    // Set 10ms deadline on 50 MB scan (which takes ~250ms)
    let (timeout_coord, _) =
        RunningCoordinator::start(&timeout_sock, &db_root, gen, &["--worker-timeout-ms=15"]);

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

    // Measure recovery time (subsequent clean scan)
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

    println!("    Configured timeout:       15 ms (on 50 MB file)");
    println!(
        "    Timeout abort latency:    {:.2} ms",
        timeout_elapsed.as_secs_f64() * 1000.0
    );
    println!(
        "    Subsequent recovery scan: {:.2} ms",
        recovery_elapsed.as_secs_f64() * 1000.0
    );

    drop(timeout_coord);
    drop(coord);

    println!("\n============================================================");
    println!("Measurements successfully completed.");
    println!("============================================================");
}
