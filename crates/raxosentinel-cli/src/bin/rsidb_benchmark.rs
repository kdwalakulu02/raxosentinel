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

use raxosentinel_signatures::rsidb::{
    HashAlgorithm, InMemoryIndex, MmapCompactDirIndex, MmapSortedIndex, RsidbCompiler, RsidbIndex,
    SignatureEntry, SignatureImporter,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

fn get_process_rss_bytes() -> usize {
    if let Ok(content) = fs::read_to_string("/proc/self/status") {
        for line in content.lines() {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<usize>() {
                        return kb * 1024;
                    }
                }
            }
        }
    }
    0
}

fn synthetic_entry(i: usize) -> SignatureEntry {
    let mut hasher = Sha256::new();
    hasher.update(format!("LAB-ONLY-NOT-A-MALWARE-SIGNATURE:{}", i).as_bytes());
    let digest = hasher.finalize().to_vec();
    let size = (i % 4096 + 1) as u64;
    let name = format!("Lab.Synthetic.{:03}", i % 256);
    SignatureEntry::new(HashAlgorithm::Sha256, size, digest, name)
}

struct ArchitectureMetrics {
    name: String,
    file_size_bytes: usize,
    build_time_ms: f64,
    startup_time_ms: f64,
    rss_before_mb: f64,
    rss_after_warm_mb: f64,
    delta_rss_mb: f64,
    batch_20k_time_ms: f64,
    throughput_qps: f64,
    p50_latency_ns: u64,
    p95_latency_ns: u64,
    p99_latency_ns: u64,
    hits_validated: usize,
    misses_validated: usize,
}

fn main() {
    println!("=== RaxoSentinel RSIDB Database Architecture Benchmark Suite ===");
    let temp_dir = std::env::temp_dir().join(format!("raxo_rsidb_bench_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).expect("Failed to create temporary benchmark dir");

    let num_records = 100_000;
    println!(
        "Generating {} deterministic synthetic SHA-256 records...",
        num_records
    );
    let mut entries = Vec::with_capacity(num_records);
    for i in 0..num_records {
        entries.push(synthetic_entry(i));
    }

    // Include 17 harmless test signatures if available
    let test_fixtures_dir =
        if PathBuf::from("crates/raxosentinel-signatures/test_fixtures").exists() {
            PathBuf::from("crates/raxosentinel-signatures/test_fixtures")
        } else {
            PathBuf::from("raw referefce/raxosentinel-db-lab/upstream/unit_tests/input")
        };
    if test_fixtures_dir.exists() {
        for p in &[
            test_fixtures_dir.join("clamav.hdb"),
            test_fixtures_dir.join("other_sigs/alz.hdb"),
            test_fixtures_dir.join("other_sigs/logo.hsb"),
            test_fixtures_dir.join("other_sigs/zstd.hdb"),
        ] {
            if let Ok((parsed, _)) = SignatureImporter::parse_file(p) {
                entries.extend(parsed);
            }
        }
    }

    let total_records = entries.len();
    println!("Total evaluation records: {}", total_records);

    // Precompute 20,000 evaluation queries (10,000 true hits + 10,000 size-mismatch misses)
    println!("Preparing 20,000 pre-hashed benchmark queries...");
    let mut queries: Vec<(HashAlgorithm, u64, Vec<u8>, bool)> = Vec::with_capacity(20_000);
    for i in 0..10_000 {
        let entry = synthetic_entry((i * 7919) % num_records);
        // Hit query
        queries.push((entry.alg, entry.size, entry.digest.clone(), true));
        // Size mismatch miss query
        queries.push((entry.alg, entry.size + 100_000, entry.digest, false));
    }

    // 1. Build File Artifacts
    let plain_sorted_path = temp_dir.join("synthetic_plain_sorted.rsdb");
    let compact_dir_path = temp_dir.join("synthetic_compact_dir.rsdb");

    println!("\nCompiling Plain Sorted RSIDB (without compact directory)...");
    let t0 = Instant::now();
    let compiler_plain = RsidbCompiler::new().with_directory(false);
    compiler_plain
        .compile_to_file(entries.clone(), &plain_sorted_path)
        .unwrap();
    let build_time_plain_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let size_plain = fs::metadata(&plain_sorted_path).unwrap().len() as usize;

    println!("Compiling Compact Directory RSIDB (with 16-bit prefix directory)...");
    let t1 = Instant::now();
    let compiler_dir = RsidbCompiler::new().with_directory(true);
    compiler_dir
        .compile_to_file(entries.clone(), &compact_dir_path)
        .unwrap();
    let build_time_dir_ms = t1.elapsed().as_secs_f64() * 1000.0;
    let size_dir = fs::metadata(&compact_dir_path).unwrap().len() as usize;

    // Benchmark 1: In-Memory Hash Index
    println!("\n--- Evaluating Architecture 1: In-Memory Hash Index ---");
    let metrics_in_mem = benchmark_index(
        "In-Memory Hash Index",
        size_plain,
        build_time_plain_ms,
        || InMemoryIndex::from_file(&plain_sorted_path).unwrap(),
        &queries,
    );

    // Benchmark 2: Memory-Mapped Sorted Index
    println!("\n--- Evaluating Architecture 2: Owned Sorted Binary Index ---");
    let metrics_mmap_sorted = benchmark_index(
        "Owned Sorted Binary Index",
        size_plain,
        build_time_plain_ms,
        || MmapSortedIndex::from_file(&plain_sorted_path).unwrap(),
        &queries,
    );

    // Benchmark 3: Owned Compact Directory Index
    println!("\n--- Evaluating Architecture 3: Owned Compact Directory Index ---");
    let metrics_compact_dir = benchmark_index(
        "Owned Compact Directory Index",
        size_dir,
        build_time_dir_ms,
        || MmapCompactDirIndex::from_file(&compact_dir_path).unwrap(),
        &queries,
    );

    let results = vec![metrics_in_mem, metrics_mmap_sorted, metrics_compact_dir];
    print_markdown_report(&results, total_records);

    let report_content = generate_markdown_report(&results, total_records);
    fs::write("BENCHMARKS_RSIDB.md", report_content).expect("Failed to write BENCHMARKS_RSIDB.md");
    println!("\nBenchmark results saved to BENCHMARKS_RSIDB.md");

    // Clean up temporary files
    let _ = fs::remove_dir_all(&temp_dir);
}

fn benchmark_index<T: RsidbIndex>(
    name: &str,
    file_size_bytes: usize,
    build_time_ms: f64,
    loader: impl Fn() -> T,
    queries: &[(HashAlgorithm, u64, Vec<u8>, bool)],
) -> ArchitectureMetrics {
    let rss_before = get_process_rss_bytes();

    let start_load = Instant::now();
    let index = loader();
    let startup_time_ms = start_load.elapsed().as_secs_f64() * 1000.0;

    // Warm-up and correctness verification
    let mut hits = 0;
    let mut misses = 0;
    for (alg, size, digest, expect_hit) in queries {
        let res = index.lookup(*alg, *size, digest);
        if !res.is_empty() {
            hits += 1;
            assert!(*expect_hit, "Unexpected hit on non-matching query");
        } else {
            misses += 1;
            assert!(!*expect_hit, "Unexpected miss on true positive query");
        }
    }
    assert_eq!(hits, 10_000);
    assert_eq!(misses, 10_000);

    let rss_after_warm = get_process_rss_bytes();
    let delta_rss = rss_after_warm.saturating_sub(rss_before);

    // Timed Query Batch Measurement (3 iterations, measuring per-query latency distribution)
    let mut batch_times = Vec::new();
    let mut query_latencies_ns = Vec::with_capacity(queries.len());

    for iter in 0..3 {
        let t_start = Instant::now();
        if iter == 0 {
            for (alg, size, digest, _) in queries {
                let q_start = Instant::now();
                let _ = index.lookup(*alg, *size, digest);
                query_latencies_ns.push(q_start.elapsed().as_nanos() as u64);
            }
        } else {
            for (alg, size, digest, _) in queries {
                let _ = index.lookup(*alg, *size, digest);
            }
        }
        batch_times.push(t_start.elapsed().as_secs_f64() * 1000.0);
    }

    batch_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median_batch_time_ms = batch_times[1];
    let throughput_qps = (queries.len() as f64) / (median_batch_time_ms / 1000.0);

    query_latencies_ns.sort_unstable();
    let p50 = query_latencies_ns[query_latencies_ns.len() * 50 / 100];
    let p95 = query_latencies_ns[query_latencies_ns.len() * 95 / 100];
    let p99 = query_latencies_ns[query_latencies_ns.len() * 99 / 100];

    ArchitectureMetrics {
        name: name.to_string(),
        file_size_bytes,
        build_time_ms,
        startup_time_ms,
        rss_before_mb: rss_before as f64 / (1024.0 * 1024.0),
        rss_after_warm_mb: rss_after_warm as f64 / (1024.0 * 1024.0),
        delta_rss_mb: delta_rss as f64 / (1024.0 * 1024.0),
        batch_20k_time_ms: median_batch_time_ms,
        throughput_qps,
        p50_latency_ns: p50,
        p95_latency_ns: p95,
        p99_latency_ns: p99,
        hits_validated: hits,
        misses_validated: misses,
    }
}

fn generate_markdown_report(results: &[ArchitectureMetrics], total_records: usize) -> String {
    let mut out = String::new();
    out.push_str("# RaxoSentinel Intelligence Database (RSIDB) Architecture Benchmark\n\n");
    out.push_str("## Benchmark Overview & Evaluation Methodology\n\n");
    out.push_str(&format!(
        "- **Workload**: {} total records (100,000 synthetic SHA-256 records + 17 official ClamAV harmless fixtures)\n",
        total_records
    ));
    out.push_str("- **Query Dataset**: 20,000 pre-hashed queries (10,000 true positive hits + 10,000 size-mismatch misses)\n");
    out.push_str("- **Verification**: 100% detection accuracy verified on all implementations (0 false positives, 0 false negatives)\n");

    out.push_str("## 1. Rust Architecture Comparison: In-Memory vs Owned Sorted vs Owned Compact Directory\n\n");
    out.push_str("| Implementation Architecture | Storage Size | Build Time | Startup / Load Time | Steady Warm RSS | RSS Delta | 20k Query Batch | Throughput (QPS) | p50 Latency | p95 Latency | p99 Latency | Detection Parity |\n");
    out.push_str(
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n",
    );

    for m in results {
        let size_str = format!("{:.2} MiB", m.file_size_bytes as f64 / (1024.0 * 1024.0));
        out.push_str(&format!(
            "| **{}** | {} | {:.1} ms | **{:.3} ms** | {:.2} MiB (base {:.1}M) | **+{:.2} MiB** | {:.2} ms | **{:.0} qps** | {} ns | {} ns | {} ns | **100%** ({}/{}) |\n",
            m.name,
            size_str,
            m.build_time_ms,
            m.startup_time_ms,
            m.rss_after_warm_mb,
            m.rss_before_mb,
            m.delta_rss_mb,
            m.batch_20k_time_ms,
            m.throughput_qps,
            m.p50_latency_ns,
            m.p95_latency_ns,
            m.p99_latency_ns,
            m.hits_validated,
            m.hits_validated + m.misses_validated,
        ));
    }

    out.push_str("\nIndex constructors use owned buffers; these measurements do not describe memory mapping. Results are local to this synthetic benchmark and should not be treated as production capacity.\n");

    out
}

fn print_markdown_report(results: &[ArchitectureMetrics], total_records: usize) {
    let report = generate_markdown_report(results, total_records);
    println!("\n{}", report);
}
