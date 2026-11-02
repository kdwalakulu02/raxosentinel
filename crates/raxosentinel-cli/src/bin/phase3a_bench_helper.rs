// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! Harmless fixture generation and isolated scanner-component timing.
use raxosentinel_core::{hash_file_bounded, ResourceLimits, ResourceTracker};
use raxosentinel_signatures::rsidb::{
    HashAlgorithm, MmapSortedIndex, RsidbCompiler, SignatureEntry,
};
use sha2::{Digest, Sha256};
use std::{io::Write, path::Path, time::Instant};
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: phase3a_bench_helper prepare|hash|db-load PATH"
    );
    let path = Path::new(&args[2]);
    match args[1].as_str() {
        "prepare" => {
            for n in [1_000_000usize, 10_000_000, 50_000_000] {
                let mut file = std::fs::File::create(path.join(format!("{n}.bin"))).unwrap();
                let block: Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
                let mut remaining = n;
                while remaining > 0 {
                    let len = remaining.min(block.len());
                    file.write_all(&block[..len]).unwrap();
                    remaining -= len;
                }
                file.sync_all().unwrap();
            }
            let sample = b"phase3a synthetic benchmark signature only";
            let db = RsidbCompiler::new()
                .with_directory(false)
                .compile(vec![SignatureEntry::new(
                    HashAlgorithm::Sha256,
                    sample.len() as u64,
                    Sha256::digest(sample).to_vec(),
                    "SyntheticBenchmarkFixture",
                )])
                .unwrap();
            std::fs::write(path.join("fixture.rsidb"), db).unwrap();
        }
        "hash" => {
            let limits = ResourceLimits {
                max_file_size: 60_000_000,
                max_scan_duration_ms: 60_000,
                ..Default::default()
            };
            let mut tracker = ResourceTracker::new(limits);
            let start = Instant::now();
            let result = hash_file_bounded(path, &mut tracker).unwrap();
            println!(
                "{{\"bytes\":{},\"elapsed_ms\":{:.6}}}",
                result.bytes_processed,
                start.elapsed().as_secs_f64() * 1000.0
            );
        }
        "db-load" => {
            let start = Instant::now();
            let _db = MmapSortedIndex::from_file(path).unwrap();
            println!(
                "{{\"elapsed_ms\":{:.6}}}",
                start.elapsed().as_secs_f64() * 1000.0
            );
        }
        _ => panic!("unknown operation"),
    }
}
