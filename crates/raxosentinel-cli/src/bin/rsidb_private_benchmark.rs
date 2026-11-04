// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! Release-mode local benchmark; accepts private evidence or legacy embedded response.
use raxosentinel_signatures::rsidb::{HashAlgorithm, MmapSortedIndex, RsidbIndex};
use std::{hint::black_box, path::Path, time::Instant};
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 2 || args.len() > 3 {
        eprintln!("Usage: rsidb_private_benchmark DATABASE [EVIDENCE]");
        std::process::exit(2);
    }
    let path = Path::new(&args[1]);
    if args.len() == 3 {
        raxosentinel_signatures::rsidb::malwarebazaar::verify_sidecar(path)
            .expect("sidecar verification failed");
    }
    let start = Instant::now();
    let db = MmapSortedIndex::from_file(path).expect("invalid database");
    let load = start.elapsed();
    let raw = if args.len() == 3 {
        std::fs::read_to_string(&args[2]).unwrap()
    } else {
        let p: serde_json::Value = serde_json::from_str(db.provenance()).unwrap();
        p["response_utf8"].as_str().unwrap().to_owned()
    };
    let response: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let queries: Vec<(u64, Vec<u8>)> = response["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| {
            let hash = hex::decode(r["sha256_hash"].as_str()?).ok()?;
            let size = r["file_size"].as_u64()?;
            if db.has_match(HashAlgorithm::Sha256, size, &hash) {
                Some((size, hash))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(queries.len(), db.record_count(HashAlgorithm::Sha256));
    for (size, hash) in &queries {
        assert!(!db.has_match(HashAlgorithm::Sha256, 0, hash));
        assert!(!db.has_match(HashAlgorithm::Sha256, size.saturating_add(1), hash));
    }
    let iterations = 10_000;
    let start = Instant::now();
    for _ in 0..iterations {
        for (size, hash) in &queries {
            black_box(db.has_match(HashAlgorithm::Sha256, *size, black_box(hash)));
        }
    }
    let positive = start.elapsed();
    let start = Instant::now();
    for _ in 0..iterations {
        for (_, hash) in &queries {
            black_box(db.has_match(HashAlgorithm::Sha256, 0, black_box(hash)));
        }
    }
    let negative = start.elapsed();
    let n = queries.len() * iterations;
    println!("records={} db_bytes={} evidence_bytes={} load_us={} positive_per_sec={:.0} negative_per_sec={:.0}", queries.len(), std::fs::metadata(path).unwrap().len(), if args.len() == 3 { std::fs::metadata(&args[2]).unwrap().len() } else { 0 }, load.as_micros(), n as f64 / positive.as_secs_f64(), n as f64 / negative.as_secs_f64());
}
