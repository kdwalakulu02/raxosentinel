// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! Local warm-cache timings and migration of already verified private evidence.
use raxosentinel_signatures::rsidb::{
    malwarebazaar::{private_store, verify_sidecar},
    MmapSortedIndex, RsidbIndex,
};
use std::path::Path;
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: private_generation_benchmark ROOT GENERATION SAMPLES [LEGACY_DATABASE]");
        std::process::exit(2);
    }
    let root = Path::new(&args[1]);
    let generation = &args[2];
    if args.len() == 5 {
        let old = Path::new(&args[4]);
        verify_sidecar(old).expect("legacy evidence rejected");
        let db = MmapSortedIndex::from_bytes(std::fs::read(old).unwrap()).unwrap();
        let manifest: serde_json::Value = serde_json::from_str(db.provenance()).unwrap();
        let timestamp = manifest["acquired_unix_seconds"].as_u64().unwrap();
        let evidence =
            std::fs::read(old.with_file_name(manifest["sidecar"].as_str().unwrap())).unwrap();
        private_store::publish(root, generation, &evidence, timestamp).expect("publication failed");
    } else if args.len() != 4 {
        std::process::exit(2);
    }
    let samples: usize = args[3].parse().expect("invalid sample count");
    assert!(samples > 0);
    let mut values = Vec::new();
    let mut records = 0;
    for _ in 0..samples {
        let start = std::time::Instant::now();
        private_store::incomplete(root).expect("staging inspection failed");
        let (db, times) =
            private_store::load_timed(root, generation).expect("verified load failed");
        records = db.total_records();
        values.push((
            times.database.as_micros(),
            times.evidence.as_micros(),
            start.elapsed().as_micros(),
        ));
    }
    fn describe(mut values: Vec<u128>) -> (u128, u128, u128) {
        values.sort_unstable();
        (
            values[values.len() / 2],
            values[0],
            values[values.len() - 1],
        )
    }
    println!("records={records} samples={samples} warm-cache_us database(median,min,max)={:?} evidence={:?} total={:?}", describe(values.iter().map(|x| x.0).collect()), describe(values.iter().map(|x| x.1).collect()), describe(values.iter().map(|x| x.2).collect()));
}
