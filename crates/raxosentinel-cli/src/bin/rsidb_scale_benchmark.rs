// Copyright (C) 2026 RaxoSentinel Contributors
// SPDX-License-Identifier: GPL-2.0-or-later
//! Synthetic operational RSIDB benchmark; does not model acquisition-history verification.
use raxosentinel_signatures::rsidb::{
    HashAlgorithm, MmapSortedIndex, RsidbCompiler, RsidbIndex, SignatureEntry,
};
use sha2::{Digest, Sha256};
use std::{hint::black_box, time::Instant};
fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .expect("expected synthetic count")
        .parse()
        .expect("invalid count");
    assert!(n > 0);
    let entries: Vec<_> = (0..n)
        .map(|i| {
            let digest = Sha256::digest(format!("RAXO-SYNTHETIC-ONLY-{i}").as_bytes()).to_vec();
            SignatureEntry::new(
                HashAlgorithm::Sha256,
                (i % 4096 + 1) as u64,
                digest,
                "SyntheticFixture",
            )
        })
        .collect();
    let sample: Vec<_> = entries
        .iter()
        .take(n.min(1000))
        .map(|e| (e.size, e.digest.clone()))
        .collect();
    let t = Instant::now();
    let bytes = RsidbCompiler::new()
        .with_directory(n >= 65_536)
        .compile(entries)
        .unwrap();
    let compile = t.elapsed();
    let size = bytes.len();
    let t = Instant::now();
    let db = MmapSortedIndex::from_bytes(bytes).unwrap();
    let load = t.elapsed();
    let loops = 100_000usize;
    let t = Instant::now();
    for i in 0..loops {
        let (size, digest) = &sample[i % sample.len()];
        assert!(black_box(db.has_match(
            HashAlgorithm::Sha256,
            *size,
            black_box(digest)
        )));
    }
    let positive = t.elapsed();
    let t = Instant::now();
    for i in 0..loops {
        let (size, digest) = &sample[i % sample.len()];
        assert!(!black_box(db.has_match(
            HashAlgorithm::Sha256,
            *size + 100_000,
            black_box(digest)
        )));
    }
    let negative = t.elapsed();
    println!("synthetic_records={n} rsidb_bytes={size} compile_ms={:.3} structural_load_ms={:.3} positive_per_sec={:.0} negative_per_sec={:.0}",compile.as_secs_f64()*1000.0,load.as_secs_f64()*1000.0,loops as f64/positive.as_secs_f64(),loops as f64/negative.as_secs_f64());
}
