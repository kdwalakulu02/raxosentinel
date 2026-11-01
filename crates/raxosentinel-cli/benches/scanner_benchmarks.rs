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

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use raxosentinel_core::{hash_reader_bounded, MemoryUsage, ResourceLimits, ResourceTracker};
use raxosentinel_email::EmailScanner;
use raxosentinel_signatures::SignatureDatabase;
use std::io::Cursor;

fn bench_hashing_and_pattern_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("bounded_stream_scan");
    let db = SignatureDatabase::with_defaults();

    for size_kb in [64, 512, 2048] {
        let size_bytes = size_kb * 1024;
        let mut sample_data = vec![0x41u8; size_bytes];
        // Embed a pattern halfway through
        let mid = size_bytes / 2;
        let pattern = b"RAXOSENTINEL-SYNTHETIC-TEST-SIGNATURE";
        sample_data[mid..mid + pattern.len()].copy_from_slice(pattern);

        group.throughput(Throughput::Bytes(size_bytes as u64));

        group.bench_function(format!("scan_{}_kib", size_kb), |b| {
            b.iter(|| {
                let limits = ResourceLimits::default();
                let mut tracker = ResourceTracker::new(limits);
                let mut cursor = Cursor::new(black_box(&sample_data));

                let _hash = hash_reader_bounded(&mut cursor, &mut tracker).unwrap();
                cursor.set_position(0);
                let _threats = db.match_stream(&mut cursor, &mut tracker).unwrap();
            });
        });
    }

    group.finish();
}

fn bench_email_mime_parsing_and_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("email_mime_scan");
    let db = SignatureDatabase::with_defaults();
    let scanner = EmailScanner::new(&db);

    let raw_email = b"MIME-Version: 1.0\r\n\
From: sender@corporate-domain.com\r\n\
To: recipient@client-domain.com\r\n\
Subject: Monthly Financial Statement and Analysis\r\n\
Content-Type: multipart/mixed; boundary=\"BOUNDARY_TAG\"\r\n\
\r\n\
--BOUNDARY_TAG\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Hello,\r\n\
Please review the attached statement.\r\n\
Best regards,\r\n\
Finance Team\r\n\
--BOUNDARY_TAG\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"statement_october.pdf\"\r\n\
\r\n\
%PDF-1.4\r\n1 0 obj\r\n<< /Type /Catalog >>\r\nendobj\r\n\
--BOUNDARY_TAG--\r\n";

    group.throughput(Throughput::Bytes(raw_email.len() as u64));

    group.bench_function("parse_and_scan_multipart_email", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let mut tracker = ResourceTracker::new(limits);
            let report = scanner
                .scan_bytes(black_box(raw_email), Some("statement.eml"), &mut tracker)
                .unwrap();
            black_box(report);
        });
    });

    group.finish();
}

fn bench_memory_measurements(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_footprint");
    let db = SignatureDatabase::with_defaults();

    // 10 MiB buffer
    let data_10mb = vec![0x55u8; 10 * 1024 * 1024];

    group.bench_function("measure_10mb_streaming_memory", |b| {
        b.iter(|| {
            let initial_mem = MemoryUsage::capture();
            let limits = ResourceLimits::default();
            let mut tracker = ResourceTracker::new(limits);
            let mut cursor = Cursor::new(black_box(&data_10mb));

            let _ = hash_reader_bounded(&mut cursor, &mut tracker).unwrap();
            cursor.set_position(0);
            let _ = db.match_stream(&mut cursor, &mut tracker).unwrap();

            let post_mem = MemoryUsage::capture();
            black_box((initial_mem, post_mem));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hashing_and_pattern_scanning,
    bench_email_mime_parsing_and_scanning,
    bench_memory_measurements
);
criterion_main!(benches);
