#![no_main]

use libfuzzer_sys::fuzz_target;
use raxosentinel_core::{ResourceLimits, ResourceTracker};
use raxosentinel_email::EmailScanner;
use raxosentinel_signatures::SignatureDatabase;
use std::sync::OnceLock;

static DB: OnceLock<SignatureDatabase> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }

    let db = DB.get_or_init(SignatureDatabase::with_defaults);

    let limits = ResourceLimits {
        max_file_size: 1024 * 1024,
        max_scan_duration_ms: 500,
        max_email_attachments: 10,
        max_email_depth: 3,
        buffer_size: 8192,
        ..Default::default()
    };
    let mut tracker = ResourceTracker::new(limits);
    let scanner = EmailScanner::new(db);

    // Scanner must never crash or panic on arbitrary malformed MIME or nested bytes
    let _ = scanner.scan_bytes(data, Some("fuzz_target.eml"), &mut tracker);
});
