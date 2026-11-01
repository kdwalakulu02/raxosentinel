#![no_main]

use libfuzzer_sys::fuzz_target;
use raxosentinel_core::{ResourceLimits, ResourceTracker};
use raxosentinel_signatures::SignatureDatabase;
use std::io::Cursor;
use std::sync::OnceLock;

static DB: OnceLock<SignatureDatabase> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }

    let db = DB.get_or_init(SignatureDatabase::with_defaults);

    // 1. In-memory pattern match
    let _ = db.match_bytes(data);

    // 2. Stream chunked match with boundary crossing
    let limits = ResourceLimits {
        buffer_size: 64, // deliberately small chunk to aggressively exercise carry_buf crossing
        max_file_size: 1024 * 1024,
        ..Default::default()
    };
    let mut tracker = ResourceTracker::new(limits);
    let mut cursor = Cursor::new(data);
    let _ = db.match_stream(&mut cursor, &mut tracker);
});
