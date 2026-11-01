#![no_main]

use libfuzzer_sys::fuzz_target;
use raxosentinel_signatures::{load_rules_from_str, SignatureDatabase};

fuzz_target!(|data: &[u8]| {
    // Only test UTF-8 strings up to reasonable size
    if data.len() > 2 * 1024 * 1024 {
        return;
    }

    if let Ok(json_str) = std::str::from_utf8(data) {
        let mut db = SignatureDatabase::new();
        // Parser must reject invalid JSON, oversized patterns, or malicious rules safely
        let _ = load_rules_from_str(json_str, &mut db);
    }
});
