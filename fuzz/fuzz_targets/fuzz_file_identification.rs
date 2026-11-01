#![no_main]

use libfuzzer_sys::fuzz_target;
use raxosentinel_filetypes::{check_extension_mismatch, detect_type};

fuzz_target!(|data: &[u8]| {
    // 1. Fuzz raw file type detection with arbitrary headers / bytes
    let ft = detect_type(data);

    // 2. Fuzz extension mismatch detection with generated or varied filenames
    if let Ok(filename_candidate) = std::str::from_utf8(data) {
        let _ = check_extension_mismatch(filename_candidate, &ft);
    }

    // Also test common malicious naming patterns against detected type
    let test_names = [
        "invoice.pdf.exe",
        "doc.pdf\u{202E}exe",
        "document.docx.",
        "payload.scr",
        "normal.txt",
    ];
    for name in &test_names {
        let _ = check_extension_mismatch(name, &ft);
    }
});
