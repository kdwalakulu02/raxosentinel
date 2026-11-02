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

use crate::types::{FileCategory, FileType};
use raxosentinel_core::{Severity, Threat, ThreatCategory};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Detects file type from the leading bytes of content.
pub fn detect_type(header: &[u8]) -> FileType {
    if header.is_empty() {
        return FileType::new(
            "application/x-empty",
            FileCategory::Text,
            "Empty File",
            &[],
            false,
            false,
            false,
        );
    }

    // 1. Executables & Binaries
    if header.len() >= 2 && &header[0..2] == b"MZ" {
        // Check for PE header offset at 0x3C
        if header.len() >= 0x40 {
            let pe_offset =
                u32::from_le_bytes([header[0x3C], header[0x3D], header[0x3E], header[0x3F]])
                    as usize;

            if let Some(pe_end) = pe_offset.checked_add(4) {
                if header.len() >= pe_end && &header[pe_offset..pe_end] == b"PE\0\0" {
                    return FileType::new(
                        "application/vnd.microsoft.portable-executable",
                        FileCategory::Executable,
                        "Windows PE Executable / Dynamic Link Library",
                        &["exe", "dll", "sys", "scr", "ocx", "cpl"],
                        true,
                        true,
                        false,
                    );
                }
            }
        }
        return FileType::new(
            "application/x-dosexec",
            FileCategory::Executable,
            "MS-DOS Executable",
            &["exe", "com"],
            true,
            true,
            false,
        );
    }

    if header.len() >= 4 && &header[0..4] == b"\x7fELF" {
        return FileType::new(
            "application/x-executable",
            FileCategory::Executable,
            "ELF Executable / Shared Object",
            &["so", "bin", "elf"],
            true,
            true,
            false,
        );
    }

    // Mach-O binaries (32-bit, 64-bit, big/little endian)
    if header.len() >= 4 {
        let magic = &header[0..4];
        if magic == [0xfe, 0xed, 0xfa, 0xce]
            || magic == [0xce, 0xfa, 0xed, 0xfe]
            || magic == [0xfe, 0xed, 0xfa, 0xcf]
            || magic == [0xcf, 0xfa, 0xed, 0xfe]
        {
            return FileType::new(
                "application/x-mach-binary",
                FileCategory::Executable,
                "Mach-O Binary",
                &["dylib", "bundle"],
                true,
                true,
                false,
            );
        }
        // Mach-O Fat Binary or Java Class: 0xCAFEBABE
        if magic == [0xca, 0xfe, 0xba, 0xbe] {
            if header.len() >= 8 {
                let minor = u16::from_be_bytes([header[4], header[5]]);
                let major = u16::from_be_bytes([header[6], header[7]]);
                if (45..=70).contains(&major) {
                    return FileType::new(
                        "application/x-java-applet",
                        FileCategory::Executable,
                        format!("Java Class File (v{}.{})", major, minor),
                        &["class"],
                        true,
                        true,
                        false,
                    );
                }
            }
            return FileType::new(
                "application/x-mach-binary",
                FileCategory::Executable,
                "Mach-O Fat Binary",
                &["dylib"],
                true,
                true,
                false,
            );
        }
    }

    if header.len() >= 4 && &header[0..4] == b"\0asm" {
        return FileType::new(
            "application/wasm",
            FileCategory::Executable,
            "WebAssembly Binary",
            &["wasm"],
            true,
            true,
            false,
        );
    }

    // 2. Documents
    if header.len() >= 5 && &header[0..5] == b"%PDF-" {
        return FileType::new(
            "application/pdf",
            FileCategory::Document,
            "Portable Document Format (PDF)",
            &["pdf"],
            false,
            true, // PDFs can embed JavaScript or form actions
            false,
        );
    }

    if header.len() >= 5 && &header[0..5] == b"{\\rtf" {
        return FileType::new(
            "application/rtf",
            FileCategory::Document,
            "Rich Text Format (RTF)",
            &["rtf"],
            false,
            true, // RTFs frequently contain exploits
            false,
        );
    }

    // Microsoft Compound Document (OLE CFBF)
    if header.len() >= 8 && header[0..8] == [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] {
        return FileType::new(
            "application/x-ole-storage",
            FileCategory::Document,
            "Microsoft Compound Document (Legacy Office / OLE)",
            &["doc", "xls", "ppt", "msg"],
            false,
            true, // Can contain VBA macros
            false,
        );
    }

    // 3. Archives & Containers
    if header.len() >= 4 && (&header[0..4] == b"PK\x03\x04" || &header[0..4] == b"PK\x05\x06") {
        // Check if this ZIP container is an Office OpenXML document
        let is_openxml = check_zip_for_openxml(header);
        if is_openxml {
            return FileType::new(
                "application/vnd.openxmlformats-officedocument",
                FileCategory::Document,
                "Office Open XML Document (DOCX/XLSX/PPTX)",
                &["docx", "xlsx", "pptx", "docm", "xlsm"],
                false,
                true,
                true,
            );
        }

        return FileType::new(
            "application/zip",
            FileCategory::Archive,
            "ZIP Archive",
            &["zip", "jar"],
            false,
            false,
            true,
        );
    }

    if header.len() >= 2 && header[0..2] == [0x1f, 0x8b] {
        return FileType::new(
            "application/gzip",
            FileCategory::Archive,
            "GZIP Compressed Archive",
            &["gz", "tgz"],
            false,
            false,
            true,
        );
    }

    if header.len() >= 3 && &header[0..3] == b"BZh" {
        return FileType::new(
            "application/x-bzip2",
            FileCategory::Archive,
            "BZIP2 Compressed Archive",
            &["bz2"],
            false,
            false,
            true,
        );
    }

    if header.len() >= 6 && header[0..6] == [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] {
        return FileType::new(
            "application/x-7z-compressed",
            FileCategory::Archive,
            "7-Zip Archive",
            &["7z"],
            false,
            false,
            true,
        );
    }

    if header.len() >= 7 && &header[0..7] == b"Rar!\x1a\x07\x00" {
        return FileType::new(
            "application/vnd.rar",
            FileCategory::Archive,
            "RAR 4.x Archive",
            &["rar"],
            false,
            false,
            true,
        );
    }

    if header.len() >= 8 && &header[0..8] == b"Rar!\x1a\x07\x01\x00" {
        return FileType::new(
            "application/vnd.rar",
            FileCategory::Archive,
            "RAR 5.x Archive",
            &["rar"],
            false,
            false,
            true,
        );
    }

    if header.len() >= 6 && header[0..6] == [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] {
        return FileType::new(
            "application/x-xz",
            FileCategory::Archive,
            "XZ Archive",
            &["xz"],
            false,
            false,
            true,
        );
    }

    // TAR header (ustar, GNU or V7 format)
    if is_tar_header(header) {
        return FileType::new(
            "application/x-tar",
            FileCategory::Archive,
            "TAR Archive",
            &["tar"],
            false,
            false,
            true,
        );
    }

    // 4. Images
    if header.len() >= 8 && header[0..8] == [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] {
        return FileType::new(
            "image/png",
            FileCategory::Image,
            "PNG Image",
            &["png"],
            false,
            false,
            false,
        );
    }

    if header.len() >= 3 && header[0..3] == [0xff, 0xd8, 0xff] {
        return FileType::new(
            "image/jpeg",
            FileCategory::Image,
            "JPEG Image",
            &["jpg", "jpeg"],
            false,
            false,
            false,
        );
    }

    if header.len() >= 6 && (&header[0..6] == b"GIF87a" || &header[0..6] == b"GIF89a") {
        return FileType::new(
            "image/gif",
            FileCategory::Image,
            "GIF Image",
            &["gif"],
            false,
            false,
            false,
        );
    }

    if header.len() >= 2 && &header[0..2] == b"BM" {
        return FileType::new(
            "image/bmp",
            FileCategory::Image,
            "Bitmap Image",
            &["bmp"],
            false,
            false,
            false,
        );
    }

    if header.len() >= 12 && &header[0..4] == b"RIFF" && &header[8..12] == b"WEBP" {
        return FileType::new(
            "image/webp",
            FileCategory::Image,
            "WebP Image",
            &["webp"],
            false,
            false,
            false,
        );
    }

    // 5. Scripts & HTML
    if header.len() >= 2 && &header[0..2] == b"#!" {
        let preview = String::from_utf8_lossy(&header[..header.len().min(128)]);
        if preview.contains("python") {
            return FileType::new(
                "text/x-python",
                FileCategory::Script,
                "Python Script",
                &["py"],
                false,
                true,
                false,
            );
        }
        return FileType::new(
            "text/x-shellscript",
            FileCategory::Script,
            "Shell Script",
            &["sh", "bash"],
            false,
            true,
            false,
        );
    }

    // 6. Email / MIME detection
    if is_email_mime(header) {
        return FileType::new(
            "message/rfc822",
            FileCategory::Email,
            "RFC 822 Email Message (MIME)",
            &["eml", "msg"],
            false,
            true,
            true, // Can contain attachments
        );
    }

    // 7. HTML or XML
    if is_html_or_xml(header) {
        return FileType::new(
            "text/html",
            FileCategory::Document,
            "HTML Document",
            &["html", "htm"],
            false,
            true,
            false,
        );
    }

    // 8. Plain Text vs Binary
    if is_ascii_or_utf8(header) {
        FileType::plain_text()
    } else {
        FileType::unknown()
    }
}

/// Detects file type from a file path by reading up to 8 KiB of header data.
pub fn detect_file_type(path: &Path) -> std::io::Result<FileType> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; 8192];
    let bytes_read = file.read(&mut buffer)?;
    Ok(detect_type(&buffer[..bytes_read]))
}

/// Identifies deceptive filename extensions (e.g. executable or script disguised as PDF/JPG, RTLO, double extensions).
pub fn check_extension_mismatch(filename: &str, detected_type: &FileType) -> Option<Threat> {
    // 1. Check for Right-To-Left Override (RTLO) and directional spoofing (U+202A..=U+202E, U+2066..=U+2069, U+200E, U+200F)
    if filename.chars().any(|c| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}')) {
        return Some(Threat::new(
            "Suspicious.Filename.RightToLeftOverride",
            ThreatCategory::ExtensionMismatch,
            Severity::Critical,
            format!("Malicious Unicode directional override (RTLO) detected in filename: '{}'", filename),
            "filename_security_audit",
        ).with_location(filename));
    }

    // 2. Check for trailing space or dot evasion (e.g., 'payload.exe.' or 'invoice.pdf.exe ')
    let trimmed = filename.trim().trim_end_matches('.');
    if trimmed != filename && !trimmed.is_empty() {
        let p_trimmed = Path::new(trimmed);
        if let Some(t_ext) = p_trimmed
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_lowercase())
        {
            let dangerous_exts = [
                "exe", "scr", "bat", "cmd", "vbs", "ps1", "pif", "com", "hta", "jar", "dll",
            ];
            if dangerous_exts.contains(&t_ext.as_str()) {
                return Some(Threat::new(
                    "Suspicious.Filename.TrailingDelimiterEvasion",
                    ThreatCategory::ExtensionMismatch,
                    Severity::High,
                    format!("Filename '{}' conceals dangerous extension '.{}' via trailing spaces or dots", filename, t_ext),
                    "filename_security_audit",
                ).with_location(filename));
            }
        }
    }

    let path = Path::new(filename);
    let ext = path.extension()?.to_str()?.to_lowercase();

    // Check for double extensions like 'invoice.pdf.exe'
    let file_stem = path.file_stem()?.to_str()?;
    if let Some(inner_path) = Path::new(file_stem).extension() {
        let inner_ext = inner_path.to_str()?.to_lowercase();
        if is_deceptive_inner_extension(&inner_ext) && detected_type.is_executable {
            return Some(Threat::new(
                "Suspicious.DoubleExtension.Executable",
                ThreatCategory::ExtensionMismatch,
                Severity::High,
                format!(
                    "Deceptive double extension detected in '{}'. Appears as '.{}.{}' but contains executable code.",
                    filename, inner_ext, ext
                ),
                "extension_analysis",
            ).with_location(filename));
        }
    }

    // Check if filename claims to be a safe document or image, but actual content is executable
    let claims_benign_document_or_image = matches!(
        ext.as_str(),
        "pdf" | "jpg" | "jpeg" | "png" | "gif" | "txt" | "csv" | "bmp"
    );

    if claims_benign_document_or_image && detected_type.is_executable {
        return Some(Threat::new(
            "Suspicious.ExtensionMismatch.DisguisedExecutable",
            ThreatCategory::ExtensionMismatch,
            Severity::Critical,
            format!(
                "Severe file type mismatch: '{}' has a '.{}' extension, but content is an executable ({})",
                filename, ext, detected_type.description
            ),
            "content_inspection",
        ).with_location(filename));
    }

    None
}

fn is_deceptive_inner_extension(ext: &str) -> bool {
    matches!(
        ext,
        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "jpg" | "jpeg" | "png" | "txt"
    )
}

/// Determines if the byte slice begins with a valid TAR archive header
/// (POSIX ustar, GNU tar, or V7 tar format).
pub fn is_tar_header(header: &[u8]) -> bool {
    // 1. POSIX ustar / GNU tar magic check at offset 257..262
    if header.len() >= 262 && &header[257..262] == b"ustar" {
        return true;
    }

    // 2. V7 Tar header checksum validation on 512-byte header block
    if header.len() >= 512 {
        if header[0] == 0 {
            return false;
        }
        let chk_bytes = &header[148..156];
        let mut chk_val: u32 = 0;
        let mut has_digit = false;
        for &b in chk_bytes {
            if (b'0'..=b'7').contains(&b) {
                has_digit = true;
                chk_val = (chk_val << 3) + (b - b'0') as u32;
            } else if b == 0 || b == b' ' {
                if has_digit {
                    break;
                }
            } else {
                return false;
            }
        }

        if has_digit {
            let mut unsigned_sum: u32 = 0;
            let mut signed_sum: i32 = 0;
            for (i, &b) in header[..512].iter().enumerate() {
                let v = if (148..156).contains(&i) { 0x20u8 } else { b };
                unsigned_sum += v as u32;
                signed_sum += (v as i8) as i32;
            }
            if unsigned_sum == chk_val || signed_sum == chk_val as i32 {
                let mode_has_octal = header[100..108].iter().any(|&b| (b'0'..=b'7').contains(&b));
                let size_has_octal = header[124..136].iter().any(|&b| (b'0'..=b'7').contains(&b));
                if mode_has_octal || size_has_octal {
                    return true;
                }
            }
        }
    }
    false
}

fn check_zip_for_openxml(header: &[u8]) -> bool {
    // Search for '[Content_Types].xml' or 'word/' or 'xl/' inside initial ZIP header data
    let marker = b"[Content_Types].xml";
    header.windows(marker.len()).any(|w| w == marker)
}

fn is_email_mime(header: &[u8]) -> bool {
    // Check for mbox start
    if header.starts_with(b"From ") {
        return true;
    }

    let search_len = header.len().min(4096);
    let sample = String::from_utf8_lossy(&header[..search_len]);

    // Check for RFC 822 headers at line boundaries
    let header_indicators = [
        "From:",
        "To:",
        "Subject:",
        "Date:",
        "Received:",
        "MIME-Version:",
        "Content-Type:",
        "Message-ID:",
        "Return-Path:",
        "Delivered-To:",
    ];

    let mut found_count = 0;
    for line in sample.lines() {
        let trimmed = line.trim_start();
        for indicator in &header_indicators {
            if trimmed.starts_with(indicator) {
                found_count += 1;
                break;
            }
        }
        if found_count >= 2 {
            return true;
        }
    }

    false
}

fn is_html_or_xml(header: &[u8]) -> bool {
    let sample = String::from_utf8_lossy(&header[..header.len().min(512)]).to_lowercase();
    sample.starts_with("<!doctype html")
        || sample.starts_with("<html")
        || sample.starts_with("<?xml")
}

fn is_ascii_or_utf8(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }

    // Must be valid UTF-8
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Check for binary control characters (excluding tab, LF, CR)
    for c in s.chars() {
        if c.is_control() && c != '\t' && c != '\n' && c != '\r' {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_pe_executable() {
        let mut pe_data = vec![0u8; 256];
        pe_data[0] = b'M';
        pe_data[1] = b'Z';
        pe_data[0x3C] = 0x80; // PE offset at 128
        pe_data[0x80..0x84].copy_from_slice(b"PE\0\0");

        let ft = detect_type(&pe_data);
        assert_eq!(ft.category, FileCategory::Executable);
        assert!(ft.is_executable);
        assert_eq!(
            ft.mime_type,
            "application/vnd.microsoft.portable-executable"
        );
    }

    #[test]
    fn test_detect_dos_executable() {
        let mut dos_data = vec![0u8; 32];
        dos_data[0] = b'M';
        dos_data[1] = b'Z';

        let ft = detect_type(&dos_data);
        assert_eq!(ft.category, FileCategory::Executable);
        assert!(ft.is_executable);
        assert_eq!(ft.mime_type, "application/x-dosexec");
    }

    #[test]
    fn test_detect_elf() {
        let elf_data = b"\x7fELF\x02\x01\x01\x00";
        let ft = detect_type(elf_data);
        assert_eq!(ft.category, FileCategory::Executable);
        assert!(ft.is_executable);
        assert_eq!(ft.mime_type, "application/x-executable");
    }

    #[test]
    fn test_detect_pdf() {
        let pdf_data = b"%PDF-1.7\r\n1 0 obj...";
        let ft = detect_type(pdf_data);
        assert_eq!(ft.category, FileCategory::Document);
        assert_eq!(ft.mime_type, "application/pdf");
        assert!(ft.can_contain_code);
    }

    #[test]
    fn test_detect_zip() {
        let zip_data = b"PK\x03\x04\x14\x00\x00\x00";
        let ft = detect_type(zip_data);
        assert_eq!(ft.category, FileCategory::Archive);
        assert_eq!(ft.mime_type, "application/zip");
        assert!(ft.is_archive);
    }

    #[test]
    fn test_detect_email() {
        let eml =
            b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nHello";
        let ft = detect_type(eml);
        assert_eq!(ft.category, FileCategory::Email);
        assert_eq!(ft.mime_type, "message/rfc822");
    }

    #[test]
    fn test_detect_empty_file() {
        let ft = detect_type(b"");
        assert_eq!(ft.mime_type, "application/x-empty");
    }

    #[test]
    fn test_extension_mismatch_detected() {
        let mut pe_data = vec![0u8; 256];
        pe_data[0] = b'M';
        pe_data[1] = b'Z';
        pe_data[0x3C] = 0x80;
        pe_data[0x80..0x84].copy_from_slice(b"PE\0\0");
        let ft = detect_type(&pe_data);

        // Disguised as invoice.pdf
        let mismatch = check_extension_mismatch("invoice.pdf", &ft);
        assert!(mismatch.is_some());
        let threat = mismatch.unwrap();
        assert_eq!(threat.category, ThreatCategory::ExtensionMismatch);
        assert_eq!(threat.severity, Severity::Critical);
    }

    #[test]
    fn test_double_extension_detected() {
        let mut pe_data = vec![0u8; 256];
        pe_data[0] = b'M';
        pe_data[1] = b'Z';
        pe_data[0x3C] = 0x80;
        pe_data[0x80..0x84].copy_from_slice(b"PE\0\0");
        let ft = detect_type(&pe_data);

        let mismatch = check_extension_mismatch("invoice.pdf.exe", &ft);
        assert!(mismatch.is_some());
        let threat = mismatch.unwrap();
        assert_eq!(threat.category, ThreatCategory::ExtensionMismatch);
    }
}
