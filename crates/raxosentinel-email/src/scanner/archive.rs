// RaxoSentinel - Email and file malware scanning engine
// Copyright (C) 2026 RaxoSentinel Contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! Bounded, in-memory inspection of archives and compressed streams: ZIP
//! (including Office Open XML packages and multiple/embedded ZIP structures), TAR,
//! GZIP, BZIP2, XZ and OLE2/CFB compound files.
//!
//! Nothing is written to the filesystem; member names are display labels only, so
//! path traversal names cannot cause writes. Every member is read through an
//! [`Extractor`]: members up to the buffer limit are inspected recursively with
//! `scan_object`, larger ones are pattern/YARA-scanned in streaming mode. Each
//! member counts against `max_archive_members`, a 1000:1 expansion ratio and the
//! extracted/streamed byte budgets. Structures that cannot be fully inspected
//! (encrypted, unsupported methods, unreferenced or overlapping entries,
//! truncation, trailing data, macros) are never CLEAN.

use super::extract::{Extracted, Extractor};
use super::{more_severe, plausible_zip_local_header, EmailScanner};
use raxosentinel_core::{ResourceTracker, ScanError, ScanReport, ScanStatus};
use std::collections::HashSet;
use std::io::{Cursor, Read};

pub(crate) type Issue = Option<(ScanStatus, String)>;

/// Diagnostic codes prefixed to archive inspection messages.
pub(crate) mod code {
    pub const MALFORMED: &str = "ARCHIVE_MALFORMED";
    pub const TRUNCATED: &str = "ARCHIVE_TRUNCATED";
    pub const TRAILING: &str = "ARCHIVE_TRAILING_DATA";
    pub const RATIO: &str = "ARCHIVE_RATIO_EXCEEDED";
    pub const LIMIT: &str = "ARCHIVE_LIMIT";
    pub const MEMBER_CORRUPT: &str = "ARCHIVE_MEMBER_CORRUPT";
    pub const ENCRYPTED: &str = "ARCHIVE_ENCRYPTED";
    pub const UNSUPPORTED_METHOD: &str = "ARCHIVE_UNSUPPORTED_METHOD";
    pub const ZIP_UNREFERENCED: &str = "ZIP_UNREFERENCED_STRUCTURE";
    pub const ZIP_OVERLAP: &str = "ZIP_OVERLAPPING_ENTRIES";
    pub const ZIP_STRUCTURES: &str = "ZIP_TOO_MANY_STRUCTURES";
    pub const TAR_UNSUPPORTED: &str = "TAR_UNSUPPORTED_ENTRY";
    pub const OFFICE_ACTIVE: &str = "OFFICE_ACTIVE_CONTENT";
    pub const OFFICE_ENCRYPTED: &str = "OFFICE_ENCRYPTED";
}

/// Decompressed bytes allowed per compressed byte before an object is treated as
/// a decompression bomb.
pub(crate) const MAX_EXPANSION_RATIO: u64 = 1000;
/// Small members may always expand this far, regardless of ratio.
const RATIO_FLOOR: u64 = 1 << 20;
/// Separate ZIP end-of-central-directory structures opened per object.
const MAX_ZIP_STRUCTURES: usize = 16;
/// TAR metadata records (GNU long names, PAX headers) are buffered up to this size.
const MAX_TAR_METADATA: u64 = 1 << 20;
/// XZ decoder memory limit (KiB): enough for `xz -9`/`-9e` (64 MiB dictionary).
const XZ_MEM_LIMIT_KIB: u32 = 96 * 1024;
const READ_CHUNK: usize = 64 * 1024;
const MAX_LABEL_CHARS: usize = 256;

/// Sub-reports and the most severe inspection issue of one container.
#[derive(Default)]
pub(crate) struct Inspected {
    pub subs: Vec<ScanReport>,
    pub issue: Issue,
    /// Byte spans of the container whose content was decoded and inspected; the
    /// embedded-container sweep of the outer object skips them.
    pub covered: Vec<(usize, usize)>,
}

impl Inspected {
    pub fn raise(&mut self, status: ScanStatus, message: String) {
        self.issue = more_severe(self.issue.take(), Some((status, message)));
    }
}

/// Compressed single-stream formats decoded member by member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamFormat {
    Gzip,
    Bzip2,
    Xz,
}

impl StreamFormat {
    fn name(self) -> &'static str {
        match self {
            StreamFormat::Gzip => "GZIP",
            StreamFormat::Bzip2 => "BZIP2",
            StreamFormat::Xz => "XZ",
        }
    }
}

fn label_of(parent: &str, name: &str) -> String {
    let clean: String = name
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_LABEL_CHARS)
        .collect();
    format!("{parent}/{clean}")
}

fn within(spans: &[(usize, usize)], pos: usize) -> bool {
    spans.iter().any(|&(s, e)| s <= pos && pos < e)
}

impl EmailScanner<'_> {
    /// Reads one archive member or decompressed stream and inspects it.
    /// `packed` is the compressed size used for the expansion-ratio check.
    pub(crate) fn inspect_member(
        &self,
        reader: &mut dyn Read,
        label: &str,
        packed: u64,
        tracker: &mut ResourceTracker,
        depth: usize,
        out: &mut Inspected,
    ) -> Result<(), ScanError> {
        let start = tracker.elapsed_millis();
        let ratio_limit = packed.saturating_mul(MAX_EXPANSION_RATIO).max(RATIO_FLOOR);
        let buffer_limit = tracker.limits().max_email_attachment_size;
        let mut problem: Issue = None;
        let extracted = {
            let mut ex = Extractor::new(self.db, tracker, buffer_limit);
            let mut chunk = vec![0u8; READ_CHUNK];
            let mut total = 0u64;
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        total += n as u64;
                        if total > ratio_limit {
                            problem = Some((
                                ScanStatus::Failed,
                                format!(
                                    "{}: {label} expands beyond {MAX_EXPANSION_RATIO}:1 \
                                     ({packed} compressed bytes); possible decompression bomb",
                                    code::RATIO
                                ),
                            ));
                            break;
                        }
                        use super::pdf_decode::ChunkSink;
                        if ex.write(&chunk[..n]).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        problem = Some((
                            ScanStatus::Unsupported,
                            format!(
                                "{}: {label} could not be fully decompressed: {e}",
                                code::MEMBER_CORRUPT
                            ),
                        ));
                        break;
                    }
                }
            }
            ex.finish(problem.is_none())
        };
        match extracted {
            Err(e @ ScanError::Timeout { .. }) => return Err(e),
            Err(e) => out.raise(
                ScanStatus::Failed,
                format!("{}: {label}: {e}", code::LIMIT),
            ),
            Ok(Extracted::Buffered(buf)) => {
                if let Err(e) = tracker.record_extracted_bytes(buf.len()) {
                    if matches!(e, ScanError::Timeout { .. }) {
                        return Err(e);
                    }
                    out.raise(ScanStatus::Failed, format!("{}: {label}: {e}", code::LIMIT));
                } else {
                    match self.scan_object(&buf, label, None, tracker, depth) {
                        Ok(r) => out.subs.push(r),
                        Err(e @ ScanError::Timeout { .. }) => return Err(e),
                        Err(e) => out.raise(
                            ScanStatus::Failed,
                            format!("{}: {label} scan failed: {e}", code::LIMIT),
                        ),
                    }
                }
            }
            Ok(Extracted::Streamed(object)) => {
                let ms = tracker.elapsed_millis().saturating_sub(start);
                out.subs.push(object.report(label, ms));
            }
        }
        if let Some((status, message)) = problem {
            out.raise(status, message);
        }
        Ok(())
    }

    fn admit_member(
        &self,
        tracker: &mut ResourceTracker,
        out: &mut Inspected,
    ) -> Result<bool, ScanError> {
        match tracker.register_archive_member() {
            Ok(()) => Ok(true),
            Err(e @ ScanError::Timeout { .. }) => Err(e),
            Err(e) => {
                out.raise(
                    ScanStatus::Failed,
                    format!("{}: archive member limit reached: {e}", code::LIMIT),
                );
                Ok(false)
            }
        }
    }

    /// Decodes concatenated GZIP/BZIP2/XZ members; each member is inspected as an
    /// object. Data after the last member must be absent (or XZ stream padding).
    pub(crate) fn scan_compressed(
        &self,
        format: StreamFormat,
        data: &[u8],
        parent: &str,
        tracker: &mut ResourceTracker,
        depth: usize,
    ) -> Result<Inspected, ScanError> {
        let mut out = Inspected::default();
        if let Err(e) = tracker.check_depth(depth) {
            out.raise(ScanStatus::Failed, format!("{} not inspected: {e}", format.name()));
            return Ok(out);
        }
        // The whole stream is decoded; trailing data is reported.
        out.covered.push((0, data.len()));
        if format == StreamFormat::Xz {
            // lzma-rust2 decodes concatenated streams and stream padding itself.
            if self.admit_member(tracker, &mut out)? {
                let mut reader =
                    lzma_rust2::XzReader::new_mem_limit(data, true, XZ_MEM_LIMIT_KIB);
                let label = format!("{parent}/xz-content");
                self.inspect_member(&mut reader, &label, data.len() as u64, tracker, depth, &mut out)?;
            }
            return Ok(out);
        }
        let mut remaining = data;
        let mut index = 0usize;
        while !remaining.is_empty() {
            tracker.check_timeout()?;
            let magic: &[u8] = match format {
                StreamFormat::Gzip => b"\x1f\x8b\x08",
                _ => b"BZh",
            };
            if !remaining.starts_with(magic) {
                out.raise(
                    ScanStatus::Unsupported,
                    format!(
                        "{}: {} bytes after the last {} member were not inspected",
                        code::TRAILING,
                        remaining.len(),
                        format.name()
                    ),
                );
                break;
            }
            if !self.admit_member(tracker, &mut out)? {
                break;
            }
            let label = format!("{parent}/{}-member-{index}", format.name().to_lowercase());
            let mut cursor = remaining;
            let next = match format {
                StreamFormat::Gzip => {
                    let mut decoder = flate2::bufread::GzDecoder::new(&mut cursor);
                    self.inspect_member(&mut decoder, &label, remaining.len() as u64, tracker, depth, &mut out)?;
                    drop(decoder);
                    cursor
                }
                _ => {
                    let mut decoder = bzip2::bufread::BzDecoder::new(&mut cursor);
                    self.inspect_member(&mut decoder, &label, remaining.len() as u64, tracker, depth, &mut out)?;
                    drop(decoder);
                    cursor
                }
            };
            if out.issue.is_some() {
                break;
            }
            if next.len() >= remaining.len() {
                out.raise(
                    ScanStatus::Failed,
                    format!("{}: {} decoder made no progress", code::MALFORMED, format.name()),
                );
                break;
            }
            remaining = next;
            index += 1;
        }
        Ok(out)
    }

    /// Inspects every ZIP structure in `data`: each end-of-central-directory record
    /// outside already-covered spans is opened as its own archive, members are
    /// de-duplicated by local-header offset, and any local or central header not
    /// explained by an opened archive (or by `skip`, e.g. inspected PDF streams)
    /// makes the result non-CLEAN.
    pub(crate) fn scan_zip(
        &self,
        data: &[u8],
        parent: &str,
        skip: &[(usize, usize)],
        tracker: &mut ResourceTracker,
        depth: usize,
    ) -> Result<Inspected, ScanError> {
        let mut out = Inspected::default();
        if let Err(e) = tracker.check_depth(depth) {
            out.raise(ScanStatus::Failed, format!("ZIP not inspected: {e}"));
            return Ok(out);
        }

        let mut eocds: Vec<(usize, usize)> = memchr::memmem::find_iter(data, b"PK\x05\x06")
            .filter_map(|p| {
                let comment = data.get(p + 20..p + 22)?;
                let end = p + 22 + u16::from_le_bytes([comment[0], comment[1]]) as usize;
                (end <= data.len()).then_some((p, end))
            })
            .collect();
        eocds.reverse();

        let mut covered: Vec<(usize, usize)> = Vec::new();
        let mut entries: Vec<(usize, usize)> = Vec::new();
        let mut seen: HashSet<u64> = HashSet::new();
        let mut names: Vec<String> = Vec::new();
        let mut opened = 0usize;

        if eocds.is_empty() {
            let message = match zip::ZipArchive::new(Cursor::new(data)) {
                Ok(_) => "no end of central directory record".to_string(),
                Err(e) => e.to_string(),
            };
            out.raise(
                ScanStatus::Unsupported,
                format!("{}: Malformed ZIP container: {message}", code::MALFORMED),
            );
        }
        for &(pos, end) in &eocds {
            tracker.check_timeout()?;
            if within(&covered, pos) || within(skip, pos) {
                continue;
            }
            if opened == MAX_ZIP_STRUCTURES {
                out.raise(
                    ScanStatus::Unsupported,
                    format!(
                        "{}: more than {MAX_ZIP_STRUCTURES} ZIP structures; remaining ones \
                         not inspected",
                        code::ZIP_STRUCTURES
                    ),
                );
                break;
            }
            let mut archive = match zip::ZipArchive::new(Cursor::new(&data[..end])) {
                Ok(a) => a,
                Err(e) => {
                    out.raise(
                        ScanStatus::Unsupported,
                        format!(
                            "{}: Malformed ZIP container (end record at offset {pos}): {e}",
                            code::MALFORMED
                        ),
                    );
                    covered.push((pos, end));
                    continue;
                }
            };
            opened += 1;
            let cd_start = (archive.central_directory_start() as usize).min(pos);
            covered.push((cd_start, end));
            self.scan_zip_archive(
                &mut archive,
                parent,
                tracker,
                depth,
                &mut out,
                &mut covered,
                &mut entries,
                &mut seen,
                &mut names,
            )?;
        }

        // Overlapping member data (the "overlapping files" bomb technique, or
        // ambiguous structures) is never treated as fully inspected.
        entries.sort_unstable();
        if let Some(w) = entries.windows(2).find(|w| w[1].0 < w[0].1) {
            out.raise(
                ScanStatus::Failed,
                format!(
                    "{}: ZIP entries at offsets {} and {} overlap",
                    code::ZIP_OVERLAP,
                    w[0].0,
                    w[1].0
                ),
            );
        }

        // Headers that no opened central directory explains may hide content.
        tracker.check_timeout()?;
        let unexplained = |magic: &[u8], valid: fn(&[u8]) -> bool| {
            memchr::memmem::find_iter(data, magic)
                .find(|&p| !within(&covered, p) && !within(skip, p) && valid(&data[p..]))
        };
        if let Some(p) = unexplained(b"PK\x03\x04", plausible_zip_local_header) {
            out.raise(
                ScanStatus::Unsupported,
                format!(
                    "{}: ZIP local header at offset {p} is not referenced by any central \
                     directory; its contents were not inspected",
                    code::ZIP_UNREFERENCED
                ),
            );
        } else if let Some(p) = unexplained(b"PK\x01\x02", plausible_zip_central_header) {
            out.raise(
                ScanStatus::Unsupported,
                format!(
                    "{}: ZIP central directory header at offset {p} is not part of an \
                     inspected archive",
                    code::ZIP_UNREFERENCED
                ),
            );
        }

        office_package_checks(&names, &mut out);
        covered.extend(entries);
        out.covered = covered;
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_zip_archive(
        &self,
        archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
        parent: &str,
        tracker: &mut ResourceTracker,
        depth: usize,
        out: &mut Inspected,
        covered: &mut Vec<(usize, usize)>,
        entries: &mut Vec<(usize, usize)>,
        seen: &mut HashSet<u64>,
        names: &mut Vec<String>,
    ) -> Result<(), ScanError> {
        for i in 0..archive.len() {
            tracker.check_timeout()?;
            let meta = match archive.by_index_raw(i) {
                Ok(f) => {
                    let span = (
                        f.header_start() as usize,
                        (f.data_start().saturating_add(f.compressed_size())) as usize,
                    );
                    Some((
                        f.name().to_string(),
                        f.is_dir(),
                        f.encrypted(),
                        f.header_start(),
                        span,
                        f.compressed_size(),
                    ))
                }
                Err(e) => {
                    out.raise(
                        ScanStatus::Unsupported,
                        format!("{}: ZIP member {i} unreadable: {e}", code::MALFORMED),
                    );
                    None
                }
            };
            let Some((name, is_dir, encrypted, header, span, packed)) = meta else {
                continue;
            };
            if !seen.insert(header) {
                continue;
            }
            covered.push(span);
            entries.push(span);
            names.push(name.clone());
            if is_dir && packed == 0 {
                continue;
            }
            if !self.admit_member(tracker, out)? {
                return Ok(());
            }
            let label = label_of(parent, &name);
            if encrypted {
                out.raise(
                    ScanStatus::Unsupported,
                    format!("{}: Encrypted ZIP member: {label}", code::ENCRYPTED),
                );
                continue;
            }
            let mut file = match archive.by_index(i) {
                Ok(f) => f,
                Err(zip::result::ZipError::UnsupportedArchive(m)) => {
                    out.raise(
                        ScanStatus::Unsupported,
                        format!(
                            "{}: ZIP member {label} not inspectable: {m}",
                            code::UNSUPPORTED_METHOD
                        ),
                    );
                    continue;
                }
                Err(e) => {
                    out.raise(
                        ScanStatus::Unsupported,
                        format!("{}: ZIP member {label} unreadable: {e}", code::MALFORMED),
                    );
                    continue;
                }
            };
            self.inspect_member(&mut file, &label, packed, tracker, depth, out)?;
        }
        Ok(())
    }

    /// Inspects TAR members (ustar, GNU and PAX). Long names and PAX size overrides
    /// are honoured; sparse/multi-volume entries, bad checksums, truncation and
    /// non-zero data after the end-of-archive marker are reported, never CLEAN.
    pub(crate) fn scan_tar(
        &self,
        data: &[u8],
        parent: &str,
        tracker: &mut ResourceTracker,
        depth: usize,
    ) -> Result<Inspected, ScanError> {
        let mut out = Inspected::default();
        if let Err(e) = tracker.check_depth(depth) {
            out.raise(ScanStatus::Failed, format!("TAR not inspected: {e}"));
            return Ok(out);
        }
        // Headers and member bodies are all decoded; trailing data is reported.
        out.covered.push((0, data.len()));
        let mut pos = 0usize;
        let mut long_name: Option<String> = None;
        let mut pax_size: Option<u64> = None;
        let mut pax_path: Option<String> = None;
        loop {
            tracker.check_timeout()?;
            let Some(header) = data.get(pos..pos + 512) else {
                let detail = if pos == data.len() {
                    "end-of-archive marker missing".to_string()
                } else {
                    format!("partial header at offset {pos}")
                };
                out.raise(
                    ScanStatus::Unsupported,
                    format!("{}: TAR archive truncated ({detail})", code::TRUNCATED),
                );
                break;
            };
            if header.iter().all(|&b| b == 0) {
                if let Some(p) = data[pos..].iter().position(|&b| b != 0) {
                    out.raise(
                        ScanStatus::Unsupported,
                        format!(
                            "{}: data after the TAR end-of-archive marker at offset {} was \
                             not inspected",
                            code::TRAILING,
                            pos + p
                        ),
                    );
                }
                break;
            }
            if !tar_checksum_ok(header) {
                out.raise(
                    ScanStatus::Unsupported,
                    format!(
                        "{}: invalid TAR header checksum at offset {pos}",
                        code::MALFORMED
                    ),
                );
                break;
            }
            let Some(header_size) = tar_number(&header[124..136]) else {
                out.raise(
                    ScanStatus::Unsupported,
                    format!("{}: invalid TAR size field at offset {pos}", code::MALFORMED),
                );
                break;
            };
            let typeflag = header[156];
            let size = if matches!(typeflag, b'x' | b'g' | b'L' | b'K') {
                header_size
            } else {
                pax_size.take().unwrap_or(header_size)
            };
            let start = pos + 512;
            let Some(end) = usize::try_from(size)
                .ok()
                .and_then(|s| start.checked_add(s))
                .filter(|&e| e <= data.len())
            else {
                out.raise(
                    ScanStatus::Unsupported,
                    format!(
                        "{}: TAR entry at offset {pos} declares {size} bytes beyond the end \
                         of the archive",
                        code::TRUNCATED
                    ),
                );
                break;
            };
            let body = &data[start..end];
            let next = start + body.len().div_ceil(512) * 512;

            match typeflag {
                b'L' | b'x' | b'g' | b'K' if size > MAX_TAR_METADATA => {
                    out.raise(
                        ScanStatus::Failed,
                        format!("{}: TAR metadata record of {size} bytes", code::LIMIT),
                    );
                    break;
                }
                b'L' => {
                    long_name = Some(cstr(body));
                }
                b'K' => {}
                b'x' | b'g' => match parse_pax(body) {
                    Ok(pax) => {
                        if pax.sparse {
                            out.raise(
                                ScanStatus::Unsupported,
                                format!(
                                    "{}: GNU sparse TAR entry at offset {pos} not inspected",
                                    code::TAR_UNSUPPORTED
                                ),
                            );
                        }
                        if typeflag == b'x' {
                            pax_size = pax.size;
                            pax_path = pax.path;
                        }
                    }
                    Err(e) => {
                        out.raise(
                            ScanStatus::Unsupported,
                            format!("{}: PAX header at offset {pos}: {e}", code::MALFORMED),
                        );
                        break;
                    }
                },
                b'S' | b'M' => {
                    out.raise(
                        ScanStatus::Unsupported,
                        format!(
                            "{}: TAR entry type '{}' at offset {pos} not inspected",
                            code::TAR_UNSUPPORTED,
                            typeflag as char
                        ),
                    );
                    long_name = None;
                    pax_path = None;
                }
                b'1'..=b'6' | b'V' if body.is_empty() => {
                    long_name = None;
                    pax_path = None;
                }
                _ => {
                    // Regular files and unknown types carrying data are inspected.
                    let name = pax_path
                        .take()
                        .or(long_name.take())
                        .unwrap_or_else(|| tar_name(header));
                    if self.admit_member(tracker, &mut out)? {
                        let label = label_of(parent, &name);
                        let mut reader = body;
                        self.inspect_member(
                            &mut reader,
                            &label,
                            body.len() as u64,
                            tracker,
                            depth,
                            &mut out,
                        )?;
                    } else {
                        break;
                    }
                }
            }
            pos = next;
        }
        Ok(out)
    }

    /// Inspects the streams of an OLE2/CFB compound file (legacy Office, MSG,
    /// embedded OLE objects). VBA projects and encrypted Office packages are
    /// reported as UNSCANNED: macro code is not analysed.
    pub(crate) fn scan_cfb(
        &self,
        data: &[u8],
        parent: &str,
        tracker: &mut ResourceTracker,
        depth: usize,
    ) -> Result<Inspected, ScanError> {
        let mut out = Inspected::default();
        if let Err(e) = tracker.check_depth(depth) {
            out.raise(ScanStatus::Failed, format!("OLE2/CFB not inspected: {e}"));
            return Ok(out);
        }
        // Every stream is read; unallocated sectors are not (documented limitation).
        out.covered.push((0, data.len()));
        let opened = std::panic::catch_unwind(|| cfb::CompoundFile::open(Cursor::new(data)));
        let mut file = match opened {
            Ok(Ok(f)) => f,
            Ok(Err(e)) => {
                out.raise(
                    ScanStatus::Unsupported,
                    format!("{}: Malformed OLE2/CFB file: {e}", code::MALFORMED),
                );
                return Ok(out);
            }
            Err(_) => {
                out.raise(
                    ScanStatus::Unsupported,
                    format!("{}: OLE2/CFB parser rejected the file", code::MALFORMED),
                );
                return Ok(out);
            }
        };
        let mut streams = Vec::new();
        for entry in file.walk() {
            let path = entry.path().to_string_lossy().into_owned();
            let name = entry.name().to_ascii_lowercase();
            if entry.is_storage() && matches!(name.as_str(), "vba" | "_vba_project_cur" | "macros")
            {
                out.raise(
                    ScanStatus::Unsupported,
                    format!(
                        "{}: VBA macro project ({path}) present; macro code is not analysed",
                        code::OFFICE_ACTIVE
                    ),
                );
            }
            if entry.is_stream() {
                if matches!(name.as_str(), "encryptedpackage" | "encryptioninfo") {
                    out.raise(
                        ScanStatus::Unsupported,
                        format!(
                            "{}: encrypted Office document ({path}); contents not inspected",
                            code::OFFICE_ENCRYPTED
                        ),
                    );
                }
                streams.push((entry.path().to_path_buf(), path, entry.len()));
            }
        }
        for (path, display, len) in streams {
            tracker.check_timeout()?;
            if !self.admit_member(tracker, &mut out)? {
                break;
            }
            let label = label_of(parent, display.trim_start_matches('/'));
            match file.open_stream(&path) {
                Ok(mut stream) => {
                    self.inspect_member(&mut stream, &label, len.max(1), tracker, depth, &mut out)?
                }
                Err(e) => out.raise(
                    ScanStatus::Unsupported,
                    format!("{}: OLE2 stream {label} unreadable: {e}", code::MALFORMED),
                ),
            }
        }
        Ok(out)
    }
}

/// Office Open XML packages: report active content that is not analysed.
fn office_package_checks(names: &[String], out: &mut Inspected) {
    if !names.iter().any(|n| n == "[Content_Types].xml") {
        return;
    }
    for name in names {
        let lower = name.to_ascii_lowercase();
        let what = if lower.ends_with("vbaproject.bin") {
            "VBA macro project"
        } else if lower.contains("/macrosheets/") {
            "Excel 4.0 (XLM) macro sheet"
        } else if lower.contains("/activex/") && lower.ends_with(".bin") {
            "ActiveX control"
        } else {
            continue;
        };
        out.raise(
            ScanStatus::Unsupported,
            format!(
                "{}: Office document contains a {what} ({}); active content is not analysed",
                code::OFFICE_ACTIVE,
                name.chars().take(MAX_LABEL_CHARS).collect::<String>()
            ),
        );
        return;
    }
}

fn plausible_zip_central_header(r: &[u8]) -> bool {
    let u16_at = |i: usize| r.get(i..i + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    u16_at(6).is_none_or(|v| v <= 100)
        && u16_at(10).is_none_or(|m| matches!(m, 0..=20 | 93 | 95 | 96 | 97 | 98 | 99))
        && u16_at(28).is_none_or(|n| (1..=4096).contains(&n))
}

/// ustar/GNU/V7 header checksum (unsigned or historic signed sum).
fn tar_checksum_ok(h: &[u8]) -> bool {
    let Some(stored) = tar_number(&h[148..156]) else {
        return false;
    };
    let mut unsigned: u64 = 0;
    let mut signed: i64 = 0;
    for (i, &b) in h.iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += b as u64;
        signed += b as i8 as i64;
    }
    stored == unsigned || stored as i64 == signed
}

/// Octal (NUL/space terminated) or GNU base-256 numeric field.
fn tar_number(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|&b| b & 0x80 != 0) {
        if field[0] & 0x40 != 0 {
            return None;
        }
        let mut v: u64 = (field[0] & 0x3f) as u64;
        for &b in &field[1..] {
            v = v.checked_mul(256)?.checked_add(b as u64)?;
        }
        return Some(v);
    }
    let text = field
        .iter()
        .copied()
        .skip_while(|&b| b == b' ')
        .take_while(|&b| b != 0 && b != b' ');
    let mut v: u64 = 0;
    let mut digits = 0;
    for b in text {
        if !(b'0'..=b'7').contains(&b) {
            return None;
        }
        v = v.checked_mul(8)?.checked_add((b - b'0') as u64)?;
        digits += 1;
    }
    (digits > 0 || field.iter().all(|&b| b == 0 || b == b' ')).then_some(v)
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn tar_name(h: &[u8]) -> String {
    let name = cstr(&h[0..100]);
    if &h[257..262] == b"ustar" && h[263] == b'0' {
        let prefix = cstr(&h[345..500]);
        if !prefix.is_empty() {
            return format!("{prefix}/{name}");
        }
    }
    name
}

#[derive(Default)]
struct Pax {
    size: Option<u64>,
    path: Option<String>,
    sparse: bool,
}

/// Parses PAX extended header records (`"<len> <key>=<value>\n"`).
fn parse_pax(mut body: &[u8]) -> Result<Pax, String> {
    let mut pax = Pax::default();
    while !body.is_empty() {
        if body.iter().all(|&b| b == 0) {
            break;
        }
        let space = body
            .iter()
            .position(|&b| b == b' ')
            .ok_or("record without length")?;
        let len: usize = std::str::from_utf8(&body[..space])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or("invalid record length")?;
        if len <= space + 1 || len > body.len() || body[len - 1] != b'\n' {
            return Err("inconsistent record length".into());
        }
        let record = &body[space + 1..len - 1];
        let eq = record
            .iter()
            .position(|&b| b == b'=')
            .ok_or("record without '='")?;
        let (key, value) = (&record[..eq], &record[eq + 1..]);
        match key {
            b"size" => {
                pax.size = Some(
                    std::str::from_utf8(value)
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .ok_or("invalid size")?,
                )
            }
            b"path" => pax.path = Some(String::from_utf8_lossy(value).into_owned()),
            k if k.starts_with(b"GNU.sparse.") => pax.sparse = true,
            _ => {}
        }
        body = &body[len..];
    }
    Ok(pax)
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxosentinel_core::ResourceLimits;
    use raxosentinel_signatures::SignatureDatabase;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::CompressionMethod;

    const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    /// `python3 -c "import lzma; lzma.compress(EICAR)"`
    const EICAR_XZ: &str = "fd377a585a000004e6d6b4460200210116000000742fe5a301004358354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a00faab49d4013391b600015c44fa2239471fb6f37d010000000004595a";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn zip_of(entries: &[(&str, &[u8], CompressionMethod)]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data, method) in entries {
            w.start_file(*name, SimpleFileOptions::default().compression_method(*method))
                .unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn scan_with(data: &[u8], name: &str, limits: ResourceLimits) -> ScanReport {
        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let mut tracker = ResourceTracker::new(limits);
        scanner.scan_object(data, name, None, &mut tracker, 0).unwrap()
    }

    fn scan(data: &[u8], name: &str) -> ScanReport {
        scan_with(data, name, ResourceLimits::default())
    }

    fn error_of(r: &ScanReport) -> &str {
        r.error.as_deref().unwrap_or("")
    }

    #[test]
    fn zip_stored_deflated_clean_and_detected() {
        let clean = zip_of(&[
            ("a.txt", b"stored text", CompressionMethod::Stored),
            ("b.txt", b"deflated text", CompressionMethod::Deflated),
        ]);
        let r = scan(&clean, "ok.zip");
        assert_eq!(r.status, ScanStatus::Clean, "{:?}", r.error);
        assert_eq!(r.sub_targets.len(), 2);
        for method in [CompressionMethod::Stored, CompressionMethod::Deflated] {
            let bad = zip_of(&[("a.txt", b"hi", method), ("e.com", EICAR, method)]);
            let r = scan(&bad, "bad.zip");
            assert_eq!(r.status, ScanStatus::Infected);
        }
    }

    #[test]
    fn nested_and_depth_limited_zip() {
        let inner = zip_of(&[("e.txt", EICAR, CompressionMethod::Deflated)]);
        let middle = zip_of(&[("inner.zip", &inner, CompressionMethod::Deflated)]);
        let outer = zip_of(&[("middle.zip", &middle, CompressionMethod::Stored)]);
        assert_eq!(scan(&outer, "outer.zip").status, ScanStatus::Infected);
        let clean_inner = zip_of(&[("t.txt", b"text", CompressionMethod::Deflated)]);
        let clean_outer = zip_of(&[("i.zip", &clean_inner, CompressionMethod::Deflated)]);
        let r = scan_with(
            &clean_outer,
            "deep.zip",
            ResourceLimits {
                max_email_depth: 1,
                ..Default::default()
            },
        );
        assert_ne!(r.status, ScanStatus::Clean);
    }

    #[test]
    fn multiple_zip_structures_are_all_inspected() {
        let first = zip_of(&[("a.txt", b"first", CompressionMethod::Deflated)]);
        let second = zip_of(&[("e.txt", EICAR, CompressionMethod::Deflated)]);
        let clean_second = zip_of(&[("b.txt", b"second", CompressionMethod::Deflated)]);

        let r = scan(&[first.clone(), second].concat(), "two.zip");
        assert_eq!(r.status, ScanStatus::Infected);
        let r = scan(&[first.clone(), clean_second].concat(), "two-clean.zip");
        assert_eq!(r.status, ScanStatus::Clean, "{:?}", r.error);
        assert_eq!(r.sub_targets.len(), 2);

        // A local file record without a central directory, hidden before a valid ZIP.
        let hidden = zip_of(&[("e.txt", EICAR, CompressionMethod::Stored)]);
        let cd = memchr::memmem::find(&hidden, b"PK\x01\x02").unwrap();
        let carrier = zip_of(&[("c.txt", b"carrier", CompressionMethod::Deflated)]);
        let r = scan(&[&hidden[..cd], &carrier[..]].concat(), "smuggled.zip");
        assert_ne!(r.status, ScanStatus::Clean);
        let hidden_clean = zip_of(&[("x.txt", b"benign hidden", CompressionMethod::Stored)]);
        let cd = memchr::memmem::find(&hidden_clean, b"PK\x01\x02").unwrap();
        let r = scan(&[&hidden_clean[..cd], &carrier[..]].concat(), "smuggled2.zip");
        assert_eq!(r.status, ScanStatus::Unsupported);
        assert!(error_of(&r).contains(code::ZIP_UNREFERENCED), "{:?}", r.error);
    }

    #[test]
    fn pdf_zip_polyglot_contents_are_inspected() {
        let pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n";
        let payload = zip_of(&[("e.txt", EICAR, CompressionMethod::Deflated)]);
        let r = scan(&[&pdf[..], &payload[..]].concat(), "poly.pdf");
        assert_eq!(r.status, ScanStatus::Infected);
        let benign = zip_of(&[("t.txt", b"text", CompressionMethod::Deflated)]);
        let r = scan(&[&pdf[..], &benign[..]].concat(), "poly2.pdf");
        assert_ne!(r.status, ScanStatus::Infected);
        assert!(r.sub_targets.iter().any(|s| s
            .target
            .file_name
            .as_deref()
            .is_some_and(|n| n.ends_with("t.txt"))));
    }

    #[test]
    fn truncated_corrupt_and_encrypted_zip_are_not_clean() {
        let zip = zip_of(&[("t.txt", &[b'a'; 4000], CompressionMethod::Deflated)]);
        for cut in [zip.len() - 10, zip.len() / 2, 30] {
            assert_ne!(scan(&zip[..cut], "cut.zip").status, ScanStatus::Clean, "cut {cut}");
        }
        // Corrupt the deflate body.
        let mut corrupt = zip.clone();
        for b in &mut corrupt[40..50] {
            *b ^= 0xff;
        }
        assert_ne!(scan(&corrupt, "corrupt.zip").status, ScanStatus::Clean);

        // Set the "encrypted" general-purpose flag in both headers.
        let mut enc = zip_of(&[("s.txt", b"secret", CompressionMethod::Stored)]);
        enc[6] |= 1;
        let cd = memchr::memmem::find(&enc, b"PK\x01\x02").unwrap();
        enc[cd + 8] |= 1;
        let r = scan(&enc, "enc.zip");
        assert_eq!(r.status, ScanStatus::Unsupported);
        assert!(error_of(&r).contains(code::ENCRYPTED), "{:?}", r.error);
    }

    #[test]
    fn zip_bomb_ratio_and_member_limits() {
        let zeros = vec![0u8; 16 << 20];
        let bomb = zip_of(&[("zeros.bin", &zeros, CompressionMethod::Deflated)]);
        drop(zeros);
        let slow_ok = ResourceLimits {
            max_scan_duration_ms: 300_000,
            ..Default::default()
        };
        let r = scan_with(&bomb, "bomb.zip", slow_ok);
        assert_eq!(r.status, ScanStatus::Failed, "{:?}", r.error);
        assert!(error_of(&r).contains(code::RATIO), "{:?}", r.error);

        let many: Vec<(String, Vec<u8>)> =
            (0..20).map(|i| (format!("f{i}.txt"), vec![b'x'; 10])).collect();
        let refs: Vec<(&str, &[u8], CompressionMethod)> = many
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice(), CompressionMethod::Stored))
            .collect();
        let r = scan_with(
            &zip_of(&refs),
            "many.zip",
            ResourceLimits {
                max_archive_members: 5,
                ..Default::default()
            },
        );
        assert_eq!(r.status, ScanStatus::Failed);
        assert!(error_of(&r).contains(code::LIMIT));
    }

    #[test]
    fn large_members_are_streamed_with_bounded_buffers() {
        let mut big = vec![b'a'; 3 << 20];
        let at = (1 << 20) - 10; // straddles a 64 KiB read and the 1 MiB YARA block
        big[at..at + EICAR.len()].copy_from_slice(EICAR);
        let limits = ResourceLimits {
            max_buffered_object_bytes: 256 * 1024,
            ..Default::default()
        };
        let zip = zip_of(&[("big.bin", &big, CompressionMethod::Deflated)]);
        let r = scan_with(&zip, "big.zip", limits.clone());
        assert_eq!(r.status, ScanStatus::Infected);

        let inner = zip_of(&[("big.bin", &vec![b'b'; 1 << 20], CompressionMethod::Stored)]);
        let outer = zip_of(&[("inner.zip", &inner, CompressionMethod::Stored)]);
        let r = scan_with(&outer, "big-nested.zip", limits);
        assert_eq!(r.status, ScanStatus::Failed);
        assert!(
            error_of(&r).contains(super::super::extract::CODE_STREAM_CONTAINER),
            "{:?}",
            r.error
        );
    }

    #[test]
    fn stored_compressed_members_are_not_false_unscanned() {
        use flate2::{write::GzEncoder, Compression};
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(b"plain text").unwrap();
        let gz = gz.finish().unwrap();
        let z = zip_of(&[("a.txt.gz", &gz, CompressionMethod::Stored)]);
        let r = scan(&z, "gz.zip");
        assert_eq!(r.status, ScanStatus::Clean, "{:?}", r.error);

        // A RAR hidden in data prefixed to the ZIP is outside every member.
        let prefixed = [&b"Rar!\x1a\x07\x00junk"[..], &z[..]].concat();
        let r = scan(&prefixed, "prefixed.zip");
        assert_eq!(r.status, ScanStatus::Unsupported, "{:?}", r.error);
    }

    #[test]
    fn hostile_member_names_are_labels_only() {
        let zip = zip_of(&[
            ("../../../../tmp/raxo-escape.txt", b"x", CompressionMethod::Stored),
            ("/etc/raxo-abs.txt", b"y", CompressionMethod::Stored),
            ("ctl\u{7}\u{1b}name.txt", b"z", CompressionMethod::Stored),
        ]);
        let r = scan(&zip, "names.zip");
        assert_eq!(r.status, ScanStatus::Clean, "{:?}", r.error);
        assert!(!std::path::Path::new("/tmp/raxo-escape.txt").exists());
        assert!(r.sub_targets.iter().all(|s| !s
            .target
            .file_name
            .as_deref()
            .unwrap()
            .chars()
            .any(|c| c.is_control())));
    }

    fn ooxml(extra: &[(&str, &[u8])]) -> Vec<u8> {
        let mut entries: Vec<(&str, &[u8], CompressionMethod)> = vec![
            (
                "[Content_Types].xml",
                b"<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>",
                CompressionMethod::Deflated,
            ),
            ("_rels/.rels", b"<Relationships/>", CompressionMethod::Deflated),
            ("word/document.xml", b"<w:document>Hello</w:document>", CompressionMethod::Deflated),
        ];
        entries.extend(extra.iter().map(|(n, d)| (*n, *d, CompressionMethod::Deflated)));
        zip_of(&entries)
    }

    #[test]
    fn office_open_xml_packages() {
        let r = scan(&ooxml(&[]), "letter.docx");
        assert_eq!(r.status, ScanStatus::Clean, "{:?}", r.error);
        assert_eq!(r.sub_targets.len(), 3);

        let embedded = zip_of(&[("e.txt", EICAR, CompressionMethod::Deflated)]);
        let r = scan(&ooxml(&[("word/embeddings/package.zip", &embedded)]), "e.docx");
        assert_eq!(r.status, ScanStatus::Infected);

        for (name, file) in [
            ("word/vbaProject.bin", "m.docm"),
            ("xl/macrosheets/sheet1.xml", "m.xlsm"),
            ("ppt/activeX/activeX1.bin", "m.pptx"),
        ] {
            let r = scan(&ooxml(&[(name, b"opaque")]), file);
            assert_eq!(r.status, ScanStatus::Unsupported, "{name}");
            assert!(error_of(&r).contains(code::OFFICE_ACTIVE), "{:?}", r.error);
        }
        // Malware beats "unsupported active content".
        let r = scan(&ooxml(&[("word/vbaProject.bin", EICAR)]), "m.docm");
        assert_eq!(r.status, ScanStatus::Infected);
    }

    fn cfb_with(streams: &[(&str, &[u8])], storages: &[&str]) -> Vec<u8> {
        let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        for s in storages {
            comp.create_storage(s).unwrap();
        }
        for (path, data) in streams {
            comp.create_stream(path).unwrap().write_all(data).unwrap();
        }
        comp.flush().unwrap();
        comp.into_inner().into_inner()
    }

    #[test]
    fn ole2_compound_files() {
        let r = scan(&cfb_with(&[("/WordDocument", b"plain text")], &[]), "a.doc");
        assert_eq!(r.status, ScanStatus::Clean, "{:?}", r.error);
        let r = scan(&cfb_with(&[("/Ole10Native", EICAR)], &[]), "b.doc");
        assert_eq!(r.status, ScanStatus::Infected);
        let r = scan(
            &cfb_with(&[("/Macros/VBA/Module1", b"Attribute VB_Name = \"Module1\"")], &["/Macros", "/Macros/VBA"]),
            "c.doc",
        );
        assert_eq!(r.status, ScanStatus::Unsupported);
        assert!(error_of(&r).contains(code::OFFICE_ACTIVE));
        let r = scan(&cfb_with(&[("/EncryptedPackage", b"\x01\x02")], &[]), "d.docx");
        assert_eq!(r.status, ScanStatus::Unsupported);
        assert!(error_of(&r).contains(code::OFFICE_ENCRYPTED));
        let mut broken = cfb_with(&[("/WordDocument", b"x")], &[]);
        broken.truncate(600);
        assert_ne!(scan(&broken, "e.doc").status, ScanStatus::Clean);
    }

    #[test]
    fn bzip2_and_xz_streams() {
        use bzip2::{write::BzEncoder, Compression};
        let bz = |data: &[u8]| {
            let mut e = BzEncoder::new(Vec::new(), Compression::default());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        };
        let r = scan(&bz(b"plain"), "a.bz2");
        assert_eq!(r.status, ScanStatus::Clean, "{:?}", r.error);
        assert_eq!(scan(&bz(EICAR), "b.bz2").status, ScanStatus::Infected);
        let two = [bz(b"one"), bz(b"two")].concat();
        let r = scan(&two, "c.bz2");
        assert_eq!(r.status, ScanStatus::Clean, "{:?}", r.error);
        assert_eq!(r.sub_targets.len(), 2);
        let mut trailing = bz(b"one");
        trailing.extend_from_slice(b"junk");
        assert_eq!(scan(&trailing, "d.bz2").status, ScanStatus::Unsupported);
        let good = bz(&[b'q'; 5000]);
        assert_ne!(scan(&good[..good.len() / 2], "e.bz2").status, ScanStatus::Clean);

        let xz = hex(EICAR_XZ);
        assert_eq!(scan(&xz, "a.xz").status, ScanStatus::Infected);
        let mut corrupt = xz.clone();
        let n = corrupt.len();
        corrupt[n - 20] ^= 0x55;
        assert_ne!(scan(&corrupt, "b.xz").status, ScanStatus::Clean);
        let mut trailing = xz.clone();
        trailing.extend_from_slice(b"junk");
        assert_ne!(scan(&trailing, "c.xz").status, ScanStatus::Clean);
        assert_ne!(scan(&xz[..xz.len() - 8], "d.xz").status, ScanStatus::Clean);
    }

    #[test]
    fn unsupported_formats_are_unscanned() {
        for (magic, name) in [
            (&b"Rar!\x1a\x07\x01\x00rest"[..], "a.rar"),
            (&b"7z\xbc\xaf\x27\x1c\x00\x04rest"[..], "a.7z"),
            (&b"MSCF\x00\x00\x00\x00rest"[..], "a.cab"),
        ] {
            let r = scan(magic, name);
            assert_eq!(r.status, ScanStatus::Unsupported, "{name}");
            assert!(error_of(&r).contains("ARCHIVE_UNSUPPORTED_FORMAT"));
            // ... also when nested in a supported archive.
            let z = zip_of(&[(name, magic, CompressionMethod::Deflated)]);
            assert_eq!(scan(&z, "outer.zip").status, ScanStatus::Unsupported);
        }
    }

    fn tar_header(name: &str, size: usize, typeflag: u8) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        h[136..148].copy_from_slice(b"00000000000\0");
        h[156] = typeflag;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        h
    }

    fn tar_entry(name: &str, body: &[u8], typeflag: u8) -> Vec<u8> {
        let mut v = tar_header(name, body.len(), typeflag);
        v.extend_from_slice(body);
        v.resize(v.len().div_ceil(512) * 512, 0);
        v
    }

    #[test]
    fn tar_variants() {
        let end = vec![0u8; 1024];
        let long = "d/".repeat(80) + "eicar.txt";
        let gnu = [
            tar_entry("././@LongLink", format!("{long}\0").as_bytes(), b'L'),
            tar_entry("short", EICAR, b'0'),
            end.clone(),
        ]
        .concat();
        let r = scan(&gnu, "gnu.tar");
        assert_eq!(r.status, ScanStatus::Infected);
        assert!(r.sub_targets[0]
            .target
            .file_name
            .as_deref()
            .unwrap()
            .ends_with("eicar.txt"));

        let record = format!("{} size={}\n", 9 + EICAR.len().to_string().len() + 1, EICAR.len());
        let pax = [
            tar_entry("PaxHeader", record.as_bytes(), b'x'),
            tar_entry("f", EICAR, b'0'),
            end.clone(),
        ]
        .concat();
        assert_eq!(scan(&pax, "pax.tar").status, ScanStatus::Infected);

        let mut trailing = [tar_entry("a.txt", b"ok", b'0'), end.clone()].concat();
        trailing.extend_from_slice(b"hidden");
        let r = scan(&trailing, "t.tar");
        assert_eq!(r.status, ScanStatus::Unsupported);
        assert!(error_of(&r).contains(code::TRAILING));

        let mut bad = [tar_entry("a.txt", b"ok", b'0'), end.clone()].concat();
        bad[0] = b'b';
        assert_ne!(scan(&bad, "bad.tar").status, ScanStatus::Clean);

        let sparse = [tar_entry("s", b"", b'S'), end.clone()].concat();
        assert_eq!(scan(&sparse, "s.tar").status, ScanStatus::Unsupported);
        let dirs = [
            tar_entry("dir/", b"", b'5'),
            tar_entry("link", b"", b'2'),
            tar_entry("dir/a.txt", b"text", b'0'),
            end,
        ]
        .concat();
        let r = scan(&dirs, "dirs.tar");
        assert_eq!(r.status, ScanStatus::Clean, "{:?}", r.error);
        assert_eq!(r.sub_targets.len(), 1);
    }

    #[test]
    fn archive_layers_combine_and_scanner_recovers() {
        use bzip2::{write::BzEncoder, Compression};
        let tar = [tar_entry("e.txt", EICAR, b'0'), vec![0u8; 1024]].concat();
        let mut e = BzEncoder::new(Vec::new(), Compression::default());
        e.write_all(&tar).unwrap();
        let tbz = e.finish().unwrap();
        let zip = zip_of(&[("x.tar.bz2", &tbz, CompressionMethod::Stored)]);
        assert_eq!(scan(&zip, "layers.zip").status, ScanStatus::Infected);

        // The same scanner keeps working after errors.
        let db = SignatureDatabase::with_defaults();
        let scanner = EmailScanner::new(&db);
        let mut t = ResourceTracker::new(ResourceLimits::default());
        let broken = scanner.scan_object(&zip[..zip.len() - 5], "b.zip", None, &mut t, 0);
        assert_ne!(broken.unwrap().status, ScanStatus::Clean);
        let mut t = ResourceTracker::new(ResourceLimits::default());
        let ok = scanner
            .scan_object(&zip_of(&[("a", b"b", CompressionMethod::Stored)]), "ok.zip", None, &mut t, 0)
            .unwrap();
        assert_eq!(ok.status, ScanStatus::Clean);
    }
}
