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

//! Strict, bounded PDF stream filter decoding (ISO 32000-1 §7.4).
//!
//! Unlike lopdf's lenient decoders (which log and return partial output on corrupt
//! data), every decoder here reports whether the stream was decoded *completely*, so
//! truncated or corrupt content can never be presented as fully inspected. Every
//! decoder enforces an output cap, a compression-ratio limit and a wall-clock deadline
//! and allocates fallibly.

use std::time::Instant;

/// Maximum filters in one stream's chain. Real documents use one or two.
pub(crate) const MAX_FILTERS: usize = 8;
/// Maximum ratio of decoded output to raw stream bytes across a whole filter chain.
/// A single deflate layer cannot exceed ~1032:1, so this rejects nested-compression
/// bombs without rejecting maximally compressed ordinary content.
pub(crate) const MAX_CHAIN_RATIO: u64 = 1100;
/// Outputs at or below this size are exempt from the ratio limit (tiny inputs).
pub(crate) const RATIO_FLOOR: u64 = 1024 * 1024;
const CHUNK: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureKind {
    /// Valid PDF feature that this engine does not decode (UNSCANNED).
    Unsupported,
    /// Corrupt or truncated encoded data (UNSCANNED).
    Malformed,
    /// Resource budget exhausted: size, ratio (ERROR).
    Limit,
    /// Scan deadline reached.
    Timeout,
}

#[derive(Debug)]
pub(crate) struct DecodeFailure {
    pub kind: FailureKind,
    pub message: String,
    /// Output produced before the failure; still scanned so detections are never lost.
    pub partial: Vec<u8>,
}

impl DecodeFailure {
    fn new(kind: FailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            partial: Vec::new(),
        }
    }
    fn with_partial(mut self, partial: Vec<u8>) -> Self {
        self.partial = partial;
        self
    }
}

/// Decoding parameters relevant to supported filters (`/DecodeParms`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Params {
    pub predictor: Option<i64>,
    pub colors: Option<i64>,
    pub bits_per_component: Option<i64>,
    pub columns: Option<i64>,
    pub early_change: Option<i64>,
    /// Crypt filter `/Name`.
    pub name: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub(crate) struct FilterSpec {
    pub name: Vec<u8>,
    pub params: Params,
}

/// Successfully decoded stream.
#[derive(Debug)]
pub(crate) struct Decoded {
    pub data: Vec<u8>,
    /// Terminal image codec left encoded (DCT, JPX, JBIG2, CCITT).
    pub image_codec: Option<&'static str>,
    /// Number of filters actually applied.
    pub applied: usize,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Budget {
    /// Maximum decoded bytes for this stream.
    pub cap: usize,
    pub deadline: Instant,
}

impl Budget {
    fn check_deadline(&self) -> Result<(), DecodeFailure> {
        if Instant::now() >= self.deadline {
            Err(DecodeFailure::new(
                FailureKind::Timeout,
                "scan deadline reached while decoding",
            ))
        } else {
            Ok(())
        }
    }
}

enum Filter {
    Flate,
    Lzw,
    AsciiHex,
    Ascii85,
    RunLength,
    Crypt,
    Image(&'static str),
}

fn classify(name: &[u8]) -> Option<Filter> {
    Some(match name {
        b"FlateDecode" | b"Fl" => Filter::Flate,
        b"LZWDecode" | b"LZW" => Filter::Lzw,
        b"ASCIIHexDecode" | b"AHx" => Filter::AsciiHex,
        b"ASCII85Decode" | b"A85" => Filter::Ascii85,
        b"RunLengthDecode" | b"RL" => Filter::RunLength,
        b"Crypt" => Filter::Crypt,
        b"DCTDecode" | b"DCT" => Filter::Image("DCTDecode"),
        b"JPXDecode" => Filter::Image("JPXDecode"),
        b"JBIG2Decode" => Filter::Image("JBIG2Decode"),
        b"CCITTFaxDecode" | b"CCF" => Filter::Image("CCITTFaxDecode"),
        _ => return None,
    })
}

/// Applies a complete filter chain. Terminal image codecs are not decoded: their
/// (possibly pre-decoded) encoded bytes are returned for scanning.
pub(crate) fn decode_chain(
    raw: &[u8],
    filters: &[FilterSpec],
    budget: Budget,
) -> Result<Decoded, DecodeFailure> {
    if filters.len() > MAX_FILTERS {
        return Err(DecodeFailure::new(
            FailureKind::Unsupported,
            format!(
                "{} filters exceed the supported chain length",
                filters.len()
            ),
        ));
    }
    let raw_len = raw.len() as u64;
    // Bound every layer by the stream cap and the chain ratio relative to the raw bytes.
    let ratio_cap = raw_len.saturating_mul(MAX_CHAIN_RATIO).max(RATIO_FLOOR);
    let layer_cap = (budget.cap as u64).min(ratio_cap) as usize;
    let cap_is_ratio = ratio_cap < budget.cap as u64;

    let mut current: Option<Vec<u8>> = None;
    let mut applied = 0usize;
    for (index, spec) in filters.iter().enumerate() {
        budget.check_deadline()?;
        let input: &[u8] = current.as_deref().unwrap_or(raw);
        let Some(filter) = classify(&spec.name) else {
            return Err(DecodeFailure::new(
                FailureKind::Unsupported,
                format!(
                    "unsupported filter /{}",
                    String::from_utf8_lossy(&spec.name)
                ),
            )
            .with_partial(current.unwrap_or_default()));
        };
        let layer_budget = Budget {
            cap: layer_cap,
            ..budget
        };
        let result = match filter {
            Filter::Image(codec) => {
                if index + 1 != filters.len() {
                    return Err(DecodeFailure::new(
                        FailureKind::Unsupported,
                        format!("image filter /{codec} is not the last filter"),
                    )
                    .with_partial(current.unwrap_or_default()));
                }
                return Ok(Decoded {
                    data: current.unwrap_or_else(|| raw.to_vec()),
                    image_codec: Some(codec),
                    applied,
                });
            }
            Filter::Crypt => {
                let identity = spec
                    .params
                    .name
                    .as_deref()
                    .is_none_or(|name| name == b"Identity");
                if index != 0 || !identity {
                    return Err(DecodeFailure::new(
                        FailureKind::Unsupported,
                        "non-identity /Crypt stream filter",
                    ));
                }
                continue;
            }
            Filter::Flate => inflate(input, layer_budget)
                .and_then(|data| apply_predictor(data, &spec.params, layer_budget)),
            Filter::Lzw => lzw(input, &spec.params, layer_budget)
                .and_then(|data| apply_predictor(data, &spec.params, layer_budget)),
            Filter::AsciiHex => ascii_hex(input, layer_budget),
            Filter::Ascii85 => ascii85(input, layer_budget),
            Filter::RunLength => run_length(input, layer_budget),
        };
        match result {
            Ok(data) => {
                current = Some(data);
                applied += 1;
            }
            Err(mut failure) => {
                if failure.kind == FailureKind::Limit && cap_is_ratio {
                    failure.message = format!(
                        "decoded size exceeds {MAX_CHAIN_RATIO}:1 compression ratio ({})",
                        failure.message
                    );
                }
                return Err(failure);
            }
        }
    }
    Ok(Decoded {
        data: current.unwrap_or_else(|| raw.to_vec()),
        image_codec: None,
        applied,
    })
}

fn limit_failure(cap: usize, partial: Vec<u8>) -> DecodeFailure {
    DecodeFailure::new(
        FailureKind::Limit,
        format!("decoded size exceeds {cap} bytes"),
    )
    .with_partial(partial)
}

fn alloc_failure() -> DecodeFailure {
    DecodeFailure::new(FailureKind::Limit, "cannot allocate decode buffer")
}

/// Grows `out` fallibly, by at most `CHUNK` or its current length, never past `cap + 1`.
fn grow(out: &mut Vec<u8>, cap: usize) -> Result<(), DecodeFailure> {
    let target = cap.saturating_add(1);
    let additional = CHUNK
        .max(out.len())
        .min(target.saturating_sub(out.len()))
        .max(1);
    out.try_reserve_exact(additional)
        .map_err(|_| alloc_failure())
}

fn push_checked(out: &mut Vec<u8>, bytes: &[u8], cap: usize) -> Result<(), DecodeFailure> {
    if out.len().saturating_add(bytes.len()) > cap {
        return Err(limit_failure(cap, Vec::new()));
    }
    if out.capacity() - out.len() < bytes.len() {
        let want = bytes.len().max(CHUNK.max(out.len()).min(cap - out.len()));
        out.try_reserve_exact(want).map_err(|_| alloc_failure())?;
    }
    out.extend_from_slice(bytes);
    Ok(())
}

/// Returns true when `input` starts with a valid RFC 1950 zlib header.
fn zlib_header(input: &[u8]) -> bool {
    input.len() >= 2
        && input[0] & 0x0f == 8
        && input[0] >> 4 <= 7
        && (u16::from(input[0]) << 8 | u16::from(input[1])) % 31 == 0
}

/// FlateDecode. The zlib wrapper is parsed here and the deflate body decoded raw, so a
/// missing or wrong Adler-32 (common in real-world writers) is tolerated, but the
/// deflate data itself must be valid and reach its final block.
pub(crate) fn inflate(input: &[u8], budget: Budget) -> Result<Vec<u8>, DecodeFailure> {
    use flate2::{Decompress, FlushDecompress, Status};
    let body = if zlib_header(input) {
        if input[1] & 0x20 != 0 {
            return Err(DecodeFailure::new(
                FailureKind::Unsupported,
                "zlib preset dictionary",
            ));
        }
        &input[2..]
    } else {
        input
    };
    let cap = budget.cap;
    let mut decoder = Decompress::new(false);
    let mut out: Vec<u8> = Vec::new();
    // Ordinary streams fit in one step; avoid regrowth for typical content.
    out.try_reserve_exact(body.len().saturating_mul(4).clamp(64, CHUNK).min(cap + 1))
        .map_err(|_| alloc_failure())?;
    loop {
        budget.check_deadline()?;
        if out.len() == out.capacity() {
            if out.len() > cap {
                out.truncate(cap);
                return Err(limit_failure(cap, out));
            }
            grow(&mut out, cap)?;
        }
        let consumed = decoder.total_in() as usize;
        let before_out = out.len();
        let status = decoder.decompress_vec(&body[consumed..], &mut out, FlushDecompress::None);
        if out.len() > cap {
            out.truncate(cap);
            return Err(limit_failure(cap, out));
        }
        match status {
            Ok(Status::StreamEnd) => return Ok(out),
            Ok(Status::Ok) | Ok(Status::BufError) => {
                let progressed = decoder.total_in() as usize != consumed || out.len() != before_out;
                if !progressed && out.len() < out.capacity() {
                    return Err(DecodeFailure::new(
                        FailureKind::Malformed,
                        "truncated deflate data (no final block)",
                    )
                    .with_partial(out));
                }
            }
            Err(e) => {
                return Err(DecodeFailure::new(
                    FailureKind::Malformed,
                    format!("corrupt deflate data: {e}"),
                )
                .with_partial(out))
            }
        }
    }
}

/// LZWDecode via `weezl` (PDF uses MSB-first codes, 8-bit symbols, EarlyChange=1 by
/// default). The end-of-data code is required for complete decoding.
fn lzw(input: &[u8], params: &Params, budget: Budget) -> Result<Vec<u8>, DecodeFailure> {
    use weezl::{decode::Decoder, BitOrder, LzwStatus};
    let mut decoder = match params.early_change.unwrap_or(1) {
        1 => Decoder::with_tiff_size_switch(BitOrder::Msb, 8),
        0 => Decoder::new(BitOrder::Msb, 8),
        other => {
            return Err(DecodeFailure::new(
                FailureKind::Unsupported,
                format!("LZW EarlyChange {other}"),
            ))
        }
    };
    let cap = budget.cap;
    let mut out = Vec::new();
    let mut chunk = vec![0u8; CHUNK.min(cap + 1)];
    let mut rest = input;
    loop {
        budget.check_deadline()?;
        let result = decoder.decode_bytes(rest, &mut chunk);
        rest = &rest[result.consumed_in..];
        if let Err(failure) = push_checked(&mut out, &chunk[..result.consumed_out], cap) {
            return Err(failure.with_partial(out));
        }
        match result.status {
            Ok(LzwStatus::Done) => return Ok(out),
            Ok(LzwStatus::Ok) => {}
            Ok(LzwStatus::NoProgress) => {
                return Err(DecodeFailure::new(
                    FailureKind::Malformed,
                    "truncated LZW data (no end-of-data code)",
                )
                .with_partial(out))
            }
            Err(e) => {
                return Err(DecodeFailure::new(
                    FailureKind::Malformed,
                    format!("corrupt LZW data: {e}"),
                )
                .with_partial(out))
            }
        }
        if result.consumed_in == 0 && result.consumed_out == 0 {
            return Err(DecodeFailure::new(
                FailureKind::Malformed,
                "truncated LZW data (no end-of-data code)",
            )
            .with_partial(out));
        }
    }
}

fn is_pdf_whitespace(b: u8) -> bool {
    matches!(b, b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

/// ASCIIHexDecode: whitespace ignored, `>` terminates, odd final digit padded with 0.
pub(crate) fn ascii_hex(input: &[u8], budget: Budget) -> Result<Vec<u8>, DecodeFailure> {
    let cap = budget.cap;
    let mut out = Vec::new();
    out.try_reserve_exact((input.len() / 2 + 1).min(cap))
        .map_err(|_| alloc_failure())?;
    let mut high: Option<u8> = None;
    for (i, &b) in input.iter().enumerate() {
        if i % (1 << 20) == 0 {
            budget.check_deadline()?;
        }
        let nibble = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            b'>' => break,
            _ if is_pdf_whitespace(b) => continue,
            _ => {
                return Err(DecodeFailure::new(
                    FailureKind::Malformed,
                    format!("invalid ASCIIHex character 0x{b:02x}"),
                )
                .with_partial(out))
            }
        };
        match high.take() {
            None => high = Some(nibble),
            Some(h) => {
                if out.len() >= cap {
                    return Err(limit_failure(cap, out));
                }
                out.push(h << 4 | nibble);
            }
        }
    }
    if let Some(h) = high {
        if out.len() >= cap {
            return Err(limit_failure(cap, out));
        }
        out.push(h << 4);
    }
    Ok(out)
}

fn ascii85_value(group: &[u8; 5]) -> Option<u32> {
    group.iter().try_fold(0u32, |acc, &d| {
        acc.checked_mul(85)?.checked_add(u32::from(d))
    })
}

/// ASCII85Decode: `z` shorthand, `~>` terminator, partial final group of 2-4 chars.
pub(crate) fn ascii85(input: &[u8], budget: Budget) -> Result<Vec<u8>, DecodeFailure> {
    let cap = budget.cap;
    let mut out = Vec::new();
    out.try_reserve_exact((input.len() / 5 * 4 + 4).min(cap))
        .map_err(|_| alloc_failure())?;
    let malformed = |msg: &str, out: Vec<u8>| {
        DecodeFailure::new(FailureKind::Malformed, format!("ASCII85: {msg}")).with_partial(out)
    };
    let mut group = [0u8; 5];
    let mut n = 0usize;
    let mut iter = input.iter().enumerate();
    while let Some((i, &b)) = iter.next() {
        if i % (1 << 20) == 0 {
            budget.check_deadline()?;
        }
        match b {
            b'~' => match iter.find(|(_, c)| !is_pdf_whitespace(**c)) {
                // Anything after the terminator is not part of the stream data.
                Some((_, b'>')) | None => break,
                Some(_) => return Err(malformed("invalid end-of-data marker", out)),
            },
            b'z' if n == 0 => {
                if out.len() + 4 > cap {
                    return Err(limit_failure(cap, out));
                }
                out.extend_from_slice(&[0; 4]);
            }
            b'!'..=b'u' => {
                group[n] = b - b'!';
                n += 1;
                if n == 5 {
                    let Some(value) = ascii85_value(&group) else {
                        return Err(malformed("group value overflow", out));
                    };
                    if out.len() + 4 > cap {
                        return Err(limit_failure(cap, out));
                    }
                    out.extend_from_slice(&value.to_be_bytes());
                    n = 0;
                }
            }
            _ if is_pdf_whitespace(b) => {}
            _ => return Err(malformed(&format!("invalid character 0x{b:02x}"), out)),
        }
    }
    if n == 1 {
        return Err(malformed("single-character final group", out));
    }
    if n > 1 {
        for slot in group.iter_mut().skip(n) {
            *slot = 84;
        }
        let Some(value) = ascii85_value(&group) else {
            return Err(malformed("group value overflow", out));
        };
        if out.len() + n - 1 > cap {
            return Err(limit_failure(cap, out));
        }
        out.extend_from_slice(&value.to_be_bytes()[..n - 1]);
    }
    Ok(out)
}

/// RunLengthDecode (PackBits-style). Truncated runs are malformed.
pub(crate) fn run_length(input: &[u8], budget: Budget) -> Result<Vec<u8>, DecodeFailure> {
    let cap = budget.cap;
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut steps = 0usize;
    while i < input.len() {
        steps += 1;
        if steps.is_multiple_of(65536) {
            budget.check_deadline()?;
        }
        let len = input[i];
        i += 1;
        let pushed = match len {
            128 => return Ok(out),
            0..=127 => {
                let count = usize::from(len) + 1;
                let Some(literal) = input.get(i..i + count) else {
                    return Err(DecodeFailure::new(
                        FailureKind::Malformed,
                        "truncated RunLength literal run",
                    )
                    .with_partial(out));
                };
                i += count;
                push_checked(&mut out, literal, cap)
            }
            _ => {
                let Some(&byte) = input.get(i) else {
                    return Err(DecodeFailure::new(
                        FailureKind::Malformed,
                        "truncated RunLength repeat run",
                    )
                    .with_partial(out));
                };
                i += 1;
                push_checked(&mut out, &[byte; 128][..257 - usize::from(len)], cap)
            }
        };
        if let Err(failure) = pushed {
            return Err(failure.with_partial(out));
        }
    }
    // A missing end-of-data byte is tolerated: no input was left undecoded.
    Ok(out)
}

/// Applies `/Predictor` from FlateDecode/LZWDecode parameters.
fn apply_predictor(
    data: Vec<u8>,
    params: &Params,
    budget: Budget,
) -> Result<Vec<u8>, DecodeFailure> {
    let predictor = params.predictor.unwrap_or(1);
    if predictor == 1 {
        return Ok(data);
    }
    let unsupported = |msg: String| DecodeFailure::new(FailureKind::Unsupported, msg);
    let colors = params.colors.unwrap_or(1);
    let bpc = params.bits_per_component.unwrap_or(8);
    let columns = params.columns.unwrap_or(1);
    if !(1..=32).contains(&colors)
        || ![1, 2, 4, 8, 16].contains(&bpc)
        || !(1..=(1 << 24)).contains(&columns)
    {
        return Err(unsupported(format!(
            "predictor parameters Colors {colors}, BitsPerComponent {bpc}, Columns {columns}"
        ))
        .with_partial(data));
    }
    // Bounded above, so these products cannot overflow.
    let bits_per_pixel = (colors * bpc) as usize;
    let bytes_per_row = (bits_per_pixel * columns as usize).div_ceil(8);
    let bpp = bits_per_pixel.div_ceil(8).max(1);
    budget.check_deadline()?;
    match predictor {
        2 => {
            if bpc != 8 {
                return Err(
                    unsupported(format!("TIFF predictor with {bpc} bits per component"))
                        .with_partial(data),
                );
            }
            let mut data = data;
            for row in data.chunks_mut(bytes_per_row) {
                for i in bpp..row.len() {
                    row[i] = row[i].wrapping_add(row[i - bpp]);
                }
            }
            Ok(data)
        }
        10..=15 => png_predictor(&data, bpp, bytes_per_row, budget),
        other => Err(unsupported(format!("predictor {other}")).with_partial(data)),
    }
}

/// PNG predictors (one filter-type byte per row). A trailing partial row is decoded
/// with the bytes present, so no input is left uninspected.
fn png_predictor(
    data: &[u8],
    bpp: usize,
    bytes_per_row: usize,
    budget: Budget,
) -> Result<Vec<u8>, DecodeFailure> {
    use lopdf::filters::png::{decode_row, FilterType};
    let stride = bytes_per_row + 1;
    let mut out = Vec::new();
    out.try_reserve_exact(data.len() - data.len().div_ceil(stride))
        .map_err(|_| alloc_failure())?;
    let mut previous = Vec::new();
    previous
        .try_reserve_exact(bytes_per_row.min(data.len()))
        .map_err(|_| alloc_failure())?;
    previous.resize(bytes_per_row.min(data.len()), 0u8);
    for (index, row) in data.chunks(stride).enumerate() {
        if index.is_multiple_of(4096) {
            budget.check_deadline()?;
        }
        let Ok(filter) = FilterType::try_from(row[0]) else {
            return Err(DecodeFailure::new(
                FailureKind::Malformed,
                format!("invalid PNG predictor type {}", row[0]),
            )
            .with_partial(data.to_vec()));
        };
        let start = out.len();
        out.extend_from_slice(&row[1..]);
        let current = &mut out[start..];
        decode_row(filter, bpp, &previous[..current.len()], current);
        previous[..current.len()].copy_from_slice(current);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::Duration;

    fn budget(cap: usize) -> Budget {
        Budget {
            cap,
            deadline: Instant::now() + Duration::from_secs(30),
        }
    }

    fn spec(name: &[u8]) -> FilterSpec {
        FilterSpec {
            name: name.to_vec(),
            params: Params::default(),
        }
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn flate_complete_truncated_corrupt_and_raw() {
        let payload = b"hello flate world ".repeat(100);
        let enc = zlib(&payload);
        assert_eq!(inflate(&enc, budget(1 << 20)).unwrap(), payload);
        // Wrong Adler-32 tolerated: deflate data is complete.
        let mut bad_adler = enc.clone();
        let n = bad_adler.len();
        bad_adler[n - 1] ^= 0xff;
        assert_eq!(inflate(&bad_adler, budget(1 << 20)).unwrap(), payload);
        // Truncated: partial output kept, but malformed.
        let err = inflate(&enc[..enc.len() / 2], budget(1 << 20)).unwrap_err();
        assert_eq!(err.kind, FailureKind::Malformed);
        // Corrupt block type.
        let err = inflate(&[0x78, 0x9c, 0xff, 0xff, 0xff], budget(1 << 20)).unwrap_err();
        assert_eq!(err.kind, FailureKind::Malformed);
        // Headerless raw deflate.
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(&payload).unwrap();
        assert_eq!(
            inflate(&e.finish().unwrap(), budget(1 << 20)).unwrap(),
            payload
        );
    }

    #[test]
    fn flate_matches_lopdf_and_enforces_cap_and_ratio() {
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let enc = zlib(&payload);
        let lopdf_out = lopdf::Stream::new(
            lopdf::dictionary! { "Filter" => "FlateDecode" },
            enc.clone(),
        )
        .decompressed_content()
        .unwrap();
        assert_eq!(inflate(&enc, budget(1 << 20)).unwrap(), lopdf_out);
        assert_eq!(
            inflate(&enc, budget(1000)).unwrap_err().kind,
            FailureKind::Limit
        );
        // Exactly-at-cap output is complete, not a limit failure.
        assert_eq!(inflate(&enc, budget(payload.len())).unwrap(), payload);
        // Double-deflate bomb: 64 MiB zeros -> ~64 KiB -> a few hundred bytes.
        let zeros = vec![0u8; 64 << 20];
        let twice = zlib(&zlib(&zeros));
        let filters = [spec(b"FlateDecode"), spec(b"FlateDecode")];
        let err = decode_chain(&twice, &filters, budget(usize::MAX >> 1)).unwrap_err();
        assert_eq!(err.kind, FailureKind::Limit);
        assert!(err.message.contains("ratio"), "{}", err.message);
        // Single-layer maximally compressed data stays within the ratio limit.
        let once = zlib(&vec![0u8; 8 << 20]);
        let ok = decode_chain(&once, &[spec(b"FlateDecode")], budget(16 << 20)).unwrap();
        assert_eq!(ok.data.len(), 8 << 20);
    }

    #[test]
    fn ascii_filters_reference_vectors() {
        let data: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
        let hex: String = data.iter().map(|b| format!("{b:02X} ")).collect::<String>() + ">";
        assert_eq!(ascii_hex(hex.as_bytes(), budget(1 << 20)).unwrap(), data);
        assert_eq!(ascii_hex(b"4 1 4>", budget(16)).unwrap(), b"A@");
        assert_eq!(ascii_hex(b"414>", budget(16)).unwrap(), b"A@");
        assert_eq!(
            ascii_hex(b"41G1>", budget(16)).unwrap_err().kind,
            FailureKind::Malformed
        );
        // Reference vectors from Python's base64.a85encode (Adobe alphabet).
        // lopdf 0.47's ASCII85 decoder disagrees with these, so it is not used.
        for (encoded, plain) in [
            (b"87cURD]i,\"Ebo80~>".as_slice(), b"Hello World!".as_slice()),
            (b"87cURD_*#4DfTZ)~>", b"Hello, World"),
            (b"z!!~>", b"\0\0\0\0\0"),
            (b"9jqo^BlbD-BleB1DJ+*+F(f,q~>", b"Man is distinguished"),
            (b"9jqo^ BlbD-\nBleB1 DJ+*+F(f,q", b"Man is distinguished"),
        ] {
            assert_eq!(ascii85(encoded, budget(1 << 20)).unwrap(), plain);
        }
        assert_eq!(
            ascii85(b"ab{cd~>", budget(64)).unwrap_err().kind,
            FailureKind::Malformed
        );
        assert_eq!(
            ascii85(b"!~>", budget(64)).unwrap_err().kind,
            FailureKind::Malformed
        );
    }

    #[test]
    fn run_length_and_lzw() {
        assert_eq!(
            run_length(&[2, b'a', b'b', b'c', 254, b'x', 128], budget(64)).unwrap(),
            b"abcxxx"
        );
        assert_eq!(
            run_length(&[5, b'a'], budget(64)).unwrap_err().kind,
            FailureKind::Malformed
        );
        assert_eq!(
            run_length(&[129, b'z'].repeat(1000), budget(1000))
                .unwrap_err()
                .kind,
            FailureKind::Limit
        );
        let payload = b"-----A---B LZW test LZW test LZW test".repeat(50);
        let encoded = weezl::encode::Encoder::with_tiff_size_switch(weezl::BitOrder::Msb, 8)
            .encode(&payload)
            .unwrap();
        assert_eq!(
            lzw(&encoded, &Params::default(), budget(1 << 20)).unwrap(),
            payload
        );
        let err = lzw(
            &encoded[..encoded.len() / 2],
            &Params::default(),
            budget(1 << 20),
        )
        .unwrap_err();
        assert_eq!(err.kind, FailureKind::Malformed);
        let plain = weezl::encode::Encoder::new(weezl::BitOrder::Msb, 8)
            .encode(&payload)
            .unwrap();
        let params = Params {
            early_change: Some(0),
            ..Default::default()
        };
        assert_eq!(lzw(&plain, &params, budget(1 << 20)).unwrap(), payload);
    }

    #[test]
    fn predictors() {
        // PNG Up predictor, 3 columns, 1 colour, 8 bits.
        let rows = [2u8, 1, 2, 3, 2, 1, 1, 1];
        let params = Params {
            predictor: Some(12),
            columns: Some(3),
            ..Default::default()
        };
        let out = apply_predictor(rows.to_vec(), &params, budget(64)).unwrap();
        assert_eq!(out, [1, 2, 3, 2, 3, 4]);
        // Partial trailing row is still decoded.
        let out = apply_predictor(rows[..6].to_vec(), &params, budget(64)).unwrap();
        assert_eq!(out, [1, 2, 3, 2]);
        let bad = apply_predictor(vec![9, 0, 0, 0], &params, budget(64)).unwrap_err();
        assert_eq!(bad.kind, FailureKind::Malformed);
        // TIFF predictor 2.
        let params = Params {
            predictor: Some(2),
            columns: Some(4),
            ..Default::default()
        };
        assert_eq!(
            apply_predictor(vec![1, 1, 1, 1], &params, budget(64)).unwrap(),
            [1, 2, 3, 4]
        );
        let params = Params {
            predictor: Some(7),
            ..Default::default()
        };
        assert_eq!(
            apply_predictor(vec![1], &params, budget(64))
                .unwrap_err()
                .kind,
            FailureKind::Unsupported
        );
    }

    #[test]
    fn chains_images_and_unknown_filters() {
        let payload = b"chain payload".repeat(10);
        let hex: String = zlib(&payload).iter().map(|b| format!("{b:02x}")).collect();
        let out = decode_chain(
            hex.as_bytes(),
            &[spec(b"AHx"), spec(b"Fl")],
            budget(1 << 20),
        )
        .unwrap();
        assert_eq!(out.data, payload);
        assert_eq!(out.applied, 2);
        let jpeg = decode_chain(b"\xff\xd8\xff", &[spec(b"DCTDecode")], budget(64)).unwrap();
        assert_eq!(jpeg.image_codec, Some("DCTDecode"));
        assert_eq!(jpeg.applied, 0);
        let err = decode_chain(
            b"x",
            &[spec(b"DCTDecode"), spec(b"FlateDecode")],
            budget(64),
        )
        .unwrap_err();
        assert_eq!(err.kind, FailureKind::Unsupported);
        let err = decode_chain(b"x", &[spec(b"RaxoUnknown")], budget(64)).unwrap_err();
        assert_eq!(err.kind, FailureKind::Unsupported);
        let mut crypt = spec(b"Crypt");
        crypt.params.name = Some(b"StdCF".to_vec());
        assert_eq!(
            decode_chain(b"x", &[crypt], budget(64)).unwrap_err().kind,
            FailureKind::Unsupported
        );
        assert_eq!(
            decode_chain(b"x", &[spec(b"Crypt")], budget(64))
                .unwrap()
                .data,
            b"x"
        );
        let expired = Budget {
            cap: 64,
            deadline: Instant::now() - Duration::from_millis(1),
        };
        assert_eq!(
            decode_chain(b"x", &[spec(b"AHx")], expired)
                .unwrap_err()
                .kind,
            FailureKind::Timeout
        );
    }
}
