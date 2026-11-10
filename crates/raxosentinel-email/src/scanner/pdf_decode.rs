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
    pub(crate) fn new(kind: FailureKind, message: impl Into<String>) -> Self {
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
    #[cfg_attr(not(test), allow(dead_code))]
    pub applied: usize,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Budget {
    /// Maximum decoded bytes for this stream (final filter output).
    pub cap: usize,
    /// Maximum bytes held in memory for any intermediate filter output.
    pub buffer_cap: usize,
    pub deadline: Instant,
}

fn check_deadline(deadline: Instant) -> Result<(), DecodeFailure> {
    if Instant::now() >= deadline {
        Err(DecodeFailure::new(
            FailureKind::Timeout,
            "scan deadline reached while decoding",
        ))
    } else {
        Ok(())
    }
}

/// Receives decoded output incrementally, in chunks of at most [`CHUNK`] bytes.
pub(crate) trait ChunkSink {
    fn write(&mut self, data: &[u8]) -> Result<(), DecodeFailure>;
}

/// Collects output in memory with fallible allocation.
#[derive(Default)]
pub(crate) struct VecSink(pub Vec<u8>);

impl ChunkSink for VecSink {
    fn write(&mut self, data: &[u8]) -> Result<(), DecodeFailure> {
        self.0.try_reserve(data.len()).map_err(|_| alloc_failure())?;
        self.0.extend_from_slice(data);
        Ok(())
    }
}

/// Capped, staged writer in front of a sink. At most `cap` bytes are ever delivered;
/// exceeding it delivers the bytes up to the cap and fails with `Limit`.
struct Out<'s> {
    sink: &'s mut dyn ChunkSink,
    cap: usize,
    written: usize,
    buf: Vec<u8>,
}

impl<'s> Out<'s> {
    fn new(sink: &'s mut dyn ChunkSink, cap: usize) -> Self {
        Self {
            sink,
            cap,
            written: 0,
            buf: Vec::new(),
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), DecodeFailure> {
        let room = self.cap - self.written;
        if bytes.len() > room {
            self.stage(&bytes[..room])?;
            self.flush()?;
            return Err(limit_failure(self.cap));
        }
        self.stage(bytes)
    }

    fn push_byte(&mut self, byte: u8) -> Result<(), DecodeFailure> {
        if self.written < self.cap && self.buf.len() < CHUNK {
            self.buf.push(byte);
            self.written += 1;
            Ok(())
        } else {
            self.push(&[byte])
        }
    }

    fn stage(&mut self, bytes: &[u8]) -> Result<(), DecodeFailure> {
        self.written += bytes.len();
        if self.buf.len() + bytes.len() > CHUNK {
            self.flush()?;
            if bytes.len() >= CHUNK {
                return self.sink.write(bytes);
            }
        }
        if self.buf.capacity() == 0 {
            self.buf
                .try_reserve_exact(CHUNK.min(self.cap.max(64)))
                .map_err(|_| alloc_failure())?;
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), DecodeFailure> {
        if !self.buf.is_empty() {
            let r = self.sink.write(&self.buf);
            self.buf.clear();
            r?;
        }
        Ok(())
    }
}

/// Runs a decoder into `out` and always flushes what it produced, so partial
/// output reaches the sink (and is scanned) even when decoding fails.
fn run(out: &mut Out<'_>, decode: impl FnOnce(&mut Out<'_>) -> Result<(), DecodeFailure>) -> Result<(), DecodeFailure> {
    let result = decode(out);
    let flushed = out.flush();
    result.and(flushed)
}

#[derive(Clone, Copy)]
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

/// True when the chain only leaves an image codec in place (plus identity /Crypt),
/// i.e. the "decoded" output would be the raw stream bytes.
pub(crate) fn is_undecoded_image(filters: &[FilterSpec]) -> bool {
    let Some((last, rest)) = filters.split_last() else {
        return false;
    };
    matches!(classify(&last.name), Some(Filter::Image(_)))
        && rest.len() <= 1
        && rest.iter().all(|spec| {
            matches!(classify(&spec.name), Some(Filter::Crypt))
                && spec
                    .params
                    .name
                    .as_deref()
                    .is_none_or(|name| name == b"Identity")
        })
}

/// Outcome of a chain decoded into a sink.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChainInfo {
    pub image_codec: Option<&'static str>,
    pub applied: usize,
}

/// Applies a complete filter chain, delivering the final output to `sink` in chunks
/// so it never has to be held in memory. Intermediate filter outputs (only present
/// in multi-filter chains) are buffered up to `budget.buffer_cap`. Terminal image
/// codecs are not decoded: their (possibly pre-decoded) encoded bytes are emitted.
/// On failure the sink has already received all output produced before the failure.
pub(crate) fn decode_chain_to(
    raw: &[u8],
    filters: &[FilterSpec],
    budget: Budget,
    sink: &mut dyn ChunkSink,
) -> Result<ChainInfo, DecodeFailure> {
    if filters.len() > MAX_FILTERS {
        return Err(DecodeFailure::new(
            FailureKind::Unsupported,
            format!(
                "{} filters exceed the supported chain length",
                filters.len()
            ),
        ));
    }
    // Plan the chain first so the last decoding filter can stream into the sink.
    let mut decoders: Vec<(Filter, &FilterSpec)> = Vec::new();
    let mut image_codec = None;
    let mut stop: Option<DecodeFailure> = None;
    for (index, spec) in filters.iter().enumerate() {
        let Some(filter) = classify(&spec.name) else {
            stop = Some(DecodeFailure::new(
                FailureKind::Unsupported,
                format!(
                    "unsupported filter /{}",
                    String::from_utf8_lossy(&spec.name)
                ),
            ));
            break;
        };
        match filter {
            Filter::Image(codec) => {
                if index + 1 != filters.len() {
                    stop = Some(DecodeFailure::new(
                        FailureKind::Unsupported,
                        format!("image filter /{codec} is not the last filter"),
                    ));
                    break;
                }
                image_codec = Some(codec);
            }
            Filter::Crypt => {
                let identity = spec
                    .params
                    .name
                    .as_deref()
                    .is_none_or(|name| name == b"Identity");
                if index != 0 || !identity {
                    stop = Some(DecodeFailure::new(
                        FailureKind::Unsupported,
                        "non-identity /Crypt stream filter",
                    ));
                    break;
                }
            }
            _ => decoders.push((filter, spec)),
        }
    }

    let raw_len = raw.len() as u64;
    // Bound every layer by the stream cap and the chain ratio relative to the raw bytes.
    let ratio_cap = raw_len.saturating_mul(MAX_CHAIN_RATIO).max(RATIO_FLOOR);
    let layer_cap = (budget.cap as u64).min(ratio_cap) as usize;
    let cap_is_ratio = ratio_cap < budget.cap as u64;
    let buffer_cap = layer_cap.min(budget.buffer_cap);
    let ratio_message = |mut failure: DecodeFailure, cap: usize| {
        if failure.kind == FailureKind::Limit && cap_is_ratio && cap == layer_cap {
            failure.message = format!(
                "decoded size exceeds {MAX_CHAIN_RATIO}:1 compression ratio ({})",
                failure.message
            );
        }
        failure
    };

    if decoders.is_empty() {
        if let Some(failure) = stop {
            return Err(failure);
        }
        for piece in raw.chunks(CHUNK) {
            check_deadline(budget.deadline)?;
            sink.write(piece)?;
        }
        return Ok(ChainInfo {
            image_codec,
            applied: 0,
        });
    }

    let mut current: Option<Vec<u8>> = None;
    let last = decoders.len() - 1;
    for (k, (filter, spec)) in decoders.iter().enumerate() {
        check_deadline(budget.deadline)?;
        let input: &[u8] = current.as_deref().unwrap_or(raw);
        if k == last {
            let mut out = Out::new(sink, layer_cap);
            decode_layer(*filter, spec, input, &mut out, budget.deadline)
                .map_err(|f| ratio_message(f, layer_cap))?;
        } else {
            let mut collected = VecSink::default();
            let result = {
                let mut out = Out::new(&mut collected, buffer_cap);
                decode_layer(*filter, spec, input, &mut out, budget.deadline)
            };
            if let Err(mut failure) = result {
                if failure.kind == FailureKind::Limit && buffer_cap < layer_cap {
                    failure.message =
                        format!("intermediate filter output exceeds {buffer_cap} bytes");
                }
                for piece in collected.0.chunks(CHUNK) {
                    sink.write(piece)?;
                }
                return Err(ratio_message(failure, buffer_cap));
            }
            current = Some(collected.0);
        }
    }
    if let Some(failure) = stop {
        return Err(failure);
    }
    Ok(ChainInfo {
        image_codec,
        applied: decoders.len(),
    })
}

/// Applies a complete filter chain into memory (used where the whole output is
/// needed, e.g. object streams). Failure carries the partial output.
pub(crate) fn decode_chain(
    raw: &[u8],
    filters: &[FilterSpec],
    budget: Budget,
) -> Result<Decoded, DecodeFailure> {
    let mut collected = VecSink::default();
    match decode_chain_to(raw, filters, budget, &mut collected) {
        Ok(info) => Ok(Decoded {
            data: collected.0,
            image_codec: info.image_codec,
            applied: info.applied,
        }),
        Err(failure) => Err(failure.with_partial(collected.0)),
    }
}

fn decode_layer(
    filter: Filter,
    spec: &FilterSpec,
    input: &[u8],
    out: &mut Out<'_>,
    deadline: Instant,
) -> Result<(), DecodeFailure> {
    match filter {
        Filter::Flate => with_predictor(&spec.params, out, deadline, |o| {
            inflate_to(input, o, deadline)
        }),
        Filter::Lzw => with_predictor(&spec.params, out, deadline, |o| {
            lzw_to(input, &spec.params, o, deadline)
        }),
        Filter::AsciiHex => run(out, |o| ascii_hex_to(input, o, deadline)),
        Filter::Ascii85 => run(out, |o| ascii85_to(input, o, deadline)),
        Filter::RunLength => run(out, |o| run_length_to(input, o, deadline)),
        Filter::Crypt | Filter::Image(_) => Ok(()),
    }
}

fn limit_failure(cap: usize) -> DecodeFailure {
    DecodeFailure::new(
        FailureKind::Limit,
        format!("decoded size exceeds {cap} bytes"),
    )
}

fn alloc_failure() -> DecodeFailure {
    DecodeFailure::new(FailureKind::Limit, "cannot allocate decode buffer")
}

fn trailing_failure(rest: &[u8], what: &str) -> Result<(), DecodeFailure> {
    if rest.iter().all(|&b| is_pdf_whitespace(b)) {
        Ok(())
    } else {
        Err(DecodeFailure::new(
            FailureKind::Malformed,
            format!(
                "{} bytes of uninspected data after the end of {what} data",
                rest.len()
            ),
        ))
    }
}

/// Returns true when `input` starts with a valid RFC 1950 zlib header.
fn zlib_header(input: &[u8]) -> bool {
    input.len() >= 2
        && input[0] & 0x0f == 8
        && input[0] >> 4 <= 7
        && (u16::from(input[0]) << 8 | u16::from(input[1])) % 31 == 0
}

/// FlateDecode. The zlib wrapper is parsed here and the deflate body decoded raw.
/// The deflate data must be valid and reach its final block. After it, up to four
/// bytes (the Adler-32 checksum, which real-world writers often truncate or get
/// wrong) are tolerated, followed only by PDF whitespace: any other trailing bytes
/// would sit inside a stream span that is treated as inspected, so they are
/// reported as malformed rather than silently ignored.
fn inflate_to(input: &[u8], out: &mut Out<'_>, deadline: Instant) -> Result<(), DecodeFailure> {
    use flate2::{Decompress, FlushDecompress, Status};
    let zlib = zlib_header(input);
    let body = if zlib {
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
    let mut decoder = Decompress::new(false);
    let mut scratch = Vec::new();
    scratch
        .try_reserve_exact(CHUNK)
        .map_err(|_| alloc_failure())?;
    scratch.resize(CHUNK.min(out.cap.saturating_add(1)).max(64), 0);
    loop {
        check_deadline(deadline)?;
        let in_before = decoder.total_in();
        let out_before = decoder.total_out();
        let status = decoder.decompress(
            &body[in_before as usize..],
            &mut scratch,
            FlushDecompress::None,
        );
        let produced = (decoder.total_out() - out_before) as usize;
        out.push(&scratch[..produced])?;
        match status {
            Ok(Status::StreamEnd) => {
                let rest = &body[decoder.total_in() as usize..];
                let rest = if zlib { &rest[rest.len().min(4)..] } else { rest };
                return trailing_failure(rest, "deflate");
            }
            Ok(Status::Ok) | Ok(Status::BufError) => {
                if produced == 0 && decoder.total_in() == in_before {
                    return Err(DecodeFailure::new(
                        FailureKind::Malformed,
                        "truncated deflate data (no final block)",
                    ));
                }
            }
            Err(e) => {
                return Err(DecodeFailure::new(
                    FailureKind::Malformed,
                    format!("corrupt deflate data: {e}"),
                ))
            }
        }
    }
}

/// LZWDecode via `weezl` (PDF uses MSB-first codes, 8-bit symbols, EarlyChange=1 by
/// default). The end-of-data code is required for complete decoding.
fn lzw_to(
    input: &[u8],
    params: &Params,
    out: &mut Out<'_>,
    deadline: Instant,
) -> Result<(), DecodeFailure> {
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
    let truncated = || {
        DecodeFailure::new(
            FailureKind::Malformed,
            "truncated LZW data (no end-of-data code)",
        )
    };
    let mut chunk = vec![0u8; CHUNK.min(out.cap.saturating_add(1)).max(64)];
    let mut rest = input;
    loop {
        check_deadline(deadline)?;
        let result = decoder.decode_bytes(rest, &mut chunk);
        rest = &rest[result.consumed_in..];
        out.push(&chunk[..result.consumed_out])?;
        match result.status {
            Ok(LzwStatus::Done) => return trailing_failure(rest, "LZW"),
            Ok(LzwStatus::Ok) => {}
            Ok(LzwStatus::NoProgress) => return Err(truncated()),
            Err(e) => {
                return Err(DecodeFailure::new(
                    FailureKind::Malformed,
                    format!("corrupt LZW data: {e}"),
                ))
            }
        }
        if result.consumed_in == 0 && result.consumed_out == 0 {
            return Err(truncated());
        }
    }
}

fn is_pdf_whitespace(b: u8) -> bool {
    matches!(b, b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

/// ASCIIHexDecode: whitespace ignored, `>` terminates, odd final digit padded with 0.
fn ascii_hex_to(input: &[u8], out: &mut Out<'_>, deadline: Instant) -> Result<(), DecodeFailure> {
    let mut high: Option<u8> = None;
    let mut end = input.len();
    for (i, &b) in input.iter().enumerate() {
        if i % (1 << 20) == 0 {
            check_deadline(deadline)?;
        }
        let nibble = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            b'>' => {
                end = i + 1;
                break;
            }
            _ if is_pdf_whitespace(b) => continue,
            _ => {
                return Err(DecodeFailure::new(
                    FailureKind::Malformed,
                    format!("invalid ASCIIHex character 0x{b:02x}"),
                ))
            }
        };
        match high.take() {
            None => high = Some(nibble),
            Some(h) => out.push_byte(h << 4 | nibble)?,
        }
    }
    if let Some(h) = high {
        out.push_byte(h << 4)?;
    }
    trailing_failure(&input[end..], "ASCIIHex")
}

fn ascii85_value(group: &[u8; 5]) -> Option<u32> {
    group.iter().try_fold(0u32, |acc, &d| {
        acc.checked_mul(85)?.checked_add(u32::from(d))
    })
}

/// ASCII85Decode: `z` shorthand, `~>` terminator, partial final group of 2-4 chars.
fn ascii85_to(input: &[u8], out: &mut Out<'_>, deadline: Instant) -> Result<(), DecodeFailure> {
    let malformed =
        |msg: &str| DecodeFailure::new(FailureKind::Malformed, format!("ASCII85: {msg}"));
    let mut group = [0u8; 5];
    let mut n = 0usize;
    let mut i = 0usize;
    let mut end = input.len();
    while i < input.len() {
        let b = input[i];
        if i % (1 << 20) == 0 {
            check_deadline(deadline)?;
        }
        i += 1;
        match b {
            b'~' => {
                let mut j = i;
                while j < input.len() && is_pdf_whitespace(input[j]) {
                    j += 1;
                }
                match input.get(j) {
                    Some(b'>') => end = j + 1,
                    None => end = j,
                    Some(_) => return Err(malformed("invalid end-of-data marker")),
                }
                break;
            }
            b'z' if n == 0 => out.push(&[0; 4])?,
            b'!'..=b'u' => {
                group[n] = b - b'!';
                n += 1;
                if n == 5 {
                    let Some(value) = ascii85_value(&group) else {
                        return Err(malformed("group value overflow"));
                    };
                    out.push(&value.to_be_bytes())?;
                    n = 0;
                }
            }
            _ if is_pdf_whitespace(b) => {}
            _ => return Err(malformed(&format!("invalid character 0x{b:02x}"))),
        }
    }
    if n == 1 {
        return Err(malformed("single-character final group"));
    }
    if n > 1 {
        for slot in group.iter_mut().skip(n) {
            *slot = 84;
        }
        let Some(value) = ascii85_value(&group) else {
            return Err(malformed("group value overflow"));
        };
        out.push(&value.to_be_bytes()[..n - 1])?;
    }
    trailing_failure(&input[end..], "ASCII85")
}

/// RunLengthDecode (PackBits-style). Truncated runs are malformed.
fn run_length_to(input: &[u8], out: &mut Out<'_>, deadline: Instant) -> Result<(), DecodeFailure> {
    let mut i = 0usize;
    let mut steps = 0usize;
    while i < input.len() {
        steps += 1;
        if steps.is_multiple_of(65536) {
            check_deadline(deadline)?;
        }
        let len = input[i];
        i += 1;
        match len {
            128 => return trailing_failure(&input[i..], "RunLength"),
            0..=127 => {
                let count = usize::from(len) + 1;
                let Some(literal) = input.get(i..i + count) else {
                    return Err(DecodeFailure::new(
                        FailureKind::Malformed,
                        "truncated RunLength literal run",
                    ));
                };
                i += count;
                out.push(literal)?;
            }
            _ => {
                let Some(&byte) = input.get(i) else {
                    return Err(DecodeFailure::new(
                        FailureKind::Malformed,
                        "truncated RunLength repeat run",
                    ));
                };
                i += 1;
                out.push(&[byte; 128][..257 - usize::from(len)])?;
            }
        }
    }
    // A missing end-of-data byte is tolerated: no input was left undecoded.
    Ok(())
}

#[derive(Clone, Copy)]
enum PredictorKind {
    Tiff,
    Png,
}

/// Validated `/Predictor` configuration; `Ok(None)` means no prediction.
fn predictor_config(params: &Params) -> Result<Option<(PredictorKind, usize, usize)>, DecodeFailure> {
    let predictor = params.predictor.unwrap_or(1);
    if predictor == 1 {
        return Ok(None);
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
        )));
    }
    // Bounded above, so these products cannot overflow.
    let bits_per_pixel = (colors * bpc) as usize;
    let bytes_per_row = (bits_per_pixel * columns as usize).div_ceil(8);
    let bpp = bits_per_pixel.div_ceil(8).max(1);
    match predictor {
        2 if bpc == 8 => Ok(Some((PredictorKind::Tiff, bpp, bytes_per_row))),
        2 => Err(unsupported(format!(
            "TIFF predictor with {bpc} bits per component"
        ))),
        10..=15 => Ok(Some((PredictorKind::Png, bpp, bytes_per_row))),
        other => Err(unsupported(format!("predictor {other}"))),
    }
}

/// Row-by-row predictor adapter: holds one row and the previous row only.
struct PredictorSink<'o, 's> {
    out: &'o mut Out<'s>,
    kind: PredictorKind,
    bpp: usize,
    stride: usize,
    row: Vec<u8>,
    previous: Vec<u8>,
    rows: usize,
    deadline: Instant,
}

impl PredictorSink<'_, '_> {
    fn emit_row(&mut self) -> Result<(), DecodeFailure> {
        use lopdf::filters::png::{decode_row, FilterType};
        self.rows += 1;
        if self.rows.is_multiple_of(4096) {
            check_deadline(self.deadline)?;
        }
        match self.kind {
            PredictorKind::Tiff => {
                for i in self.bpp..self.row.len() {
                    self.row[i] = self.row[i].wrapping_add(self.row[i - self.bpp]);
                }
                self.out.push(&self.row)?;
            }
            PredictorKind::Png => {
                let Ok(filter) = FilterType::try_from(self.row[0]) else {
                    return Err(DecodeFailure::new(
                        FailureKind::Malformed,
                        format!("invalid PNG predictor type {}", self.row[0]),
                    ));
                };
                let current = &mut self.row[1..];
                decode_row(filter, self.bpp, &self.previous[..current.len()], current);
                self.previous[..current.len()].copy_from_slice(current);
                self.out.push(&self.row[1..])?;
            }
        }
        self.row.clear();
        Ok(())
    }

    /// Decodes a trailing partial row with the bytes present.
    fn finish(&mut self) -> Result<(), DecodeFailure> {
        if self.row.is_empty() {
            return Ok(());
        }
        self.emit_row()
    }
}

impl ChunkSink for PredictorSink<'_, '_> {
    fn write(&mut self, mut data: &[u8]) -> Result<(), DecodeFailure> {
        while !data.is_empty() {
            let take = (self.stride - self.row.len()).min(data.len());
            self.row.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.row.len() == self.stride {
                self.emit_row()?;
            }
        }
        Ok(())
    }
}

/// Applies `/Predictor` from FlateDecode/LZWDecode parameters while streaming. With
/// unsupported predictor parameters the un-predicted data is still delivered (and
/// scanned) before the stream is reported as unsupported.
fn with_predictor(
    params: &Params,
    out: &mut Out<'_>,
    deadline: Instant,
    decode: impl FnOnce(&mut Out<'_>) -> Result<(), DecodeFailure>,
) -> Result<(), DecodeFailure> {
    let (kind, bpp, bytes_per_row) = match predictor_config(params) {
        Ok(None) => return run(out, decode),
        Ok(Some(config)) => config,
        Err(unsupported) => {
            run(out, decode)?;
            return Err(unsupported);
        }
    };
    let stride = match kind {
        PredictorKind::Tiff => bytes_per_row,
        PredictorKind::Png => bytes_per_row + 1,
    };
    let cap = out.cap;
    let mut row = Vec::new();
    row.try_reserve_exact(stride).map_err(|_| alloc_failure())?;
    let mut previous = Vec::new();
    previous
        .try_reserve_exact(bytes_per_row)
        .map_err(|_| alloc_failure())?;
    previous.resize(bytes_per_row, 0);
    let mut sink = PredictorSink {
        out,
        kind,
        bpp,
        stride,
        row,
        previous,
        rows: 0,
        deadline,
    };
    let decoded = {
        let mut inner = Out::new(&mut sink, cap);
        run(&mut inner, decode)
    };
    let finished = sink.finish();
    let flushed = sink.out.flush();
    decoded.and(finished).and(flushed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::Duration;

    fn budget(cap: usize) -> Budget {
        Budget {
            cap,
            buffer_cap: cap,
            deadline: Instant::now() + Duration::from_secs(30),
        }
    }

    fn collect(
        cap: usize,
        decode: impl FnOnce(&mut Out<'_>) -> Result<(), DecodeFailure>,
    ) -> Result<Vec<u8>, DecodeFailure> {
        let mut sink = VecSink::default();
        let result = {
            let mut out = Out::new(&mut sink, cap);
            run(&mut out, decode)
        };
        match result {
            Ok(()) => Ok(sink.0),
            Err(f) => Err(f.with_partial(sink.0)),
        }
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    fn inflate(input: &[u8], b: Budget) -> Result<Vec<u8>, DecodeFailure> {
        collect(b.cap, |o| inflate_to(input, o, b.deadline))
    }
    fn ascii_hex(input: &[u8], b: Budget) -> Result<Vec<u8>, DecodeFailure> {
        collect(b.cap, |o| ascii_hex_to(input, o, b.deadline))
    }
    fn ascii85(input: &[u8], b: Budget) -> Result<Vec<u8>, DecodeFailure> {
        collect(b.cap, |o| ascii85_to(input, o, b.deadline))
    }
    fn run_length(input: &[u8], b: Budget) -> Result<Vec<u8>, DecodeFailure> {
        collect(b.cap, |o| run_length_to(input, o, b.deadline))
    }
    fn lzw(input: &[u8], params: &Params, b: Budget) -> Result<Vec<u8>, DecodeFailure> {
        collect(b.cap, |o| lzw_to(input, params, o, b.deadline))
    }
    fn apply_predictor(data: Vec<u8>, params: &Params, b: Budget) -> Result<Vec<u8>, DecodeFailure> {
        collect(b.cap, |o| {
            with_predictor(params, o, b.deadline, |inner| inner.push(&data))
        })
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
            buffer_cap: 64,
            deadline: Instant::now() - Duration::from_millis(1),
        };
        assert_eq!(
            decode_chain(b"x", &[spec(b"AHx")], expired)
                .unwrap_err()
                .kind,
            FailureKind::Timeout
        );
    }

    /// Phase 3D end-of-data policy: only integrity bytes and PDF whitespace may
    /// follow the end of the encoded data; anything else is uninspected content.
    #[test]
    fn trailing_data_after_end_of_data() {
        let payload = b"trailing policy payload ".repeat(50);
        let enc = zlib(&payload);
        let body = &enc[..enc.len() - 4];
        // Missing or truncated Adler-32 with nothing after it: complete.
        for keep in 0..=4 {
            let mut v = body.to_vec();
            v.extend_from_slice(&enc[enc.len() - 4..][..keep]);
            assert_eq!(inflate(&v, budget(1 << 20)).unwrap(), payload, "adler {keep}");
        }
        let mut ws = enc.clone();
        ws.extend_from_slice(b"\r\n \t\x0c\x00");
        assert_eq!(inflate(&ws, budget(1 << 20)).unwrap(), payload);
        // The Phase 3C.3 fixture shape: truncated Adler then garbage.
        let mut garbage = enc[..enc.len() - 2].to_vec();
        garbage.extend_from_slice(&b"\x00garbage\xff".repeat(8));
        let err = inflate(&garbage, budget(1 << 20)).unwrap_err();
        assert_eq!(err.kind, FailureKind::Malformed);
        assert!(err.message.contains("uninspected"), "{}", err.message);
        assert_eq!(err.partial, payload);

        let err = ascii_hex(b"414243> PK\x03\x04", budget(64)).unwrap_err();
        assert_eq!((err.kind, err.partial.as_slice()), (FailureKind::Malformed, &b"ABC"[..]));
        assert_eq!(ascii_hex(b"414243>\r\n", budget(64)).unwrap(), b"ABC");
        let err = ascii85(b"87cURD]i,\"Ebo80~> hidden", budget(64)).unwrap_err();
        assert_eq!(err.kind, FailureKind::Malformed);
        assert_eq!(err.partial, b"Hello World!");
        let err = run_length(b"\x02abc\x80extra", budget(64)).unwrap_err();
        assert_eq!((err.kind, err.partial.as_slice()), (FailureKind::Malformed, &b"abc"[..]));
        assert_eq!(run_length(b"\x02abc\x80\n", budget(64)).unwrap(), b"abc");
    }

    struct Chunks(Vec<usize>, Vec<u8>);
    impl ChunkSink for Chunks {
        fn write(&mut self, data: &[u8]) -> Result<(), DecodeFailure> {
            self.0.push(data.len());
            self.1.extend_from_slice(data);
            Ok(())
        }
    }

    #[test]
    fn streaming_chain_is_bounded_and_equivalent() {
        let payload: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        let hex: String = zlib(&payload).iter().map(|b| format!("{b:02x}")).collect();
        let filters = [spec(b"AHx"), spec(b"Fl")];
        let mut sink = Chunks(Vec::new(), Vec::new());
        let b = Budget {
            cap: 8 << 20,
            buffer_cap: 4 << 20,
            deadline: deadline(),
        };
        decode_chain_to(hex.as_bytes(), &filters, b, &mut sink).unwrap();
        assert_eq!(sink.1, payload);
        // The final layer reaches the sink in bounded chunks.
        assert!(sink.0.len() > 1);
        assert!(sink.0.iter().all(|&n| n <= CHUNK), "{:?}", sink.0);
        // Intermediate layers must fit the buffer cap even when the output cap is larger.
        let small = Budget {
            cap: 8 << 20,
            buffer_cap: 1 << 20,
            deadline: deadline(),
        };
        let hex_payload: String = payload.iter().map(|b| format!("{b:02x}")).collect();
        let deflated_hex = zlib(hex_payload.as_bytes());
        let mut sink = Chunks(Vec::new(), Vec::new());
        let err = decode_chain_to(&deflated_hex, &[spec(b"Fl"), spec(b"AHx")], small, &mut sink)
            .unwrap_err();
        assert_eq!(err.kind, FailureKind::Limit);
        // Partial intermediate output is still inspected.
        assert!(!sink.1.is_empty() && hex_payload.as_bytes().starts_with(&sink.1));
        let mut sink = Chunks(Vec::new(), Vec::new());
        decode_chain_to(&deflated_hex, &[spec(b"Fl"), spec(b"AHx")], budget(8 << 20), &mut sink)
            .unwrap();
        assert_eq!(sink.1, payload);
        // The output cap delivers bytes up to the cap, then fails.
        let mut sink = Chunks(Vec::new(), Vec::new());
        let err = decode_chain_to(&zlib(&payload), &[spec(b"Fl")], budget(1_000_000), &mut sink)
            .unwrap_err();
        assert_eq!(err.kind, FailureKind::Limit);
        assert_eq!(sink.1.len(), 1_000_000);
        assert_eq!(sink.1[..], payload[..1_000_000]);
    }
}
