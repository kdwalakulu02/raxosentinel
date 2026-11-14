//! ClamAV-compatible content signatures: `.ndb` body signatures and pattern-only
//! `.ldb` logical signatures for the file types that reach mail scanning
//! (documents, HTML, PDF, mail, text/scripts, Flash, Java, graphics, any).
//!
//! Executable targets (PE/ELF/Mach-O) are deliberately not compiled: executables
//! are rejected by policy before content matching matters. Signatures using
//! features that cannot be evaluated faithfully (PCRE, byte-compare, macros,
//! fuzzy image hashes, container/PE conditions, executable-relative offsets) are
//! skipped rather than approximated, so every compiled signature matches with
//! ClamAV semantics or does not load at all.
//!
//! Matching: every pattern gets a literal anchor (the longest exact byte run
//! whose position inside its segment is fixed). All anchors of one target go
//! into one Aho-Corasick automaton; anchor hits are verified against the full
//! pattern (wildcards, nibbles, alternations, bounded and unbounded gaps). A
//! per-scan step budget bounds verification work on adversarial input.

use std::collections::HashMap;

const MIN_ANCHOR: usize = 3;
/// Anchors are trie prefixes; longer literals are checked during verification.
const MAX_ANCHOR: usize = 8;
const MAX_NEEDLE: usize = 16;
const MAX_INLINE_GAP: usize = 32;
const MAX_SUBSIGS: usize = 64;
const MAX_COUNT: u32 = 1024;
/// Verification steps allowed per scanned buffer.
pub const DEFAULT_STEP_BUDGET: u64 = 40_000_000;

/// ClamAV target types that are compiled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    Any,
    Ole2,
    Html,
    Mail,
    Graphics,
    Ascii,
    Pdf,
    Flash,
    Java,
}

impl Target {
    const ALL: [Target; 9] = [
        Target::Any,
        Target::Ole2,
        Target::Html,
        Target::Mail,
        Target::Graphics,
        Target::Ascii,
        Target::Pdf,
        Target::Flash,
        Target::Java,
    ];

    fn from_clamav(n: &str) -> Option<Self> {
        Some(match n {
            "0" => Target::Any,
            "2" => Target::Ole2,
            "3" => Target::Html,
            "4" => Target::Mail,
            "5" => Target::Graphics,
            "7" => Target::Ascii,
            "10" => Target::Pdf,
            "11" => Target::Flash,
            "12" => Target::Java,
            _ => return None,
        })
    }

    fn index(self) -> usize {
        Target::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    /// Classifies a buffer the way ClamAV picks the target type for it.
    pub fn classify(data: &[u8]) -> Target {
        let head = &data[..data.len().min(4096)];
        if head.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
            return Target::Ole2;
        }
        if find(&head[..head.len().min(1024)], b"%PDF-").is_some() {
            return Target::Pdf;
        }
        if head.len() >= 3 && matches!(&head[..3], b"FWS" | b"CWS" | b"ZWS") {
            return Target::Flash;
        }
        if head.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
            return Target::Java;
        }
        if head.starts_with(b"GIF8")
            || head.starts_with(b"\x89PNG")
            || head.starts_with(&[0xFF, 0xD8, 0xFF])
            || head.starts_with(b"II*\0")
            || head.starts_with(b"MM\0*")
            || (head.starts_with(b"BM") && head.len() > 14)
        {
            return Target::Graphics;
        }
        if !looks_textual(head) {
            return Target::Any;
        }
        let lower: Vec<u8> = head.iter().map(u8::to_ascii_lowercase).collect();
        const MAIL_HEADERS: [&[u8]; 6] = [
            b"received:",
            b"return-path:",
            b"delivered-to:",
            b"from:",
            b"mime-version:",
            b"message-id:",
        ];
        if MAIL_HEADERS.iter().any(|h| lower.starts_with(h)) {
            return Target::Mail;
        }
        const HTML_MARKERS: [&[u8]; 7] = [
            b"<html",
            b"<!doctype html",
            b"<head",
            b"<body",
            b"<script",
            b"<iframe",
            b"<meta",
        ];
        if HTML_MARKERS.iter().any(|m| find(&lower, m).is_some()) {
            return Target::Html;
        }
        Target::Ascii
    }

    fn normalized(self) -> bool {
        matches!(self, Target::Html | Target::Ascii)
    }
}

fn looks_textual(head: &[u8]) -> bool {
    if head.is_empty() || head.contains(&0) {
        return false;
    }
    let printable = head
        .iter()
        .filter(|&&b| b == b'\t' || b == b'\n' || b == b'\r' || b == 0x0c || b >= 0x20)
        .count();
    printable * 100 >= head.len() * 95
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Lowercases ASCII and collapses whitespace runs to one space (ClamAV text normalization).
pub fn normalize_text(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut in_space = false;
    for &b in data {
        if b.is_ascii_whitespace() || b == 0x0b {
            if !in_space {
                out.push(b' ');
                in_space = true;
            }
        } else {
            out.push(b.to_ascii_lowercase());
            in_space = false;
        }
    }
    out
}

/// HTML normalization: comments removed, then text-normalized.
pub fn normalize_html(data: &[u8]) -> Vec<u8> {
    let mut stripped = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i..].starts_with(b"<!--") {
            match find(&data[i + 4..], b"-->") {
                Some(end) => i += 4 + end + 3,
                None => break,
            }
        } else {
            stripped.push(data[i]);
            i += 1;
        }
    }
    normalize_text(&stripped)
}

/// One pattern position. Kept to 3 bytes: compiled databases hold millions.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Elem {
    Lit(u8),
    /// Lowercase ASCII letter matched case-insensitively.
    NoCase(u8),
    Mask {
        val: u8,
        mask: u8,
    },
    Any,
    /// Index into the owning segment's `alts`.
    Alt(u8),
}

#[derive(Clone, Debug, PartialEq)]
struct AltSet {
    alts: Vec<Vec<(u8, u8)>>,
    neg: bool,
}

impl AltSet {
    fn len_range(&self) -> (usize, usize) {
        (
            self.alts.iter().map(Vec::len).min().unwrap_or(0),
            self.alts.iter().map(Vec::len).max().unwrap_or(0),
        )
    }

    fn widen(&self) -> AltSet {
        AltSet {
            alts: self
                .alts
                .iter()
                .map(|x| x.iter().flat_map(|&p| [p, (0, 0xFF)]).collect())
                .collect(),
            neg: self.neg,
        }
    }
}

#[derive(Clone, Debug)]
struct Seg {
    elems: Box<[Elem]>,
    alts: Box<[AltSet]>,
    min_len: usize,
    max_len: usize,
    /// Exact literal run at a fixed offset from the segment start, used to jump
    /// between candidate positions with `memmem` instead of trying every byte.
    needle: Option<(usize, Box<[u8]>)>,
}

impl Seg {
    fn new(elems: Vec<Elem>, alts: Vec<AltSet>) -> Self {
        let mut seg = Seg {
            elems: elems.into_boxed_slice(),
            alts: alts.into_boxed_slice(),
            min_len: 0,
            max_len: 0,
            needle: None,
        };
        (seg.min_len, seg.max_len) = seg.elems.iter().fold((0, 0), |(a, b), e| {
            let (x, y) = seg.len_range(e);
            (a + x, b + y)
        });
        seg.needle = seg.find_needle();
        seg
    }

    fn find_needle(&self) -> Option<(usize, Box<[u8]>)> {
        let mut best: Option<(usize, usize)> = None;
        let mut run: Option<usize> = None;
        let close = |rs: usize, end: usize, best: &mut Option<(usize, usize)>| {
            let len = (end - rs).min(MAX_NEEDLE);
            if best.is_none_or(|(_, l)| len > l) {
                *best = Some((rs, len));
            }
        };
        for (i, e) in self.elems.iter().enumerate() {
            if matches!(e, Elem::Lit(_)) {
                run.get_or_insert(i);
                continue;
            }
            if let Some(rs) = run.take() {
                close(rs, i, &mut best);
            }
            let (lo, hi) = self.len_range(e);
            if lo != hi {
                // Later offsets are not fixed relative to the segment start.
                return best.map(|(o, l)| self.needle_at(o, l));
            }
        }
        if let Some(rs) = run {
            close(rs, self.elems.len(), &mut best);
        }
        best.map(|(o, l)| self.needle_at(o, l))
    }

    fn needle_at(&self, ei: usize, len: usize) -> (usize, Box<[u8]>) {
        // Every element before `ei` is fixed-width here.
        let off = self.elems[..ei].iter().map(|e| self.len_range(e).0).sum();
        let bytes = self.elems[ei..ei + len]
            .iter()
            .map(|e| match e {
                Elem::Lit(b) => *b,
                _ => unreachable!("needle covers literals only"),
            })
            .collect();
        (off, bytes)
    }

    /// First position in `[from, hi]` where this segment could start.
    fn next_candidate(&self, data: &[u8], from: usize, hi: usize) -> Option<usize> {
        if from > hi {
            return None;
        }
        let Some((off, nd)) = &self.needle else {
            return Some(from);
        };
        let lo = from + off;
        let end = (hi + off + nd.len()).min(data.len());
        if lo >= end {
            return None;
        }
        memchr::memmem::find(&data[lo..end], nd).map(|i| from + i)
    }

    /// Last position in `[lo, to]` where this segment could start.
    fn prev_candidate(&self, data: &[u8], lo: usize, to: usize) -> Option<usize> {
        if lo > to {
            return None;
        }
        let Some((off, nd)) = &self.needle else {
            return Some(to);
        };
        let start = lo + off;
        let end = (to + off + nd.len()).min(data.len());
        if start >= end {
            return None;
        }
        memchr::memmem::rfind(&data[start..end], nd).map(|i| lo + i)
    }

    fn len_range(&self, e: &Elem) -> (usize, usize) {
        match e {
            Elem::Alt(i) => self.alts[*i as usize].len_range(),
            _ => (1, 1),
        }
    }

    /// Matches this segment at `pos`, returning the end offset of the first match.
    fn match_at(&self, data: &[u8], pos: usize) -> Option<usize> {
        match_elems(&self.elems, &self.alts, data, pos)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Gap {
    min: usize,
    max: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Offset {
    Any,
    Abs(usize, usize),
    Eof(usize, usize),
}

impl Offset {
    fn parse(s: &str) -> Option<Self> {
        if s == "*" {
            return Some(Offset::Any);
        }
        let (base, shift) = match s.split_once(',') {
            Some((b, sh)) => (b, sh.parse().ok()?),
            None => (s, 0),
        };
        if let Some(n) = base.strip_prefix("EOF-") {
            return Some(Offset::Eof(n.parse().ok()?, shift));
        }
        Some(Offset::Abs(base.parse().ok()?, shift))
    }

    fn allows(self, start: usize, len: usize) -> bool {
        match self {
            Offset::Any => true,
            Offset::Abs(n, sh) => start >= n && start <= n + sh,
            Offset::Eof(n, sh) => n <= len && start >= len - n && start <= len - n + sh,
        }
    }

    fn candidates(self, len: usize) -> Option<std::ops::Range<usize>> {
        match self {
            Offset::Any => None,
            Offset::Abs(n, sh) => Some(n..n + sh + 1),
            Offset::Eof(n, sh) if n <= len => Some(len - n..len - n + sh + 1),
            Offset::Eof(..) => Some(0..0),
        }
    }
}

#[derive(Clone, Debug)]
struct Pattern {
    segs: Vec<Seg>,
    gaps: Vec<Gap>,
    offset: Offset,
    fullword: bool,
    sig: u32,
    sub: u8,
    /// (segment index, element index, run length) of the anchor; None = positional.
    anchor: Option<(usize, usize, usize)>,
    /// Byte offset of the anchor within its (fixed-width up to the anchor) segment.
    anchor_prefix: usize,
}

#[derive(Clone, Debug)]
enum Node {
    Sub(u8),
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
    Cmp {
        node: Box<Node>,
        op: u8,
        n: u32,
        distinct: Option<u32>,
    },
}

impl Node {
    fn eval(&self, counts: &[u32]) -> (bool, u32, u64) {
        match self {
            Node::Sub(i) => {
                let c = counts.get(*i as usize).copied().unwrap_or(0);
                (c > 0, c, if c > 0 { 1u64 << i } else { 0 })
            }
            Node::And(a, b) => {
                let (am, at, ak) = a.eval(counts);
                let (bm, bt, bk) = b.eval(counts);
                (am && bm, at.saturating_add(bt), ak | bk)
            }
            Node::Or(a, b) => {
                let (am, at, ak) = a.eval(counts);
                let (bm, bt, bk) = b.eval(counts);
                (am || bm, at.saturating_add(bt), ak | bk)
            }
            Node::Cmp {
                node,
                op,
                n,
                distinct,
            } => {
                let (_, t, k) = node.eval(counts);
                let ok = match op {
                    b'=' => t == *n,
                    b'>' => t > *n,
                    _ => t < *n,
                } && distinct.is_none_or(|d| k.count_ones() >= d);
                (ok, t, k)
            }
        }
    }

    fn max_sub(&self) -> u8 {
        match self {
            Node::Sub(i) => *i,
            Node::And(a, b) | Node::Or(a, b) => a.max_sub().max(b.max_sub()),
            Node::Cmp { node, .. } => node.max_sub(),
        }
    }
}

struct ExprParser<'a> {
    s: &'a [u8],
    i: usize,
}

impl ExprParser<'_> {
    fn num(&mut self) -> Option<u32> {
        let start = self.i;
        while self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
            self.i += 1;
        }
        std::str::from_utf8(&self.s[start..self.i])
            .ok()?
            .parse()
            .ok()
    }

    fn or(&mut self) -> Option<Node> {
        let mut left = self.and()?;
        while self.s.get(self.i) == Some(&b'|') {
            self.i += 1;
            left = Node::Or(Box::new(left), Box::new(self.and()?));
        }
        Some(left)
    }

    fn and(&mut self) -> Option<Node> {
        let mut left = self.cmp()?;
        while self.s.get(self.i) == Some(&b'&') {
            self.i += 1;
            left = Node::And(Box::new(left), Box::new(self.cmp()?));
        }
        Some(left)
    }

    fn cmp(&mut self) -> Option<Node> {
        let node = match self.s.get(self.i)? {
            b'(' => {
                self.i += 1;
                let n = self.or()?;
                if self.s.get(self.i) != Some(&b')') {
                    return None;
                }
                self.i += 1;
                n
            }
            c if c.is_ascii_digit() => {
                let n = self.num()?;
                if n as usize >= MAX_SUBSIGS {
                    return None;
                }
                Node::Sub(n as u8)
            }
            _ => return None,
        };
        let Some(&op) = self
            .s
            .get(self.i)
            .filter(|c| matches!(c, b'=' | b'>' | b'<'))
        else {
            return Some(node);
        };
        self.i += 1;
        let n = self.num()?;
        let distinct = if self.s.get(self.i) == Some(&b',') {
            self.i += 1;
            Some(self.num()?)
        } else {
            None
        };
        Some(Node::Cmp {
            node: Box::new(node),
            op,
            n,
            distinct,
        })
    }
}

fn parse_expr(s: &str) -> Option<Node> {
    let mut p = ExprParser {
        s: s.as_bytes(),
        i: 0,
    };
    let node = p.or()?;
    (p.i == p.s.len()).then_some(node)
}

fn hex_nibble(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// Parses one hex byte token (`ab`, `a?`, `?b`, `??`) into (value, mask).
fn hex_pair(a: u8, b: u8) -> Option<(u8, u8)> {
    match (a, b) {
        (b'?', b'?') => Some((0, 0)),
        (b'?', y) => Some((hex_nibble(y)?, 0x0F)),
        (x, b'?') => Some((hex_nibble(x)? << 4, 0xF0)),
        (x, y) => Some(((hex_nibble(x)? << 4) | hex_nibble(y)?, 0xFF)),
    }
}

fn parse_gap(body: &str) -> Option<Gap> {
    if let Some(m) = body.strip_prefix('-') {
        return Some(Gap {
            min: 0,
            max: Some(m.parse().ok()?),
        });
    }
    if let Some(n) = body.strip_suffix('-') {
        return Some(Gap {
            min: n.parse().ok()?,
            max: None,
        });
    }
    if let Some((a, b)) = body.split_once('-') {
        let (min, max) = (a.parse().ok()?, b.parse().ok()?);
        return (min <= max).then_some(Gap {
            min,
            max: Some(max),
        });
    }
    let n = body.parse().ok()?;
    Some(Gap {
        min: n,
        max: Some(n),
    })
}

/// Parses a ClamAV hex signature body into segments separated by gaps.
fn parse_hex(hex: &str) -> Option<(Vec<Seg>, Vec<Gap>)> {
    let s = hex.as_bytes();
    let mut segs = Vec::new();
    let mut gaps = Vec::new();
    let mut cur: Vec<Elem> = Vec::new();
    let mut cur_alts: Vec<AltSet> = Vec::new();
    let mut i = 0;
    let push_gap = |cur: &mut Vec<Elem>,
                    cur_alts: &mut Vec<AltSet>,
                    segs: &mut Vec<Seg>,
                    gaps: &mut Vec<Gap>,
                    g: Gap| {
        if g.max == Some(g.min) && g.min <= MAX_INLINE_GAP && !cur.is_empty() {
            cur.extend(std::iter::repeat_n(Elem::Any, g.min));
            return Some(());
        }
        if cur.is_empty() {
            return None;
        }
        segs.push(Seg::new(std::mem::take(cur), std::mem::take(cur_alts)));
        gaps.push(g);
        Some(())
    };
    while i < s.len() {
        match s[i] {
            b'*' => {
                push_gap(
                    &mut cur,
                    &mut cur_alts,
                    &mut segs,
                    &mut gaps,
                    Gap { min: 0, max: None },
                )?;
                i += 1;
            }
            b'{' | b'[' => {
                let close = if s[i] == b'{' { b'}' } else { b']' };
                let end = i + s[i..].iter().position(|&c| c == close)?;
                let g = parse_gap(std::str::from_utf8(&s[i + 1..end]).ok()?)?;
                push_gap(&mut cur, &mut cur_alts, &mut segs, &mut gaps, g)?;
                i = end + 1;
            }
            b'!' | b'(' => {
                let neg = s[i] == b'!';
                if neg {
                    i += 1;
                    if s.get(i) != Some(&b'(') {
                        return None;
                    }
                }
                let end = i + s[i..].iter().position(|&c| c == b')')?;
                let mut alts = Vec::new();
                for alt in s[i + 1..end].split(|&c| c == b'|') {
                    if alt.is_empty() || alt.len() % 2 != 0 {
                        return None;
                    }
                    let bytes: Option<Vec<(u8, u8)>> =
                        alt.chunks(2).map(|p| hex_pair(p[0], p[1])).collect();
                    alts.push(bytes?);
                }
                if alts.is_empty() {
                    return None;
                }
                if neg && alts.iter().any(|a| a.len() != alts[0].len()) {
                    return None;
                }
                cur.push(Elem::Alt(u8::try_from(cur_alts.len()).ok()?));
                cur_alts.push(AltSet { alts, neg });
                i = end + 1;
            }
            _ => {
                let (a, b) = (s[i], *s.get(i + 1)?);
                cur.push(match hex_pair(a, b)? {
                    (_, 0) => Elem::Any,
                    (v, 0xFF) => Elem::Lit(v),
                    (val, mask) => Elem::Mask { val, mask },
                });
                i += 2;
            }
        }
    }
    if cur.is_empty() {
        return None;
    }
    segs.push(Seg::new(cur, cur_alts));
    Some((segs, gaps))
}

/// Best run of literal elements whose start offset within its segment is fixed.
/// Runs of one repeated byte (e.g. `00 00 00`) hit constantly in binary data and
/// only qualify when long.
fn choose_anchor(segs: &[Seg]) -> Option<(usize, usize, usize)> {
    let lit = |e: &Elem| match e {
        Elem::Lit(b) | Elem::NoCase(b) => Some(*b),
        _ => None,
    };
    type Scored = ((usize, usize), (usize, usize, usize));
    let mut best: Option<Scored> = None;
    let mut consider = |si: usize, run_start: usize, run: &[Elem]| {
        if run.len() < MIN_ANCHOR {
            return;
        }
        // Most distinctive window of at most MAX_ANCHOR bytes.
        let len = run.len().min(MAX_ANCHOR);
        let (off, _) = (0..=run.len() - len)
            .map(|o| {
                let mut seen = [false; 256];
                let distinct = run[o..o + len]
                    .iter()
                    .filter_map(lit)
                    .filter(|&b| !std::mem::replace(&mut seen[b as usize], true))
                    .count();
                (o, distinct)
            })
            .max_by_key(|&(o, d)| (d, std::cmp::Reverse(o)))
            .unwrap_or((0, 0));
        let start = run_start + off;
        let elems = &run[off..off + len];
        let first = lit(&elems[0]);
        let uniform = elems.iter().all(|e| lit(e) == first);
        if uniform && len < 8 {
            return;
        }
        let score = (usize::from(!uniform), len);
        if best.is_none_or(|(b, _)| score > b) {
            best = Some((score, (si, start, len)));
        }
    };
    for (si, seg) in segs.iter().enumerate() {
        let mut run_start = None;
        for (ei, e) in seg.elems.iter().enumerate() {
            if lit(e).is_some() {
                run_start.get_or_insert(ei);
                continue;
            }
            if let Some(rs) = run_start.take() {
                consider(si, rs, &seg.elems[rs..ei]);
            }
            let (lo, hi) = seg.len_range(e);
            if lo != hi {
                break;
            }
        }
        if let Some(rs) = run_start {
            consider(si, rs, &seg.elems[rs..]);
        }
    }
    best.map(|(_, a)| a)
}

fn apply_modifiers(segs: &mut [Seg], gaps: &mut [Gap], nocase: bool, wide: bool) {
    for seg in segs.iter_mut() {
        if nocase {
            for e in seg.elems.iter_mut() {
                if let Elem::Lit(b) = *e {
                    if b.is_ascii_alphabetic() {
                        *e = Elem::NoCase(b.to_ascii_lowercase());
                    }
                }
            }
        }
        if wide {
            let elems = seg
                .elems
                .iter()
                .flat_map(|&e| match e {
                    Elem::Alt(_) => vec![e],
                    _ => vec![e, Elem::Lit(0)],
                })
                .collect();
            *seg = Seg::new(elems, seg.alts.iter().map(AltSet::widen).collect());
        }
    }
    if wide {
        for g in gaps.iter_mut() {
            g.min *= 2;
            g.max = g.max.map(|m| m * 2);
        }
    }
}

/// Builds the pattern variants for one signature body (`[offset:]hex[::mods]`).
fn compile_subsig(text: &str, sig: u32, sub: u8, offset_default: Offset) -> Option<Vec<Pattern>> {
    if text.contains('/') || text.contains('$') || text.starts_with("fuzzy_img") {
        return None;
    }
    let (body, mods) = match text.split_once("::") {
        Some((b, m)) => (b, m),
        None => (text, ""),
    };
    if !mods.chars().all(|c| matches!(c, 'i' | 'w' | 'a' | 'f')) {
        return None;
    }
    let (offset, hex) = match body.split_once(':') {
        Some((o, h)) => (Offset::parse(o)?, h),
        None => (offset_default, body),
    };
    let nocase = mods.contains('i');
    let fullword = mods.contains('f');
    let wide = mods.contains('w');
    let ascii = mods.contains('a') || !wide;
    let mut out = Vec::new();
    for w in [false, true] {
        if (w && !wide) || (!w && !ascii) {
            continue;
        }
        let (mut segs, mut gaps) = parse_hex(hex)?;
        apply_modifiers(&mut segs, &mut gaps, nocase, w);
        let anchor = choose_anchor(&segs);
        if anchor.is_none() && offset == Offset::Any {
            return None;
        }
        let anchor_prefix = anchor.map_or(0, |(si, ei, _)| {
            let seg = &segs[si];
            seg.elems[..ei].iter().map(|e| seg.len_range(e).0).sum()
        });
        out.push(Pattern {
            segs,
            gaps,
            offset,
            fullword,
            sig,
            sub,
            anchor,
            anchor_prefix,
        });
    }
    Some(out)
}

#[derive(Clone, Debug)]
struct Sig {
    name: String,
    target: Target,
    file_size: Option<(u64, u64)>,
    logic: Option<Node>,
    nsubs: u8,
}

/// A parsed, compilable signature line.
struct Parsed {
    sig: Sig,
    patterns: Vec<Pattern>,
}

fn parse_ndb(line: &str, sig_id: u32) -> Option<Parsed> {
    let f: Vec<&str> = line.split(':').collect();
    if !(4..=6).contains(&f.len()) || f[0].is_empty() {
        return None;
    }
    if f.len() == 6 {
        return None; // max functionality level set: retired signature
    }
    let target = Target::from_clamav(f[1])?;
    let offset = Offset::parse(f[2])?;
    let patterns = compile_subsig(f[3], sig_id, 0, offset)?;
    Some(Parsed {
        sig: Sig {
            name: f[0].to_string(),
            target,
            file_size: None,
            logic: None,
            nsubs: 1,
        },
        patterns,
    })
}

fn parse_ldb(line: &str, sig_id: u32) -> Option<Parsed> {
    let f: Vec<&str> = line.split(';').collect();
    if f.len() < 4 || f[0].is_empty() || f.len() - 3 > MAX_SUBSIGS {
        return None;
    }
    let mut target = None;
    let mut file_size = None;
    for kv in f[1].split(',') {
        let (k, v) = kv.split_once(':')?;
        match k {
            "Target" => target = Target::from_clamav(v),
            "Engine" => {
                let (_, max) = v.split_once('-')?;
                if max.parse::<u32>().ok()? < 255 {
                    return None;
                }
            }
            "FileSize" => {
                let (a, b) = v.split_once('-').unwrap_or((v, v));
                file_size = Some((a.parse().ok()?, b.parse().ok()?));
            }
            _ => return None,
        }
    }
    let target = target?;
    let logic = parse_expr(f[2])?;
    let nsubs = (f.len() - 3) as u8;
    if logic.max_sub() >= nsubs {
        return None;
    }
    let mut patterns = Vec::new();
    for (i, sub) in f[3..].iter().enumerate() {
        patterns.extend(compile_subsig(sub, sig_id, i as u8, Offset::Any)?);
    }
    Some(Parsed {
        sig: Sig {
            name: f[0].to_string(),
            target,
            file_size,
            logic: Some(logic),
            nsubs,
        },
        patterns,
    })
}

fn parse_line(kind: &str, line: &str, sig_id: u32) -> Option<Parsed> {
    match kind {
        "ndb" => parse_ndb(line, sig_id),
        "ldb" => parse_ldb(line, sig_id),
        _ => None,
    }
}

/// True when the ClamAV signature line is supported by this engine.
pub fn is_supported(kind: &str, line: &str) -> bool {
    parse_line(kind, line, 0).is_some()
}

/// Signature name of a ClamAV `.ndb`/`.ldb` line (without parsing it).
pub fn signature_name<'a>(kind: &str, line: &'a str) -> &'a str {
    let sep = if kind == "ldb" { ';' } else { ':' };
    line.split(sep).next().unwrap_or("")
}

const GRAM_HASH: u64 = 0x9E37_79B9_7F4A_7C15;

/// Hash index from a 3-, 4- or 8-byte gram to anchor ids, fronted by a bit
/// filter small enough to stay in L2 so most scanned positions cost one probe.
struct GramIndex {
    filter: Box<[u64]>,
    filter_shift: u32,
    /// Bucket `h` covers `entries[starts[h]..starts[h + 1]]`.
    starts: Box<[u32]>,
    entries: Box<[(u64, u32)]>,
    shift: u32,
}

impl GramIndex {
    fn new(mut keys: Vec<(u64, u32)>) -> Self {
        let buckets = keys.len().next_power_of_two().clamp(1 << 8, 1 << 20);
        let shift = 64 - buckets.trailing_zeros();
        let slot = |k: u64| (k.wrapping_mul(GRAM_HASH) >> shift) as usize;
        keys.sort_unstable_by_key(|&(k, id)| (slot(k), k, id));
        let mut starts = vec![0u32; buckets + 1];
        for &(k, _) in &keys {
            starts[slot(k) + 1] += 1;
        }
        for h in 0..buckets {
            starts[h + 1] += starts[h];
        }
        let nbits = (keys.len() * 16).next_power_of_two().clamp(1 << 9, 1 << 20);
        let filter_shift = 64 - nbits.trailing_zeros();
        let mut filter = vec![0u64; nbits / 64].into_boxed_slice();
        for &(k, _) in &keys {
            let h = (k.wrapping_mul(GRAM_HASH).rotate_left(32) >> filter_shift) as usize;
            filter[h / 64] |= 1 << (h % 64);
        }
        GramIndex {
            filter,
            filter_shift,
            starts: starts.into_boxed_slice(),
            entries: keys.into_boxed_slice(),
            shift,
        }
    }

    /// Anchor ids whose gram equals `k`.
    #[inline(always)]
    fn get(&self, k: u64) -> impl Iterator<Item = u32> + '_ {
        let m = k.wrapping_mul(GRAM_HASH);
        let f = (m.rotate_left(32) >> self.filter_shift) as usize;
        let entries: &[(u64, u32)] = if self.filter[f / 64] & (1 << (f % 64)) == 0 {
            &[]
        } else {
            let h = (m >> self.shift) as usize;
            &self.entries[self.starts[h] as usize..self.starts[h + 1] as usize]
        };
        entries.iter().filter(move |e| e.0 == k).map(|e| e.1)
    }
}

/// Rough rarity of a byte in text and binary content; picks which 4-gram of an
/// anchor keys the index so that e.g. `    eval` is found via `eval`.
fn byte_rarity(b: u8) -> u32 {
    match b {
        b' ' | b'\t' | b'\n' | b'\r' | 0 | 0xFF => 0,
        b'e' | b't' | b'a' | b'o' | b'i' | b'n' | b's' | b'r' | b'h' | b'l' | b'c' | b'u' => 2,
        b'a'..=b'z' => 3,
        b'0'..=b'9' | b'A'..=b'Z' => 4,
        b'.' | b',' | b'(' | b')' | b';' | b'=' | b'"' | b'\'' | b'/' | b'<' | b'>' | b'-'
        | b'_' => 3,
        0x20..=0x7E => 5,
        _ => 4,
    }
}

/// Anchor literals of one target, matched with a rolling gram scan: every
/// anchor is 3..=MAX_ANCHOR bytes; its rarest 4-gram (or the whole 3-byte
/// anchor) keys an index and only index hits compare the full anchor.
struct AnchorSet {
    /// Anchor bytes; case-insensitive anchors are stored lowercase.
    anchors: Vec<Box<[u8]>>,
    nocase: Vec<bool>,
    /// Offset of the indexed gram within each anchor.
    gram_off: Vec<u8>,
    /// Anchor id -> pattern indices.
    owners: Vec<Vec<u32>>,
    grams3: GramIndex,
    grams4: GramIndex,
    /// Full 8-byte anchors: only genuine anchor occurrences reach this index.
    grams8: GramIndex,
    /// Bit filter over the leading 3 bytes of every indexed gram; the scan loop
    /// probes only this and leaves the gram indexes to the rare hits.
    prefix: Box<[u64]>,
    prefix_shift: u32,
}

impl AnchorSet {
    /// Grams are keyed case-folded, so exact and case-insensitive anchors share
    /// one pass; candidates are then compared with the anchor's own case rule.
    fn new(anchors: Vec<(Vec<u8>, bool)>, owners: Vec<Vec<u32>>) -> Self {
        let (anchors, nocase): (Vec<Vec<u8>>, Vec<bool>) = anchors.into_iter().unzip();
        let gram = |a: &[u8]| {
            a.iter()
                .rev()
                .fold(0u64, |k, &b| k << 8 | u64::from(b.to_ascii_lowercase()))
        };
        let mut keys3 = Vec::new();
        let mut keys4 = Vec::new();
        let mut keys8 = Vec::new();
        let mut gram_off = Vec::with_capacity(anchors.len());
        for (id, a) in anchors.iter().enumerate() {
            if a.len() == 3 || a.len() >= 8 {
                let len = a.len().min(8);
                let keys = if len == 3 { &mut keys3 } else { &mut keys8 };
                keys.push((gram(&a[..len]), id as u32));
                gram_off.push(0);
                continue;
            }
            let score = |o: usize| {
                let w = &a[o..o + 4];
                let distinct = (0..4).filter(|&i| !w[..i].contains(&w[i])).count() as u32;
                w.iter().map(|&b| byte_rarity(b)).sum::<u32>() + 2 * distinct
            };
            let off = (0..=a.len() - 4)
                .max_by_key(|&o| (score(o), std::cmp::Reverse(o)))
                .unwrap_or(0);
            keys4.push((gram(&a[off..off + 4]), id as u32));
            gram_off.push(off as u8);
        }
        let total = keys3.len() + keys4.len() + keys8.len();
        let nbits = (total * 8).next_power_of_two().clamp(1 << 9, 1 << 19);
        let prefix_shift = 32 - nbits.trailing_zeros();
        let mut prefix = vec![0u64; nbits / 64].into_boxed_slice();
        for &(k, _) in keys3.iter().chain(&keys4).chain(&keys8) {
            let h = prefix_slot(k, prefix_shift);
            prefix[h / 64] |= 1 << (h % 64);
        }
        AnchorSet {
            prefix,
            prefix_shift,
            grams3: GramIndex::new(keys3),
            grams4: GramIndex::new(keys4),
            grams8: GramIndex::new(keys8),
            anchors: anchors.into_iter().map(Vec::into_boxed_slice).collect(),
            nocase,
            gram_off,
            owners,
        }
    }

    /// Calls `f(anchor_id, start)` for every anchor occurrence, in roughly
    /// ascending order of start. Stops early when `f` returns false.
    fn for_each_match(&self, data: &[u8], mut f: impl FnMut(u32, usize) -> bool) {
        let n = data.len();
        if n < MIN_ANCHOR {
            return;
        }
        let fold = |b: u8| u64::from(b.to_ascii_lowercase());
        // Folded bytes data[pos..pos + 8], little-endian (zero past the end).
        let mut w = data[..n.min(7)]
            .iter()
            .rev()
            .fold(0u64, |k, &b| k << 8 | fold(b));
        for pos in 0..=n - 3 {
            if pos + 7 < n {
                w |= fold(data[pos + 7]) << 56;
            }
            let h = prefix_slot(w, self.prefix_shift);
            if self.prefix[h / 64] & (1 << (h % 64)) != 0 && !self.probe(data, pos, w, &mut f) {
                return;
            }
            w >>= 8;
        }
    }

    /// Looks up the grams starting at `pos` (window `w`); false stops the scan.
    #[inline(never)]
    fn probe(
        &self,
        data: &[u8],
        pos: usize,
        w: u64,
        f: &mut impl FnMut(u32, usize) -> bool,
    ) -> bool {
        let n = data.len();
        let found = |id: u32, start: usize| {
            let a = &self.anchors[id as usize];
            data.get(start..start + a.len()).is_some_and(|d| {
                if self.nocase[id as usize] {
                    d.iter()
                        .zip(a.iter())
                        .all(|(&x, &y)| x.to_ascii_lowercase() == y)
                } else {
                    d == &a[..]
                }
            })
        };
        for id in self.grams3.get(w & 0x00FF_FFFF) {
            if found(id, pos) && !f(id, pos) {
                return false;
            }
        }
        if pos + 4 <= n {
            for id in self.grams4.get(w & 0xFFFF_FFFF) {
                let Some(start) = pos.checked_sub(usize::from(self.gram_off[id as usize])) else {
                    continue;
                };
                if found(id, start) && !f(id, start) {
                    return false;
                }
            }
        }
        if pos + 8 <= n {
            for id in self.grams8.get(w) {
                if found(id, pos) && !f(id, pos) {
                    return false;
                }
            }
        }
        true
    }
}

#[inline(always)]
fn prefix_slot(w: u64, shift: u32) -> usize {
    ((w as u32 & 0x00FF_FFFF).wrapping_mul(0x9E37_79B1) >> shift) as usize
}

struct TargetIndex {
    anchors: Option<AnchorSet>,
    positional: Vec<u32>,
}

/// Outcome of matching one buffer.
#[derive(Debug, Default, PartialEq)]
pub struct ContentMatches {
    pub names: Vec<String>,
    /// Verification stopped early because the step budget ran out.
    pub budget_exhausted: bool,
}

/// Compiled content signature engine.
pub struct ContentEngine {
    sigs: Vec<Sig>,
    patterns: Vec<Pattern>,
    targets: Vec<TargetIndex>,
    step_budget: u64,
}

impl std::fmt::Debug for ContentEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentEngine")
            .field("signatures", &self.sigs.len())
            .field("patterns", &self.patterns.len())
            .finish()
    }
}

impl ContentEngine {
    /// Compiles a signature file of `ndb\t<line>` / `ldb\t<line>` records.
    /// Unsupported or malformed lines are skipped.
    pub fn from_text(text: &str) -> Result<Self, String> {
        let mut sigs = Vec::new();
        let mut patterns = Vec::new();
        for line in text.lines() {
            let Some((kind, body)) = line.split_once('\t') else {
                continue;
            };
            if let Some(p) = parse_line(kind, body, sigs.len() as u32) {
                sigs.push(p.sig);
                patterns.extend(p.patterns);
            }
        }
        let mut targets = Vec::new();
        for t in Target::ALL {
            let mut anchors: Vec<(Vec<u8>, bool)> = Vec::new();
            let mut owners: Vec<Vec<u32>> = Vec::new();
            let mut ids: HashMap<(Vec<u8>, bool), usize> = HashMap::new();
            let mut positional = Vec::new();
            for (pi, p) in patterns.iter().enumerate() {
                if sigs[p.sig as usize].target != t {
                    continue;
                }
                let Some((si, ei, len)) = p.anchor else {
                    positional.push(pi as u32);
                    continue;
                };
                let run = &p.segs[si].elems[ei..ei + len];
                let is_nocase = run.iter().any(|e| matches!(e, Elem::NoCase(_)));
                let bytes: Vec<u8> = run
                    .iter()
                    .map(|e| match e {
                        Elem::Lit(b) | Elem::NoCase(b) => *b,
                        _ => 0,
                    })
                    .collect();
                let key = (bytes, is_nocase);
                let id = *ids.entry(key.clone()).or_insert_with(|| {
                    anchors.push(key);
                    owners.push(Vec::new());
                    anchors.len() - 1
                });
                owners[id].push(pi as u32);
            }
            targets.push(TargetIndex {
                anchors: (!anchors.is_empty()).then(|| AnchorSet::new(anchors, owners)),
                positional,
            });
        }
        #[cfg(target_os = "linux")]
        unsafe {
            libc::malloc_trim(0);
        }
        Ok(ContentEngine {
            sigs,
            patterns,
            targets,
            step_budget: DEFAULT_STEP_BUDGET,
        })
    }

    pub fn with_step_budget(mut self, steps: u64) -> Self {
        self.step_budget = steps;
        self
    }

    pub fn signature_count(&self) -> usize {
        self.sigs.len()
    }

    /// Matches a buffer: `Any` signatures on the raw bytes plus the signatures of the
    /// buffer's own type (on the normalized view for HTML/text).
    pub fn scan(&self, data: &[u8]) -> ContentMatches {
        self.scan_inner(data, true, Target::classify(data))
    }

    /// Matches only the signatures of `target`, for buffers whose type the caller
    /// already knows (e.g. a raw mail message).
    pub fn scan_as(&self, data: &[u8], target: Target) -> ContentMatches {
        self.scan_inner(data, false, target)
    }

    fn scan_inner(&self, data: &[u8], any: bool, kind: Target) -> ContentMatches {
        // Large buffers get proportionally more work before reporting a partial scan.
        let budget = self
            .step_budget
            .max(self.step_budget.saturating_mul(data.len() as u64) / (4 << 20));
        let mut state = ScanState::new(budget);
        if any {
            self.run_target(Target::Any, data, &mut state);
        }
        if kind != Target::Any {
            if kind.normalized() {
                let view = if kind == Target::Html {
                    normalize_html(data)
                } else {
                    normalize_text(data)
                };
                self.run_target(kind, &view, &mut state);
            } else {
                self.run_target(kind, data, &mut state);
            }
        }
        let mut names: Vec<String> = state
            .hit_sigs
            .iter()
            .filter(|&&s| self.sig_matches(s as usize, &state, data.len()))
            .map(|&s| self.sigs[s as usize].name.clone())
            .collect();
        names.sort();
        names.dedup();
        ContentMatches {
            names,
            budget_exhausted: state.exhausted,
        }
    }

    fn sig_matches(&self, s: usize, state: &ScanState, file_len: usize) -> bool {
        let sig = &self.sigs[s];
        if let Some((lo, hi)) = sig.file_size {
            if (file_len as u64) < lo || (file_len as u64) > hi {
                return false;
            }
        }
        let counts: Vec<u32> = (0..sig.nsubs)
            .map(|i| state.counts.get(&(s as u32, i)).copied().unwrap_or(0))
            .collect();
        match &sig.logic {
            None => counts[0] > 0,
            Some(node) => node.eval(&counts).0,
        }
    }

    fn run_target(&self, t: Target, data: &[u8], state: &mut ScanState) {
        let index = &self.targets[t.index()];
        if let Some(set) = &index.anchors {
            set.for_each_match(data, |aid, at| {
                for &pi in &set.owners[aid as usize] {
                    let p = &self.patterns[pi as usize];
                    let (si, _, _) = p.anchor.expect("anchored pattern");
                    let Some(seg_start) = at.checked_sub(p.anchor_prefix) else {
                        continue;
                    };
                    if let Some(start) = verify_anchored(pi, p, si, seg_start, data, state) {
                        state.record(p, start);
                    }
                }
                !state.exhausted
            });
            if state.exhausted {
                return;
            }
        }
        for &pi in &index.positional {
            let p = &self.patterns[pi as usize];
            if let Some(range) = p.offset.candidates(data.len()) {
                for start in range {
                    if start > data.len() || state.exhausted {
                        break;
                    }
                    if let Some(s) = verify_anchored(pi, p, 0, start, data, state) {
                        state.record(p, s);
                        break;
                    }
                }
            }
        }
    }
}

/// Cached gap searches keyed by (pattern, segment). Anchor hits arrive in
/// ascending order, so unbounded `*` gaps reuse earlier results instead of
/// rescanning the buffer for every hit.
type GapMemo = HashMap<(u32, u16), (usize, Option<(usize, usize)>)>;

struct ScanState {
    fwd: GapMemo,
    bwd: GapMemo,
    counts: HashMap<(u32, u8), u32>,
    last_start: HashMap<(u32, u8), usize>,
    hit_sigs: Vec<u32>,
    steps_left: u64,
    exhausted: bool,
}

impl ScanState {
    fn new(budget: u64) -> Self {
        ScanState {
            fwd: HashMap::new(),
            bwd: HashMap::new(),
            counts: HashMap::new(),
            last_start: HashMap::new(),
            hit_sigs: Vec::new(),
            steps_left: budget,
            exhausted: false,
        }
    }

    fn step(&mut self, n: u64) -> bool {
        if self.steps_left < n {
            self.exhausted = true;
            self.steps_left = 0;
            return false;
        }
        self.steps_left -= n;
        true
    }

    fn record(&mut self, p: &Pattern, start: usize) {
        if self.last_start.insert((p.sig, p.sub), start) == Some(start) {
            return;
        }
        let c = self.counts.entry((p.sig, p.sub)).or_insert(0);
        if *c == 0 && !self.hit_sigs.contains(&p.sig) {
            self.hit_sigs.push(p.sig);
        }
        *c = (*c + 1).min(MAX_COUNT);
    }
}

fn byte_ok(b: u8, (val, mask): (u8, u8)) -> bool {
    b & mask == val & mask
}

/// Matches `elems` at `pos`. Iterates over fixed-width elements and only
/// recurses at alternations, so long segments do not grow the stack.
fn match_elems(elems: &[Elem], alts: &[AltSet], data: &[u8], mut pos: usize) -> Option<usize> {
    for (i, e) in elems.iter().enumerate() {
        let ok = match *e {
            Elem::Lit(b) => data.get(pos) == Some(&b),
            Elem::NoCase(b) => data.get(pos).map(u8::to_ascii_lowercase) == Some(b),
            Elem::Mask { val, mask } => data.get(pos).is_some_and(|&x| byte_ok(x, (val, mask))),
            Elem::Any => pos < data.len(),
            Elem::Alt(ai) => {
                let set = &alts[ai as usize];
                let rest = &elems[i + 1..];
                let fits = |alt: &[(u8, u8)]| {
                    data.get(pos..pos + alt.len())
                        .is_some_and(|w| w.iter().zip(alt).all(|(&b, &p)| byte_ok(b, p)))
                };
                if set.neg {
                    let len = set.alts[0].len();
                    if pos + len > data.len() || set.alts.iter().any(|a| fits(a)) {
                        return None;
                    }
                    return match_elems(rest, alts, data, pos + len);
                }
                return set
                    .alts
                    .iter()
                    .filter(|a| fits(a))
                    .find_map(|a| match_elems(rest, alts, data, pos + a.len()));
            }
        };
        if !ok {
            return None;
        }
        pos += 1;
    }
    Some(pos)
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Verifies `p` given that segment `si` starts at `seg_start`; returns the match start.
fn verify_anchored(
    pi: u32,
    p: &Pattern,
    si: usize,
    seg_start: usize,
    data: &[u8],
    state: &mut ScanState,
) -> Option<usize> {
    if !state.step(p.segs[si].elems.len() as u64) {
        return None;
    }
    let mut end = p.segs[si].match_at(data, seg_start)?;
    for j in si + 1..p.segs.len() {
        let g = p.gaps[j - 1];
        let lo = end + g.min;
        let hi = g.max.map_or(data.len(), |m| (end + m).min(data.len()));
        let seg = &p.segs[j];
        let key = (pi, j as u16);
        if g.max.is_none() {
            if let Some(&(from, res)) = state.fwd.get(&key) {
                if lo >= from {
                    match res {
                        None => return None,
                        Some((c, e)) if c >= lo => {
                            end = e;
                            continue;
                        }
                        Some(_) => {}
                    }
                }
            }
        }
        let found = search_forward(seg, data, lo, hi, state);
        if state.exhausted {
            return None;
        }
        if g.max.is_none() {
            state.fwd.insert(key, (lo, found));
        }
        end = found?.1;
    }
    let mut start = seg_start;
    for j in (0..si).rev() {
        let g = p.gaps[j];
        let seg = &p.segs[j];
        let hi = start.checked_sub(g.min + seg.min_len)?;
        let lo = g.max.map_or(0, |m| start.saturating_sub(m + seg.max_len));
        let accept =
            |e: usize| e <= start && g.max.is_none_or(|m| start - e <= m) && start - e >= g.min;
        // With a fixed-length segment and no upper bound, `accept` reduces to `s <= hi`,
        // so the nearest match below a larger `hi` can be found incrementally.
        let memo = g.max.is_none() && seg.min_len == seg.max_len;
        let key = (pi, j as u16);
        let mut search_lo = lo;
        let mut fallback = None;
        if memo {
            if let Some(&(searched_hi, best)) = state.bwd.get(&key) {
                if hi >= searched_hi {
                    search_lo = searched_hi + 1;
                    fallback = Some(best);
                } else if let Some((b, _)) = best.filter(|&(b, _)| b <= hi) {
                    start = b;
                    continue;
                }
            }
        }
        let found = match search_backward(seg, data, search_lo, hi, &accept, state) {
            Some(f) => Some(f),
            None if state.exhausted => return None,
            None => fallback.flatten(),
        };
        if memo {
            state.bwd.insert(key, (hi, found));
        }
        start = found?.0;
    }
    if !p.offset.allows(start, data.len()) {
        return None;
    }
    if p.fullword
        && (start > 0 && is_word(data[start - 1]) || data.get(end).is_some_and(|&b| is_word(b)))
    {
        return None;
    }
    Some(start)
}

/// Earliest match of `seg` starting in `[lo, hi]`, as (start, end).
fn search_forward(
    seg: &Seg,
    data: &[u8],
    lo: usize,
    hi: usize,
    state: &mut ScanState,
) -> Option<(usize, usize)> {
    let mut s = lo;
    while let Some(c) = seg.next_candidate(data, s, hi) {
        if !state.step(1 + (c - s) as u64 / 64) {
            return None;
        }
        if let Some(e) = seg.match_at(data, c) {
            return Some((c, e));
        }
        s = c + 1;
    }
    None
}

/// Nearest match of `seg` starting in `[lo, hi]` (searching downward) that `accept`s.
fn search_backward(
    seg: &Seg,
    data: &[u8],
    lo: usize,
    hi: usize,
    accept: &dyn Fn(usize) -> bool,
    state: &mut ScanState,
) -> Option<(usize, usize)> {
    let mut s = hi;
    while let Some(c) = seg.prev_candidate(data, lo, s) {
        if !state.step(1 + (s - c) as u64 / 64) {
            return None;
        }
        if let Some(e) = seg.match_at(data, c) {
            if accept(e) {
                return Some((c, e));
            }
        }
        if c == 0 {
            return None;
        }
        s = c - 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(lines: &[&str]) -> ContentEngine {
        ContentEngine::from_text(&lines.join("\n")).unwrap()
    }

    fn hex(s: &str) -> String {
        s.bytes().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn ndb_wildcards_gaps_and_alternatives() {
        let sig = format!(
            "ndb\tTest.Body:0:*:{}??{}{{2-6}}(41|42)6?{}*{}",
            hex("evil"),
            hex("cmd"),
            hex("tail"),
            hex("end")
        );
        let e = engine(&[&sig]);
        let hit = b"xx evil!cmd...Bctail-----end";
        assert_eq!(e.scan(hit).names, vec!["Test.Body"]);
        // gap too large and wrong alternative
        assert!(e.scan(b"evil!cmd........Bctail end").names.is_empty());
        assert!(e.scan(b"evil!cmd..Cctail end").names.is_empty());
    }

    #[test]
    fn offsets_and_negated_alternatives() {
        let e = engine(&[
            &format!("ndb\tTest.Abs:0:4:{}", hex("MAGIC")),
            &format!("ndb\tTest.Eof:0:EOF-3:{}", hex("END")),
            &format!("ndb\tTest.Neg:0:*:{}!(41|42){}", hex("pre"), hex("post")),
        ]);
        assert_eq!(
            e.scan(b"1234MAGIC....END").names,
            vec!["Test.Abs", "Test.Eof"]
        );
        assert!(e.scan(b"123MAGIC.END..").names.is_empty());
        assert_eq!(e.scan(b"preCpost").names, vec!["Test.Neg"]);
        assert!(e.scan(b"preApost").names.is_empty());
    }

    #[test]
    fn ldb_logic_counts_and_modifiers() {
        let e = engine(&[&format!(
            "ldb\tTest.Logic;Engine:51-255,Target:0;(0&1)|2>1;{};{}::i;{}::w",
            hex("alpha"),
            hex("BeTa"),
            hex("wd")
        )]);
        assert_eq!(e.scan(b"alpha ... BETA").names, vec!["Test.Logic"]);
        assert!(e.scan(b"alpha only").names.is_empty());
        assert!(e.scan(b"w\0d\0 once").names.is_empty());
        assert_eq!(e.scan(b"w\0d\0 and w\0d\0").names, vec!["Test.Logic"]);
        let none = engine(&[&format!(
            "ldb\tTest.Not;Target:0;0&1=0;{};{}",
            hex("abc"),
            hex("xyz")
        )]);
        assert_eq!(none.scan(b"abc").names, vec!["Test.Not"]);
        assert!(none.scan(b"abc xyz").names.is_empty());
    }

    #[test]
    fn targets_and_normalization() {
        let e = engine(&[
            &format!("ndb\tHtml.Test:3:*:{}", hex("<script> eval(")),
            &format!("ndb\tPdf.Test:10:*:{}", hex("/JavaScript")),
        ]);
        let html = b"<html><!-- x --><SCRIPT>\n\n  EVAL(1)</script></html>";
        assert_eq!(e.scan(html).names, vec!["Html.Test"]);
        assert!(e.scan(b"\0binary <script> eval(").names.is_empty());
        assert_eq!(e.scan(b"%PDF-1.7 /JavaScript").names, vec!["Pdf.Test"]);
        assert!(e.scan(b"text /JavaScript").names.is_empty());
    }

    #[test]
    fn unsupported_features_are_skipped() {
        for (kind, line) in [
            ("ndb", "Win.X:1:*:41424344"),
            ("ndb", "X:0:EP+0:41424344"),
            ("ndb", "X:0:*:41??42"),
            ("ldb", "X;Target:0;0;0/abc/"),
            ("ldb", "X;Target:2,Container:CL_TYPE_ZIP;0;41424344"),
            ("ldb", "X;Target:0;0&1;41424344"),
        ] {
            assert!(!is_supported(kind, line), "{line}");
        }
        assert!(is_supported("ndb", "X:0:EOF-4:41??42"));
    }

    #[test]
    fn anchor_lengths_case_folding_and_repeated_gaps() {
        let e = engine(&[
            &format!("ndb\tT.Three:0:*:{}", hex("q%z")),
            &format!("ndb\tT.Five:0:*:{}", hex("vwxyz")),
            &format!("ndb\tT.Long:0:*:{}", hex("longanchor-123")),
            &format!(
                "ldb\tT.Case;Target:0;0&1;{}::i;{}",
                hex("MiXeD"),
                hex("mixed!")
            ),
            &format!(
                "ldb\tT.Gaps;Target:0;0>2;{}*{}*{}",
                hex("ab1"),
                hex("cd2"),
                hex("ef3")
            ),
        ]);
        let pad = |s: &[u8]| {
            [
                b"0123456789".repeat(50).as_slice(),
                s,
                b"9876543210".repeat(50).as_slice(),
            ]
            .concat()
        };
        assert_eq!(e.scan(&pad(b"q%z")).names, vec!["T.Three"]);
        assert_eq!(e.scan(&pad(b"..vwxyz..")).names, vec!["T.Five"]);
        assert!(e.scan(&pad(b"vwxy")).names.is_empty());
        assert_eq!(e.scan(&pad(b"longanchor-123")).names, vec!["T.Long"]);
        assert!(e.scan(&pad(b"longanchor-124")).names.is_empty());
        assert_eq!(e.scan(&pad(b"mIxEd and mixed!")).names, vec!["T.Case"]);
        assert!(e.scan(&pad(b"mIxEd and MIXED!")).names.is_empty());
        // Each ab1/cd2 start must be counted independently despite gap memoization.
        let many = pad(b"ab1 ab1 ab1 cd2 cd2 ef3");
        assert_eq!(e.scan(&many).names, vec!["T.Gaps"]);
        assert!(e.scan(&pad(b"ab1 ab1 cd2 ef3")).names.is_empty());
        assert!(e.scan(&pad(b"ef3 ab1 ab1 ab1 cd2")).names.is_empty());
    }

    #[test]
    fn budget_exhaustion_is_reported() {
        let e = engine(&[&format!("ndb\tTest.Slow:0:*:{}*{}", hex("abc"), hex("xyz"))])
            .with_step_budget(1000);
        let data = b"abc".repeat(30_000);
        let r = e.scan(&data);
        assert!(r.names.is_empty());
        assert!(r.budget_exhausted);
    }
}
