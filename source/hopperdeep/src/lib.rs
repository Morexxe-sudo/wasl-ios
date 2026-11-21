//! # hopperdeep — the `deep1` lossless container
//!
//! `deep1` splits an already-compressed file into its structural pieces (PDF streams, ZIP entry
//! payloads, PNG IDAT runs, gzip members, bare JPEGs), replaces each DEFLATE stream by
//! `preflate` plaintext + corrections and each JPEG by Lepton bytes, wraps the result in a
//! self-describing container, and zstd-compresses the whole thing with all cores.
//!
//! Decoding reverses the process **streaming**, against the *expected* original size and SHA-256
//! taken from the sealed manifest (both mandatory): the container header must agree with them, the
//! total output is capped at that size, and every segment's declared length is checked against the
//! remaining budget *before* anything is allocated. A peer's container is untrusted: nothing sized
//! by the container is ever pre-allocated. Every public entry point catches panics, so a malformed
//! input becomes a [`DeepError`] rather than a process abort.

#![deny(missing_docs)]

mod jni_bridge;
mod scan;
mod transform;

use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io::{self, BufWriter, Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub use transform::{adler32, crc32};

/// Container magic (`HDP1`).
pub const MAGIC: &[u8; 4] = b"HDP1";
/// Container format version. Bump to `deep2` if the layout ever changes.
pub const VERSION: u8 = 1;
/// Hard cap on the original (reconstructed) size of a `deep1` payload: 1 GiB. The decoder takes
/// the expected size from the sealed manifest, so a peer cannot ask for more than this.
pub const MAX_OSIZE: u64 = 1024 * 1024 * 1024;
/// Hard cap on the *streamed* (zstd-decompressed) container: it is never held in memory, but a
/// zstd bomb must still stop burning CPU. Each segment is additionally bounded by the remaining
/// output budget (see `decode_stream`).
pub const MAX_CONTAINER: u64 = 2 * 1024 * 1024 * 1024;
/// Inputs above this size should use the path-based API (callers enforce this elsewhere).
pub const IN_MEMORY_LIMIT: usize = 64 * 1024 * 1024;

const TAG_RAW: u8 = 0;
const TAG_DEFLATE: u8 = 1;
const TAG_JPEG: u8 = 2;
const TAG_PNG_IDAT: u8 = 3;

/// Every failure mode of the library. Carries a human-readable reason for the JNI bridge to turn
/// into a Java `IOException`; nothing is ever swallowed into a partial result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeepError(pub String);

impl fmt::Display for DeepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for DeepError {}
impl From<String> for DeepError {
    fn from(s: String) -> Self {
        DeepError(s)
    }
}

fn err<S: Into<String>>(s: S) -> DeepError {
    DeepError(s.into())
}

fn cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
}

/// Build the rayon pool once, sized to all logical cores (owner's "use more CPU" request).
fn ensure_rayon() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let n = cores();
        let _ = rayon::ThreadPoolBuilder::new().num_threads(n).build_global();
    });
}

// ------------------------------------------------------------------ segments

enum Segment {
    Raw(Vec<u8>),
    Deflate {
        orig_len: usize,
        corrections: Vec<u8>,
        plain: Vec<u8>,
    },
    Jpeg {
        orig_len: usize,
        lep: Vec<u8>,
    },
    PngIdat {
        orig_len: usize,
        chunk_lens: Vec<u32>,
        header: [u8; 2],
        adler: [u8; 4],
        corrections: Vec<u8>,
        plain: Vec<u8>,
    },
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

impl Segment {
    fn write_to(&self, out: &mut Vec<u8>) {
        match self {
            Segment::Raw(data) => {
                out.push(TAG_RAW);
                put_u64(out, data.len() as u64);
                out.extend_from_slice(data);
            }
            Segment::Deflate { orig_len, corrections, plain } => {
                out.push(TAG_DEFLATE);
                put_u64(out, *orig_len as u64);
                put_u64(out, corrections.len() as u64);
                out.extend_from_slice(corrections);
                put_u64(out, plain.len() as u64);
                out.extend_from_slice(plain);
            }
            Segment::Jpeg { orig_len, lep } => {
                out.push(TAG_JPEG);
                put_u64(out, *orig_len as u64);
                put_u64(out, lep.len() as u64);
                out.extend_from_slice(lep);
            }
            Segment::PngIdat { orig_len, chunk_lens, header, adler, corrections, plain } => {
                out.push(TAG_PNG_IDAT);
                put_u64(out, *orig_len as u64);
                put_u32(out, chunk_lens.len() as u32);
                for &n in chunk_lens {
                    put_u32(out, n);
                }
                out.extend_from_slice(header);
                out.extend_from_slice(adler);
                put_u64(out, corrections.len() as u64);
                out.extend_from_slice(corrections);
                put_u64(out, plain.len() as u64);
                out.extend_from_slice(plain);
            }
        }
    }
}

/// Rebuild the exact PNG IDAT chunk run. Every length has been bounded by the caller (the sum of the
/// chunk lengths plus 12 bytes of framing per chunk equals `orig_len`, which is within the output
/// budget), so the allocations below are budget-sized, never attacker-sized.
fn rebuild_png_idat(
    chunk_lens: &[u32],
    header: [u8; 2],
    adler: [u8; 4],
    corrections: &[u8],
    plain: &[u8],
    orig_len: usize,
) -> Result<Vec<u8>, DeepError> {
    if chunk_lens.is_empty() || chunk_lens.len() > 1_000_000 {
        return Err(err("invalid PNG IDAT chunk count"));
    }
    let zlib_len: usize = chunk_lens.iter().try_fold(0usize, |acc, &n| acc.checked_add(n as usize))
        .ok_or_else(|| err("PNG IDAT length overflow"))?;
    if zlib_len < 6 {
        return Err(err("truncated PNG IDAT stream"));
    }
    let framed = zlib_len
        .checked_add(chunk_lens.len().checked_mul(12).ok_or_else(|| err("PNG IDAT length overflow"))?)
        .ok_or_else(|| err("PNG IDAT length overflow"))?;
    if framed != orig_len {
        return Err(err("PNG IDAT chunk lengths do not match region length"));
    }
    let deflate = transform::deflate_decode(plain, corrections, zlib_len - 6)?;
    let mut z = Vec::with_capacity(zlib_len);
    z.extend_from_slice(&header);
    z.extend_from_slice(&deflate);
    z.extend_from_slice(&adler);
    if z.len() != zlib_len {
        return Err(err("PNG zlib stream length mismatch"));
    }
    if !transform::valid_zlib_header(&z[..2]) {
        return Err(err("PNG zlib header mismatch"));
    }
    if transform::adler32(plain) != u32::from_be_bytes(adler) {
        return Err(err("PNG Adler-32 mismatch"));
    }

    let mut region = Vec::with_capacity(orig_len);
    let mut pos = 0usize;
    for &clen in chunk_lens {
        let clen = clen as usize;
        let data = z.get(pos..pos + clen).ok_or_else(|| err("PNG IDAT split out of bounds"))?;
        pos += clen;
        let mut tmp = Vec::with_capacity(4 + clen);
        tmp.extend_from_slice(b"IDAT");
        tmp.extend_from_slice(data);
        let crc = transform::crc32(&tmp);
        // PNG chunk length and CRC are big-endian (the container itself is little-endian).
        region.extend_from_slice(&(clen as u32).to_be_bytes());
        region.extend_from_slice(b"IDAT");
        region.extend_from_slice(data);
        region.extend_from_slice(&crc.to_be_bytes());
    }
    if pos != zlib_len {
        return Err(err("PNG IDAT lengths do not cover zlib stream"));
    }
    if region.len() != orig_len {
        return Err(err("reconstructed PNG IDAT region length mismatch"));
    }
    Ok(region)
}

// ------------------------------------------------------------------ scanning → segments

/// preflate rejected a valid stream: keep it verbatim, unless an independent bounded inflate
/// proves it is a zip bomb (in which case the whole encode must fail).
fn deflate_fallback(raw: &[u8]) -> Result<Segment, DeepError> {
    if transform::expansion_exceeds(raw, transform::ZIP_BOMB_CAP) {
        Err(err("DEFLATE stream expands past the 1 GiB cap (zip bomb)"))
    } else {
        Ok(Segment::Raw(raw.to_vec()))
    }
}

/// The verbatim bytes of a span (used when a span is not transformed: failure, deadline).
fn raw_segment(data: &[u8], span: &scan::Span) -> Segment {
    let (s, e) = match span {
        scan::Span::Raw { start, end }
        | scan::Span::Deflate { start, end, .. }
        | scan::Span::Jpeg { start, end } => (*start, *end),
        scan::Span::PngIdat { region_start, region_end, .. } => (*region_start, *region_end),
    };
    Segment::Raw(data[s..e].to_vec())
}

fn build_segment(data: &[u8], span: &scan::Span) -> Result<Segment, DeepError> {
    match span {
        scan::Span::Raw { start, end } => Ok(Segment::Raw(data[*start..*end].to_vec())),
        scan::Span::Deflate { start, end, adler } => {
            let raw = &data[*start..*end];
            // preflate 0.7.6 rejects some *valid* DEFLATE streams (e.g. miniz_oxide's incomplete
            // Huffman trees). That must never abort the whole file: keep the bytes verbatim so the
            // reconstruction stays bit-exact and let the outer zstd try on the original stream.
            // A stream past the per-segment plaintext cap is kept verbatim too (the decoder bounds
            // its memory by that cap); only a real >1 GiB expansion is a zip bomb that aborts.
            let parts = match transform::deflate_encode(raw) {
                Ok(p) => p,
                Err(_) => return deflate_fallback(raw),
            };
            if let Some(a) = adler {
                if transform::adler32(&parts.plaintext) != u32::from_be_bytes(*a) {
                    return Ok(Segment::Raw(raw.to_vec()));
                }
            }
            Ok(Segment::Deflate {
                orig_len: raw.len(),
                corrections: parts.corrections,
                plain: parts.plaintext,
            })
        }
        scan::Span::Jpeg { start, end } => {
            let jpeg = &data[*start..*end];
            // A JPEG Lepton cannot (or must not) handle never aborts the file: keep it RAW and
            // carry on with the remaining segments.
            match catch_unwind(AssertUnwindSafe(|| transform::jpeg_encode(jpeg))) {
                Ok(Ok(lep)) => Ok(Segment::Jpeg { orig_len: jpeg.len(), lep }),
                Ok(Err(_)) | Err(_) => Ok(Segment::Raw(jpeg.to_vec())),
            }
        }
        scan::Span::PngIdat { region_start, region_end, data_spans } => {
            let mut z = Vec::new();
            for &(s, e) in data_spans {
                z.extend_from_slice(&data[s..e]);
            }
            if z.len() < 6 || !transform::valid_zlib_header(&z[..2]) {
                return Ok(Segment::Raw(data[*region_start..*region_end].to_vec()));
            }
            let mut header = [0u8; 2];
            header.copy_from_slice(&z[..2]);
            let mut adler = [0u8; 4];
            adler.copy_from_slice(&z[z.len() - 4..]);
            let body = &z[2..z.len() - 4];
            let parts = match transform::deflate_encode(body) {
                Ok(p) => p,
                Err(_) => {
                    if transform::expansion_exceeds(body, transform::ZIP_BOMB_CAP) {
                        return Err(err("PNG IDAT expands past the 1 GiB cap (zip bomb)"));
                    }
                    return Ok(Segment::Raw(data[*region_start..*region_end].to_vec()));
                }
            };
            if transform::adler32(&parts.plaintext) != u32::from_be_bytes(adler) {
                return Ok(Segment::Raw(data[*region_start..*region_end].to_vec()));
            }
            let chunk_lens: Vec<u32> = data_spans
                .iter()
                .map(|&(s, e)| (e - s) as u32)
                .collect();
            Ok(Segment::PngIdat {
                orig_len: region_end - region_start,
                chunk_lens,
                header,
                adler,
                corrections: parts.corrections,
                plain: parts.plaintext,
            })
        }
    }
}

// ------------------------------------------------------------------ zstd outer frame

fn zstd_compress(container: &[u8]) -> Result<Vec<u8>, DeepError> {
    // Spend more CPU where it is cheap: small/medium containers get the strongest zstd level,
    // which is what makes deep1 pay off on text. Above 4 MiB level 19 costs several seconds, so we
    // step down to keep the §1 budget (10 MB pack ≤ 1.5 s) while still using the long window.
    let level = if container.len() <= 4 * 1024 * 1024 {
        19
    } else if container.len() <= 64 * 1024 * 1024 {
        15
    } else {
        12
    };
    let mut enc = zstd::stream::write::Encoder::new(Vec::new(), level)
        .map_err(|e| err(format!("zstd encoder: {e}")))?;
    enc.multithread(cores() as u32)
        .map_err(|e| err(format!("zstd multithread: {e}")))?;
    enc.window_log(27)
        .map_err(|e| err(format!("zstd window_log: {e}")))?;
    enc.write_all(container)
        .map_err(|e| err(format!("zstd write: {e}")))?;
    enc.finish().map_err(|e| err(format!("zstd compress: {e}")))
}

/// Streaming reader that refuses to yield more than `left` bytes (zstd bomb guard): the 1-byte
/// probe at the cap turns "more data than allowed" into an error instead of silent truncation.
struct Capped<R: Read> {
    inner: R,
    left: u64,
}
impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::new(io::ErrorKind::InvalidData, "decompressed container exceeds hard cap")),
            };
        }
        let want = buf.len().min(self.left.min(usize::MAX as u64) as usize);
        let n = self.inner.read(&mut buf[..want])?;
        self.left -= n as u64;
        Ok(n)
    }
}

// ------------------------------------------------------------------ reader

/// Pull parser over the decompressed container stream. Nothing here ever allocates more than the
/// bytes that actually arrived: a declared length is a *limit to check*, not a capacity to reserve.
struct Rd<R: Read> {
    r: R,
}
impl<R: Read> Rd<R> {
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], DeepError> {
        let mut b = [0u8; N];
        self.r.read_exact(&mut b).map_err(map_read_err)?;
        Ok(b)
    }
    fn u8(&mut self) -> Result<u8, DeepError> {
        Ok(self.fixed::<1>()?[0])
    }
    fn u32(&mut self) -> Result<u32, DeepError> {
        Ok(u32::from_le_bytes(self.fixed::<4>()?))
    }
    fn u64(&mut self) -> Result<u64, DeepError> {
        Ok(u64::from_le_bytes(self.fixed::<8>()?))
    }
    /// A declared length, checked against `max` (the caller's remaining budget) before use.
    fn len(&mut self, max: u64, what: &str) -> Result<usize, DeepError> {
        let v = self.u64()?;
        if v > max {
            return Err(err(format!("{what} length {v} exceeds budget {max}")));
        }
        Ok(v as usize)
    }
    fn bytes(&mut self, n: usize) -> Result<Vec<u8>, DeepError> {
        let mut v = Vec::new();
        v.try_reserve(n.min(1 << 20)).map_err(|_| err("out of memory"))?;
        (&mut self.r).take(n as u64).read_to_end(&mut v).map_err(map_read_err)?;
        if v.len() != n {
            return Err(err("truncated container"));
        }
        Ok(v)
    }
}

fn map_read_err(e: io::Error) -> DeepError {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        err("truncated container")
    } else {
        err(format!("zstd decompress: {e}"))
    }
}

// ------------------------------------------------------------------ core encode/decode

/// Deadline and cancellation for one encode. Checked before each segment is analysed.
struct Ctl {
    deadline: Option<Instant>,
    cancel: Arc<AtomicBool>,
}
impl Ctl {
    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
    fn expired(&self) -> bool {
        self.deadline.map_or(false, |d| Instant::now() >= d)
    }
}

static CANCELS: Mutex<Vec<(u64, Arc<AtomicBool>)>> = Mutex::new(Vec::new());

struct CancelGuard(u64);
impl Drop for CancelGuard {
    fn drop(&mut self) {
        if self.0 != 0 {
            if let Ok(mut v) = CANCELS.lock() {
                v.retain(|(t, _)| *t != self.0);
            }
        }
    }
}

/// Ask an in-flight [`encode_with`] (registered under `token`) to stop at the next segment boundary.
/// A token that is not running is ignored.
pub fn cancel(token: u64) {
    if token == 0 {
        return;
    }
    if let Ok(v) = CANCELS.lock() {
        for (t, f) in v.iter() {
            if *t == token {
                f.store(true, Ordering::Relaxed);
            }
        }
    }
}

fn encode_inner(data: &[u8], ctl: &Ctl) -> Result<Vec<u8>, DeepError> {
    if data.len() as u64 > MAX_OSIZE {
        return Err(err("input exceeds the 1 GiB deep1 cap"));
    }
    ensure_rayon();
    let osize = data.len() as u64;
    let digest = Sha256::digest(data);

    let spans = scan::scan(data);
    let segments: Vec<Segment> = spans
        .par_iter()
        .map(|span| {
            if ctl.cancelled() {
                return Err(err("cancelled"));
            }
            // Past the deadline: stop analysing, keep the rest verbatim so the container stays valid.
            if ctl.expired() {
                return Ok(raw_segment(data, span));
            }
            build_segment(data, span)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut container = Vec::new();
    container.extend_from_slice(MAGIC);
    container.push(VERSION);
    put_u64(&mut container, osize);
    container.extend_from_slice(&digest);
    put_u32(&mut container, segments.len() as u32);
    for seg in &segments {
        seg.write_to(&mut container);
    }
    drop(segments);
    if container.len() as u64 > MAX_CONTAINER {
        return Err(err("container exceeds the decode cap"));
    }
    if ctl.cancelled() {
        return Err(err("cancelled"));
    }

    let packed = zstd_compress(&container)?;
    drop(container);
    if ctl.cancelled() {
        return Err(err("cancelled"));
    }

    // Mandatory sender verification (§2.2): decode what we just produced under the exact rules a
    // receiver applies (expected size and SHA-256 from here) and compare. Any failure returns an
    // error so the caller falls back to plain zstd for this file.
    let sha: [u8; 32] = digest.into();
    let check = decode_to_vec(&packed, osize, &sha)?;
    if check.as_slice() != data {
        return Err(err("sender verification failed: decode != original"));
    }
    Ok(packed)
}

/// Streaming decode of a `deep1` payload (zstd frame around the container) into `dst`.
///
/// `osize` and `osha` are the *expected* original size and SHA-256 from the sealed manifest. The
/// container header must match both, the output never exceeds `osize`, each segment's declared sizes
/// are validated against the remaining budget before allocation, and the running SHA-256 of
/// everything written must equal `osha`. On any error `dst` may hold a partial prefix: callers
/// must discard it (the path/Vec wrappers do).
fn decode_stream<R: Read, W: Write>(
    src: R,
    dst: &mut W,
    osize: u64,
    osha: &[u8; 32],
) -> Result<(), DeepError> {
    if osize > MAX_OSIZE {
        return Err(err("original size exceeds the 1 GiB deep1 cap"));
    }
    let mut dec = zstd::stream::read::Decoder::new(src)
        .map_err(|e| err(format!("zstd decoder: {e}")))?;
    // Bomb guard: never accept a window larger than the encoder's long-mode window.
    dec.window_log_max(27)
        .map_err(|e| err(format!("zstd window_log_max: {e}")))?;
    let mut rd = Rd { r: Capped { inner: dec, left: MAX_CONTAINER } };

    if &rd.fixed::<4>()? != MAGIC {
        return Err(err("bad deep1 magic"));
    }
    if rd.u8()? != VERSION {
        return Err(err("unsupported deep1 version"));
    }
    if rd.u64()? != osize {
        return Err(err("deep1 container size does not match the manifest osize"));
    }
    if &rd.fixed::<32>()? != osha {
        return Err(err("checksum_mismatch: container SHA-256 does not match the manifest osha"));
    }
    let count = rd.u32()?;
    if count > 20_000_000 {
        return Err(err("too many segments"));
    }

    let mut hasher = Sha256::new();
    let mut written = 0u64;
    let mut copy_buf = vec![0u8; 64 * 1024];
    for _ in 0..count {
        let remaining = osize - written;
        let tag = rd.u8()?;
        let piece: Vec<u8> = match tag {
            TAG_RAW => {
                // Verbatim bytes stream straight through in 64 KiB steps: a RAW segment is never
                // buffered, however large it is (and it can never exceed the remaining budget).
                let n = rd.len(remaining, "raw segment")? as u64;
                let mut left = n;
                while left > 0 {
                    let k = left.min(copy_buf.len() as u64) as usize;
                    rd.r.read_exact(&mut copy_buf[..k]).map_err(map_read_err)?;
                    hasher.update(&copy_buf[..k]);
                    dst.write_all(&copy_buf[..k]).map_err(|e| err(format!("write output: {e}")))?;
                    left -= k as u64;
                }
                written += n;
                continue;
            }
            TAG_DEFLATE => {
                let orig_len = rd.len(remaining.min(transform::MAX_DEFLATE_BYTES as u64), "deflate segment")?;
                let cn = rd.len(transform::corrections_bound(orig_len) as u64, "corrections")?;
                let corrections = rd.bytes(cn)?;
                let pn = rd.len(transform::plain_bound(orig_len) as u64, "plaintext")?;
                let plain = rd.bytes(pn)?;
                transform::deflate_decode(&plain, &corrections, orig_len)?
            }
            TAG_JPEG => {
                let orig_len = rd.len(remaining.min(transform::MAX_JPEG_BYTES as u64), "jpeg segment")?;
                let ln = rd.len(transform::lepton_bound(orig_len) as u64, "lepton stream")?;
                let lep = rd.bytes(ln)?;
                transform::jpeg_decode(&lep, orig_len)?
            }
            TAG_PNG_IDAT => {
                let orig_len = rd.len(remaining, "png segment")?;
                let n = rd.u32()? as u64;
                // Each chunk costs 12 framing bytes of the region, so the count is bounded by the budget.
                if n == 0 || n > 1_000_000 || n * 12 > orig_len as u64 {
                    return Err(err("invalid PNG IDAT chunk count"));
                }
                let mut chunk_lens = Vec::new();
                let mut zlib_len = 0u64;
                for _ in 0..n {
                    let c = rd.u32()?;
                    zlib_len += c as u64;
                    if zlib_len + n * 12 > orig_len as u64 {
                        return Err(err("PNG IDAT chunk lengths exceed region length"));
                    }
                    chunk_lens.push(c);
                }
                let header = rd.fixed::<2>()?;
                let adler = rd.fixed::<4>()?;
                let zl = zlib_len as usize;
                let cn = rd.len(transform::corrections_bound(zl) as u64, "corrections")?;
                let corrections = rd.bytes(cn)?;
                let pn = rd.len(transform::plain_bound(zl) as u64, "plaintext")?;
                let plain = rd.bytes(pn)?;
                rebuild_png_idat(&chunk_lens, header, adler, &corrections, &plain, orig_len)?
            }
            _ => return Err(err(format!("unknown segment tag {tag}"))),
        };
        if piece.len() as u64 > remaining {
            return Err(err("reconstruction would exceed original size"));
        }
        hasher.update(&piece);
        dst.write_all(&piece)
            .map_err(|e| err(format!("write output: {e}")))?;
        written += piece.len() as u64;
    }
    // The container must end exactly here (a probe read, bounded by the cap).
    let mut probe = [0u8; 1];
    match rd.r.read(&mut probe) {
        Ok(0) => {}
        Ok(_) => return Err(err("trailing bytes in deep1 container")),
        Err(e) => return Err(map_read_err(e)),
    }
    if written != osize {
        return Err(err("reconstructed size != original size"));
    }
    if hasher.finalize()[..] != osha[..] {
        return Err(err("checksum_mismatch: reconstructed SHA-256 differs from the manifest osha"));
    }
    dst.flush().map_err(|e| err(format!("write output: {e}")))?;
    Ok(())
}

fn decode_to_vec(compressed: &[u8], osize: u64, osha: &[u8; 32]) -> Result<Vec<u8>, DeepError> {
    // No up-front capacity: the Vec only ever grows by bytes that were actually reconstructed, and
    // decode_stream never writes past `osize`.
    let mut out = Vec::new();
    decode_stream(compressed, &mut out, osize, osha)?;
    Ok(out)
}

// ------------------------------------------------------------------ public API

/// Version string including the exact crate versions this build was compiled against.
pub fn version_string() -> String {
    format!(
        "hopperdeep {} / deep1-v{} / preflate-rs 0.7.6 / lepton 0.5.8 / zstd 0.13.3",
        env!("CARGO_PKG_VERSION"),
        VERSION
    )
}

/// True when this native library is loaded and the deep1 codec is usable.
pub fn is_available() -> bool {
    true
}

/// Parse a 64-hex SHA-256 (either case). Anything else is rejected: `osha` is mandatory for deep1.
pub fn parse_sha_hex(s: &str) -> Result<[u8; 32], DeepError> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return Err(err("osha must be 64 hex characters"));
    }
    let nib = |c: u8| -> Result<u8, DeepError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(err("osha must be 64 hex characters")),
        }
    };
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (nib(b[2 * i])? << 4) | nib(b[2 * i + 1])?;
    }
    Ok(out)
}

/// Encode an in-memory byte buffer into the zstd-compressed `deep1` container that would be sent.
pub fn encode(data: &[u8]) -> Result<Vec<u8>, DeepError> {
    encode_with(data, None, 0)
}

/// [`encode`] with a time budget and a cancellation token.
///
/// After `budget` elapses no further segment is analysed (each remaining one is kept verbatim, so
/// the container is still valid); `cancel(token)` aborts with the error `"cancelled"`. `token == 0`
/// means "not cancellable". Both are checked between segments and before the zstd/verify stages,
/// not inside a single segment's transform.
pub fn encode_with(data: &[u8], budget: Option<Duration>, token: u64) -> Result<Vec<u8>, DeepError> {
    let flag = Arc::new(AtomicBool::new(false));
    if token != 0 {
        if let Ok(mut v) = CANCELS.lock() {
            v.push((token, flag.clone()));
        }
    }
    let _guard = CancelGuard(token);
    let ctl = Ctl { deadline: budget.map(|b| Instant::now() + b), cancel: flag };
    catch_unwind(AssertUnwindSafe(|| encode_inner(data, &ctl)))
        .unwrap_or_else(|p| Err(err(format!("encoder panic: {p:?}"))))
}

/// Decode a `deep1` payload back into the exact original bytes. `osize` and `osha` come from the
/// sealed manifest and are verified (see [`decode_stream`]'s contract); nothing is returned unless
/// size and SHA-256 both match.
pub fn decode(compressed: &[u8], osize: u64, osha: &[u8; 32]) -> Result<Vec<u8>, DeepError> {
    catch_unwind(AssertUnwindSafe(|| decode_to_vec(compressed, osize, osha)))
        .unwrap_or_else(|p| Err(err(format!("decoder panic: {p:?}"))))
}

/// Streaming decode into any writer (same contract as [`decode`], without a result buffer). On
/// error `dst` may hold a partial prefix that the caller must discard.
pub fn decode_to_writer<W: Write>(
    compressed: &[u8],
    dst: &mut W,
    osize: u64,
    osha: &[u8; 32],
) -> Result<(), DeepError> {
    catch_unwind(AssertUnwindSafe(|| decode_stream(compressed, dst, osize, osha)))
        .unwrap_or_else(|p| Err(err(format!("decoder panic: {p:?}"))))
}

/// Path-based encode for inputs above [`IN_MEMORY_LIMIT`].
///
/// LIMITATION (v0.7 C1): this reads the file into a single byte buffer and buffers each transformed
/// segment in memory; it is correct for all inputs but does not stream the *encode* (Hopper only
/// deep-encodes files up to 64 MiB, so the receiver-side decode is where streaming matters).
pub fn encode_path(path: &Path) -> Result<Vec<u8>, DeepError> {
    let data = fs::read(path).map_err(|e| err(format!("read {}: {e}", path.display())))?;
    encode(&data)
}

/// Streaming path-to-path decode: reads the payload at `compressed`, writes the verified
/// reconstruction to `out`, and **removes `out` on any failure** (never a partial or unverified file).
/// Memory is bounded by the largest single segment, never by the file size.
pub fn decode_file(compressed: &Path, out: &Path, osize: u64, osha: &[u8; 32]) -> Result<(), DeepError> {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), DeepError> {
        let input = fs::File::open(compressed)
            .map_err(|e| err(format!("open {}: {e}", compressed.display())))?;
        let file = fs::File::create(out)
            .map_err(|e| err(format!("create {}: {e}", out.display())))?;
        let mut w = BufWriter::with_capacity(256 * 1024, file);
        decode_stream(input, &mut w, osize, osha)?;
        w.into_inner()
            .map_err(|e| err(format!("write {}: {e}", out.display())))?
            .sync_all()
            .map_err(|e| err(format!("sync {}: {e}", out.display())))
    }))
    .unwrap_or_else(|p| Err(err(format!("decoder panic: {p:?}"))));
    if result.is_err() {
        let _ = fs::remove_file(out);
    }
    result
}
