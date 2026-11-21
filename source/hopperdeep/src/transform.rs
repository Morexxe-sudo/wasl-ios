//! Low-level, format-independent transforms used by the deep1 encoder/decoder.
//!
//! Nothing here scans a container format; that lives in [`crate::scan`]. This module only knows
//! how to split one raw DEFLATE stream into plaintext + corrections, one JPEG into Lepton bytes,
//! and how to compute the two checksums PNG/gzip framing needs.

use lepton_jpeg::{decode_lepton, encode_lepton, EnabledFeatures, DEFAULT_THREAD_POOL};
use preflate_rs::{
    preflate_whole_deflate_stream, recreate_whole_deflate_stream, ExitCode, PreflateConfig,
};
use std::io::Cursor;

/// Per-segment plaintext cap: a DEFLATE stream is deep-encoded only if it expands to at most this
/// much, and the decoder never accepts a larger plaintext. This is what bounds receiver memory.
pub const MAX_DEFLATE_PLAIN: usize = 256 << 20;
/// A stream that inflates past this is a zip bomb and aborts the whole encode (§2.1 safety).
pub const ZIP_BOMB_CAP: usize = 1 << 30;
/// A DEFLATE bitstream can be slightly larger than its plaintext (incompressible blocks).
pub const MAX_DEFLATE_BYTES: usize = MAX_DEFLATE_PLAIN + (1 << 24);
/// Lepton's own default (128 MiB): larger JPEGs stay RAW. Never raise it above this.
pub const MAX_JPEG_BYTES: usize = 128 << 20;
/// JPEG dimension caps (Lepton allocates coefficient planes from these): 12,000 px per side...
pub const MAX_JPEG_DIM: u32 = 12_000;
/// ...and 100 megapixels in total.
pub const MAX_JPEG_PIXELS: u64 = 100_000_000;
/// A real JPEG never describes more than this many pixels per file byte (flat progressive images
/// are the extreme); it stops a tiny file from declaring a huge image and forcing a big allocation.
pub const MAX_JPEG_PIXELS_PER_BYTE: u64 = 1024;

/// A DEFLATE stream cannot expand by more than 1032:1, so a plaintext longer than this for a stream
/// of `deflate_len` bytes is impossible: the decoder rejects it before reading it.
pub fn plain_bound(deflate_len: usize) -> usize {
    MAX_DEFLATE_PLAIN.min(deflate_len.saturating_mul(1032).saturating_add(1024))
}
/// Upper bound on preflate's correction stream for a stream of `deflate_len` bytes. The sender
/// verifies every container under the same bound, so a legitimate file that needs more simply stays
/// RAW instead of being deep-encoded.
pub fn corrections_bound(deflate_len: usize) -> usize {
    deflate_len.saturating_mul(8).saturating_add(1 << 20)
}
/// Upper bound on a Lepton stream for a JPEG of `jpeg_len` bytes (same sender-verified rule).
pub fn lepton_bound(jpeg_len: usize) -> usize {
    jpeg_len.saturating_add(jpeg_len / 2).saturating_add(1 << 20)
}

fn config() -> PreflateConfig {
    PreflateConfig {
        max_chain_length: 4096,
        plain_text_limit: MAX_DEFLATE_PLAIN,
        // We verify the whole container with SHA-256 after decoding; an extra per-stream
        // recompression here would double encode time for no extra safety.
        verify_compression: false,
    }
}

/// Result of analysing one raw DEFLATE stream.
pub struct DeflateParts {
    pub corrections: Vec<u8>,
    pub plaintext: Vec<u8>,
}

/// Why preflate analysis could not be used for one stream.
#[derive(Debug)]
pub enum DeflateFailure {
    /// The stream expands past the per-segment plaintext cap. The caller decides whether it is just
    /// too big to deep-encode (keep RAW) or a real zip bomb (abort), with an independent inflate.
    Limit,
    /// preflate cannot represent this (valid) stream; keeping the bytes RAW is safe.
    Other,
}

/// Split an exact raw DEFLATE byte slice into plaintext + reconstruction corrections.
///
/// The caller must pass the exact stream (no zlib header, no trailing bytes): if preflate
/// consumes fewer bytes than supplied we report an error instead of silently dropping data.
pub fn deflate_encode(raw: &[u8]) -> Result<DeflateParts, DeflateFailure> {
    if raw.len() > MAX_DEFLATE_BYTES {
        return Err(DeflateFailure::Limit);
    }
    let (result, plain) = preflate_whole_deflate_stream(raw, &config())
        .map_err(|e| if e.exit_code() == ExitCode::PlainTextLimit { DeflateFailure::Limit } else { DeflateFailure::Other })?;
    if result.compressed_size != raw.len() {
        return Err(DeflateFailure::Other);
    }
    let plaintext = plain.text().to_vec();
    if plaintext.len() > plain_bound(raw.len()) {
        return Err(DeflateFailure::Limit);
    }
    if result.corrections.len() > corrections_bound(raw.len()) {
        return Err(DeflateFailure::Other);
    }
    Ok(DeflateParts {
        corrections: result.corrections,
        plaintext,
    })
}

/// Count the expansion of a stream preflate could not analyse. Streaming with a fixed buffer, so
/// even a multi-gigabyte zip bomb is bounded in memory; stops as soon as `cap` is exceeded.
pub fn expansion_exceeds(raw: &[u8], cap: usize) -> bool {
    use flate2::read::DeflateDecoder;
    use std::io::Read;
    let mut dec = DeflateDecoder::new(raw);
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0usize;
    loop {
        match dec.read(&mut buf) {
            Ok(0) | Err(_) => return false,
            Ok(n) => {
                total = match total.checked_add(n) {
                    Some(v) => v,
                    None => return true,
                };
                if total > cap {
                    return true;
                }
            }
        }
    }
}

/// Rebuild the exact raw DEFLATE stream from plaintext + corrections.
pub fn deflate_decode(
    plaintext: &[u8],
    corrections: &[u8],
    expected_len: usize,
) -> Result<Vec<u8>, String> {
    if plaintext.len() > MAX_DEFLATE_PLAIN || expected_len > MAX_DEFLATE_BYTES {
        return Err("DEFLATE segment exceeds hard cap".to_string());
    }
    let out = recreate_whole_deflate_stream(plaintext, corrections)
        .map_err(|e| format!("preflate reconstruction failed: {e:?}"))?;
    if out.len() != expected_len {
        return Err(format!(
            "reconstructed DEFLATE length {} != expected {expected_len}",
            out.len()
        ));
    }
    Ok(out)
}

fn lepton_features() -> EnabledFeatures {
    let mut f = EnabledFeatures::compat_lepton_vector_write();
    f.max_processor_threads = std::cmp::max(1, num_cpus()) as u32;
    // Keep Lepton's own 128 MiB file cap (MAX_JPEG_BYTES) and bound the dimensions it will allocate for.
    f.max_jpeg_file_size = MAX_JPEG_BYTES as u32;
    f.max_jpeg_width = MAX_JPEG_DIM;
    f.max_jpeg_height = MAX_JPEG_DIM;
    f
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
}

/// Image dimensions from the SOF marker of a JPEG header (the bytes before the first SOS). A whole
/// JPEG starts with SOI; Lepton's stored header omits it, so both are accepted. Returns `None` if no
/// frame header is found.
pub fn jpeg_dimensions(header: &[u8]) -> Option<(u32, u32)> {
    let mut p = if header.len() >= 2 && header[0] == 0xff && header[1] == 0xd8 { 2usize } else { 0usize };
    while p + 1 < header.len() {
        if header[p] != 0xff {
            p += 1;
            continue;
        }
        let m = header[p + 1];
        if m == 0xff {
            p += 1; // fill byte
            continue;
        }
        p += 2;
        match m {
            0x00 | 0x01 | 0xd0..=0xd8 => continue, // stuffing / TEM / RSTn / SOI: no length
            0xd9 | 0xda => return None,            // EOI / SOS before any SOF
            _ => {}
        }
        if p + 2 > header.len() {
            return None;
        }
        let len = ((header[p] as usize) << 8) | header[p + 1] as usize;
        let is_sof = matches!(m, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf);
        if is_sof {
            if len < 8 || p + 7 > header.len() {
                return None;
            }
            let h = ((header[p + 3] as u32) << 8) | header[p + 4] as u32;
            let w = ((header[p + 5] as u32) << 8) | header[p + 6] as u32;
            return Some((w, h));
        }
        if len < 2 {
            return None;
        }
        p += len;
    }
    None
}

/// Reject JPEGs whose declared geometry would make Lepton allocate too much.
fn check_jpeg_geometry(dims: Option<(u32, u32)>, jpeg_len: usize) -> Result<(), String> {
    let (w, h) = dims.ok_or_else(|| "JPEG frame header not found".to_string())?;
    if w == 0 || h == 0 || w > MAX_JPEG_DIM || h > MAX_JPEG_DIM {
        return Err(format!("JPEG dimensions {w}x{h} exceed {MAX_JPEG_DIM}x{MAX_JPEG_DIM}"));
    }
    let px = w as u64 * h as u64;
    if px > MAX_JPEG_PIXELS {
        return Err(format!("JPEG has {px} pixels, over the {MAX_JPEG_PIXELS} cap"));
    }
    if px > (jpeg_len as u64).saturating_mul(MAX_JPEG_PIXELS_PER_BYTE).saturating_add(1 << 16) {
        return Err("JPEG declares far more pixels than its size can encode".to_string());
    }
    Ok(())
}

/// Validate a Lepton stream *before* handing it to the decoder, using only bounded reads: the
/// decoder trusts a header field (`hdrs`) to size a buffer, so a hostile stream could otherwise ask
/// it for 4 GiB. We check the fixed header, the declared JPEG size, the JPEG-header length (it is a
/// prefix of the original file, so it cannot exceed it) and the declared geometry.
fn lepton_preflight(lep: &[u8], expected_len: usize) -> Result<(), String> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    const FIXED: usize = 28;
    if lep.len() < FIXED || lep[0] != 0xcf || lep[1] != 0x84 {
        return Err("invalid Lepton segment".to_string());
    }
    let jpeg_size = u32::from_le_bytes([lep[20], lep[21], lep[22], lep[23]]) as usize;
    if jpeg_size != expected_len {
        return Err("Lepton size does not match the segment length".to_string());
    }
    let chs = u32::from_le_bytes([lep[24], lep[25], lep[26], lep[27]]) as usize;
    if chs > lep.len() - FIXED {
        return Err("Lepton header overruns the segment".to_string());
    }
    let mut z = ZlibDecoder::new(&lep[FIXED..FIXED + chs]);
    let mut head = [0u8; 7];
    z.read_exact(&mut head).map_err(|_| "invalid Lepton header".to_string())?;
    if &head[..3] != b"HDR" {
        return Err("invalid Lepton header".to_string());
    }
    let hdrs = u32::from_le_bytes([head[3], head[4], head[5], head[6]]) as usize;
    if hdrs > expected_len {
        return Err("Lepton JPEG header longer than the JPEG".to_string());
    }
    let mut hdr = Vec::new();
    (&mut z).take(hdrs as u64).read_to_end(&mut hdr).map_err(|_| "invalid Lepton header".to_string())?;
    if hdr.len() != hdrs {
        return Err("truncated Lepton header".to_string());
    }
    check_jpeg_geometry(jpeg_dimensions(&hdr), expected_len)
}

/// Losslessly recompress one JPEG with Lepton. Errors are propagated so the caller can keep the
/// segment RAW (CMYK, arithmetic-coded, oversized or otherwise unsupported JPEGs never get corrupted).
pub fn jpeg_encode(jpeg: &[u8]) -> Result<Vec<u8>, String> {
    if jpeg.is_empty() || jpeg.len() > MAX_JPEG_BYTES {
        return Err(format!("invalid JPEG size: {}", jpeg.len()));
    }
    check_jpeg_geometry(jpeg_dimensions(jpeg), jpeg.len())?;
    let features = lepton_features();
    let mut reader = Cursor::new(jpeg);
    let mut writer = Cursor::new(Vec::new());
    encode_lepton(&mut reader, &mut writer, &features, &DEFAULT_THREAD_POOL)
        .map_err(|e| format!("lepton encode failed: {e:?}"))?;
    let out = writer.into_inner();
    if out.is_empty() || out.len() > lepton_bound(jpeg.len()) {
        return Err("lepton produced an invalid stream".to_string());
    }
    Ok(out)
}

/// Restore the exact original JPEG bytes from a Lepton stream.
pub fn jpeg_decode(lep: &[u8], expected_len: usize) -> Result<Vec<u8>, String> {
    if lep.is_empty() || expected_len == 0 || lep.len() > lepton_bound(expected_len) || expected_len > MAX_JPEG_BYTES {
        return Err("invalid Lepton segment".to_string());
    }
    lepton_preflight(lep, expected_len)?;
    let features = lepton_features();
    let mut reader = Cursor::new(lep);
    // Capacity is budget-sized (expected_len <= remaining output budget <= MAX_JPEG_BYTES).
    let mut out = Vec::with_capacity(expected_len);
    decode_lepton(&mut reader, &mut out, &features, &DEFAULT_THREAD_POOL)
        .map_err(|e| format!("lepton decode failed: {e:?}"))?;
    if out.len() != expected_len {
        return Err(format!(
            "lepton decoded {} bytes, expected {expected_len}",
            out.len()
        ));
    }
    Ok(out)
}

/// Adler-32 (the zlib trailer checksum).
pub fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// CRC-32/ISO-HDLC (the PNG chunk checksum).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// A zlib header is valid if CM=8, CINFO<=7 and (CMF<<8|FLG) % 31 == 0.
pub fn valid_zlib_header(h: &[u8]) -> bool {
    if h.len() < 2 || h[0] & 0x0f != 8 || h[0] >> 4 > 7 {
        return false;
    }
    (((h[0] as u16) << 8) | h[1] as u16) % 31 == 0
}
