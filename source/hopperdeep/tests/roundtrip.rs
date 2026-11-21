//! End-to-end deep1 tests: every supported container, negative/fuzz cases, and honest measurements.

use flate2::write::{DeflateEncoder, ZlibEncoder};
use flate2::Compression;
use hopperdeep::{crc32, decode, encode, DeepError, MAGIC, VERSION};
use sha2::{Digest, Sha256};
use std::io::Write;

const BASELINE_JPEG: &[u8] = include_bytes!("fixtures/baseline.jpg");
const PROGRESSIVE_JPEG: &[u8] = include_bytes!("fixtures/progressive.jpg");
const CMYK_JPEG: &[u8] = include_bytes!("fixtures/cmyk.jpg");

// ------------------------------------------------------------------ fixture builders

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Decode against the original's size and SHA-256 (what the sealed manifest carries).
fn dec(packed: &[u8], original: &[u8]) -> Result<Vec<u8>, DeepError> {
    decode(packed, original.len() as u64, &sha(original))
}

fn deflate_raw(data: &[u8], level: u32) -> Vec<u8> {
    let mut e = DeflateEncoder::new(Vec::new(), Compression::new(level));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn zlib(data: &[u8], level: u32) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::new(level));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn text(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut i = 0usize;
    while out.len() < n {
        out.extend_from_slice(
            format!(
                "line {:06}: the quick brown fox jumps over the lazy dog; seq={} checksum={:08x}\n",
                i, i, i.wrapping_mul(2654435761)
            )
            .as_bytes(),
        );
        i += 1;
    }
    out.truncate(n);
    out
}

/// Minimal valid PDF with `streams` already serialized (dictionary + data included).
fn pdf_with_stream_bodies(bodies: &[Vec<u8>]) -> Vec<u8> {
    let mut objects: Vec<Vec<u8>> = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>".to_vec(),
    ];
    let mut refs = Vec::new();
    for (i, body) in bodies.iter().enumerate() {
        objects.push(body.clone());
        refs.push(format!("{} 0 R", 6 + i));
    }
    objects[2] = format!(
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents [{}] /Resources << /Font << /F1 5 0 R >> >> >>",
        refs.join(" ")
    )
    .into_bytes();
    objects.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec());

    let mut pdf = Vec::new();
    let mut offsets = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n");
    for (i, obj) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        pdf.extend_from_slice(obj);
        pdf.extend_from_slice(b"\nendobj\n");
    }
    let xref = pdf.len();
    pdf.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets {
        pdf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            objects.len() + 1,
            xref
        )
        .as_bytes(),
    );
    pdf
}

fn flate_pdf(plain: &[u8], level: u32) -> Vec<u8> {
    let z = zlib(plain, level);
    let body = {
        let mut b = Vec::new();
        b.extend_from_slice(format!("<< /Length {} /Filter /FlateDecode >>\nstream\n", z.len()).as_bytes());
        b.extend_from_slice(&z);
        b.extend_from_slice(b"\nendstream");
        b
    };
    pdf_with_stream_bodies(&[body])
}

fn dct_pdf(jpeg: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(format!("<< /Length {} /Filter /DCTDecode >>\nstream\n", jpeg.len()).as_bytes());
    b.extend_from_slice(jpeg);
    b.extend_from_slice(b"\nendstream");
    pdf_with_stream_bodies(&[b])
}

fn indirect_length_pdf(jpeg: &[u8]) -> Vec<u8> {
    // `/Length 9 0 R` is indirect; the scanner must fall back to searching for `endstream`.
    let mut b = Vec::new();
    b.extend_from_slice(b"<< /Length 9 0 R /Filter /DCTDecode >>\nstream\n");
    b.extend_from_slice(jpeg);
    b.extend_from_slice(b"\nendstream");
    let mut pdf = pdf_with_stream_bodies(&[b]);
    pdf.extend_from_slice(b"9 0 obj\n");
    pdf.extend_from_slice(format!("{}\nendobj\n", jpeg.len()).as_bytes());
    pdf
}

struct ZipEntry {
    name: &'static str,
    method: u16,
    plain: Vec<u8>,
    stored: Vec<u8>,
    crc: u32,
}

fn deflate_entry(name: &'static str, plain: &[u8], level: u32) -> ZipEntry {
    ZipEntry {
        name,
        method: 8,
        plain: plain.to_vec(),
        stored: deflate_raw(plain, level),
        crc: crc32(plain),
    }
}

fn stored_jpeg_entry(name: &'static str, jpeg: &[u8]) -> ZipEntry {
    ZipEntry {
        name,
        method: 0,
        plain: jpeg.to_vec(),
        stored: jpeg.to_vec(),
        crc: crc32(jpeg),
    }
}

fn build_zip(entries: &[ZipEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offsets = Vec::new();
    for e in entries {
        offsets.push(out.len() as u32);
        let nb = e.name.as_bytes();
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // version
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&e.method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0u16.to_le_bytes()); // date
        out.extend_from_slice(&e.crc.to_le_bytes());
        out.extend_from_slice(&(e.stored.len() as u32).to_le_bytes());
        out.extend_from_slice(&(e.plain.len() as u32).to_le_bytes());
        out.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra
        out.extend_from_slice(nb);
        out.extend_from_slice(&e.stored);
    }
    let cd_start = out.len() as u32;
    for (e, &off) in entries.iter().zip(&offsets) {
        let nb = e.name.as_bytes();
        out.extend_from_slice(b"PK\x01\x02");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&e.method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&e.crc.to_le_bytes());
        out.extend_from_slice(&(e.stored.len() as u32).to_le_bytes());
        out.extend_from_slice(&(e.plain.len() as u32).to_le_bytes());
        out.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra
        out.extend_from_slice(&0u16.to_le_bytes()); // comment
        out.extend_from_slice(&0u16.to_le_bytes()); // disk
        out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        out.extend_from_slice(&off.to_le_bytes());
        out.extend_from_slice(nb);
    }
    let cd_size = out.len() as u32 - cd_start;
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn png_chunk(out: &mut Vec<u8>, typ: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(typ);
    out.extend_from_slice(data);
    let mut tmp = Vec::with_capacity(4 + data.len());
    tmp.extend_from_slice(typ);
    tmp.extend_from_slice(data);
    out.extend_from_slice(&crc32(&tmp).to_be_bytes());
}

fn png_with_idat(split: usize) -> Vec<u8> {
    let (w, h) = (32u32, 32u32);
    let mut raw = Vec::new();
    for y in 0..h {
        raw.push(0u8); // filter: none
        for x in 0..w {
            raw.push((x as u8).wrapping_mul(7));
            raw.push((y as u8).wrapping_mul(11));
            raw.push(((x + y) as u8).wrapping_mul(3));
        }
    }
    let z = zlib(&raw, 6);
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    png_chunk(&mut out, b"IHDR", &ihdr);
    for part in z.chunks(split) {
        png_chunk(&mut out, b"IDAT", part);
    }
    png_chunk(&mut out, b"IEND", &[]);
    out
}

fn gzip_member(plain: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(plain).unwrap();
    e.finish().unwrap()
}

// ------------------------------------------------------------------ round trips

fn assert_round_trip(name: &str, original: &[u8]) {
    let packed = encode(original).unwrap_or_else(|e| panic!("{name}: encode failed: {e}"));
    assert_eq!(&packed[..4], &[0x28, 0xb5, 0x2f, 0xfd], "{name}: not a zstd frame");
    let restored = dec(&packed, original).unwrap_or_else(|e| panic!("{name}: decode failed: {e}"));
    assert_eq!(restored, original, "{name}: not bit-exact");
    assert_eq!(Sha256::digest(&restored), Sha256::digest(original), "{name}: SHA mismatch");
    eprintln!("[ok] {name}: {} -> {} bytes", original.len(), packed.len());
}

#[test]
fn raw_deflate_levels_1_6_9_in_pdf() {
    for level in [1u32, 6, 9] {
        let pdf = flate_pdf(&text(200_000), level);
        assert_round_trip(&format!("pdf-flate-L{level}"), &pdf);
    }
}

#[test]
fn pdf_dctdecode_baseline_and_progressive() {
    assert_round_trip("pdf-dct-baseline", &dct_pdf(BASELINE_JPEG));
    assert_round_trip("pdf-dct-progressive", &dct_pdf(PROGRESSIVE_JPEG));
    assert_round_trip("pdf-dct-indirect-length", &indirect_length_pdf(BASELINE_JPEG));
}

#[test]
fn zip_deflate_and_stored_jpeg() {
    let zip = build_zip(&[
        deflate_entry("word/document.xml", &text(120_000), 6),
        deflate_entry("word/styles.xml", &text(30_000), 9),
        deflate_entry("docProps/core.xml", &text(2_000), 1),
        stored_jpeg_entry("word/media/photo1.jpeg", BASELINE_JPEG),
    ]);
    assert_round_trip("zip-deflate+jpeg", &zip);
}

#[test]
fn png_with_idat_chunks() {
    assert_round_trip("png-single-idat", &png_with_idat(usize::MAX));
    assert_round_trip("png-split-idat", &png_with_idat(37));
}

#[test]
fn bare_jpeg_and_gzip() {
    assert_round_trip("jpeg-baseline", BASELINE_JPEG);
    assert_round_trip("jpeg-progressive", PROGRESSIVE_JPEG);
    assert_round_trip("gzip", &gzip_member(&text(80_000)));
}

#[test]
fn empty_and_plain_inputs() {
    assert_round_trip("empty", b"");
    assert_round_trip("plain-text", &text(4096));
}

// ------------------------------------------------------------------ negative / fuzz

fn assert_err(name: &str, data: &[u8]) {
    let t0 = std::time::Instant::now();
    match encode(data) {
        Ok(_) => panic!("{name}: expected encode to fail"),
        Err(e) => {
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            eprintln!("[ok] {name}: rejected in {ms:.1} ms ({e})");
            assert!(ms < 90_000.0, "{name}: took too long");
        }
    }
}

#[test]
fn negative_truncated_and_bitflipped() {
    let pdf = flate_pdf(&text(20_000), 6);
    let packed = encode(&pdf).unwrap();

    assert!(dec(&packed[..packed.len() - 1], &pdf).is_err(), "truncated container accepted");
    assert!(dec(&packed[..12], &pdf).is_err(), "short container accepted");
    assert!(dec(b"", &pdf).is_err(), "empty container accepted");
    assert!(dec(b"not a deep1 container at all", &pdf).is_err(), "random bytes accepted");

    let mut flipped = packed.clone();
    let mid = flipped.len() / 2;
    flipped[mid] ^= 0x40;
    assert!(dec(&flipped, &pdf).is_err(), "bit-flipped container accepted");

    let mut magic = packed.clone();
    magic[0] ^= 0xff;
    assert!(dec(&magic, &pdf).is_err(), "bad magic accepted");
}

#[test]
fn negative_random_bytes() {
    let seed: Vec<u8> = (0..4096).map(|i| (i * 37 + 11) as u8).collect();
    // No supported magic: the encoder stores it RAW, which is correct and must round-trip.
    assert_round_trip("random-as-raw", &seed);
    // Random bytes are never a valid deep1 container.
    assert!(dec(&seed, &seed).is_err());
}

/// #11: a JPEG Lepton rejects (CMYK) no longer aborts the whole encode: that segment stays RAW.
#[test]
fn unsupported_jpeg_stays_raw_and_round_trips() {
    assert_round_trip("cmyk-jpeg-raw", CMYK_JPEG);
    // ...and a good JPEG next to it in a PDF is still recompressed.
    let pdf = pdf_with_stream_bodies(&[
        {
            let mut b = Vec::new();
            b.extend_from_slice(format!("<< /Length {} /Filter /DCTDecode >>\nstream\n", CMYK_JPEG.len()).as_bytes());
            b.extend_from_slice(CMYK_JPEG);
            b.extend_from_slice(b"\nendstream");
            b
        },
        {
            let mut b = Vec::new();
            b.extend_from_slice(format!("<< /Length {} /Filter /DCTDecode >>\nstream\n", BASELINE_JPEG.len()).as_bytes());
            b.extend_from_slice(BASELINE_JPEG);
            b.extend_from_slice(b"\nendstream");
            b
        },
    ]);
    assert_round_trip("pdf-bad-jpeg-then-good", &pdf);
    let packed = encode(&pdf).unwrap();
    assert!(packed.len() < pdf.len(), "good JPEG after a bad one must still shrink the file");
}

#[test]
fn negative_zip_bomb() {
    // 1.1 GiB of zeros compresses to ~1 MB; preflate's 1 GiB per-stream cap must reject it.
    let mut z = ZlibEncoder::new(Vec::new(), Compression::best());
    let zeros = vec![0u8; 64 * 1024];
    for _ in 0..(1_100_000_000 / zeros.len() + 1) {
        z.write_all(&zeros).unwrap();
    }
    let bomb = z.finish().unwrap();
    let mut body = Vec::new();
    body.extend_from_slice(format!("<< /Length {} /Filter /FlateDecode >>\nstream\n", bomb.len()).as_bytes());
    body.extend_from_slice(&bomb);
    body.extend_from_slice(b"\nendstream");
    let pdf = pdf_with_stream_bodies(&[body]);
    assert_err("zip-bomb-pdf", &pdf);
}

#[test]
fn crc_is_standard() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
}

#[test]
fn version_and_magic() {
    assert_eq!(&MAGIC[..], b"HDP1");
    assert_eq!(VERSION, 1);
    assert!(hopperdeep::version_string().contains("deep1-v1"));
    assert!(hopperdeep::is_available());
}

// ------------------------------------------------------------------ measurements

fn plain_zstd(data: &[u8]) -> Vec<u8> {
    let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 9).unwrap();
    let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
    enc.multithread(n as u32).unwrap();
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// §1: deep1 must beat plain zstd on a text-heavy Flate PDF; report the real numbers.
#[test]
fn text_pdf_beats_plain_zstd() {
    let pdf = flate_pdf(&text(2_000_000), 6);
    let deep = encode(&pdf).unwrap();
    let plain = plain_zstd(&pdf);
    eprintln!(
        "[measure] text PDF: original={} deep1={} ({:.2}%) plain-zstd={} ({:.2}%)",
        pdf.len(),
        deep.len(),
        100.0 * deep.len() as f64 / pdf.len() as f64,
        plain.len(),
        100.0 * plain.len() as f64 / pdf.len() as f64,
    );
    assert!(deep.len() < plain.len(), "deep1 must be smaller than plain zstd on a text PDF");
    assert!(
        (deep.len() as f64 / pdf.len() as f64) <= 0.75,
        "§1 target: >=25% saved on a text PDF"
    );
}
