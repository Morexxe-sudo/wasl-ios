//! Hostile `deep1` payloads (peers are untrusted): the mandatory-`osha` / expected-`osize` contract,
//! all-or-nothing file decode, the encoder's deadline/cancel and the oversized-JPEG RAW fallback.
//! (The memory-bomb scenarios live in `bomb.rs`, alone in their process so RSS is measurable.)

use flate2::write::ZlibEncoder;
use flate2::Compression;
use hopperdeep::{decode, decode_file, encode, encode_with, parse_sha_hex, MAGIC, VERSION};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::time::{Duration, Instant};

const GIB: u64 = 1 << 30;

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// `HDP1` header + the given raw segment bytes, wrapped in a zstd frame (default window).
fn container(osize: u64, osha: &[u8; 32], count: u32, segs: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(MAGIC);
    c.push(VERSION);
    c.extend_from_slice(&osize.to_le_bytes());
    c.extend_from_slice(osha);
    c.extend_from_slice(&count.to_le_bytes());
    c.extend_from_slice(segs);
    zstd::encode_all(&c[..], 3).unwrap()
}

fn raw_seg(len: u64, body: &[u8]) -> Vec<u8> {
    let mut s = vec![0u8]; // TAG_RAW
    s.extend_from_slice(&len.to_le_bytes());
    s.extend_from_slice(body);
    s
}

/// #4: osize and osha are the manifest's, mandatory, and checked against the container.
#[test]
fn osize_and_osha_must_match_the_manifest() {
    let data: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
    let packed = encode(&data).unwrap();
    let good = sha(&data);
    assert_eq!(decode(&packed, data.len() as u64, &good).unwrap(), data);

    // Wrong expected size (container says 50000): refused.
    assert!(decode(&packed, data.len() as u64 + 1, &good).is_err());
    assert!(decode(&packed, data.len() as u64 - 1, &good).is_err());
    // Wrong expected SHA: refused from the header, before any segment is decoded.
    let mut bad = good;
    bad[0] ^= 1;
    let e = decode(&packed, data.len() as u64, &bad).unwrap_err().0;
    assert!(e.contains("checksum_mismatch"), "{e}");
    // Expected size above the 1 GiB deep1 cap.
    assert!(decode(&packed, 2 * GIB, &good).is_err());

    // A container whose own header lies (claims another SHA) is rejected even though its bytes are fine.
    let other = sha(b"another file");
    let forged = container(data.len() as u64, &other, 1, &raw_seg(data.len() as u64, &data));
    assert!(decode(&forged, data.len() as u64, &good).is_err());
    // ...and one whose header matches the manifest but whose body is different bytes.
    let mut wrong_body = data.clone();
    wrong_body[100] ^= 0xff;
    let forged = container(data.len() as u64, &good, 1, &raw_seg(wrong_body.len() as u64, &wrong_body));
    let e = decode(&forged, data.len() as u64, &good).unwrap_err().0;
    assert!(e.contains("checksum_mismatch"), "{e}");
    // Fewer bytes than osize.
    let short = container(data.len() as u64, &good, 1, &raw_seg(10, &data[..10]));
    assert!(decode(&short, data.len() as u64, &good).is_err());

    // The hex parser: exactly 64 hex characters, nothing else.
    assert!(parse_sha_hex(&"ab".repeat(32)).is_ok());
    assert!(parse_sha_hex(&"AB".repeat(32)).is_ok());
    for bad in ["", "ab", &"ab".repeat(31), &"ab".repeat(33), &"zz".repeat(32), &format!("{}g", "a".repeat(63))] {
        assert!(parse_sha_hex(bad).is_err(), "{bad:?} accepted");
    }
}

/// decode_file streams to a path, verifies, and never leaves a partial output.
#[test]
fn decode_file_is_all_or_nothing() {
    let dir = std::env::temp_dir().join(format!("hopperdeep-hostile-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let data: Vec<u8> = (0..300_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let packed = encode(&data).unwrap();
    let inp = dir.join("in.hdp");
    let out = dir.join("out.bin");
    std::fs::write(&inp, &packed).unwrap();

    decode_file(&inp, &out, data.len() as u64, &sha(&data)).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), data);
    std::fs::remove_file(&out).unwrap();

    let mut bad = sha(&data);
    bad[31] ^= 1;
    assert!(decode_file(&inp, &out, data.len() as u64, &bad).is_err());
    assert!(!out.exists(), "a failed decode must not leave its output behind");

    // Mid-stream failure (header matches, body does not): the partially written file is removed.
    let mut wrong = data.clone();
    wrong[200_000] ^= 1;
    let forged = container(data.len() as u64, &sha(&data), 1, &raw_seg(wrong.len() as u64, &wrong));
    std::fs::write(&inp, &forged).unwrap();
    assert!(decode_file(&inp, &out, data.len() as u64, &sha(&data)).is_err());
    assert!(!out.exists(), "partial output left behind");
    let _ = std::fs::remove_dir_all(&dir);
}

fn zlib_stream(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::new(6));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn text(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut i = 0u64;
    while out.len() < n {
        out.extend_from_slice(format!("row {i:08} lorem ipsum dolor sit amet {:x}\n", i.wrapping_mul(0x9e37_79b9)).as_bytes());
        i += 1;
    }
    out.truncate(n);
    out
}

fn pdf_of_streams(n_streams: usize, each: usize) -> Vec<u8> {
    let mut pdf = b"%PDF-1.4\n".to_vec();
    for i in 0..n_streams {
        let z = zlib_stream(&text(each + i));
        pdf.extend_from_slice(format!("{} 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n", i + 1, z.len()).as_bytes());
        pdf.extend_from_slice(&z);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
    }
    pdf.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\n%%EOF\n");
    pdf
}

/// #11: past the deadline the remaining segments stay RAW; the container is valid and bit-exact.
#[test]
fn encode_deadline_keeps_remaining_segments_raw() {
    let pdf = pdf_of_streams(12, 40_000);
    let full = encode(&pdf).unwrap();
    let expired = encode_with(&pdf, Some(Duration::ZERO), 0).unwrap();
    assert_eq!(decode(&expired, pdf.len() as u64, &sha(&pdf)).unwrap(), pdf, "deadline container must round-trip");
    assert!(
        expired.len() > full.len(),
        "an expired deadline must skip the transforms (expired {} vs full {})",
        expired.len(),
        full.len()
    );
}

/// #6/#11: `cancel(token)` stops an in-flight encode promptly with the error "cancelled".
#[test]
fn encode_cancel_stops_in_flight_encode() {
    let pdf = pdf_of_streams(300, 60_000);
    let t0 = Instant::now();
    let uncancelled = encode(&pdf).unwrap();
    let full_ms = t0.elapsed().as_millis();
    drop(uncancelled);

    let token = 0x5eed_0001u64;
    let pdf2 = pdf.clone();
    let h = std::thread::spawn(move || encode_with(&pdf2, None, token));
    let started = Instant::now();
    while !h.is_finished() {
        hopperdeep::cancel(token);
        std::thread::sleep(Duration::from_millis(1));
    }
    let r = h.join().unwrap();
    let e = r.expect_err("a cancelled encode must fail");
    assert!(e.0.contains("cancelled"), "{e}");
    eprintln!("[measure] full encode {full_ms} ms, cancelled encode returned after {:?}", started.elapsed());
    // Cancelling an unknown / finished token is a harmless no-op.
    hopperdeep::cancel(token);
    hopperdeep::cancel(0);
    assert!(encode_with(&pdf, None, token).is_ok(), "a stale cancel must not poison a later encode");
}

/// #3: a JPEG declaring absurd dimensions is never handed to Lepton; the file still round-trips RAW.
#[test]
fn oversized_jpeg_dimensions_stay_raw() {
    // SOI, SOF0 60000x60000, SOS, a few scan bytes, EOI
    let mut j = vec![0xff, 0xd8, 0xff, 0xc0, 0, 11, 8, 0xea, 0x60, 0xea, 0x60, 1, 1, 0x11, 0];
    j.extend_from_slice(&[0xff, 0xda, 0, 8, 1, 1, 0, 0, 63, 0, 1, 2, 3, 0xff, 0xd9]);
    let t = Instant::now();
    let packed = encode(&j).unwrap();
    assert!(t.elapsed() < Duration::from_secs(5));
    assert_eq!(decode(&packed, j.len() as u64, &sha(&j)).unwrap(), j);
}
