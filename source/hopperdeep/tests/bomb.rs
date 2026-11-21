//! Memory-bomb test for hostile `deep1` payloads (#2/#3). Lives alone in its own test binary so the
//! process high-water mark (`VmHWM`, from `/proc/self/status`) is not polluted by other tests.

use flate2::write::ZlibEncoder;
use flate2::Compression;
use hopperdeep::{decode, decode_to_writer, MAGIC, VERSION};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use std::time::{Duration, Instant};

const GIB: u64 = 1 << 30;

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn hwm_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
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

fn put64(v: &mut Vec<u8>, n: u64) {
    v.extend_from_slice(&n.to_le_bytes());
}

fn expect_err(name: &str, r: Result<Vec<u8>, hopperdeep::DeepError>) -> String {
    match r {
        Ok(_) => panic!("{name}: hostile container accepted"),
        Err(e) => e.0,
    }
}

/// A zstd frame holding `n` zero bytes, produced by streaming (the test itself stays small).
fn zstd_zeros(n: u64) -> Vec<u8> {
    let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
    let zeros = vec![0u8; 1 << 20];
    let mut left = n;
    while left > 0 {
        let k = left.min(zeros.len() as u64) as usize;
        enc.write_all(&zeros[..k]).unwrap();
        left -= k as u64;
    }
    enc.finish().unwrap()
}

/// #2 / #3: every scenario is a few hundred bytes (or a ~30 KB zstd bomb) declaring up to 4 GiB.
#[test]
fn hostile_containers_fail_fast_with_small_rss() {
    let sink_sha = sha(b"whatever the peer claims");
    let base_kb = hwm_kb();
    let t_all = Instant::now();

    // (a) RAW segment declares 1 GiB but carries 10 bytes: truncated, nothing reserved for the claim.
    let c = container(GIB, &sink_sha, 1, &raw_seg(GIB, &[7u8; 10]));
    let e = expect_err("raw-truncated", decode(&c, GIB, &sink_sha));
    assert!(e.contains("truncated"), "{e}");

    // (b) RAW declares more than the whole remaining budget: rejected before reading anything.
    let c = container(100, &sink_sha, 1, &raw_seg(1 << 40, b""));
    let e = expect_err("raw-over-budget", decode(&c, 100, &sink_sha));
    assert!(e.contains("exceeds budget"), "{e}");

    // (c) DEFLATE segment: small orig_len, 4 GiB plaintext claim (deflate cannot expand >1032:1).
    let mut seg = vec![1u8];
    put64(&mut seg, 10);
    put64(&mut seg, 0);
    put64(&mut seg, 4 * GIB);
    let c = container(GIB, &sink_sha, 1, &seg);
    let e = expect_err("deflate-plain-claim", decode(&c, GIB, &sink_sha));
    assert!(e.contains("exceeds budget"), "{e}");

    // (d) DEFLATE segment: orig_len beyond the budget.
    let mut seg = vec![1u8];
    put64(&mut seg, 4 * GIB);
    let c = container(1000, &sink_sha, 1, &seg);
    expect_err("deflate-orig-claim", decode(&c, 1000, &sink_sha));

    // (e) JPEG segment: huge orig_len / huge lepton length claims.
    let mut seg = vec![2u8];
    put64(&mut seg, 3 * GIB);
    let c = container(GIB, &sink_sha, 1, &seg);
    expect_err("jpeg-orig-claim", decode(&c, GIB, &sink_sha));
    let mut seg = vec![2u8];
    put64(&mut seg, 1000);
    put64(&mut seg, 3 * GIB);
    let c = container(GIB, &sink_sha, 1, &seg);
    expect_err("jpeg-lep-claim", decode(&c, GIB, &sink_sha));

    // (f) PNG segment: absurd chunk count, and chunk lengths that do not fit the region.
    let mut seg = vec![3u8];
    put64(&mut seg, 1 << 30);
    seg.extend_from_slice(&u32::MAX.to_le_bytes());
    let c = container(GIB, &sink_sha, 1, &seg);
    expect_err("png-chunk-count", decode(&c, GIB, &sink_sha));
    let mut seg = vec![3u8];
    put64(&mut seg, 1000);
    seg.extend_from_slice(&2u32.to_le_bytes());
    seg.extend_from_slice(&u32::MAX.to_le_bytes());
    seg.extend_from_slice(&u32::MAX.to_le_bytes());
    let c = container(GIB, &sink_sha, 1, &seg);
    expect_err("png-chunk-lens", decode(&c, GIB, &sink_sha));

    // (g) A crafted Lepton stream whose header asks the decoder for a 4 GiB buffer (`hdrs`), and one
    // whose JPEG frame header declares 60000x60000 px. Both must be refused before Lepton runs.
    for (name, hdr_payload) in [
        ("lepton-hdrs-4gib", {
            let mut h = b"HDR".to_vec();
            h.extend_from_slice(&0xffff_fff0u32.to_le_bytes());
            h
        }),
        ("lepton-60000px", {
            let mut jpeg_hdr = vec![0xff, 0xd8, 0xff, 0xc0, 0, 11, 8, 0xea, 0x60, 0xea, 0x60, 1, 1, 0x11, 0];
            jpeg_hdr.extend_from_slice(&[0xff, 0xda]);
            let mut h = b"HDR".to_vec();
            h.extend_from_slice(&(jpeg_hdr.len() as u32).to_le_bytes());
            h.extend_from_slice(&jpeg_hdr);
            h
        }),
    ] {
        let mut z = ZlibEncoder::new(Vec::new(), Compression::fast());
        z.write_all(&hdr_payload).unwrap();
        let zh = z.finish().unwrap();
        let orig_len = 4096u64;
        let mut lep = vec![0xcf, 0x84, 0x01, b'Z', 1, 0, 0, 0];
        lep.extend_from_slice(&[0u8; 12]);
        lep.extend_from_slice(&(orig_len as u32).to_le_bytes());
        lep.extend_from_slice(&(zh.len() as u32).to_le_bytes());
        lep.extend_from_slice(&zh);
        let mut seg = vec![2u8];
        put64(&mut seg, orig_len);
        put64(&mut seg, lep.len() as u64);
        seg.extend_from_slice(&lep);
        let c = container(orig_len, &sink_sha, 1, &seg);
        let e = expect_err(name, decode(&c, orig_len, &sink_sha));
        eprintln!("[ok] {name}: {e}");
    }

    // (h) A 1 GiB zstd bomb of zeros declared as a 1 GiB RAW segment is *streamed* (64 KiB at a time)
    // into the sink: never buffered, and it ends in a checksum mismatch.
    let mut body = Vec::new();
    body.extend_from_slice(MAGIC);
    body.push(VERSION);
    body.extend_from_slice(&GIB.to_le_bytes());
    body.extend_from_slice(&sink_sha);
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&raw_seg(GIB, b"")[..9]);
    let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
    enc.write_all(&body).unwrap();
    let zeros = vec![0u8; 1 << 20];
    for _ in 0..1024 {
        enc.write_all(&zeros).unwrap();
    }
    let bomb = enc.finish().unwrap();
    let mut out = io::sink();
    let r = decode_to_writer(&bomb, &mut out, GIB, &sink_sha);
    let e = r.expect_err("1 GiB zero stream accepted").0;
    assert!(e.contains("checksum_mismatch"), "{e}");

    // (i) A 256 MiB zstd bomb behind a valid-looking empty container: trailing data is refused after one
    // probe byte instead of decompressing it.
    let mut tail = Vec::new();
    tail.extend_from_slice(MAGIC);
    tail.push(VERSION);
    tail.extend_from_slice(&0u64.to_le_bytes());
    tail.extend_from_slice(&sha(b""));
    tail.extend_from_slice(&0u32.to_le_bytes());
    let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
    enc.write_all(&tail).unwrap();
    for _ in 0..256 {
        enc.write_all(&zeros).unwrap();
    }
    let bomb = enc.finish().unwrap();
    let t = Instant::now();
    let e = expect_err("zstd-tail-bomb", decode(&bomb, 0, &sha(b"")));
    assert!(e.contains("trailing"), "{e}");
    assert!(t.elapsed() < Duration::from_secs(5), "tail bomb took {:?}", t.elapsed());

    // (j) A bare zstd stream of zeros (no container at all) stops at the magic check.
    let bare = zstd_zeros(64 << 20);
    let e = expect_err("bare-zero-stream", decode(&bare, GIB, &sink_sha));
    assert!(e.contains("magic"), "{e}");

    let growth_mb = (hwm_kb().saturating_sub(base_kb)) as f64 / 1024.0;
    eprintln!(
        "[measure] hostile containers: peak RSS growth {growth_mb:.1} MB (VmHWM {} MB), {:?} total",
        hwm_kb() / 1024,
        t_all.elapsed()
    );
    assert!(growth_mb < 96.0, "peak RSS grew by {growth_mb:.1} MB");
    assert!(t_all.elapsed() < Duration::from_secs(60));
}

