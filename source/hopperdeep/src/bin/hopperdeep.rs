//! Small CLI for the mock node and for honest speed/compression measurements.

use flate2::write::ZlibEncoder;
use flate2::Compression;
use sha2::Digest;
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

fn usage() {
    eprintln!(
        "hopperdeep {}\n\
         usage:\n  hopperdeep version\n  hopperdeep encode <in> <out>\n  hopperdeep decode <in> <out> <osize> <osha-hex>\n  hopperdeep bench [MB ...]   (default: 1 10 100)",
        hopperdeep::version_string()
    );
}

/// Deterministic text-like payload: a compact repeated paragraph with a varying sequence number.
fn text_sample(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut i = 0usize;
    while out.len() < n {
        let line = format!(
            "2026-11-21T06:35:{:02} INFO wasl.sync id=9f3a7c{:04} seq={} ok=true bytes={}\n",
            i % 60, i % 10000, i, 4096 + (i % 9000)
        );
        out.extend_from_slice(line.as_bytes());
        i += 1;
    }
    out.truncate(n);
    out
}

/// Minimal single-page PDF whose content stream is a zlib-compressed copy of `plain`.
fn pdf_with_flate(plain: &[u8], level: u32) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::new(level));
    e.write_all(plain).expect("zlib write");
    let deflated = e.finish().expect("zlib finish");

    let mut pdf = Vec::new();
    let objects: Vec<Vec<u8>> = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>".to_vec(),
        {
            let mut s = Vec::new();
            s.extend_from_slice(
                format!("<< /Length {} /Filter /FlateDecode >>\nstream\n", deflated.len()).as_bytes(),
            );
            s.extend_from_slice(&deflated);
            s.extend_from_slice(b"\nendstream");
            s
        },
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
    ];
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

fn plain_zstd(data: &[u8]) -> Vec<u8> {
    let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 9).expect("zstd encoder");
    let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
    enc.multithread(n as u32).expect("zstd mt");
    enc.write_all(data).expect("zstd write");
    enc.finish().expect("zstd finish")
}

fn bench(sizes_mb: &[usize]) {
    for &mb in sizes_mb {
        let plain = text_sample(mb * 1024 * 1024);
        let pdf = pdf_with_flate(&plain, 6);
        let t0 = Instant::now();
        let packed = hopperdeep::encode(&pdf).expect("deep encode");
        let t_pack = t0.elapsed();
        let t1 = Instant::now();
        let sha: [u8; 32] = sha2::Sha256::digest(&pdf).into();
        let restored = hopperdeep::decode(&packed, pdf.len() as u64, &sha).expect("deep decode");
        let t_unpack = t1.elapsed();
        assert_eq!(restored, pdf, "bench round trip");
        let baseline = plain_zstd(&pdf);
        println!(
            "MB={mb:>3} pdf={:>10} B deep1={:>10} B ({:>5.1}%) plain-zstd={:>10} B ({:>5.1}%) pack={:>7.1} ms unpack={:>7.1} ms",
            pdf.len(),
            packed.len(),
            100.0 * packed.len() as f64 / pdf.len() as f64,
            baseline.len(),
            100.0 * baseline.len() as f64 / pdf.len() as f64,
            t_pack.as_secs_f64() * 1000.0,
            t_unpack.as_secs_f64() * 1000.0,
        );
    }
}

fn read_arg(args: &[String], i: usize) -> PathBuf {
    args.get(i)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            usage();
            std::process::exit(2);
        })
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("version") => println!("{}", hopperdeep::version_string()),
        Some("encode") => {
            let input = read_arg(&args, 2);
            let output = read_arg(&args, 3);
            let packed = hopperdeep::encode_path(&input).expect("encode failed");
            fs::write(&output, packed).expect("write output");
        }
        Some("decode") => {
            let input = read_arg(&args, 2);
            let output = read_arg(&args, 3);
            // osize and osha come from the sealed manifest and are both mandatory.
            let osize: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
                eprintln!("decode needs <osize> and <osha-hex>");
                std::process::exit(2);
            });
            let osha = hopperdeep::parse_sha_hex(args.get(5).map(|s| s.as_str()).unwrap_or("")).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(2);
            });
            hopperdeep::decode_file(&input, &output, osize, &osha).unwrap_or_else(|e| {
                eprintln!("decode failed: {e}");
                std::process::exit(1);
            });
        }
        Some("bench") => {
            let sizes: Vec<usize> = if args.len() > 2 {
                args[2..].iter().map(|s| s.parse().expect("MB number")).collect()
            } else {
                vec![1, 10, 100]
            };
            bench(&sizes);
        }
        _ => usage(),
    }
}
