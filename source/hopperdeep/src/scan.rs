//! Container scanners: turn a byte buffer into an ordered list of [`Span`]s.
//!
//! A `Span` is either verbatim bytes (`Raw`) or a transformable region whose exact byte extent was
//! located by parsing the container's own structure. Scanners are deliberately conservative: if a
//! length is ambiguous we leave bytes `Raw` rather than risk corrupting the reconstruction. Every
//! loop advances monotonically and all offsets are checked, so malformed/truncated input cannot
//! loop forever or panic.

use crate::transform::valid_zlib_header;

/// A contiguous transformable region, described by absolute byte offsets into the source buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Span {
    /// Copy `data[start..end]` verbatim.
    Raw { start: usize, end: usize },
    /// Raw DEFLATE bytes (no zlib header/trailer) at `data[start..end]`.
    /// `adler` is the original zlib trailer (when the wrapper was a zlib stream) and is used to
    /// verify the boundary we stripped before trusting the preflate result.
    Deflate {
        start: usize,
        end: usize,
        adler: Option<[u8; 4]>,
    },
    /// A baseline/progressive JPEG at `data[start..end]`.
    Jpeg { start: usize, end: usize },
    /// A whole PNG IDAT chunk run: `data[region_start..region_end]` including chunk framing.
    /// `data_spans` are the (start,end) of each IDAT chunk's data field, in order.
    PngIdat {
        region_start: usize,
        region_end: usize,
        data_spans: Vec<(usize, usize)>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Raw,
    Pdf,
    Png,
    Zip,
    Jpeg,
    Gzip,
}

/// Detect by magic bytes, not by extension (the caller may pass an opaque path).
fn detect(data: &[u8]) -> Format {
    if data.starts_with(b"%PDF-") {
        Format::Pdf
    } else if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        Format::Png
    } else if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        Format::Zip
    } else if data.starts_with(b"\xff\xd8\xff") {
        Format::Jpeg
    } else if data.starts_with(b"\x1f\x8b\x08") {
        Format::Gzip
    } else {
        Format::Raw
    }
}

/// Top-level scan dispatch.
pub(crate) fn scan(data: &[u8]) -> Vec<Span> {
    match detect(data) {
        Format::Pdf => scan_pdf(data),
        Format::Png => scan_png(data),
        Format::Zip => scan_zip(data),
        Format::Jpeg => vec![Span::Jpeg {
            start: 0,
            end: data.len(),
        }],
        Format::Gzip => scan_gzip(data),
        Format::Raw => vec![Span::Raw {
            start: 0,
            end: data.len(),
        }],
    }
}

// ------------------------------------------------------------------ byte helpers

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from > haystack.len() || needle.len() > haystack.len() - from {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Advance past one optional EOL (CR, LF or CRLF) starting at `p`.
fn skip_eol(data: &[u8], mut p: usize) -> usize {
    if data.get(p) == Some(&b'\r') {
        p += 1;
        if data.get(p) == Some(&b'\n') {
            p += 1;
        }
    } else if data.get(p) == Some(&b'\n') {
        p += 1;
    }
    p
}

/// Consume a trailing EOL immediately before `endstream`/`endstream`-like token.
fn trim_before(data: &[u8], end: usize, start: usize) -> usize {
    if end > start && data[end - 1] == b'\n' {
        let mut e = end - 1;
        if e > start && data[e - 1] == b'\r' {
            e -= 1;
        }
        e
    } else if end > start && data[end - 1] == b'\r' {
        end - 1
    } else {
        end
    }
}

// ------------------------------------------------------------------ PDF

/// Parse a direct numeric `/Length` from a stream dictionary. Indirect references return None.
fn pdf_length(dict: &[u8]) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = find(dict, b"/Length", from) {
        let p = rel + 7;
        let mut q = p;
        while q < dict.len() && dict[q].is_ascii_whitespace() {
            q += 1;
        }
        let digits_start = q;
        while q < dict.len() && dict[q].is_ascii_digit() {
            q += 1;
        }
        if q > digits_start {
            if let Ok(s) = std::str::from_utf8(&dict[digits_start..q]) {
                if let Ok(n) = s.parse::<usize>() {
                    return Some(n);
                }
            }
        }
        // `/Length 12 0 R` is indirect: do not trust the first number. Continue searching in
        // case a later direct /Length exists; otherwise None triggers the header scan fallback.
        from = p;
    }
    None
}

fn scan_pdf(data: &[u8]) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut raw_start = 0usize;
    let mut i = 0usize;

    while let Some(rel) = find(data, b"stream", i) {
        let kw = rel;
        // Reject `endstream`, identifiers containing "stream", and non-keyword occurrences.
        if kw > 0 && is_word(data[kw - 1]) {
            i = kw + 6;
            continue;
        }
        let after = kw + 6;
        if after >= data.len() {
            break;
        }
        let ds = skip_eol(data, after);
        if ds == after {
            // Not followed by an EOL: `stream` here is not a real stream keyword.
            i = after;
            continue;
        }

        // Look back a bounded window for the enclosing dictionary.
        let lookback = ds.saturating_sub(8192);
        let dict_start = data[lookback..kw]
            .windows(2)
            .rposition(|w| w == b"<<")
            .map(|p| lookback + p)
            .unwrap_or(lookback);
        let dict = &data[dict_start..kw];
        let flate = find(dict, b"/FlateDecode", 0).is_some();
        let dct = find(dict, b"/DCTDecode", 0).is_some();
        // Predictors need the zlib layer untouched; leave those streams RAW.
        let predictor = find(dict, b"/DecodeParms", 0).is_some()
            || find(dict, b"/Predictor", 0).is_some();

        // Determine the exact stream data extent.
        let mut end_opt = None;
        if !predictor {
            if let Some(len) = pdf_length(dict) {
                if let Some(e) = ds.checked_add(len) {
                    if e <= data.len() {
                        let mut p = skip_eol(data, e);
                        if data[p..].starts_with(b"endstream") {
                            end_opt = Some(e);
                        } else if p == e && data.get(e) == Some(&b'\r') {
                            p = skip_eol(data, e + 1);
                            if data[p..].starts_with(b"endstream") {
                                end_opt = Some(e);
                            }
                        }
                    }
                }
            }
            if end_opt.is_none() {
                // Indirect or ambiguous /Length: scan for endstream, then trim its leading EOL.
                if let Some(p) = find(data, b"endstream", ds) {
                    end_opt = Some(trim_before(data, p, ds));
                }
            }
        }

        if let Some(end) = end_opt {
            if flate && !predictor && end >= ds + 6 {
                let header = &data[ds..ds + 2];
                if valid_zlib_header(header) {
                    // Store the 2-byte zlib header and 4-byte Adler trailer as RAW; only the raw
                    // DEFLATE payload is preflated.
                    if raw_start < ds + 2 {
                        spans.push(Span::Raw {
                            start: raw_start,
                            end: ds + 2,
                        });
                    }
                    let adler = [data[end - 4], data[end - 3], data[end - 2], data[end - 1]];
                    spans.push(Span::Deflate {
                        start: ds + 2,
                        end: end - 4,
                        adler: Some(adler),
                    });
                    raw_start = end - 4;
                }
            } else if dct && end > ds && data[ds..].starts_with(&[0xff, 0xd8]) {
                if raw_start < ds {
                    spans.push(Span::Raw {
                        start: raw_start,
                        end: ds,
                    });
                }
                spans.push(Span::Jpeg { start: ds, end });
                raw_start = end;
            }
            i = end.max(after);
        } else {
            i = after;
        }
    }

    if raw_start < data.len() {
        spans.push(Span::Raw {
            start: raw_start,
            end: data.len(),
        });
    }
    spans
}

// ------------------------------------------------------------------ ZIP family

/// Local file headers + data descriptors. Headers and framing stay RAW so reconstruction is
/// byte-for-byte; only deflate entries and stored JPEG entries become transformable spans.
fn scan_zip(data: &[u8]) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut raw_start = 0usize;
    let mut i = 0usize;

    while let Some(rel) = find(data, b"PK\x03\x04", i) {
        let p = rel;
        if p + 30 > data.len() {
            break;
        }
        let flags = le16(data, p + 6).unwrap_or(0);
        let method = le16(data, p + 8).unwrap_or(0);
        let comp_size = le32(data, p + 18).unwrap_or(0) as usize;
        let fn_len = le16(data, p + 26).unwrap_or(0) as usize;
        let ex_len = le16(data, p + 28).unwrap_or(0) as usize;
        let ds = match p.checked_add(30).and_then(|x| x.checked_add(fn_len)).and_then(|x| x.checked_add(ex_len)) {
            Some(v) if v <= data.len() => v,
            _ => {
                i = p + 4;
                continue;
            }
        };

        // With a data descriptor (bit 3) or an unknown size, locate `PK\x07\x08` after the data.
        // A bounded forward scan is safe: the next local header / central directory is close.
        let data_end = if flags & 0x08 != 0 || comp_size == 0 {
            find(data, b"PK\x07\x08", ds).unwrap_or(data.len())
        } else {
            ds.checked_add(comp_size).map(|e| e.min(data.len())).unwrap_or(data.len())
        };
        if data_end < ds {
            i = p + 4;
            continue;
        }

        if method == 8 && data_end > ds {
            // ZIP uses raw DEFLATE (no zlib wrapper).
            if raw_start < ds {
                spans.push(Span::Raw { start: raw_start, end: ds });
            }
            spans.push(Span::Deflate { start: ds, end: data_end, adler: None });
            raw_start = data_end;
        } else if method == 0 && data_end > ds && data[ds..].starts_with(&[0xff, 0xd8]) {
            if raw_start < ds {
                spans.push(Span::Raw { start: raw_start, end: ds });
            }
            spans.push(Span::Jpeg { start: ds, end: data_end });
            raw_start = data_end;
        }
        i = data_end.max(p + 4);
    }

    if raw_start < data.len() {
        spans.push(Span::Raw {
            start: raw_start,
            end: data.len(),
        });
    }
    spans
}

// ------------------------------------------------------------------ PNG

fn scan_png(data: &[u8]) -> Vec<Span> {
    // Signature is 8 bytes. Walk chunks: length(4) + type(4) + data + CRC(4).
    let mut i = 8usize;
    let mut data_spans: Vec<(usize, usize)> = Vec::new();
    let mut region_start = usize::MAX;
    let mut region_end = 0usize;

    while i + 8 <= data.len() {
        let len = match be32(data, i) {
            Some(v) => v as usize,
            None => break,
        };
        let ds = i + 8;
        let de = match ds.checked_add(len) {
            Some(v) if v + 4 <= data.len() => v,
            _ => break,
        };
        let chunk_end = de + 4;
        if &data[i + 4..i + 8] == b"IDAT" {
            if data_spans.is_empty() {
                region_start = i; // include the first chunk's length field
            }
            data_spans.push((ds, de));
            region_end = chunk_end;
        }
        i = chunk_end;
    }

    if data_spans.is_empty() {
        return vec![Span::Raw {
            start: 0,
            end: data.len(),
        }];
    }

    let mut spans = Vec::new();
    if region_start > 0 {
        spans.push(Span::Raw {
            start: 0,
            end: region_start,
        });
    }
    spans.push(Span::PngIdat {
        region_start,
        region_end,
        data_spans,
    });
    if region_end < data.len() {
        spans.push(Span::Raw {
            start: region_end,
            end: data.len(),
        });
    }
    spans
}

// ------------------------------------------------------------------ gzip

fn scan_gzip(data: &[u8]) -> Vec<Span> {
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 8 {
        return vec![Span::Raw { start: 0, end: data.len() }];
    }
    let flg = data[3];
    let mut p = 10usize;
    if flg & 0x04 != 0 {
        // FEXTRA
        let Some(xlen) = le16(data, p) else {
            return vec![Span::Raw { start: 0, end: data.len() }];
        };
        p += 2;
        if p + xlen as usize > data.len() {
            return vec![Span::Raw { start: 0, end: data.len() }];
        }
        p += xlen as usize;
    }
    if flg & 0x08 != 0 {
        // FNAME
        while p < data.len() && data[p] != 0 {
            p += 1;
        }
        p += 1;
    }
    if flg & 0x10 != 0 {
        // FCOMMENT
        while p < data.len() && data[p] != 0 {
            p += 1;
        }
        p += 1;
    }
    if flg & 0x02 != 0 {
        // FHCRC
        p += 2;
    }
    let deflate_end = data.len() - 8;
    if p >= deflate_end || p == 0 {
        return vec![Span::Raw { start: 0, end: data.len() }];
    }
    let mut spans = Vec::new();
    if p > 0 {
        spans.push(Span::Raw { start: 0, end: p });
    }
    spans.push(Span::Deflate { start: p, end: deflate_end, adler: None });
    spans.push(Span::Raw { start: deflate_end, end: data.len() });
    spans
}
