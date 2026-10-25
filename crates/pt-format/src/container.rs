//! File header, section records, CRC, compression, recovery and INDX
//! (spec Part II §1, §2, §7, §8).

use std::io::Write;

use crate::cbor::{Key, Map, Value};
use crate::error::{Error, Result};
use crate::section::{Body, Section, flags};

pub const MAGIC: [u8; 8] = [0x89, b'P', b'T', b'F', 0x0d, 0x0a, 0x1a, 0x0a];
pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 4;
pub const HEADER_LEN: usize = 16;
const SECTION_HEADER_LEN: usize = 16;

/// Canonical zstd level (spec Part II §7; chosen by EXP-0001).
pub const CANONICAL_ZSTD_LEVEL: i32 = 19;
/// Payloads at or below this size are stored uncompressed by the canonical writer.
pub const CANONICAL_COMPRESS_THRESHOLD: usize = 256;

/// Resource limits for reading untrusted files (spec P10).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum uncompressed payload of one section.
    pub max_section: u64,
    /// Maximum total uncompressed payload of all sections.
    pub max_total: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_section: 1 << 30,
            max_total: 4 << 30,
        }
    }
}

/// Which section types this reader knows (and so may accept as critical).
pub fn is_known_type(kind: &[u8; 4]) -> bool {
    matches!(
        kind,
        b"META"
            | b"FLOW"
            | b"CLOK"
            | b"OBSV"
            | b"CTXS"
            | b"EVNT"
            | b"PLCY"
            | b"PATH"
            | b"SERS"
            | b"VALD"
            | b"INDX"
    )
}

/// Canonical section order (spec Part II §7): known sections by rank, unknown sections after
/// them in their original relative order. Stable, so repeated sections keep their order.
pub fn canonicalize(file: &mut PtfFile) {
    const ORDER: [&[u8; 4]; 10] = [
        b"META", b"FLOW", b"CLOK", b"OBSV", b"CTXS", b"EVNT", b"PLCY", b"PATH", b"SERS", b"VALD",
    ];
    let rank = |k: &[u8; 4]| ORDER.iter().position(|o| *o == k).unwrap_or(ORDER.len());
    file.sections.retain(|s| &s.kind != b"INDX");
    file.sections.sort_by_key(|s| rank(&s.kind));
}

/// A parsed PTF file.
#[derive(Debug, Clone, PartialEq)]
pub struct PtfFile {
    pub major: u16,
    pub minor: u16,
    /// All sections except INDX, in file order.
    pub sections: Vec<Section>,
}

/// Facts about a read that a strict validator reports but a lenient reader tolerates.
#[derive(Debug, Clone, Default)]
pub struct ReadReport {
    /// Byte offset where a recovering read stopped, with the reason, if it stopped early.
    pub stopped: Option<(u64, String)>,
    /// Unknown non-critical section types that were kept but not interpreted.
    pub unknown_sections: Vec<String>,
    /// INDX was present and verified.
    pub index_verified: bool,
    /// Content digest computed while reading.
    pub content_digest: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ReadOptions {
    pub limits: Limits,
    /// Stop at the first incomplete or corrupt section and return what precedes it
    /// (observation logs, spec P7), instead of failing.
    pub recover: bool,
}

fn check_type(kind: &[u8; 4]) -> bool {
    kind.iter()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// Read a PTF file from bytes.
pub fn read(bytes: &[u8], opts: ReadOptions) -> Result<(PtfFile, ReadReport)> {
    if bytes.len() < HEADER_LEN {
        if bytes.len() >= 8 && bytes[..8] != MAGIC {
            return Err(Error::BadMagic);
        }
        return Err(Error::Truncated { offset: 0 });
    }
    if bytes[..8] != MAGIC {
        return Err(Error::BadMagic);
    }
    let major = u16::from_le_bytes([bytes[8], bytes[9]]);
    let minor = u16::from_le_bytes([bytes[10], bytes[11]]);
    let fflags = u32::from_le_bytes(bytes[12..16].try_into().expect("4"));
    if major > MAJOR || major == 0 {
        return Err(Error::UnsupportedMajor(major));
    }
    if fflags != 0 {
        return Err(Error::Reserved(format!("file flags {fflags:#x}")));
    }

    let mut report = ReadReport::default();
    let mut sections = Vec::new();
    let mut digest = blake3::Hasher::new();
    let mut total: u64 = 0;
    let mut pos = HEADER_LEN;
    let mut index: Option<(usize, Section)> = None;

    while pos < bytes.len() {
        let start = pos;
        match read_record(bytes, start, opts.limits, &mut total) {
            Ok((section, payload, end)) => {
                if index.is_some() {
                    return Err(Error::Order("INDX must be the last section".into()));
                }
                if &section.kind == b"INDX" {
                    index = Some((start, section));
                } else {
                    if sections.is_empty() && &section.kind != b"META" {
                        return Err(Error::Order("META must be the first section".into()));
                    }
                    if !sections.is_empty() && &section.kind == b"META" {
                        return Err(Error::Order("META must appear exactly once".into()));
                    }
                    digest_section(&mut digest, &section.kind, section.flags, &payload);
                    if !is_known_type(&section.kind) {
                        report.unknown_sections.push(section.kind_str());
                    }
                    sections.push(section);
                }
                pos = end;
            }
            Err(e @ (Error::Truncated { .. } | Error::Crc { .. })) if opts.recover => {
                report.stopped = Some((start as u64, e.to_string()));
                break;
            }
            Err(e) => return Err(e),
        }
    }
    if sections.is_empty() {
        if opts.recover && report.stopped.is_some() {
            return Err(Error::Truncated {
                offset: HEADER_LEN as u64,
            });
        }
        return Err(Error::Order("file has no META section".into()));
    }
    report.content_digest = digest.finalize().to_hex().to_string();
    if let Some((offset, idx)) = index {
        verify_index(&idx, &bytes[..offset], &report.content_digest)?;
        report.index_verified = true;
    }
    Ok((
        PtfFile {
            major,
            minor,
            sections,
        },
        report,
    ))
}

/// Read one section record at `start`. Returns the section, its uncompressed payload and the
/// offset after the record.
fn read_record(
    bytes: &[u8],
    start: usize,
    limits: Limits,
    total: &mut u64,
) -> Result<(Section, Vec<u8>, usize)> {
    let trunc = Error::Truncated {
        offset: start as u64,
    };
    if bytes.len() - start < SECTION_HEADER_LEN {
        return Err(trunc);
    }
    let h = &bytes[start..start + SECTION_HEADER_LEN];
    let kind: [u8; 4] = h[..4].try_into().expect("4");
    let sflags = u16::from_le_bytes([h[4], h[5]]);
    let reserved = u16::from_le_bytes([h[6], h[7]]);
    let length = u64::from_le_bytes(h[8..16].try_into().expect("8"));
    let remaining = (bytes.len() - start - SECTION_HEADER_LEN) as u64;
    if length > remaining.saturating_sub(4) || remaining < 4 {
        return Err(trunc);
    }
    let length = length as usize;
    let payload_start = start + SECTION_HEADER_LEN;
    let end = payload_start + length + 4;
    let stored_crc = u32::from_le_bytes(bytes[end - 4..end].try_into().expect("4"));
    if crc32c::crc32c(&bytes[start..end - 4]) != stored_crc {
        return Err(Error::Crc {
            offset: start as u64,
        });
    }
    if !check_type(&kind) {
        return Err(Error::Schema(format!(
            "invalid section type bytes {kind:?} at byte {start}"
        )));
    }
    let critical = sflags & flags::CRITICAL != 0;
    let known = is_known_type(&kind);
    if critical && !known {
        return Err(Error::UnknownCritical(kind));
    }
    let unknown_bits = sflags & !flags::KNOWN != 0 || reserved != 0;
    if unknown_bits && critical {
        return Err(Error::Reserved(format!(
            "unknown flag bits {sflags:#x}/reserved {reserved:#x} on critical section {}",
            String::from_utf8_lossy(&kind)
        )));
    }
    let stored = &bytes[payload_start..payload_start + length];
    if unknown_bits {
        // Non-critical section with flags we do not understand: we cannot know how to
        // interpret even the stored bytes; keep them opaque (skip).
        let s = Section {
            kind,
            flags: sflags & !flags::ZSTD,
            body: Body::Opaque(stored.to_vec()),
        };
        return Ok((s, stored.to_vec(), end));
    }
    let payload = if sflags & flags::ZSTD != 0 {
        decompress(stored, limits, total)?
    } else {
        *total += length as u64;
        if length as u64 > limits.max_section || *total > limits.max_total {
            return Err(Error::Limit(format!("section of {length} bytes")));
        }
        stored.to_vec()
    };
    let section = match Section::decode_payload(kind, sflags, &payload) {
        Ok(s) => s,
        // Unknown non-critical sections may (against the spec's SHOULD for the generic
        // structure) not be generic; keep them opaque rather than fail the file.
        Err(_) if !known => Section {
            kind,
            flags: sflags & !flags::ZSTD,
            body: Body::Opaque(payload.clone()),
        },
        Err(e) => return Err(e),
    };
    Ok((section, payload, end))
}

fn decompress(stored: &[u8], limits: Limits, total: &mut u64) -> Result<Vec<u8>> {
    if stored.len() < 8 {
        return Err(Error::Compression(
            "compressed payload shorter than size prefix".into(),
        ));
    }
    let declared = u64::from_le_bytes(stored[..8].try_into().expect("8"));
    if declared > limits.max_section {
        return Err(Error::Limit(format!(
            "declared uncompressed size {declared} exceeds per-section limit {}",
            limits.max_section
        )));
    }
    *total = total.saturating_add(declared);
    if *total > limits.max_total {
        return Err(Error::Limit("total uncompressed size exceeds limit".into()));
    }
    let out = zstd::bulk::decompress(&stored[8..], declared as usize)
        .map_err(|e| Error::Compression(e.to_string()))?;
    if out.len() as u64 != declared {
        return Err(Error::Compression(format!(
            "decompressed {} bytes, declared {declared}",
            out.len()
        )));
    }
    Ok(out)
}

fn digest_section(h: &mut blake3::Hasher, kind: &[u8; 4], sflags: u16, payload: &[u8]) {
    h.update(kind);
    h.update(&(sflags & !flags::ZSTD).to_le_bytes());
    h.update(&(payload.len() as u64).to_le_bytes());
    h.update(payload);
}

fn verify_index(idx: &Section, prefix: &[u8], digest: &str) -> Result<()> {
    let file_hash = idx
        .get("file_blake3")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Schema("INDX missing file_blake3".into()))?;
    if blake3::hash(prefix).to_hex().as_str() != file_hash {
        return Err(Error::Schema(
            "INDX file_blake3 does not match file contents".into(),
        ));
    }
    let cd = idx
        .get("content_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Schema("INDX missing content_digest".into()))?;
    if cd != digest {
        return Err(Error::Schema("INDX content_digest does not match".into()));
    }
    Ok(())
}

/// How to compress when writing.
#[derive(Debug, Clone, Copy)]
pub struct WriteOptions {
    /// zstd level; `None` disables compression.
    pub zstd_level: Option<i32>,
    /// Payloads at or below this size stay uncompressed.
    pub compress_threshold: usize,
    /// Append an INDX section.
    pub index: bool,
}

impl WriteOptions {
    /// The canonical writer settings (spec Part II §7).
    pub fn canonical() -> Self {
        WriteOptions {
            zstd_level: Some(CANONICAL_ZSTD_LEVEL),
            compress_threshold: CANONICAL_COMPRESS_THRESHOLD,
            index: true,
        }
    }

    /// Streaming observation-log settings: fast compression, no index.
    pub fn obslog() -> Self {
        WriteOptions {
            zstd_level: Some(3),
            compress_threshold: CANONICAL_COMPRESS_THRESHOLD,
            index: false,
        }
    }
}

pub fn file_header(major: u16, minor: u16) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(&MAGIC);
    h[8..10].copy_from_slice(&major.to_le_bytes());
    h[10..12].copy_from_slice(&minor.to_le_bytes());
    h
}

/// Encode one section record. Returns (record bytes, uncompressed payload).
pub fn encode_record(s: &Section, opts: &WriteOptions) -> Result<(Vec<u8>, Vec<u8>)> {
    if !check_type(&s.kind) {
        return Err(Error::Schema(format!("invalid section type {:?}", s.kind)));
    }
    let payload = s.encode_payload()?;
    let opaque_unknown_flags = matches!(s.body, Body::Opaque(_)) && s.flags & !flags::KNOWN != 0;
    let (sflags, stored) = match opts.zstd_level {
        Some(level) if payload.len() > opts.compress_threshold && !opaque_unknown_flags => {
            let mut stored = Vec::with_capacity(payload.len() / 2 + 8);
            stored.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            let mut c = zstd::bulk::Compressor::new(level)
                .map_err(|e| Error::Compression(e.to_string()))?;
            // Canonical frames: no checksum, no content size (the size is in our prefix),
            // no dictionary id.
            c.include_checksum(false)
                .and_then(|_| c.include_contentsize(false))
                .and_then(|_| c.include_dictid(false))
                .map_err(|e| Error::Compression(e.to_string()))?;
            stored.extend(
                c.compress(&payload)
                    .map_err(|e| Error::Compression(e.to_string()))?,
            );
            (s.flags | flags::ZSTD, stored)
        }
        _ => (s.flags & !flags::ZSTD, payload.clone()),
    };
    let mut rec = Vec::with_capacity(SECTION_HEADER_LEN + stored.len() + 4);
    rec.extend_from_slice(&s.kind);
    rec.extend_from_slice(&sflags.to_le_bytes());
    rec.extend_from_slice(&0u16.to_le_bytes());
    rec.extend_from_slice(&(stored.len() as u64).to_le_bytes());
    rec.extend_from_slice(&stored);
    let crc = crc32c::crc32c(&rec);
    rec.extend_from_slice(&crc.to_le_bytes());
    Ok((rec, payload))
}

/// Write a complete file. Returns the content digest.
pub fn write(file: &PtfFile, opts: &WriteOptions, out: &mut impl Write) -> Result<String> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&file_header(file.major, file.minor));
    let mut digest = blake3::Hasher::new();
    let mut entries = Vec::with_capacity(file.sections.len());
    for s in &file.sections {
        if &s.kind == b"INDX" {
            continue;
        }
        let offset = buf.len();
        let (rec, payload) = encode_record(s, opts)?;
        digest_section(&mut digest, &s.kind, s.flags, &payload);
        entries.push(
            Value::map()
                .with("type", s.kind_str())
                .with("offset", offset)
                .with("length", rec.len()),
        );
        buf.extend(rec);
    }
    let content_digest = digest.finalize().to_hex().to_string();
    if opts.index {
        let mut head = Map::new();
        head.insert(Key::from("sections"), Value::Array(entries));
        head.insert(
            Key::from("file_blake3"),
            Value::from(blake3::hash(&buf).to_hex().to_string()),
        );
        head.insert(
            Key::from("content_digest"),
            Value::from(content_digest.clone()),
        );
        let idx = Section::new(b"INDX", 0, head);
        let no_compress = WriteOptions {
            zstd_level: None,
            ..*opts
        };
        let (rec, _) = encode_record(&idx, &no_compress)?;
        buf.extend(rec);
    }
    out.write_all(&buf)?;
    Ok(content_digest)
}

/// Append-only writer for crash-safe observation logs (spec P7). Every `append` writes one
/// complete section record and, if `sync` is set, flushes and fsyncs.
#[derive(Debug)]
pub struct AppendWriter {
    file: std::fs::File,
    opts: WriteOptions,
    sync: bool,
}

impl AppendWriter {
    /// Create a new log file with the given META section.
    pub fn create(path: &std::path::Path, meta: &Section, sync: bool) -> Result<Self> {
        if &meta.kind != b"META" {
            return Err(Error::Order("first appended section must be META".into()));
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(&file_header(MAJOR, MINOR))?;
        let mut w = AppendWriter {
            file,
            opts: WriteOptions::obslog(),
            sync,
        };
        w.append(meta)?;
        Ok(w)
    }

    pub fn append(&mut self, s: &Section) -> Result<()> {
        let (rec, _) = encode_record(s, &self.opts)?;
        self.file.write_all(&rec)?;
        if self.sync {
            self.file.sync_data()?;
        }
        Ok(())
    }

    pub fn finish(self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::column::{Column, Enc, Values};
    use crate::section::Table;

    fn sample() -> PtfFile {
        let meta = Section::new(
            b"META",
            flags::CRITICAL,
            Value::map().with("kind", "trace").as_map().unwrap().clone(),
        );
        let times: Vec<u64> = (0..5000)
            .map(|i| 1_000_000 + i * 120_000 + (i * 7919) % 1000)
            .collect();
        let obsv = Section::new(b"OBSV", 0, Map::new()).with_table(
            Table::new("pkt", times.len())
                .with(Column::new("tx", Enc::Delta2, Values::U64(times.clone())).clock("a.real")),
        );
        PtfFile {
            major: MAJOR,
            minor: MINOR,
            sections: vec![meta, obsv],
        }
    }

    #[test]
    fn write_read_roundtrip_canonical() {
        let f = sample();
        let mut a = Vec::new();
        let d1 = write(&f, &WriteOptions::canonical(), &mut a).unwrap();
        let (back, rep) = read(&a, ReadOptions::default()).unwrap();
        assert_eq!(back, f);
        assert!(rep.index_verified);
        assert_eq!(rep.content_digest, d1);
        let mut b = Vec::new();
        write(&back, &WriteOptions::canonical(), &mut b).unwrap();
        assert_eq!(a, b, "canonical encoding must be byte-identical");
        // Digest is independent of compression.
        let mut c = Vec::new();
        let d2 = write(
            &f,
            &WriteOptions {
                zstd_level: None,
                compress_threshold: 0,
                index: true,
            },
            &mut c,
        )
        .unwrap();
        assert_eq!(d1, d2);
        assert_ne!(a, c);
    }

    #[test]
    fn truncation_recovery_keeps_complete_sections() {
        let f = sample();
        let mut a = Vec::new();
        write(&f, &WriteOptions::obslog(), &mut a).unwrap();
        let (_, meta_len) = {
            let (rec, _) = encode_record(&f.sections[0], &WriteOptions::obslog()).unwrap();
            ((), rec.len())
        };
        for cut in HEADER_LEN + meta_len + 1..a.len() {
            let (got, rep) = read(
                &a[..cut],
                ReadOptions {
                    recover: true,
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(got.sections.len(), 1, "cut at {cut}");
            assert!(rep.stopped.is_some());
            assert!(read(&a[..cut], ReadOptions::default()).is_err());
        }
    }

    #[test]
    fn rejections() {
        let f = sample();
        let mut a = Vec::new();
        write(&f, &WriteOptions::canonical(), &mut a).unwrap();
        // bad magic
        let mut b = a.clone();
        b[1] = b'X';
        assert_eq!(
            read(&b, ReadOptions::default()).unwrap_err().kind(),
            "bad_magic"
        );
        // higher major
        let mut b = a.clone();
        b[8] = 2;
        assert_eq!(
            read(&b, ReadOptions::default()).unwrap_err().kind(),
            "unsupported_major"
        );
        // higher minor accepted
        let mut b = a.clone();
        b[10] = 9;
        assert!(
            read(&b, ReadOptions::default()).is_err(),
            "INDX hash covers the header"
        );
        // flipped payload bit
        let mut b = a.clone();
        b[HEADER_LEN + 20] ^= 1;
        assert_eq!(read(&b, ReadOptions::default()).unwrap_err().kind(), "crc");
    }

    #[test]
    fn unknown_sections() {
        let mut f = sample();
        f.sections.push(Section::new(
            b"ZZZZ",
            0,
            Value::map().with("x", 1u64).as_map().unwrap().clone(),
        ));
        let mut a = Vec::new();
        write(&f, &WriteOptions::canonical(), &mut a).unwrap();
        let (back, rep) = read(&a, ReadOptions::default()).unwrap();
        assert_eq!(rep.unknown_sections, vec!["ZZZZ"]);
        assert_eq!(back, f);
        f.sections.last_mut().unwrap().flags = flags::CRITICAL;
        let mut a = Vec::new();
        write(&f, &WriteOptions::canonical(), &mut a).unwrap();
        assert_eq!(
            read(&a, ReadOptions::default()).unwrap_err().kind(),
            "unknown_critical"
        );
    }

    #[test]
    fn decompression_bomb_guard() {
        let f = sample();
        let mut a = Vec::new();
        write(&f, &WriteOptions::canonical(), &mut a).unwrap();
        let limits = Limits {
            max_section: 1000,
            max_total: 1 << 20,
        };
        assert_eq!(
            read(
                &a,
                ReadOptions {
                    limits,
                    recover: false
                }
            )
            .unwrap_err()
            .kind(),
            "limit"
        );
    }
}
