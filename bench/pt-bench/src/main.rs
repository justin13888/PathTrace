//! Evidence experiments needing comparison dependencies.
//!
//! `pt-bench bakeoff`: EXP-0001, encoding bake-off for the PTF raw per-packet layer
//! (ADR 0011, docs/design/ptf-format.md P2/P3/P4/§7).

mod synth;

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use arrow_array::{RecordBatch, UInt64Array};
use arrow_ipc::writer::{FileWriter, IpcWriteOptions};
use arrow_schema::{DataType, Field, Schema};
use clap::{Parser, Subcommand};
use pt_format::{
    Column, Enc, Map, PtfFile, ReadOptions, Section, Table, Value, Values, WriteOptions, flags,
};

use synth::{Pkt, SCENARIOS};

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// EXP-0001: encoding bake-off. Writes results.csv and summary.txt to --out.
    Bakeoff {
        #[arg(long, env = "PT_EVIDENCE_OUT")]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Bakeoff { out } => bakeoff(&out),
    }
}

#[derive(Debug, Clone)]
struct Row {
    scenario: &'static str,
    candidate: String,
    packets: usize,
    bytes: usize,
    encode_ms: f64,
    decode_ms: f64,
}

impl Row {
    fn bpp(&self) -> f64 {
        self.bytes as f64 / self.packets as f64
    }
}

#[derive(Debug, Clone, Copy)]
struct PtfVariant {
    time_enc: Enc,
    /// Divide all timestamps by this before encoding (1 = ns, 1000 = µs).
    quant: u64,
    chunk: usize,
    level: i32,
    plain: bool,
}

impl PtfVariant {
    fn name(&self) -> String {
        if self.plain {
            return format!("ptf-plain/zstd{}/chunk{}", self.level, self.chunk);
        }
        format!(
            "ptf-{}/{}/zstd{}/chunk{}",
            self.time_enc.name(),
            if self.quant == 1 { "ns" } else { "us" },
            self.level,
            self.chunk
        )
    }
}

const CANONICAL: PtfVariant = PtfVariant {
    time_enc: Enc::Delta2,
    quant: 1,
    chunk: 65_536,
    level: 19,
    plain: false,
};

fn ptf_tables(pkts: &[Pkt], v: &PtfVariant) -> Vec<Table> {
    let mut tables = Vec::new();
    for chunk in pkts.chunk_by(|a, b| a.flow == b.flow) {
        for part in chunk.chunks(v.chunk) {
            let q = |x: u64| x / v.quant;
            let (int_enc, time_enc, small_enc) = if v.plain {
                (Enc::Plain, Enc::Plain, Enc::Plain)
            } else {
                (Enc::Delta, v.time_enc, Enc::Rle)
            };
            let col =
                |name: &str, enc: Enc, vals: Vec<u64>| Column::new(name, enc, Values::U64(vals));
            let nul = |name: &str, enc: Enc, vals: Vec<Option<u64>>| {
                Column::nullable_u64(name, enc, &vals)
            };
            let t = Table::new("pkt", part.len())
                .with(col(
                    "flow",
                    small_enc,
                    part.iter().map(|p| p.flow).collect(),
                ))
                .with(col("seq", int_enc, part.iter().map(|p| p.seq).collect()))
                .with(col(
                    "size",
                    small_enc,
                    part.iter().map(|p| p.size).collect(),
                ))
                .with(col(
                    "tx_intended",
                    time_enc,
                    part.iter().map(|p| q(p.tx_intended)).collect(),
                ))
                .with(col("tx", time_enc, part.iter().map(|p| q(p.tx)).collect()))
                .with(nul(
                    "rx",
                    time_enc,
                    part.iter().map(|p| p.rx.map(q)).collect(),
                ))
                .with(nul("tos", small_enc, part.iter().map(|p| p.tos).collect()))
                .with(nul("ttl", small_enc, part.iter().map(|p| p.ttl).collect()))
                .with(col(
                    "phase",
                    small_enc,
                    part.iter().map(|p| p.phase).collect(),
                ));
            tables.push(t);
        }
    }
    tables
}

fn ptf_file(pkts: &[Pkt], v: &PtfVariant) -> PtfFile {
    let meta = Section::new(
        b"META",
        flags::CRITICAL,
        Value::map()
            .with("kind", "trace")
            .as_map()
            .cloned()
            .unwrap_or_default(),
    );
    let mut sections = vec![meta];
    for t in ptf_tables(pkts, v) {
        sections.push(Section::new(b"OBSV", 0, Map::new()).with_table(t));
    }
    PtfFile {
        major: 1,
        minor: 0,
        sections,
    }
}

fn run_ptf(pkts: &[Pkt], v: &PtfVariant) -> Result<(usize, f64, f64)> {
    let t0 = Instant::now();
    let f = ptf_file(pkts, v);
    let mut buf = Vec::new();
    let opts = WriteOptions {
        zstd_level: Some(v.level),
        compress_threshold: 256,
        index: true,
    };
    pt_format::write(&f, &opts, &mut buf)?;
    let enc = t0.elapsed().as_secs_f64() * 1e3;
    let t1 = Instant::now();
    let (back, _) = pt_format::read(&buf, ReadOptions::default())?;
    let dec = t1.elapsed().as_secs_f64() * 1e3;
    anyhow::ensure!(back == f, "PTF round trip mismatch for {}", v.name());
    Ok((buf.len(), enc, dec))
}

fn jsonl(pkts: &[Pkt]) -> Vec<u8> {
    let mut s = String::new();
    for p in pkts {
        let o = |x: Option<u64>| x.map_or("null".to_string(), |v| v.to_string());
        let _ = writeln!(
            s,
            r#"{{"flow":{},"seq":{},"size":{},"tx_intended":{},"tx":{},"rx":{},"tos":{},"ttl":{},"phase":{}}}"#,
            p.flow,
            p.seq,
            p.size,
            p.tx_intended,
            p.tx,
            o(p.rx),
            o(p.tos),
            o(p.ttl),
            p.phase
        );
    }
    s.into_bytes()
}

fn run_jsonl(pkts: &[Pkt], level: i32) -> Result<(usize, f64, f64)> {
    let t0 = Instant::now();
    let raw = jsonl(pkts);
    let z = zstd::bulk::compress(&raw, level)?;
    let enc = t0.elapsed().as_secs_f64() * 1e3;
    let t1 = Instant::now();
    let back = zstd::bulk::decompress(&z, raw.len())?;
    let n = back
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(serde_json::from_slice::<serde_json::Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?
        .len();
    let dec = t1.elapsed().as_secs_f64() * 1e3;
    anyhow::ensure!(n == pkts.len());
    Ok((z.len(), enc, dec))
}

fn run_cbor_rows(pkts: &[Pkt], level: i32) -> Result<(usize, f64, f64)> {
    let t0 = Instant::now();
    let rows: Vec<Value> = pkts
        .iter()
        .map(|p| {
            Value::Array(vec![
                p.flow.into(),
                p.seq.into(),
                p.size.into(),
                p.tx_intended.into(),
                p.tx.into(),
                p.rx.into(),
                p.tos.into(),
                p.ttl.into(),
                p.phase.into(),
            ])
        })
        .collect();
    let raw = pt_format::cbor::encode(&Value::Array(rows))?;
    let z = zstd::bulk::compress(&raw, level)?;
    let enc = t0.elapsed().as_secs_f64() * 1e3;
    let t1 = Instant::now();
    let back = pt_format::cbor::decode(&zstd::bulk::decompress(&z, raw.len())?)?;
    let dec = t1.elapsed().as_secs_f64() * 1e3;
    anyhow::ensure!(back.as_array().map(<[Value]>::len) == Some(pkts.len()));
    Ok((z.len(), enc, dec))
}

fn run_arrow(pkts: &[Pkt], chunk: usize) -> Result<(usize, f64, f64)> {
    let t0 = Instant::now();
    let names = [
        "flow",
        "seq",
        "size",
        "tx_intended",
        "tx",
        "rx",
        "tos",
        "ttl",
        "phase",
    ];
    let nullable = |n: &str| matches!(n, "rx" | "tos" | "ttl");
    let schema = Arc::new(Schema::new(
        names
            .iter()
            .map(|n| Field::new(*n, DataType::UInt64, nullable(n)))
            .collect::<Vec<_>>(),
    ));
    let opts =
        IpcWriteOptions::default().try_with_compression(Some(arrow_ipc::CompressionType::ZSTD))?;
    let mut buf = Vec::new();
    {
        let mut w = FileWriter::try_new_with_options(&mut buf, &schema, opts)?;
        for part in pkts.chunks(chunk) {
            let col = |f: fn(&Pkt) -> u64| {
                Arc::new(UInt64Array::from_iter_values(part.iter().map(f))) as _
            };
            let ocol = |f: fn(&Pkt) -> Option<u64>| {
                Arc::new(UInt64Array::from_iter(part.iter().map(f))) as _
            };
            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![
                    col(|p| p.flow),
                    col(|p| p.seq),
                    col(|p| p.size),
                    col(|p| p.tx_intended),
                    col(|p| p.tx),
                    ocol(|p| p.rx),
                    ocol(|p| p.tos),
                    ocol(|p| p.ttl),
                    col(|p| p.phase),
                ],
            )?;
            w.write(&batch)?;
        }
        w.finish()?;
    }
    let enc = t0.elapsed().as_secs_f64() * 1e3;
    let t1 = Instant::now();
    let r = arrow_ipc::reader::FileReader::try_new(std::io::Cursor::new(&buf), None)?;
    let mut n = 0;
    for b in r {
        n += b?.num_rows();
    }
    let dec = t1.elapsed().as_secs_f64() * 1e3;
    anyhow::ensure!(n == pkts.len());
    Ok((buf.len(), enc, dec))
}

fn bakeoff(out: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(out)?;
    let mut rows = Vec::new();
    let mut variants = vec![CANONICAL];
    for level in [3, 9] {
        variants.push(PtfVariant { level, ..CANONICAL });
    }
    for chunk in [16_384, 262_144] {
        variants.push(PtfVariant { chunk, ..CANONICAL });
    }
    variants.push(PtfVariant {
        time_enc: Enc::Delta,
        ..CANONICAL
    });
    variants.push(PtfVariant {
        quant: 1000,
        ..CANONICAL
    });
    variants.push(PtfVariant {
        plain: true,
        ..CANONICAL
    });

    for sc in SCENARIOS {
        let pkts = synth::generate(sc);
        let n = pkts.len();
        eprintln!("{}: {n} packets", sc.name);
        let mut push = |candidate: String, (bytes, encode_ms, decode_ms): (usize, f64, f64)| {
            rows.push(Row {
                scenario: sc.name,
                candidate,
                packets: n,
                bytes,
                encode_ms,
                decode_ms,
            });
        };
        for v in &variants {
            push(v.name(), run_ptf(&pkts, v)?);
        }
        for level in [3, 19] {
            push(format!("jsonl/zstd{level}"), run_jsonl(&pkts, level)?);
            push(
                format!("cbor-rows/zstd{level}"),
                run_cbor_rows(&pkts, level)?,
            );
        }
        push(
            "arrow-ipc/zstd(default)/chunk65536".into(),
            run_arrow(&pkts, 65_536)?,
        );
    }

    let mut csv =
        String::from("scenario,candidate,packets,bytes,bytes_per_packet,encode_ms,decode_ms\n");
    for r in &rows {
        let _ = writeln!(
            csv,
            "{},{},{},{},{:.3},{:.1},{:.1}",
            r.scenario,
            r.candidate,
            r.packets,
            r.bytes,
            r.bpp(),
            r.encode_ms,
            r.decode_ms
        );
    }
    std::fs::write(out.join("results.csv"), &csv)?;

    // Hypothesis (experiment.toml): the canonical PTF variant (delta2, ns, chunk 65536,
    // zstd 19) is <= 8 B/packet in every scenario, is no more than 10% larger than the
    // smallest *lossless* candidate in every scenario (µs quantisation is lossy and is
    // reported only to quantify the cost of keeping ns, P4), and encodes the largest
    // scenario in <= 10 s.
    let mut summary = String::new();
    let mut pass = true;
    for sc in SCENARIOS {
        let of = |c: &str| {
            rows.iter()
                .find(|r| r.scenario == sc.name && r.candidate == c)
                .cloned()
        };
        let canon = of(&CANONICAL.name()).expect("canonical row");
        let best = rows
            .iter()
            .filter(|r| r.scenario == sc.name && !r.candidate.contains("/us/"))
            .min_by(|a, b| a.bytes.cmp(&b.bytes))
            .expect("rows");
        let ok_budget = canon.bpp() <= 8.0;
        let ok_rel = canon.bytes as f64 <= best.bytes as f64 * 1.10;
        let ok_time = canon.encode_ms <= 10_000.0;
        pass &= ok_budget && ok_rel && ok_time;
        let _ = writeln!(
            summary,
            "{}: packets={} canonical={:.3} B/pkt (budget<=8: {}), smallest-lossless={} {:.3} B/pkt (within 10%: {}), canonical encode {:.0} ms (<=10s: {})",
            sc.name,
            canon.packets,
            canon.bpp(),
            ok_budget,
            best.candidate,
            best.bpp(),
            ok_rel,
            canon.encode_ms,
            ok_time
        );
    }
    let _ = writeln!(summary, "verdict: {}", if pass { "pass" } else { "fail" });
    print!("{summary}");
    std::fs::write(out.join("summary.txt"), &summary)?;
    std::process::exit(if pass { 0 } else { 1 });
}
