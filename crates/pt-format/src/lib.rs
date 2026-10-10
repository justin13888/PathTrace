//! PTF (Path Trace Format) 1.0: reader, writer and validator.
//!
//! The normative specification is `docs/design/ptf-format.md`. Module map:
//! - [`cbor`]: deterministic CBOR profile for section heads.
//! - [`column`]: column types and encodings.
//! - [`section`]: tables and the generic section payload.
//! - [`container`]: file header, section records, compression, recovery, INDX.
//! - [`jsonl`]: lossless JSON Lines twin.

pub mod cbor;
pub mod column;
pub mod container;
pub mod error;
pub mod jsonl;
pub mod section;

pub use cbor::{Key, Map, Value};
pub use column::{ColType, Column, Data, Enc, Values};
pub use container::{
    AppendWriter, Limits, PtfFile, ReadOptions, ReadReport, WriteOptions, read, write,
};
pub use error::{Error, Result};
pub use section::{Body, Section, Table, flags};
