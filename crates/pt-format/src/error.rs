//! Error type for PTF reading, writing and validation.

use std::fmt;

/// Everything that can go wrong reading or writing PTF.
///
/// Variants are coarse-grained on purpose: the conformance corpus asserts on the variant
/// (`Error::kind`), so that independent implementations can be compared on *why* a file
/// is rejected, not on message wording.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// The first 8 bytes are not the PTF magic.
    BadMagic,
    /// The file's major version is newer than this reader supports.
    UnsupportedMajor(u16),
    /// A reserved bit is set where readers must reject.
    Reserved(String),
    /// The file ends inside a structure. `offset` is where the incomplete structure starts.
    Truncated {
        offset: u64,
    },
    /// A section's CRC32C does not match.
    Crc {
        offset: u64,
    },
    /// A critical section type unknown to this reader.
    UnknownCritical([u8; 4]),
    /// Section ordering or repetition rules violated.
    Order(String),
    /// A CBOR head violates the deterministic profile.
    Cbor(String),
    /// A table or column is malformed.
    Column(String),
    /// A configured resource limit was exceeded.
    Limit(String),
    /// zstd compression or decompression failed.
    Compression(String),
    /// A known section's head does not match its schema.
    Schema(String),
    /// JSON Lines twin is malformed.
    Json(String),
}

impl Error {
    /// Stable machine-readable name of the variant (used by the conformance corpus).
    pub fn kind(&self) -> &'static str {
        match self {
            Error::Io(_) => "io",
            Error::BadMagic => "bad_magic",
            Error::UnsupportedMajor(_) => "unsupported_major",
            Error::Reserved(_) => "reserved",
            Error::Truncated { .. } => "truncated",
            Error::Crc { .. } => "crc",
            Error::UnknownCritical(_) => "unknown_critical",
            Error::Order(_) => "order",
            Error::Cbor(_) => "cbor",
            Error::Column(_) => "column",
            Error::Limit(_) => "limit",
            Error::Compression(_) => "compression",
            Error::Schema(_) => "schema",
            Error::Json(_) => "json",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::BadMagic => write!(f, "not a PTF file (bad magic)"),
            Error::UnsupportedMajor(m) => write!(f, "PTF major version {m} is not supported"),
            Error::Reserved(s) => write!(f, "reserved field set: {s}"),
            Error::Truncated { offset } => write!(f, "truncated structure at byte {offset}"),
            Error::Crc { offset } => write!(f, "CRC mismatch in section at byte {offset}"),
            Error::UnknownCritical(t) => {
                write!(
                    f,
                    "unknown critical section {:?}",
                    String::from_utf8_lossy(t)
                )
            }
            Error::Order(s) => write!(f, "section order: {s}"),
            Error::Cbor(s) => write!(f, "CBOR: {s}"),
            Error::Column(s) => write!(f, "column: {s}"),
            Error::Limit(s) => write!(f, "limit exceeded: {s}"),
            Error::Compression(s) => write!(f, "compression: {s}"),
            Error::Schema(s) => write!(f, "schema: {s}"),
            Error::Json(s) => write!(f, "JSON Lines: {s}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
