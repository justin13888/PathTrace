//! PathTrace wire formats: probe packets ([`probe`]) and control messages ([`ctrl`]).
//! Pure encodings, no I/O. Specified in docs/design/probe.md §3.

pub mod ctrl;
pub mod probe;
