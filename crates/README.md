# crates/

Rust workspace members. Each crate owns one responsibility; dependencies flow downward only.

| Crate | Responsibility | `unsafe` | Notes |
|---|---|---|---|
| `pt-format` | Read, write, validate PTF files; JSON Lines twin; Mahimahi/netem import-export | forbidden | Fuzzed. No I/O beyond `Read`/`Write` |
| `pt-wire` | Probe packet header and control-message encodings | forbidden | Fuzzed. Pure |
| `pt-sys` | Linux and macOS syscalls, one backend per OS behind `cfg(target_os)`: sockets, timestamps (`SO_TIMESTAMPING` on Linux), `recvmmsg`/`sendmmsg`, cmsgs, `TCP_INFO`, clocks, netlink; exposes capabilities so no other crate needs `cfg` (ADR 0014) | **allowed** | Every `unsafe` block carries a `// SAFETY:` comment (clippy `undocumented_unsafe_blocks = deny`) |
| `pt-probe` | Session, measurement phases, responder, observation logging | forbidden | Threads only; no async runtime |
| `pt-derive` | Observations → path model | forbidden | Pure functions of the trace's raw layer |
| `pathtrace` | CLI binary | forbidden | `clap`; thin layer over the crates above |

`xtask/` (repository automation) lives at the workspace root, not here.

## Dependency policy

Allowed in measurement code (`pt-sys`, `pt-probe`, `pt-wire`): `libc`, `rustix`, `socket2`, `snow`, `blake3`, `crc32c`, `zstd`, `minicbor`, `rustls` (sync API, TCP/443 class only). Forbidden there (enforced by `deny.toml` where possible): async runtimes (`tokio`, `async-std`, `smol`), protocol stacks (`quinn`, `hyper`, `h2`), packet-batching layers, and shelling out to `ip`/`tc`/`ethtool`/`nft`. Only `xtask` test harness code may invoke those tools, to build ground-truth networks.

Rationale: runtimes and batching layers add timing behaviour that cannot be observed or controlled, which is fatal for a measurement tool.

## Adding a crate

1. Add a row above and in `AGENTS.md`'s crate map.
2. Use `[lints] workspace = true` (forbids `unsafe`); only `pt-sys` overrides this.
3. Add its conventional-commit scope to `.convco` if it needs a new one.
