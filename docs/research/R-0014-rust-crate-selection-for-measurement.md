# R-0014: Rust crate selection for sync measurement code
- source: crates.io metadata and source of the listed crates (2026-10-10); local test programs
- accessed: 2026-10-10
- claim-under-test: Existing crates cover mmsg, cmsg parsing, Noise IKpsk2 and netlink without an async runtime.
- verdict: confirmed
- applicability: Dependency choices under ADR 0007 (no async runtime) and REQ-SEC-005.
## Evidence

Tested on Fedora 44, kernel 7.2.4, rustc 1.99; experiment programs were throwaway (not committed).

### 7. Rust crates (crates.io, checked 2026-10-10)

| Crate | Version | Verdict |
|---|---|---|
| libc | 0.2.190 | **Use.** Has recvmmsg/sendmmsg, sock_extended_err, SO_EE_*, SOF_TIMESTAMPING_* (no TX_COMPLETION), IP(V6)_RECVERR, IP_MTU, PMTUDISC_*, UDP_GRO/SEGMENT, TCP_SAVE(D)_SYN, RTMGRP_*, hwtstamp_config. Missing: scm_timestamping, SCM_TSTAMP_*, SCM_TS_OPT_ID (generic). tcp_info caveat (section 5). |
| nix | 0.31.3 (features socket, net, uio, time) | Good: `recvmmsg`/`sendmmsg`, `ControlMessageOwned::{ScmTimestampsns, ScmTimestampns, Ipv4Tos(u8), Ipv6TClass(i32), Ipv4Ttl, Ipv6HopLimit, Ipv4RecvErr(ee, Option<sockaddr_in>), Ipv6RecvErr, UdpGroSegments}`. Send: `Ipv4Tos(&u8)`, `Ipv6TClass(&i32)`, `Ipv4Ttl`, `Ipv6HopLimit`, `TxTime`. sockopts: Timestamping, IpRecvTos, Ipv4RecvTtl, Ipv6RecvTClass, Ipv6RecvHopLimit, Ipv4RecvErr, Ipv6RecvErr, IpMtu, IpDontFrag, TcpCongestion. **Gaps:** TimestampingFlag names only 8 flags (use `from_bits_retain`), no IP_MTU_DISCOVER, no TCP_INFO, no SCM_TS_OPT_ID. Tested. |
| rustix | 1.1.5 | **Not for cmsg work**: has sendmsg/sendmmsg/recvmsg but **no recvmmsg**. Ancillary types are only ScmRights/ScmCredentials (+TxTime send). Has `set_ip_mtu_discover`, `ip_mtu`, `set_ip_tos`, `set_ipv6_recvtclass`, `tcp_congestion`. |
| socket2 | 0.6.5 | Fine for socket creation and setopts (`set_tos_v4`, `set_recv_tos_v4`, `set_recv_tclass_v6`, `set_recv_hoplimit_v6`, `tcp_congestion`). Has `recvmsg`/`sendmsg` but no cmsg parsing, no mmsg. Optional. |
| snow | 0.10.0 (MSRV 1.85) | **Noise_IKpsk2 works [tested]**: `"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"`, `.psk(2,&psk)`. msg1=101 B (5 B payload), msg2=48 B. `into_stateless_transport_mode()` with explicit nonces suits lossy/reordered UDP (tested nonce=42). Default features pull pure-Rust crypto (chacha20poly1305, blake2, curve25519-dalek, aes-gcm, sha2). |
| minicbor | 2.3.0 | Deterministic for our use: definite lengths and smallest integer encodings by default. Structs are arrays by default (`#[cbor(map)]` for maps, keys in field order). There is no automatic map-key sorting, so avoid HashMap. **Gotcha [tested]**: `[u8;16]` encodes as an array of 16 ints (38 B record). Use `#[cbor(n(0), with = "minicbor::bytes")]` to get a byte string (24 B record). |
| zstd | 0.14.2 (C libzstd via zstd-sys; `pkg-config` feature to use system lib) | Use if a C toolchain is OK. Full levels. |
| ruzstd | 0.9.0 | Pure Rust, decoder complete. **Encoder only implements `Uncompressed` and `Fastest` (~zstd -1)**; Default/Better/Best are marked UNIMPLEMENTED in source. Good if level-1 ratio is enough and no C is required. |
| crc32c | 0.6.8 (last release 2024-06) | HW-accelerated (SSE4.2/ARMv8), stable API, fine. Alternative crc-fast 1.10. |
| blake3 | 1.8.7 | Use. Default `std`; `pure` feature avoids C/asm build. |
| rustls | 0.23.45 (MSRV 1.71) | Sync use: `rustls::StreamOwned<ClientConnection, TcpStream>`. Default provider aws-lc-rs (C/cmake build; `prefer-post-quantum` default). For a lighter build use `default-features=false, features=["ring","std","tls12","logging"]`. |
| rcgen | 0.14.10 (MSRV 1.88) | Self-signed certificates: `rcgen::generate_simple_self_signed(vec!["host".into()])`. Default crypto ring. |
| uuid | 1.28.0 | feature `v7`; `Uuid::now_v7()` tested, version=7. |
| clap | 4.6.7 | derive. |
| serde_json | 1.0.152 | |
| proptest | 1.12.0 | dev-dep. |
| signal-hook | 0.4.5 | `signal_hook::flag::register(SIGINT, Arc<AtomicBool>)` suits a sync poll loop; also gives SIGTERM. |
| ctrlc | 3.5.2 | simpler, SIGINT only (+SIGTERM with `termination` feature). |

**Minimal set:** `libc`, `nix` (socket, net, uio, time), `netlink-sys` + `netlink-packet-route`
(+ `netlink-packet-core`), `snow`, `minicbor` (derive, alloc), `blake3`, `crc32c`, `uuid` (v7),
`clap`, `serde_json`, `signal-hook`; dev: `proptest`. Add `zstd` or `ruzstd`, and
`rustls` (ring) + `rcgen`, only if those features are actually in scope (Noise via snow may make TLS
unnecessary). Skip rustix and socket2 (redundant with nix+libc) and wl-nl80211/genetlink (async-oriented).

---

## Implications for PTF / probe
- Use libc + nix (socket, net, uio, time) for sockets, mmsg and cmsgs; raw constants where nix lacks names.
- snow 0.10 for Noise IKpsk2 with stateless transport (explicit nonces) for lossy UDP.
- netlink-sys + netlink-packet-route for rtnetlink; hand-rolled genl for nl80211 (avoids async deps).
- rustls (ring backend) + rcgen for the tcp/443 TLS class.
- Not chosen: rustix (no recvmmsg/cmsg parsing), wl-nl80211/genetlink (async-oriented), minicbor (own CBOR codec, ADR 0011).
