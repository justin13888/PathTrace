# EXP-0006: Probe, wire and syscall tests; end-to-end session; unsafe and dependency policy

- verdict: pass
- pinned commit: see `manifest.toml`
- requirements: REQ-PRB-001, -002, -006, -007, -008, -009, -012, -017, -018, -019, -020, -021, -023, -024, REQ-SEC-002, -003, -005, REQ-CLI-001

## Hypothesis

The capture components work individually and together, and the codebase obeys its `unsafe` and dependency policies.

## Method

The command (`manifest.toml`) chains five checks. Any failure fails the experiment:

1. `cargo test -p pt-sys -p pt-wire -p pt-probe`:
   - pt-sys: kernel RX timestamps, TOS and TTL per packet, TX stamps by OPT_ID, TCP_INFO by offset, TCP_SAVED_SYN, congestion control, rtnetlink, clocks (REQ-PRB-007, -008, -017).
   - pt-wire: probe header and keyed tag; forged and foreign-key packets rejected; QUIC header/1 framing; frames and envelopes (REQ-PRB-006, -009, -023).
   - pt-probe:
     - session security: Noise IKpsk2 handshake; unauthorised keys and a wrong PSK rejected; replay rejected (REQ-PRB-002, -021);
     - keys and pairing: 0600 files, with group- and world-readable private keys refused (REQ-SEC-002);
     - TLS 1.3 pinned to the responder certificate, with a wrong certificate failing (REQ-PRB-024); TCP connection headers authenticated;
     - flow specs, saturation controller and crash-safe recorder.
2. The netns end-to-end test (`tools/netns/session.sh`, netem 20/10 Mbit/s): a full `serve`/`probe` smoke session yields a valid, complete trace with packets in both directions and every raw table, including `tcpinfo` from both endpoints, `app`, `pairs`, `exchange`, `ifstats` and `echo` (REQ-PRB-001, -012, -018, -019, -020, REQ-CLI-001).
3. `cargo clippy --workspace --all-targets -D warnings`, with `undocumented_unsafe_blocks = deny` and `unsafe_code = forbid` outside pt-sys.
4. `grep`: no `unsafe` in any Rust source outside `crates/pt-sys/` (REQ-SEC-003).
5. `cargo deny check`: licence allowlist, advisories, bans on tokio, async-std, smol, quinn, hyper and h2 (REQ-SEC-005).

## Result

All five passed (`artifacts/stdout.log`): unit tests ok, the netns session PASS in 43 s, clippy clean, grep empty, and `advisories ok, bans ok, licenses ok, sources ok`.

## Interpretation

These tests show that the mechanisms behave as designed in namespaces on kernel 7.2. They do not show behaviour on real access networks or Wi-Fi hardware: nl80211 sampling runs only in `doctor` and real sessions, and this host has no Wi-Fi under test. That remains user acceptance (#16). REQ-PRB-020 ("a trace is always written, partial if necessary") is also exercised by EXP-0002's udp-blocked scenario (exit code 3, trace written).
