# EXP-0006-r7: Probe, wire, syscall and derive tests; end-to-end and interruption sessions; unsafe and dependency policy (re-run after #39 to #51)

- verdict: pass
- pinned commit: see `manifest.toml`
- requirements: see `experiment.toml` (same as r6)
- supersedes: [EXP-0006-r6](../EXP-0006-r6-probe-session-and-policy/) (passed; went stale when main's #39 to #51 changed the probe, syscall, wire and CLI crates and the netns harness)

## Method

Same command as r6. The namespace step now runs the twelve sessions main's fixes added or kept: r6's six (`smoke_session_through_netem`, the interruption, responder-restart, lost-handshake-reply and pinned-TLS fetch sessions) plus `tcp_fallback_session_sends_no_udp`, `tcp_fallback_tries_each_family`, `ipv6_without_a_route_falls_back_to_ipv4`, `ipv6_udp_timeout_falls_back_to_ipv4_udp`, `second_initiator_is_told_busy` (#44) and `forced_predicted_ids_join_exactly` (#47).

## Result

All steps pass: 93 unit tests (8 + 56 + 22 + 7, `artifacts/stdout.log`; r6 had 57), the twelve namespace sessions (`artifacts/stderr.log`), clippy with `-D warnings`, the `unsafe` confinement to pt-sys, and `cargo deny`. The host was shared with heavy compilation load (load average 27–30 on 16 threads) during the 83 s run.

## Interpretation

The requirements r6 met still hold with the probe and CLI fixes of #39 to #51, including REQ-PRB-030 (host-side losses, now with predicted transmit ids re-anchored at send failures) and REQ-PRB-031 (graceful interruption, resumable fetch).
