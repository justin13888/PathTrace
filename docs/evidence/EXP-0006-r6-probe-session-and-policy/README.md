# EXP-0006-r6: Probe, wire, syscall and derive tests; end-to-end and interruption sessions; unsafe and dependency policy (1.1)

- verdict: pass
- pinned commit: see `manifest.toml`
- requirements: see `experiment.toml` (adds REQ-PRB-030 and REQ-PRB-031)
- supersedes: [EXP-0006-r5](../EXP-0006-r5-probe-session-and-policy/) (passed; went stale with the 1.1 capture hardening, #37)

## Method

Same command as r2–r5. The namespace step (`cargo nextest run -p pathtrace --run-ignored ignored-only`) now runs six sessions instead of one: besides `smoke_session_through_netem`, the 1.1 tests `interrupted_session_ends_gracefully_and_stays_fetchable` (SIGINT to the initiator), `responder_signal_ends_the_session_for_both` (SIGTERM to the responder), `responder_log_fetchable_after_responder_killed_mid_session` (SIGKILL, restart, `fetch --resume`), `lost_handshake_reply_is_resent` and `fetch_resume_uses_pinned_tls_and_falls_back_to_443`. The unit tests now include the host-loss tests of pt-sys and pt-probe (SO_RXQ_OVFL, send failures, explicit and predicted transmit ids, burned-id accounting) and pt-derive's exclusion of host drops from loss, queue and policer estimates.

## Result

All steps pass: 57 unit tests (7 + 26 + 18 + 6, `artifacts/stdout.log`; r5 had 35), the six namespace sessions (`artifacts/stderr.log`), clippy with `-D warnings`, the `unsafe` confinement to pt-sys, and `cargo deny`.

## Interpretation

- REQ-PRB-031 is met: an interruption of either endpoint ends the session gracefully with a partial trace, the responder's log stays fetchable after an initiator interruption and after a responder restart, and a lost handshake reply does not end the session.
- REQ-PRB-030 is met at the unit and session level here; its ground truth (socket drops and local qdisc drops recorded and kept out of path loss) passed in both EXP-0002-r9 and r10, whose overall verdict failed only on the bytes/packet budget.
