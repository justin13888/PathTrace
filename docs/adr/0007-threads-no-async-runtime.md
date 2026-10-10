# 0007: Dedicated threads, no async runtime, in measurement code

- status: accepted
- date: 2026-10-10
- requirements: REQ-PRB-017, REQ-SEC-005
- evidence: —

## Context

Probe accuracy depends on when packets are actually sent and when arrivals are stamped. Async runtimes add scheduling (task wakeups, work stealing, timer wheels with millisecond granularity, I/O batching) that the measurement code can neither observe nor control.

## Options considered

1. **tokio**: ergonomic, mature, but timer granularity is 1 ms and task scheduling adds latency that cannot be measured.
2. **Dedicated OS threads with blocking or non-blocking syscalls**: sender threads pace with sleep-then-spin on CLOCK_MONOTONIC_RAW, receiver threads block in `recvmmsg` with kernel timestamps, control runs on its own thread, and communication uses `std::sync::mpsc` and atomics.

## Decision

Option 2. The spec's dependency policy (§13.2) is kept and enforced by `deny.toml` bans on tokio, async-std, smol, quinn, hyper and h2.

## Consequences

- More explicit thread management code in `pt-probe`.
- Pacing precision is limited only by the kernel and the timestamp source, which is recorded per flow.
- TLS on the tcp/443 class uses rustls's synchronous API.
