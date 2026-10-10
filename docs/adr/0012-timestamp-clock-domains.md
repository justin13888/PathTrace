# 0012: Packet timestamps: kernel software stamps in CLOCK_REALTIME, recorded raw with clock pairs

- status: accepted
- date: 2026-10-10
- requirements: REQ-PRB-007, REQ-PRB-008, REQ-FMT-006
- evidence: R-0010, R-0011

## Context

Draft spec §6.3 asked for "monotonic raw clocks on both sides" and kernel `SO_TIMESTAMPING` stamps. First-hand checks (R-0010, R-0011) show the two conflict: kernel software timestamps are always CLOCK_REALTIME (`__net_timestamp()` uses `ktime_get_real()`), with no monotonic or TAI option. Kernel stamps remove 9 µs at the median and up to 2 ms in the tail compared with user-space stamps. CLOCK_REALTIME is slewed by NTP (3.6 ppm observed) and can step.

## Options considered

1. **User-space CLOCK_MONOTONIC_RAW stamps only**: one clock domain, but scheduler wakeup noise of 0.1–2 ms ends up in every delay sample.
2. **Kernel stamps, converted to monotonic at capture time**: clean data, but the conversion is fixed forever (it violates P1, and a bad conversion can never be undone).
3. **Kernel stamps stored raw in the REALTIME domain**, plus CLOCK_MONOTONIC_RAW for scheduling and intended times, plus periodic minimum-width clock pairs (MONO_RAW, REALTIME, MONO_RAW; ~30 ns uncertainty) logged on both endpoints. All conversions happen at derivation time.

## Decision

Option 3. Every time column declares its domain (`a.real`, `a.mono`, `b.real`, `b.mono`). TX stamps keep both kinds the kernel offers, SCHED (qdisc enqueue) and SND (driver, after the local qdisc), because Wi-Fi drivers often provide only SCHED (R-0010). Each TX row also keeps the user-space send lag, so the timestamp source is visible per packet.

## Consequences

- NTP steps and slews during a session can be detected and corrected later from the clock pairs.
- Realtime values reveal when a capture happened, so realtime domains are `pii: quasi`, and anonymous redaction shifts them.
- Sub-µs precision is kept, which costs about 2.7 B per packet (EXP-0001); the cost is within budget.
