# R-0005: tc-netem parameters and limits
- source: iproute2 man/man8/tc-netem.8, https://github.com/iproute2/iproute2/blob/main/man/man8/tc-netem.8 (last change ee2a4a8, 2026-06-28; page footer "25 November 2011"). man7.org (https://man7.org/linux/man-pages/man8/tc-netem.8.html) refused connections on 2026-10-10. The same page also ships locally as iproute-tc 6.17.0 (Fedora 44).
- accessed: 2026-10-10
- claim-under-test: tc-netem supports delay with jitter, distribution and correlation; loss as random, state (4-state Markov) or gemodel; duplicate; reorder; corrupt; rate with packetoverhead/cellsize; slot; seed. It cannot represent time-varying rate and similar.
- verdict: confirmed (with additions: `limit`, `ecn`, `gap`, `celloverhead`, slot `packets`/`bytes`)
- applicability: Applicable as an export target (SPEC 7.7: "netem command line and delay distribution table"). Defines what a static export can carry.
## Evidence
SYNOPSIS:
> LIMIT := limit packets
> DELAY := delay TIME [ JITTER [ CORRELATION ]]] [ distribution { uniform | normal | pareto | paretonormal } ]
> LOSS := loss { random PERCENT [ CORRELATION ] | state p13 [ p31 [ p32 [ p23 [ p14]]]] | gemodel p [ r [ 1-h [ 1-k ]]] } [ ecn ]

> CORRUPT := corrupt PERCENT [ CORRELATION ]]   DUPLICATION := duplicate PERCENT [ CORRELATION ]]
> REORDERING := reorder PERCENT [ CORRELATION ] [ gap DISTANCE ]
> RATE := rate RATE [ PACKETOVERHEAD [ CELLSIZE [ CELLOVERHEAD ]]]]   SEED := seed VALUE

> SLOT := slot { MIN_DELAY [ MAX_DELAY ] | distribution { uniform | normal | pareto | paretonormal | FILE } DELAY JITTER } [ packets PACKETS ] [ bytes BYTES ]

- `state`: 4-state Markov chain. The states are 1 good, 2 good within a burst, 3 burst losses, 4 independent losses. `gemodel`: Gilbert-Elliott with p, r, 1-h (loss in bad state), 1-k (loss in good state).
- Correlation "isn't a true statistical correlation, but an approximation" (EXAMPLES).
- `seed` "reproduce the randomly generated loss or corruption events". It is documented for loss and corruption only.
- `ecn` marks instead of dropping, and needs a loss model.
- LIMITATIONS: timer granularity; reordering needs delay; "for TCP performance test results to be realistic netem must be placed on the ingress of the receiver host" (because of TSQ). Packets reorder when jitter is large, because of the internal tfifo.

What netem cannot represent. Inferred from the grammar, since the page has no such list:
- No time-varying schedule. Every parameter is a constant until changed externally with `tc qdisc change`.
- No trace-driven capacity or delivery opportunities. `rate` is a single fixed speed.
- The queue limit is in packets only. There is no AQM inside netem (it needs a child qdisc).
- No per-flow or per-transport policy by itself. It needs classifiers and filters, as in the man page's prio/tbf example.
- No policer or token bucket in netem (tbf is a separate qdisc). Egress only per qdisc, so each direction needs its own qdisc (an ifb for ingress).
## Implications for PTF / probe
- The netem exporter can carry: base delay + jitter + correlation, or a delay distribution table (`FILE`); loss as `gemodel` (PTF Gilbert-Elliott fit maps directly, see SPEC section 8) or `state`; duplicate %; reorder %; corrupt %; one static rate with packet overhead; `limit` in packets; and `seed`.
- So PTF should store loss-model parameters in the netem parameterisation (p, r, 1-h, 1-k), or in a form that converts to it losslessly. It should also store duplicate, reorder and corrupt rates with a correlation, even when it has per-event data.
- The exporter must convert byte-denominated buffer estimates to packets. Record the packet size assumed.
- Per-transport treatment, policers and time-varying capacity cannot go into a single netem qdisc. The exporter must say so explicitly (lossy export), or generate a tc script (prio + filters + tbf + scheduled `change`), which is out of scope for v1.
- SPEC table line 110 links `man8/NetEm.8.html`. The page name in iproute2 is `tc-netem.8`. man7.org was unreachable, so I could not check whether the SPEC URL resolves. Prefer the `tc-netem.8` URL.
