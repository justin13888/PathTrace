# Overlay ground truth: a macOS initiator against a Linux responder

- requirements: REQ-SCOPE-009, REQ-PRB-033, REQ-DRV-013
- adr: 0014
- issues: #95 (this harness), #66 (its first run)

Linux and macOS are the supported targets (ADR 0014, REQ-SCOPE-009): Linux for every role, macOS for the initiator roles. The namespace harness (`tools/netns/session.sh`, `cargo xtask groundtruth`, derivation.md "Validation") puts both endpoints on one Linux kernel, so it never exercises the macOS backend. This harness puts known impairments on a real path between a macOS initiator (a) and a Linux responder (b) reached over a Tailscale overlay, and checks the derived PATH against them.

## Decision: impair the responder's tailnet egress, filtered to the probe's traffic

- **Problem.** REQ-PRB-033 needs evidence that a macOS initiator's trace recovers known path behaviour, and REQ-SCOPE-009 that the platform split records what macOS cannot observe as unknown. The only machines are the owner's MacBook (aarch64, macOS 26) and focalors (Linux, Fedora, SELinux enforcing), joined by Tailscale. Neither namespace scenarios nor a lab middlebox are available between them.
- **Constraints.**
  - Only `tools/` and `xtask` exec `tc` (AGENTS.md); the shipped crates stay unchanged.
  - `sudo` on focalors asks for a password the owner types, so everything root does for a whole schedule is one invocation; the initiator drives it unprivileged over ssh.
  - Only the probe's traffic may be impaired: the ssh session that drives the steps crosses the same tailnet, and so does traffic to other peers.
  - The impairment must be removed on every exit path, including an initiator that disappears.
  - Impairments stay well below the overlay's own capacity and well above its own delay noise, or the truth is not identifiable from the trace (below).
- **Alternatives.**
  1. *dummynet on the Mac (`dnctl`/`pfctl`).* Impairs a→b, but it is a second impairment tool with its own semantics, and it runs on the platform under test, so a fault in it is indistinguishable from a fault in the macOS backend.
  2. *netem on focalors' physical NIC.* Tailscale's traffic there is WireGuard UDP to one port: a filter cannot tell probe packets from ssh, and every peer of the tailnet is impaired.
  3. *An IFB on focalors' tailnet ingress for a→b.* Possible, but doubles the root setup for a direction whose sender is the platform under test, while b→a exercises the macOS receive path, which is where the macOS-specific facts (receive stamps, host drops, no `rxq_drops`) live.
  4. **netem on focalors' `tailscale0` egress (b→a), filtered to the probe.** Chosen.
- **Choice.** `tools/overlay-gt/impair.sh` runs once under `sudo` on the responder. On `--dev tailscale0` it installs `prio bands 3` with every priority mapped to band 2 (`1:2`), so unmatched traffic is untouched, and u32 filters that send to band 1 (`1:1`, the netem child `10:`) only packets whose destination is `--peer` (the initiator's tailnet address, IPv4 or IPv6) **and** whose source port is one of the responder's ports (4433, 443, 80; UDP and TCP, deploy/README.md). Each step replaces only the netem child; the classifier stays the same, so the baseline step crosses the same qdisc tree with a netem child that adds nothing. `tailscale0` is a TUN device: its egress carries the inner IP packets before WireGuard encapsulation, so the filter sees the probe's addresses and ports, and netem's `rate` counts IP bytes (no link header, unlike the veth scenarios' 14-byte L2 correction).
- **Rationale.** One impairment tool (netem) shared with the namespace scenarios keeps the truth comparable, and the tolerances inherit from them. Filtering by destination and source port leaves ssh (port 22) and other peers alone. Impairing b→a makes the macOS host the receiver of the impaired direction and leaves a→b as the unimpaired control.
- **Validated by.** pending #66 (the first run on focalors, an evidence experiment); the checker's logic by `overlay_gt::tests` (synthetic traces, `mise run test`).

## Decision: one root process, stepped through files in a control directory

- **Problem.** Each step must change the impairment between two probe sessions, the initiator decides when, and the initiator has no root on the responder.
- **Constraints.** One `sudo` for the whole schedule; nothing root reads may make it run another command, nor read or write a file the owner's account cannot; the initiator can only use ssh/scp as the owner's account.
- **Alternatives.** A root-owned daemon or a `sudoers` rule for `tc` (a standing privilege, and a configuration change on the owner's machine); `ssh root@`; a fresh `sudo` per step (a password per step).
- **Choice.** The owner starts `sudo tools/overlay-gt/impair.sh --dev tailscale0 --peer <initiator tailnet IP> --control <dir> --timeout <s>` on the responder, with `<dir>` a directory the owner's account owns. impair.sh reads the schedule itself (`--schedule`, default `tools/overlay-gt/schedule`); a step file carries only the step's name. Per step `NN` (1-based, two digits, in schedule order):
  1. the initiator creates `NN.step` containing the step name (written to a temporary name, then renamed);
  2. impair.sh accepts it only if the name equals schedule entry `NN`, replaces the netem child with that entry's arguments, and writes `NN.ack`: the step, the netem arguments it applied, and `tc -s qdisc show` and `tc filter show` of the device;
  3. after the session the initiator creates `NN.end`; impair.sh writes `NN.stats` (`tc -s qdisc show`, whose netem counters show the drops it made) and waits for the next step.
  After the last step, or on a `done` file, it removes the qdisc and exits. The owner's account can rename, replace or link any entry of the control directory at any moment, so no check root makes on a path there holds by the time it opens it. impair.sh therefore never opens a path in the control directory as root: it keeps its own files (the schedule copy, each file's content while it is built) in a root-owned private directory (`mktemp -d`, mode 0700), and reads `NN.step` and writes `NN.ack`/`NN.stats` (`mktemp` in the directory, `chmod 0644`, renamed into place) as the directory's owner (`setpriv --reuid/--regid --clear-groups`, util-linux). A link the owner swaps in is then followed with the owner's own rights and reaches nothing the owner could not already read or write, so root is never written through. It refuses a control directory that is group- or world-writable, where an account other than the owner could plant one.
- **Rationale.** Root never takes a netem argument from a user-writable file: it applies only what the schedule it was started with says, and step names are checked against `^[A-Za-z0-9._-]+$` before use. The ack carries what was applied, so the checker compares the trace with what the kernel had, not with what the initiator asked for.
- **Validated by.** pending #66.

## Decision: removal on every exit path

- **Problem.** A qdisc left behind keeps impairing the probe ports after the experiment.
- **Constraints.** The initiator may vanish (laptop sleep, lost Wi-Fi); the owner may press Ctrl-C; the script may fail.
- **Choice.** impair.sh traps EXIT, INT, TERM and HUP and deletes the root qdisc it installed in each. A hard `--timeout` (seconds, whole schedule) ends the run from inside every wait loop, which exits through the same trap. It refuses to start if the device's root qdisc is anything but the kernel default (handle `0:`, e.g. `noqueue`, `fq_codel 0:` or `pfifo_fast 0:`), so it never deletes a qdisc it did not create.
- **Validated by.** pending #66 (the ack of the last step and the final `tc qdisc show` printed on exit).

## Decision: the schedule and why these values

- **Problem.** The values must be recoverable over a path that has its own capacity, delay noise and loss.
- **Choice.** `tools/overlay-gt/schedule` (one step per line: name, then netem arguments or `none`):

| Step | netem (b→a probe traffic) | Truth checked |
|---|---|---|
| baseline | none | the overlay's own values; every later step is compared with it |
| delay40 | `delay 40ms limit 100000` | delay increase 40 ms |
| delay40-jitter5 | `delay 40ms 5ms distribution normal limit 100000` | delay increase 40 ms (median), jitter σ 5 ms |
| loss2 | `loss 2% limit 100000` | loss 2 % |
| rate20 | `rate 20mbit limit 1000` | capacity 20 Mbit/s |
| delay30-loss1 | `delay 30ms loss 1% limit 100000` | delay increase 30 ms, loss 1 % |

- **Rationale.** A tailnet path adds its own few milliseconds of delay noise (Wi-Fi on the Mac, wireguard-go scheduling) and has its own capacity, which is far lower on a DERP-relayed path than on a direct one. Delay steps of 30–40 ms and a 5 ms jitter σ are an order of magnitude above a few milliseconds of baseline noise, so the increase is resolved. A 20 Mbit/s rate is below any direct path between two hosts on home or office access, and the checker refuses a run whose baseline b→a capacity is under twice it (a relayed path), because then the overlay, not netem, is the bottleneck. 1–2 % loss is ten times the loss of a healthy tailnet path. `limit 100000` keeps netem's 1000-packet default from dropping packets in a 40 ms delay line (1000 × 1280 B in 40 ms is 256 Mbit/s); the rate step keeps a 1000-packet queue, as a real bottleneck would have. Other values can be run by editing the file (on both machines). The checker takes the truth from the schedule copy run.sh writes into the run directory, and fails a step whose ack shows other netem arguments; it refuses netem forms its checks cannot judge (another jitter distribution, correlation, duplication).

## Decision: tolerances, fixed before the run

- **Problem.** The checks need pass bounds stated before #66 runs, so the run cannot tune them.
- **Constraints.** Start from the namespace scenarios' tolerances (`xtask/src/groundtruth.rs`, `checks`) and widen them only by noise the baseline step measures. Clocks are not synchronised, so the one-way split is `symmetric_assumed` (simulator-requirements.md, Known limits): an impairment on b→a moves both directions' base delays by half, and only their sum is identifiable.
- **Choice.** Comparisons are between a step and the baseline step of the same run. σ₀ is the baseline's b→a jitter standard deviation (`PATH.b_to_a.jitter.stddev_ns`).
  - **Delay increase** (every step whose netem has no `rate`): D = base delay a→b + base delay b→a + the b→a jitter residual median; D(step) − D(baseline) is within 1 ms + 2σ₀ of the netem delay (0 for a loss-only step). The namespace check is ±1 ms on the base delay; the median term makes the same formula hold with jitter, where the minimum falls several σ below the netem delay.
  - **Jitter** (steps with a jitter argument): √(σ² − σ₀²) of b→a within ±30 % of the netem σ (the namespace `jitter` tolerance; independent noise adds in quadrature).
  - **Loss** (steps with `loss`): b→a loss rate minus the baseline's within 2.576 standard errors (99 %, binomial over each trace's `loss.samples`) of the netem loss. The baseline's own variance is the widening.
  - **Rate** (steps with `rate`): b→a `capacity.median_rate_bps` within ±10 % of the netem rate (the namespace tolerance), with no L2 correction (TUN device); the baseline b→a capacity must be at least twice the rate.
  - **Every step**, these must hold: the netem arguments in the ack equal the schedule entry; `probe.exit` is 0 and META `complete` is true; a→b transmit times are user-space only (`PATH.a_to_b.timestamps.counts` has `user` > 0 and no `snd` or `sched`, probe.md §9.2); the macOS sender's `local_qdisc_drops` (a→b) is `unknown`; the macOS receiver's `host_drops` (b→a) is `unknown`, or `known` only by `hostdrop.host-fullsock/1` (a flat host-wide counter, derivation.md "Host drops"), never by `hostdrop.rxq-gap/1`, which a macOS receiver cannot feed; `PATH.overlay` is `known` with `overlay: true`.
- **Rationale.** A host-wide `udp_fullsock` that did not rise is an observation, not a zero standing in for an unknown, so accepting `hostdrop.host-fullsock/1` keeps the rule "unknown, never zero" without rejecting a correct trace. Bounds wider than these would let a broken macOS receive path pass.

## Decision: initiator driver and checker

- **Choice.** `tools/overlay-gt/run.sh` (POSIX sh, macOS and Linux, shellcheck clean) runs the schedule from the initiator: per step it creates the step file over ssh, waits (bounded) for the ack, runs `pathtrace probe <responder> --class home --profile <p> --out <scratch>`, creates the end file and fetches the ack and stats with scp, and keeps the `.ptf`, `.a.ptflog`, `.b.ptflog` (scp'd from the responder's state directory only when the probe could not fetch it), the probe's output and exit code, and a `tailscale ping` / `tailscale status --json` snapshot. The probe writes into a scratch directory outside the output so the `.session` file (it holds the fetch token) never enters it; the output never holds key files or `pt1:` strings. `cargo xtask overlay-gt check <dir>` applies the checks above to that directory and writes `results.md`, `results.csv` and `summary.json` (a few kB) to it, and to `$PT_EVIDENCE_OUT` when set; it exits 1 when any check fails.
- **Validated by.** `overlay_gt::tests` (synthetic PATH/META traces: passing and failing truth per check kind, schedule parsing, a whole result directory); the run itself is #66.
