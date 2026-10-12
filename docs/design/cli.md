# `pathtrace` command-line interface

- requirements: REQ-CLI-001 … REQ-CLI-004, REQ-PRB-025
- adr: 0008 (stability)

## Principles

- **One binary, both roles** (REQ-PRB-001). Commands are verbs. Every option has a sensible default except the facts only the user knows (`--class`).
- **Stable from 1.0** (REQ-CLI-002). Commands and flags are not removed without one minor release of deprecation warnings.
- **Scriptable**. Results go to stdout, progress and diagnostics to stderr, and `--json` is offered where the output is structured (REQ-CLI-003).
- **Exit codes** (REQ-CLI-004):

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Failure or invalid input (including `trace check` finding the file invalid) |
| 2 | Usage error (clap) |
| 3 | Partial result: a session completed but the responder log is missing, phases failed, a log was truncated, or the session was interrupted by SIGINT/SIGTERM. The trace is still written |

## Commands

| Command | Role | Purpose |
|---|---|---|
| `keygen [--force]` | both | Create `<config>/key` (X25519, 0600) if absent; print the public key |
| `authorize <pubkey> --name <label>` | responder | Authorise an initiator; print the pairing string `pt1:<responder-pub>:<psk>` |
| `responder add <name> <host[:port]> <pairing>` / `responder list` | initiator | Manage known responders (`<config>/responders`, 0600) |
| `serve [--port 4433] [--no-class-ports] [--state-dir] [--data-cap] [--rate-cap] [--retention-days] [--max-sessions] [-q]` | responder | Run the responder |
| `probe <responder> --class <class> [--label] [--mobility] [--tag]… [--profile auto\|smoke\|light\|standard\|deep] [--track-secs] [--out DIR] [--ipv6] [--rate-cap] [-q]` | initiator | Run a session; write `<trace_id>.a.ptflog`, fetch `<trace_id>.b.ptflog`, merge into `<trace_id>.ptf` |
| `merge <a.ptflog> [<b.ptflog>] -o <out.ptf>` | either | Offline merge (REQ-PRB-018), then derive |
| `fetch --resume <id.session>` or `fetch --responder <name> --session <hex> --token <hex> --out <file>` | initiator | Retrieve a responder log later. `--resume` reads the session file `probe` writes after the handshake (it includes the pinned TLS certificate, so the log travels over TLS); the explicit form fetches over plain TCP on the responder's port |
| `derive <file> [-o out]` | any | Re-derive PATH/SERS/PLCY/VALD from the raw layer |
| `export netem <file>` / `export mahimahi <file> -o <prefix>` | any | Export the derived model (REQ-FMT-021) |
| `import mahimahi <up> [<down>] -o <out.ptf>` | any | Import Mahimahi traces |
| `trace redact <file> --level shareable\|anonymous -o <out>` | any | Remove identifying data (REQ-FMT-016) |
| `trace check <file> [--json]` | any | Strict validation (REQ-FMT-018) |
| `trace info <file> [--json]` | any | Summary: kind, ids, profile, class, sections, tables and rows, digest; `merge_checks`, and per direction `host_drops` and `local_qdisc_drops` from PATH |
| `trace dump <file> [-o out.jsonl]` / `trace load <in.jsonl> -o <out.ptf>` | any | Lossless JSON Lines twin (REQ-FMT-014) |
| `doctor [<responder>] [--json]` | initiator | Preflight checks (REQ-PRB-025) |

`--config-dir` (env `PATHTRACE_CONFIG_DIR`) applies to all commands. The default is `$XDG_CONFIG_HOME/pathtrace`.

`PATHTRACE_RECV_BUF` and `PATHTRACE_TX_IDS` are test hooks for the ground-truth harness (probe.md §4.2), honoured by `probe` and `serve`. They change what is measured and are recorded in META `extra.test_hooks`; do not set them for field sessions.

## Decisions

### Network class is mandatory on `probe`
- **Problem**: class-level conclusions (draft spec §12) need every trace labelled. Labels added afterwards are error-prone.
- **Choice**: `--class` is required and restricted to a closed list (home, office, hotel-wifi, cafe, airport, cellular-4g, cellular-5g, train, in-flight, tether, satellite, lab, other). `--label` is free text, marked `pii: id`.
- **Alternatives**: interactive prompt (breaks scripting); optional class (silently unlabelled traces).

### `--profile auto`
- **Choice**: `light` when NetworkManager reports the egress interface as metered (`yes`/`yes (guessed)`), otherwise `standard`. The choice is printed (REQ-PRB-016).
- **Reporting**: `probe` prints the chosen profile, the egress interface, and the metered state to stderr every time `auto` decides (also with `-q`). When the state is neither `yes…` nor `no…` (no `nmcli`, an unmanaged interface, a timeout), the line is a warning that `standard` was picked blind and that capped links need `--profile light`: phone hotspots are usually not flagged as metered, so silence there would spend up to 200 MB of the user's data.

### `probe` prints the session before measuring
- **Problem**: the responder's half of a session can only be fetched with the session id and token. Printing them only at the end loses them when the probe is interrupted or crashes.
- **Choice**: right after the handshake, `probe` prints `session: <hex>` with the trace id and the session file path to stderr (also with `-q`), and writes `<trace_id>.session` (mode 0600) beside its log. The final summary on stdout repeats `session: <hex>` as in 1.0. SIGINT/SIGTERM end the session gracefully (exit 3); a second signal terminates at once. `fetch --resume` uses the session file.

### Pairing in two commands
- **Problem**: Noise IKpsk2 needs the responder's static key and a per-initiator PSK on the initiator, and the initiator's key on the responder.
- **Choice**: `keygen` on both machines, then `authorize` on the responder (prints the pairing string), then `responder add` on the initiator. Secrets never travel in command-line arguments to the network, only between the user's own terminals.

### `doctor` does not open a session
- **Problem**: REQ-PRB-025 asks for reachability of the responder on every class port, UDP included. A UDP port can only be shown open by a reply, and the responder replies only to a valid Noise handshake, which starts a real session: a responder log, a session slot (a second initiator is refused as busy), and a `fetch` token.
- **Constraints**: the responder must not answer strangers (REQ-SEC-001, REQ-PRB-004), so no unauthenticated echo; `doctor` must be cheap to run repeatedly and leave nothing behind on the responder; the end-to-end check already exists.
- **Alternatives**: a handshake-only session that `doctor` closes at once (proves UDP and pairing, but writes a responder log per run, holds the slot, and needs a wire change for a "check" session the responder discards); an unauthenticated echo on the responder (rejected: answers strangers).
- **Choice**: `doctor` still opens no session. For UDP it sends three empty datagrams, 300 ms apart, from a connected socket to each UDP class port and waits up to 1 s for an ICMP error. `refused` (ICMP port unreachable: nothing listens, or a firewall rejects) and `unreachable` (ICMP host or network unreachable) are warnings; silence is reported as `not refused`, which shows the datagrams were not rejected but not that they arrived. An empty datagram never decodes as a handshake or probe packet, so the responder ignores it (during a running session it is counted as an unknown packet). The end-to-end check stays `probe --profile smoke` (about 25 s, at most 50 MB).
- **Rationale**: a refusal is the common UDP failure (responder down, `--no-class-ports`, a host firewall rejecting) and is detected without any responder state; a silent drop is indistinguishable from delivery without a reply, which only a session can give.
- **Validated by**: unit tests of the check classifiers in `crates/pathtrace/src/doctor.rs`; EXP-0007 runs `doctor --json` from a fresh process.

### `doctor` checks
Each check is `ok`, `warn` (non-fatal), or `FAIL` (fatal: exit 1). Only facts that make a session impossible are fatal.

| Check | Fatal | What it reads |
|---|---|---|
| `kernel >= 6.1` | yes | `/proc/sys/kernel/osrelease` |
| `key` | yes | `<config>/key` |
| `kernel timestamps` | no | loopback self-test (below); `ok` only when both kernel RX and kernel TX stamps were seen |
| `clocksource` | no | `tsc` or `arch_sys_counter` |
| `clock sync` | no | `adjtimex(2)` read-only: synchronised by an NTP daemon (chrony, ntpd, systemd-timesyncd), with its estimated and maximum error. An undisciplined clock drifts during a session and widens one-way-delay uncertainty |
| `power` | no | `/sys/class/power_supply`: warns on battery (power saving adds timing noise) |
| `cpu governor` | no | `/sys/devices/system/cpu/cpu*/cpufreq`: warns on `powersave` under a driver where it pins the lowest frequency (not `intel_pstate` or `amd-pstate-epp`, whose `powersave` is a dynamic policy) |
| `resolve responder` | yes | DNS: every address of the responder |
| per family (IPv4, IPv6): `route` | no | a local route to the responder's first address of that family; a family the responder has no address for is reported and skipped |
| per family: `egress interface`, `metered`, `wifi link stats` | no | as `probe` records them |
| per family: `tcp/<port> reachable` | see below | TCP connect (3 s) to the responder port, 443 and 80 |
| per family: `udp/<port> not refused` | no | the UDP test above, on the responder port and 443 |
| per family: `tcp/<port> not intercepted` | responder port: yes; 80: no | an HTTP request (64 bytes or more, so the responder rejects it at once) on a connected port; the responder never speaks HTTP, so any `HTTP/` answer is a captive portal or transparent proxy, which also makes a TCP connect pass |
| `responder reachable` | yes | the responder port answered a TCP connect on at least one family |

Checks of the first family `probe` would use keep their 1.0 names (`tcp/4433 reachable`); the other family's carry a ` (ipv6)` or ` (ipv4)` suffix. Run `doctor` without a responder on the responder host too: its clock sync, power and timestamps matter as much.

### `doctor`'s timestamp self-test warms up
- **Problem**: the kernel enables RX timestamping lazily (deferred static-key work after the first socket asks for it), so the first datagrams after bind can arrive unstamped. A single-packet self-test then falsely reports `kernel RX stamps false` (EXP-0008).
- **Choice**: send loopback datagrams 10 ms apart, for up to 0.5 s, until both an RX stamp and a TX stamp have been seen. Report the result after that warm-up. The probe needs no change, because it records each packet's timestamp source (`rx_src`).
- **Validated by**: EXP-0007 (doctor check) and the release evidence, which run `doctor` from a fresh process.
