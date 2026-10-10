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
| 3 | Partial result: a session completed but the responder log is missing, phases failed, or a log was truncated. The trace is still written |

## Commands

| Command | Role | Purpose |
|---|---|---|
| `keygen [--force]` | both | Create `<config>/key` (X25519, 0600) if absent; print the public key |
| `authorize <pubkey> --name <label>` | responder | Authorise an initiator; print the pairing string `pt1:<responder-pub>:<psk>` |
| `responder add <name> <host[:port]> <pairing>` / `responder list` | initiator | Manage known responders (`<config>/responders`, 0600) |
| `serve [--port 4433] [--no-class-ports] [--state-dir] [--data-cap] [--rate-cap] [--retention-days] [--max-sessions] [-q]` | responder | Run the responder |
| `probe <responder> --class <class> [--label] [--mobility] [--tag]… [--profile auto\|smoke\|light\|standard\|deep] [--track-secs] [--out DIR] [--ipv6] [--rate-cap] [-q]` | initiator | Run a session; write `<trace_id>.a.ptflog`, fetch `<trace_id>.b.ptflog`, merge into `<trace_id>.ptf` |
| `merge <a.ptflog> [<b.ptflog>] -o <out.ptf>` | either | Offline merge (REQ-PRB-018) |
| `fetch --responder <name> --session <hex> --token <hex> --out <file>` | initiator | Retrieve a responder log later (printed by `probe` when fetching failed) |
| `trace check <file> [--json]` | any | Strict validation (REQ-FMT-018) |
| `trace info <file> [--json]` | any | Summary: kind, ids, profile, class, sections, tables and rows, digest |
| `trace dump <file> [-o out.jsonl]` / `trace load <in.jsonl> -o <out.ptf>` | any | Lossless JSON Lines twin (REQ-FMT-014) |
| `doctor [<responder>] [--json]` | initiator | Preflight checks (REQ-PRB-025) |

`--config-dir` (env `PATHTRACE_CONFIG_DIR`) applies to all commands. The default is `$XDG_CONFIG_HOME/pathtrace`.

## Decisions

### Network class is mandatory on `probe`
- **Problem**: class-level conclusions (draft spec §12) need every trace labelled. Labels added afterwards are error-prone.
- **Choice**: `--class` is required and restricted to a closed list (home, office, hotel-wifi, cafe, airport, cellular-4g, cellular-5g, train, in-flight, tether, satellite, lab, other). `--label` is free text, marked `pii: id`.
- **Alternatives**: interactive prompt (breaks scripting); optional class (silently unlabelled traces).

### `--profile auto`
- **Choice**: `light` when NetworkManager reports the egress interface as metered (`yes`/`yes (guessed)`), otherwise `standard`. The choice is printed (REQ-PRB-016).

### Pairing in two commands
- **Problem**: Noise IKpsk2 needs the responder's static key and a per-initiator PSK on the initiator, and the initiator's key on the responder.
- **Choice**: `keygen` on both machines, then `authorize` on the responder (prints the pairing string), then `responder add` on the initiator. Secrets never travel in command-line arguments to the network, only between the user's own terminals.

### `doctor` does not open a session
- **Choice**: an unauthenticated UDP datagram gets no reply by design (the responder must not answer strangers), so `doctor` tests TCP ports, DNS, timestamping, clocks, the interface, Wi-Fi stats and keys. The end-to-end check is `probe --profile smoke` (about 25 s, at most 50 MB).
