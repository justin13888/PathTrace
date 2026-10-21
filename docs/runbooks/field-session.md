# Runbook: capture traces on real networks

Goal: one trustworthy `.ptf` trace per session, labelled so that class-level conclusions are possible later (REQ-PRB-028, issue #16).

## What you need

A session always has two machines under your control with `pathtrace` installed on each. Only Linux and macOS are supported targets (ADR 0014): the responder runs Linux (x86_64 or aarch64, kernel ≥ 6.1); the initiator runs Linux the same way or macOS 15 or newer on Apple silicon:

- **Initiator**: the machine physically on the network you want to record (your laptop at the hotel, café or on the train). It runs `pathtrace probe`, so the trace describes the path from where it sits.
- **Responder**: a second machine with a stable, publicly reachable address (a VM or a home server with the ports in [deploy/README.md](../../deploy/README.md) open). It runs `pathtrace serve` under systemd and never initiates anything.

Set up the responder and pair the two once with [responder-deploy.md](responder-deploy.md); its smoke session must pass before the first field session. The responder must not sit on the network being measured, or the path under test is not the one the trace records.

Which release to use: for every field session, both machines run v1.1.0 (or a later release), installed as in [responder-deploy.md](responder-deploy.md). A Mac initiator needs the first release that publishes the `aarch64-apple-darwin` archive (later than v1.1.0), and the responder runs that same release. Do not use v1.0.x on any network. It lacks the capture hardening of PR #37 that the steps below rely on (the `.session` file, the clean Ctrl-C exit 3, `fetch --resume`, the merge checks and host-drop accounting), and on real paths it loses observations that cannot be recaptured afterwards. It also ramps saturations too slowly on paths with an RTT of about 300 ms or more (GEO satellite, in-flight Wi-Fi; issue #30, fixed by PR #39).

## Before each session

1. Connect to the network and note what it is (class, venue).
2. Close large downloads, sync clients and video calls on the laptop. Local traffic competes with the probe (interface counters are recorded, so it is visible, but it biases capacity).
3. Plug in the laptop: power saving adds timing noise. On a Mac, the probe holds an idle-sleep assertion for the whole session, so `caffeinate` is not needed while `doctor` reports `sleep assertion` ok; if it warns, start the probe as `caffeinate -i pathtrace probe …` and keep the lid open.
4. If the responder is reachable only over Tailscale, check that the tailnet has a direct path to it and save the output next to the trace: `tailscale ping <host> | tee "$(date -u +%Y%m%dT%H%M%SZ)-tailscale-ping.txt"` from `~/traces`. It must end with `via <ip>:<port>`, not `via DERP(<region>)`; on DERP, do not record ([responder-deploy.md](responder-deploy.md#overlay-responder-tailscale)). Repeat it right after the session. On a Mac without the Tailscale app's CLI integration turned on, there is no `tailscale` on `PATH`: run `/Applications/Tailscale.app/Contents/MacOS/Tailscale ping <host>` instead ([responder-deploy.md](responder-deploy.md#overlay-responder-tailscale)).
5. Run `pathtrace doctor vm`. It exits 1 only when a session cannot work (kernel older than 6.1 or macOS older than 15, no key, the responder's port unreachable, intercepted or not tested for interception on every address family). Read the warnings too:
   - `tcp/<port> not intercepted` warns with an answer, or `tcp/<port> reachable` failed on every port: a captive portal. Log in through a browser, then run `doctor` again. If it warns `not tested`, the connection failed the second time; run `doctor` again. A trace taken behind an unopened portal records the portal, not the path.
   - `udp/<port> not refused` warns `refused`: this network (or the responder) rejects that UDP port. The session still runs and records the UDP classes on that port as blocked (all of them, over a TCP-only session, when the responder port itself is refused). `not refused` does not prove that UDP arrives: only a session can, so the probe's own result is the final word.
   - `clock sync` warns: start an NTP daemon (chrony, or `timedatectl set-ntp true`) and wait until `doctor` reports it synchronised. On a Mac, `clock sync` always warns `sync state unknown`, because macOS does not report its sync state to `pathtrace` (R-0019): check that "Set time and date automatically" is on in System Settings > General > Date & Time, then go on. Check the responder the same way once, with `pathtrace doctor` on it.
   - `power` warns: the laptop is on battery (step 3). On a Mac it also warns when Low Power Mode is on; turn it off in System Settings > Battery for the session. `cpu governor` warns: the governor pins the lowest frequency; switch to `schedutil` or `performance` for the session. On a Mac, `doctor` does not show `clocksource`, `cpu governor`, `offloads` or `wifi link stats`, which do not apply there; `sleep assertion` warns when the probe cannot keep the Mac from idle sleep, so keep it awake yourself (lid open, on power, `caffeinate -i` as in step 3). `pacing` warns on a Mac when the pacer wakes 1 ms or more late: `pathtrace` was started under a QoS clamp or the background policy (`taskpolicy`, a launchd service, a CI runner) or the host is busy; run it from a Terminal session with other work closed. `probe` repeats the warning on stderr before it starts measuring; the session still runs and records the lateness, and the warning alone does not make the trace partial.
   - `offloads` warns: `rx-gro-list` or `rx-lro` is on for the egress interface, which changes what the probe records on this host. Run the `sudo ethtool -K …` command the warning prints (it lasts until reboot or until the interface is recreated), then run `doctor` again. Run `pathtrace doctor` on the responder too: its default-route interface is checked the same way. `rx-gro` and the segmentation offloads are listed but do not warn.
   - `tunnel` warns: the route to the responder leaves through a tunnel (Tailscale, WireGuard, another VPN; `utun*` on a Mac). The session still runs, but per-transport treatment, policers, MTU, DSCP and ECN in the trace describe the tunnel, not the network under it. To record the network itself, disconnect the VPN or exclude the responder from it, then run `doctor` again. With an overlay responder (reachable only over Tailscale, step 4) the warning is expected: record anyway, and read the trace within the limits in [responder-deploy.md](responder-deploy.md#overlay-responder-tailscale) (`trace info` shows `overlay`, and the tunnel-limited verdicts carry `overlay_limited: true`).
   - `ipv6` warns: the network or the responder has no IPv6, so only IPv4 is tested (and the probe uses IPv4). Checks with an ` (ipv6)` suffix cover the second family when both exist.

## Run

```sh
cd ~/traces
pathtrace probe vm --class <class> --label "<venue / notes>" [--mobility walking|vehicle|train|flight] [--tag <tag>]…
```

- `--class` is one of `home office hotel-wifi cafe airport cellular-4g cellular-5g train in-flight tether satellite lab other`.
- `--label` is free text (for example, "Hotel X lobby 3rd floor"). Redaction removes it before sharing.
- The profile defaults to `auto`: `light` (≤ 2 MB) on metered connections (on Linux as NetworkManager reports them; on macOS a path the system marks as expensive, such as cellular or Personal Hotspot, or constrained by Low Data Mode), `standard` (≤ 200 MB sent per endpoint, so up to about 400 MB through the laptop's link, about 100 s) otherwise. The probe prints its choice first (`[pathtrace] profile auto: …`). When the system gives no metered state (on Linux no NetworkManager) `auto` cannot tell, picks `standard`, and prints a `warning: profile auto: standard, but the metered state … is unknown` line: on a metered or capped connection (hotspot, roaming SIM, in-flight Wi-Fi) pass `--profile light` yourself. Phone hotspots are usually not flagged as metered even with NetworkManager, so check the printed state. `deep` adds `--track-secs` (default 600) of tracking with periodic short saturations, for trains and flights. On fast connections the saturation phases get shorter so that every phase fits the cap.

On a capped mobile plan, bound what the session costs with `--data-cap <bytes>` (for example `--profile standard --data-cap 30000000`): each endpoint sends at most that much, so the laptop's link carries at most twice it. The session takes as long as without the flag, but the saturations get shorter, and those that would get under 1 MB are skipped. 20–50 MB still measures capacity in both directions; `--profile light` (2 MB) measures none.

Don't use the laptop's network during the session. Moving is fine: set `--mobility`, and address changes are recorded. The light trains and the PMTU ladder pause through short outages and continue afterwards.

If the responder's name has both an IPv4 and an IPv6 address, the probe uses IPv4 unless you pass `--ipv6`. When the preferred family does not work from where you are (no IPv6 on the hotel Wi-Fi, or no IPv4 on an IPv6-only or NAT64 cellular network), the probe uses the other family and prints `[pathtrace] ipv6 unusable (…); session runs over ipv4 …` (or the reverse). The trace is still complete; it records the family it ran on.

If UDP is blocked, the probe falls back to TCP (port 443, then 4433). It then measures only TCP reachability and the TCP reference flows, skips every UDP phase, and exits 3 with `note: UDP control blocked; session ran over TCP fallback`. That is a finding about the network: keep the trace.

Right after connecting, the probe prints the session id and writes `<id>.session` next to the logs. **Keep it until the trace is complete**: it is what fetches the responder's half later. Ctrl-C ends the session early but cleanly (the probe still fetches and merges, exit 3); a second Ctrl-C quits at once.

## Results

| Exit code | Meaning | Action |
|---|---|---|
| 0 | Complete trace | Nothing |
| 3 | Partial trace (for example, the responder log could not be fetched, phases failed, UDP was blocked so only TCP was measured, or you pressed Ctrl-C) | Keep it. If the responder log is missing, run `pathtrace fetch --resume <id>.session` later from any network (TLS on the responder's port, else 443), then `pathtrace merge <id>.a.ptflog <id>.b.ptflog -o <id>.ptf` and delete `<id>.session` |
| 1 | No session (responder unreachable, keys) | `pathtrace doctor vm` |
| 1 with `error: responder busy` | The responder is running another initiator's session (it runs one at a time) | Wait for that session to finish (about 2 minutes for `standard`; `deep` runs longer) and run the probe again |

Each session leaves `<id>.a.ptflog` (laptop raw log), `<id>.b.ptflog` (responder raw log) and `<id>.ptf` (merged and derived trace). **Keep all three.** The logs are the raw evidence, and the trace can always be rebuilt from them. `<id>.session` is deleted automatically once the trace is complete.

Check a trace:

```sh
pathtrace trace check <id>.ptf
pathtrace trace info <id>.ptf | head -40
pathtrace export netem <id>.ptf          # static summary as netem arguments
```

`trace info` shows `merge_checks`: `txts_implausible` should be 0 in both directions, and `txts_unexplained_a`/`txts_unexplained_b` should be 0 (otherwise the probe also warned at the end of the session). Host-side drops are separated from path loss, and `trace info` shows them per direction: `host_drops` (the receiving socket overflowed; `packets` never exceeds `socket_drops`, and `ambiguous_losses` counts losses in a socket-drop gap that could be either) and `local_qdisc_drops` (the laptop's own queue). `pathtrace trace dump <id>.ptf` shows the whole PATH section. Non-zero values are not errors, but they mean the host, not the path, lost those packets: close other traffic and retry if they are large.

## macOS initiator over Tailscale: trust checklist

For a MacBook capturing to a Linux responder that is reachable only over Tailscale (paired as `vm-ts` in [responder-deploy.md](responder-deploy.md#overlay-responder-tailscale)). Work through it in order on every network; each step says what to do when it fails. On a Mac without the Tailscale CLI integration, read `tailscale` below as `/Applications/Tailscale.app/Contents/MacOS/Tailscale`.

### 1. Pre-flight

1. Make the session directory and enter it (archive layout in step 5; `<link>` is the access link, such as `wifi`, `ethernet` or `tether`):

   ```sh
   D=~/pathtrace-field/$(date -u +%Y-%m-%d)-<class>-<link>
   mkdir -p "$D" && cd "$D"
   ```

2. Direct path, not DERP:

   ```sh
   tailscale netcheck > "$(date -u +%Y%m%dT%H%M%SZ)-tailscale-netcheck.txt"
   tailscale ping <host> | tee "$(date -u +%Y%m%dT%H%M%SZ)-tailscale-ping.txt"
   ```

   The last line must read `pong from <host> (100.x.y.z) via <public-ip>:<port> in N ms`. On `via DERP(<region>)` the traffic is relayed over TCP and a trace would record the relay: do not record. Run `tailscale ping` again (a direct path often comes up after a few pings); if it stays on DERP and the `*-tailscale-netcheck.txt` file just written shows `UDP: false`, this network blocks Tailscale's direct UDP, so record it without the overlay (a public responder) or not at all.
3. Power: plug in, and turn off Low Power Mode (System Settings > Battery).
4. Run everything from a Terminal window in the foreground, with other work closed: not from a launchd job, a CI runner, `taskpolicy` or a script started in the background. A process started that way runs under a QoS clamp or the background policy and caps the pacer.
5. On the Mac, `pathtrace doctor vm-ts`. Every line must read `ok`, except these warnings:
   - `tunnel`: `utun<N> is a tunnel (kind utun, provider tailscale): …`. Expected over the overlay; it is why step 4 sorts the facts.
   - `pacing`: `pacer wakes N ms late at best: …`. The process is clamped or the host is loaded: close other work, start a new Terminal window and run `doctor` again. If it still warns, the session still runs and records the lateness (`tx_user_lag`, `stall` events), but a→b delay and jitter carry it: keep the trace only with a note that pacing warned.
   - `clock sync`: `not synchronised: turn on "Set time and date automatically" …`. Turn it on and wait until `doctor` reports `synchronised (estimated error … us, maximum … us)`.
   - `power`: `on battery: …` or `…, Low Power Mode on: …`. Back to step 3.
   - `sleep assertion`: a session cannot keep the Mac awake. Start the probe as `caffeinate -i pathtrace probe …` and keep the lid open.
   - `kernel timestamps`: `kernel RX stamps false; …`. b→a arrival times are user-space and less precise; record anyway.
   - Any other warning: as in [Before each session](#before-each-session) step 5. A `FAIL` line means no session: fix it first.
6. On the responder (once per trip, and again after it rebooted), with the service's own key directory:

   ```sh
   sudo -u pathtrace env PATHTRACE_CONFIG_DIR=/var/lib/pathtrace/config pathtrace doctor
   ```

   Every line must read `ok`, except: `clock sync` (`not synchronised: start an NTP daemon …`: run `timedatectl set-ntp true` or start chrony, then run it again; a session without sync on both ends gives one-way delays you cannot trust), `offloads` (run the `sudo ethtool -K …` it prints), `kernel timestamps` or `clocksource` (record anyway; precision is lower), `cpu governor` (switch to `performance` or `schedutil`). `tunnel` reads `not a tunnel` here: the check follows the responder's default route, not the tailnet.

### 2. Session

Smoke first: on every new network, run a smoke session and go through step 3 on it before the real one. If the smoke trace fails a check there, fix the cause before spending a full session's data.

```sh
pathtrace probe vm-ts --class <class> --label "<venue / notes>" --profile smoke
pathtrace probe vm-ts --class <class> --label "<venue / notes>" [--mobility …] [--profile …]
```

| `--class` | Real session |
|---|---|
| `home`, `office`, `hotel-wifi`, `cafe`, `airport`, `lab`, `other` | default profile (`auto`) |
| `cellular-4g`, `cellular-5g`, `tether`, `satellite` | `--profile light` unless the printed `profile auto: …` line already chose `light`; add `--mobility walking` or `vehicle` when moving |
| `train` | `--mobility train --profile deep` (`--track-secs`, default 600) |
| `in-flight` | `--mobility flight --profile deep` |

The probe prints `session: <session> (trace <id>; session file …)` before measuring: note `<session>` (8 hex digits) with the venue. On a Mac it may print `warning: pacer wakes …` next; that is the `doctor` pacing warning from step 1.5, and the session continues. Right after the session, run the `tailscale ping` of step 1.2 again: a path that switched to DERP during the session changes what the trace describes.

### 3. After the session: what `trace info` must show

`pathtrace trace info <id>.ptf` prints one JSON object. Check these fields (macOS 15 ships `jq`, so `pathtrace trace info <id>.ptf --json | jq '{complete, merge_checks, host_drops, local_qdisc_drops, overlay, tx_timestamps}'` shows them alone). The initiator (the Mac) is `a`, the responder `b`.

| Field | Pass | When it fails |
|---|---|---|
| `complete` | `true` | `false` (exit 3): read the `note:` lines the probe printed. Responder log missing: `pathtrace fetch --resume <id>.session`, then `pathtrace merge <id>.a.ptflog <id>.b.ptflog -o <id>.ptf`. Phases failed or Ctrl-C: keep it as partial and note why, then rerun |
| `merge_checks.b_to_a.txts_implausible`, `merge_checks.txts_unexplained_b` | `0` (the Linux responder's TX stamps) | Keep it: the trace is usable and the raw logs keep every stamp for a later re-merge. Note it; if it repeats, compare the responder's kernel against 6.13 ([responder-deploy.md](responder-deploy.md#maintenance)) |
| `merge_checks.a_to_b`, `merge_checks.txts_unexplained_a` | all `0`, `txts_joined` `0` too | Expected on a Mac: it has no kernel TX stamps, so there is nothing to join (`tx_timestamps.a_to_b` counts only `user`) |
| `host_drops.a_to_b` (the responder's sockets) | `status: known`, `packets: 0` | Non-zero: the responder host, not the path, dropped those packets. Close what else runs on it and rerun. If `packets` is large against the loss, discard the trace from analysis (keep its files, noted as host-limited) |
| `local_qdisc_drops.b_to_a` (the responder's queue) | `status: known`, `drops: 0` | As above |
| `local_qdisc_drops.a_to_b` (the Mac's queue) | `status: unknown`, `reason: no qdisc counters recorded` | Expected: macOS has no queue-drop counter. Not a failure |
| `host_drops.b_to_a` (the Mac's sockets) | `status: known`, `packets: 0`, method `hostdrop.host-fullsock/1` | `status: unknown` with `reason: host-wide counter rose` (and `host_socket_drops`) or `host-wide counter decreased`: macOS cannot say whose socket dropped, so b→a loss may include host drops. Not a failure; note it, and rerun with other apps closed if b→a loss matters |
| `overlay` | `overlay: true`, `provider: tailscale`, `kind: utun`, `mtu: 1280` | `overlay: false` with an overlay responder: the route did not use the tailnet, so the trace is not an overlay trace; check `pathtrace responder list` names the tailnet address. `status: unknown`: the trace was written by a release before PTF 1.2; upgrade both machines |

Then `pathtrace trace check <id>.ptf` must print `valid: …`. Never delete the files of a trace that fails a row, even one discarded from analysis; note which row failed in a `notes.txt` in the session directory: a failed check is a finding about the session, and the raw logs allow a re-derivation later.

### 4. Which facts hold over the overlay

Every probe packet, of every class and transport, travels inside one WireGuard UDP flow over the Mac's `utun` interface (MTU 1280) to the responder's Tailscale endpoint.

- **End to end, valid:** delay (`base_delay`), jitter, loss, capacity, reorder, duplication (`duplicate`) and queue. These are measurements of the path the traffic took, tunnel included (its encapsulation and encryption are part of what they measure).
- **The tunnel, not the access network:** per-transport treatment (every PLCY class), policers, MTU, DSCP and ECN. The network under the tunnel sees one UDP flow, not the probe's classes, ports, protocols or codepoints, and the MTU is the tunnel's 1280. The trace marks these with `overlay_limited: true`; read them as facts about the tunnel, and record the network without the overlay when they are what you need.

### 5. Archive

Each session directory `~/pathtrace-field/<date>-<class>-<link>/` keeps, per session: `<id>.a.ptflog`, `<id>.b.ptflog`, `<id>.ptf`, and the Tailscale snapshot (the `*-tailscale-netcheck.txt` file from before and the `*-tailscale-ping.txt` files from before and after, each named by the UTC time it was taken), and `notes.txt` (the session id, venue, and any warning or failed row). A second session on the same network and day goes in the same directory: its files have their own `<id>`.

The probe fetches the responder's log itself, as `<id>.b.ptflog`. If that and `fetch --resume` both fail (the session file is lost, or the responder's port is not reachable from where you are now), copy it from the responder over SSH (on the tailnet). The service keeps it as `b.ptflog` in `/var/lib/pathtrace/state/sessions/<session>/` for 14 days ([responder-deploy.md](responder-deploy.md#maintenance)), owned by the `pathtrace` user. Copy only `b.ptflog`: the `fetch_token` next to it is a secret.

```sh
ssh -t <host> sudo ls -t /var/lib/pathtrace/state/sessions       # newest first; match <session> from step 2
ssh -t <host> sudo install -m 0644 -o '$USER' /var/lib/pathtrace/state/sessions/<session>/b.ptflog '~/<id>.b.ptflog'
scp <host>:<id>.b.ptflog .
pathtrace merge <id>.a.ptflog <id>.b.ptflog -o <id>.ptf
```

Keep overlay traces in `~/pathtrace-field/` and apart from the field corpus of #16 (`~/traces`): their tunnel-limited verdicts describe the tunnel, so they do not count toward the access-network classes there.

## Sampling plan (draft spec §12)

- Repeat sessions on the same network at different times of day. Variation within a network is often larger than between networks.
- Before trusting a class-level conclusion, aim for at least 20–30 sessions across at least 5 distinct networks in that class.
- Minimum corpus for the v1.0 field acceptance (#16): 50 traces across 4 classes.

## Privacy

Traces contain your public IP addresses, hostname, Wi-Fi BSSID (hashed), labels and timestamps. All of these are marked `pii` in the file. Never publish raw traces; share redacted copies instead:

```sh
pathtrace trace redact <id>.ptf --level shareable -o <id>.shareable.ptf   # removes identifying data
pathtrace trace redact <id>.ptf --level anonymous -o <id>.anon.ptf        # also network details, wall-clock time
```

## Later: improved derivation

Derivation methods improve over time. Re-derive any trace with the newest release:

```sh
pathtrace derive <id>.ptf                # rewrites PATH/SERS/PLCY/VALD; raw sections untouched
```
